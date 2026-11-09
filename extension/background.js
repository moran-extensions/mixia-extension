import { randomB64, decryptJson, deriveVaultKey, sealVault, validateVaultEnvelope, createLocalKey, sealLocalVault, openLocalVault } from './lib/crypto.js';
import { emptySnapshot, validateSnapshot } from './lib/snapshot.js';
import { parseBackupFile, decryptMixiaBackup } from './lib/mixia-backup.js';
import { totp } from './lib/otp.js';

const AUTO_LOCK_MS = 5 * 60 * 1000;
const PREVIEW_MS = 2 * 60 * 1000;
let unlocked = null, pending = null, pendingTimer = null;
let operationBusy = false, modeChanging = false, generation = 0, restoring = null;
function clearPreview() { clearTimeout(pendingTimer); pendingTimer = null; pending = null; }
function lock() { generation++; unlocked = null; clearPreview(); }
function requireUnlocked(touch = false) {
  if (unlocked?.lockEnabled && Date.now() - unlocked.touched >= AUTO_LOCK_MS) lock();
  if (!unlocked) throw new Error('请先解锁电脑保险库');
  if (touch) unlocked.touched = Date.now();
  return unlocked;
}
function session(value, lockEnabled) { return { ...value, lockEnabled, codes: new Map(), touched: Date.now() }; }
async function restoreLocal() {
  if (unlocked) return;
  if (!restoring) restoring = (async () => {
    const version = generation, { vault } = await chrome.storage.local.get('vault');
    if (vault?.format !== 'mixia-local-vault') return;
    const value = await openLocalVault(vault);
    value.snapshot = validateSnapshot(value.snapshot, { initial: true });
    if (generation === version && !unlocked) unlocked = session(value, false);
  })().finally(() => { restoring = null; });
  await restoring;
}
async function prepareVault(snapshot, lockEnabled, password) {
  if (lockEnabled) {
    const salt = randomB64(16), key = await deriveVaultKey(password, salt);
    return { value: session({ key, salt, snapshot }, true), vault: { ...await sealVault(key, salt, snapshot), lockEnabled: true } };
  }
  const value = session({ ...await createLocalKey(), snapshot }, false);
  return { value, vault: await sealLocalVault(value.key, value.localKey, snapshot) };
}
async function sealState(state, snapshot) {
  return state.lockEnabled ? { ...await sealVault(state.key, state.salt, snapshot), lockEnabled: true } : sealLocalVault(state.key, state.localKey, snapshot);
}
async function status() {
  if (unlocked?.lockEnabled && Date.now() - unlocked.touched >= AUTO_LOCK_MS) lock();
  const { vault } = await chrome.storage.local.get('vault');
  return { exists: Boolean(vault), unlocked: Boolean(unlocked), count: unlocked?.snapshot.accounts.length ?? 0,
    lockEnabled: vault?.lockEnabled === true, needsMigration: Boolean(vault && vault.format === 'mixia-desktop-vault' && vault.lockEnabled !== true),
    importedAt: unlocked?.snapshot.createdAt, source: unlocked?.snapshot.deviceName,
    snapshotId: unlocked?.snapshot.id };
}
async function exclusive(action) {
  if (operationBusy) throw new Error('正在处理，请稍后再试');
  operationBusy = true;
  try { return await action(); } finally { operationBusy = false; }
}
async function handle(message) {
  await restoreLocal();
  switch (message.type) {
    case 'STATUS': return status();
    case 'SETUP': return exclusive(async () => {
      const version = generation;
      if ((await chrome.storage.local.get('vault')).vault) throw new Error('保险库已经存在，请解锁');
      const prepared = await prepareVault(emptySnapshot(), message.lockEnabled === true, message.password);
      if (generation !== version) throw new Error('设置已取消，请重试');
      await chrome.storage.local.set({ vault: prepared.vault });
      if (generation === version) unlocked = prepared.value;
      return status();
    });
    case 'UNLOCK': return exclusive(async () => {
      if (unlocked) return status();
      const version = generation;
      const { vault } = await chrome.storage.local.get('vault');
      validateVaultEnvelope(vault);
      let key, snapshot;
      try {
        key = await deriveVaultKey(message.password, vault.salt);
        snapshot = validateSnapshot(await decryptJson(key, vault, 'mixia-vault/v1'), { initial: true });
      } catch { throw new Error('电脑解锁密码不正确，或保险库已损坏'); }
      if (generation !== version) throw new Error('解锁已取消');
      if (vault.lockEnabled === true) unlocked = session({ key, salt: vault.salt, snapshot }, true);
      else {
        // Existing password-encrypted data needs one authenticated migration.
        const prepared = await prepareVault(snapshot, false);
        if (generation !== version) throw new Error('解锁已取消');
        modeChanging = true;
        try {
          await chrome.storage.local.set({ vault: prepared.vault });
          if (generation === version) unlocked = prepared.value;
        } finally { modeChanging = false; }
      }
      return status();
    });
    case 'SET_LOCK': return exclusive(async () => {
      if (typeof message.enabled !== 'boolean') throw new Error('锁屏设置无效');
      const state = requireUnlocked(true);
      if (state.lockEnabled === message.enabled) return status();
      modeChanging = true;
      try {
        const prepared = await prepareVault(state.snapshot, message.enabled, message.password);
        if (unlocked !== state) throw new Error('设置已取消，请重新解锁');
        await chrome.storage.local.set({ vault: prepared.vault });
        unlocked = prepared.value; clearPreview();
        return status();
      } finally { modeChanging = false; }
    });
    case 'LOCK': {
      if (modeChanging) throw new Error('正在更新锁屏设置，请稍后再试');
      const { vault } = await chrome.storage.local.get('vault');
      if (modeChanging) throw new Error('正在更新锁屏设置，请稍后再试');
      if (vault?.format !== 'mixia-desktop-vault') throw new Error('请先开启锁屏密码');
      lock(); return status();
    }
    case 'TOUCH': requireUnlocked(true); return { ok: true };
    case 'CODES': {
      const state = requireUnlocked(), now = Date.now();
      const accounts = await Promise.all(state.snapshot.accounts.map(async account => {
        const counter = Math.floor(now / 1000 / account.period);
        let cached = state.codes.get(account.id);
        if (!cached || cached.counter !== counter) {
          cached = { counter, ...await totp(account, now) };
          state.codes.set(account.id, cached);
        }
        return { id: account.id, name: account.name, issuer: account.issuer, code: cached.code, remaining: account.period - (Math.floor(now / 1000) % account.period), period: account.period };
      }));
      if (unlocked !== state) throw new Error('保险库已锁定');
      return { accounts, snapshotId: state.snapshot.id };
    }
    case 'IMPORT_PREVIEW': return exclusive(async () => {
      const state = requireUnlocked(true);
      clearPreview();
      const value = parseBackupFile(message.text);
      let snapshot, source;
      if (value.format === 'mixia-desktop-vault') {
        const backup = validateVaultEnvelope(value);
        try {
          const key = await deriveVaultKey(message.password, backup.salt);
          snapshot = validateSnapshot(await decryptJson(key, backup, 'mixia-vault/v1'), { initial: true });
        } catch { throw new Error('电脑备份密码不正确，或备份已损坏'); }
        source = '电脑加密备份';
      } else {
        snapshot = await decryptMixiaBackup(value, message.password);
        source = '秘匣手机备份';
      }
      if (unlocked !== state) throw new Error('保险库已锁定，请重新解锁后导入');
      const token = crypto.randomUUID();
      pending = { token, snapshot, state, source, baseId: state.snapshot.id, expires: Date.now() + PREVIEW_MS };
      pendingTimer = setTimeout(() => { if (pending?.token === token) clearPreview(); }, PREVIEW_MS);
      return { token, count: snapshot.accounts.length, currentCount: state.snapshot.accounts.length, source,
        examples: snapshot.accounts.slice(0, 5).map(item => ({ name: item.name, issuer: item.issuer })) };
    });
    case 'IMPORT_COMMIT': return exclusive(async () => {
      const state = requireUnlocked(true), preview = pending;
      if (!preview || typeof message.token !== 'string' || preview.token !== message.token || preview.state !== state || preview.baseId !== state.snapshot.id || Date.now() >= preview.expires) throw new Error('导入预览已失效，请重新解密文件');
      if (!preview.snapshot.accounts.length && message.allowEmpty !== true) throw new Error('请勾选确认清空电脑账户');
      const snapshot = { ...preview.snapshot, id: crypto.randomUUID(), createdAt: Date.now(), deviceName: preview.source, allowEmpty: preview.snapshot.accounts.length === 0 };
      const encrypted = await sealState(state, snapshot);
      if (unlocked !== state || pending !== preview || Date.now() >= preview.expires) throw new Error('导入已取消或保险库已锁定');
      await chrome.storage.local.set({ vault: encrypted });
      if (unlocked === state) { state.snapshot = snapshot; state.codes = new Map(); state.touched = Date.now(); }
      clearPreview();
      return status();
    });
    case 'IMPORT_CANCEL': {
      if (typeof message.token === 'string' && message.token === pending?.token) clearPreview();
      return { ok: true };
    }
    case 'BACKUP': {
      const state = requireUnlocked(true);
      if (state.lockEnabled) {
        const backup = await sealVault(state.key, state.salt, state.snapshot);
        if (unlocked !== state) throw new Error('账户已更新，请重新导出');
        return backup;
      }
      if (typeof message.password !== 'string' || message.password.length < 10 || message.password.length > 1024) throw new Error('加密备份密码需为 10–1024 个字符');
      const salt = randomB64(16), key = await deriveVaultKey(message.password, salt);
      const backup = await sealVault(key, salt, state.snapshot);
      if (unlocked !== state) throw new Error('账户已更新，请重新导出');
      return backup;
    }
    default: throw new Error('不支持的操作');
  }
}
chrome.runtime.onMessage.addListener((message, sender, respond) => {
  if (sender.id !== chrome.runtime.id || !sender.url?.startsWith(chrome.runtime.getURL('')) || !message || typeof message.type !== 'string') return false;
  handle(message).then(data => respond({ ok: true, data }), error => respond({ ok: false, error: error.message || '操作未完成，请重试；原账户仍然保留' }));
  return true;
});
chrome.alarms.create('auto-lock', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener(() => { if (unlocked?.lockEnabled && Date.now() - unlocked.touched >= AUTO_LOCK_MS) lock(); });
