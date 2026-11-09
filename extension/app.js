const $ = id => document.getElementById(id);
let state, busy = false, refreshing = false, accountVersion = '', accounts = [], preview = null, importRevision = 0;
const cards = new Map();
const popup = location.pathname.endsWith('/popup.html');
let wantsImport = new URL(location.href).searchParams.has('import');
let securityAction = 'lock';
let messageTimer;
if (popup) document.body.classList.add('popup'); else $('expand').hidden = true;
async function send(type, extra = {}) {
  const result = await chrome.runtime.sendMessage({ type, ...extra });
  if (!result?.ok) throw new Error(result?.error || '操作未完成，请重试');
  return result.data;
}
function message(text, success = false) {
  clearTimeout(messageTimer); $('message').textContent = text; $('message').hidden = !text; $('message').classList.toggle('success', success);
  if (text && success) messageTimer = setTimeout(() => message(''), 2200);
}
function closeSettings() { if ($('settings-dialog').open) $('settings-dialog').close(); }
async function action(fn) {
  if (busy) return;
  busy = true;
  for (const button of document.querySelectorAll('button')) button.disabled = true;
  try { await fn(); } catch (error) { message(error.message); }
  finally { busy = false; for (const button of document.querySelectorAll('button')) button.disabled = false; renderPreview(); await refresh(); }
}
function render() {
  $('auth').hidden = state.unlocked; $('lock').hidden = !state.unlocked || !state.lockEnabled; $('accounts-view').hidden = !state.unlocked;
  $('settings-open').hidden = !state.unlocked; $('count').hidden = !state.unlocked;
  const needsPassword = state.exists || $('setup-lock').checked;
  $('setup-lock-row').hidden = state.exists;
  $('auth-password-fields').hidden = !needsPassword; $('password').required = needsPassword; $('password').disabled = !needsPassword;
  $('confirm-field').hidden = state.exists;
  $('confirm').required = !state.exists && needsPassword; $('confirm').disabled = state.exists || !needsPassword;
  $('password').autocomplete = state.exists ? 'current-password' : 'new-password';
  $('auth-title').textContent = state.needsMigration ? '完成一次升级' : state.exists ? '欢迎回来' : '把秘匣带到电脑';
  $('auth-copy').textContent = state.needsMigration ? '输入一次原电脑密码，转换后默认免解锁。以后需要锁屏时，可在右上角设置中主动开启。' : state.exists ? '解锁本机保险库，查看你的验证码。手机不在身边，也可以使用。' : '默认直接打开验证码。你也可以主动开启锁屏密码。手机备份密码会在选择文件后单独输入。';
  $('auth-submit').textContent = state.needsMigration ? '确认并启用免解锁' : state.exists ? '解锁验证码' : needsPassword ? '设置密码并导入' : '开始导入';
  $('auth-note').textContent = state.exists && !state.needsMigration ? '五分钟无操作自动锁定。电脑密码与手机备份密码相互独立。' : '免解锁时，可使用此浏览器资料的人也可查看验证码。';
  $('lock-enabled').checked = state.lockEnabled;
  $('lock-enabled').disabled = busy;
  $('lock-help').textContent = state.lockEnabled ? '已开启：五分钟无操作或浏览器重启后需输入密码。' : '已关闭：直接查看验证码；可使用此浏览器资料的人也可查看。';
  if (!state.unlocked) {
    if ($('import-dialog').open) $('import-dialog').close();
    if ($('security-dialog').open) $('security-dialog').close();
    closeSettings();
    accounts = []; cards.clear(); $('account-list').replaceChildren(); accountVersion = ''; $('search').value = '';
    return;
  }
  $('count').textContent = String(state.count); $('empty').hidden = Boolean(state.count); $('search-wrap').hidden = !state.count;
  $('backup').disabled = busy || !state.count;
  $('import-info').textContent = state.source ? `${state.source} · ${new Date(state.importedAt).toLocaleString('zh-CN')}` : '尚未导入账户';
}
function filter() {
  const query = $('search').value.trim().toLocaleLowerCase(); let matches = 0;
  for (const item of accounts) {
    const card = cards.get(item.id); if (!card) continue;
    card.hidden = !`${item.name} ${item.issuer}`.toLocaleLowerCase().includes(query);
    if (!card.hidden) matches++;
  }
  $('account-list').hidden = !matches;
  $('no-results').hidden = !accounts.length || Boolean(matches);
}
function drawAccounts(data) {
  accounts = data.accounts;
  if (accountVersion !== data.snapshotId) {
    cards.clear(); $('account-list').replaceChildren();
    for (const item of accounts) {
      const button = document.createElement('button'); button.className = 'account'; button.type = 'button'; button.title = '点击复制验证码';
      const avatar = document.createElement('span'); avatar.className = 'avatar'; avatar.textContent = (item.issuer || item.name || '秘').slice(0, 1).toUpperCase(); avatar.setAttribute('aria-hidden', 'true');
      const text = document.createElement('span'); text.className = 'account-text';
      for (const [cls, value] of [['issuer', item.issuer || '未命名发行方'], ['account-name', item.name], ['code', '']]) { const node = document.createElement('div'); node.className = cls; node.textContent = value; text.append(node); }
      const timer = document.createElement('span'); timer.className = 'timer'; const progress = document.createElement('progress'); progress.setAttribute('aria-label', '验证码剩余有效期'); const seconds = document.createElement('span'); seconds.className = 'seconds'; timer.append(progress, seconds);
      button.append(avatar, text, timer);
      button.addEventListener('click', () => action(async () => {
        await send('TOUCH'); const latest = (await send('CODES')).accounts.find(account => account.id === item.id);
        if (!latest) throw new Error('账户已更新，请重新选择');
        await navigator.clipboard.writeText(latest.code); message('验证码已复制', true);
      }));
      cards.set(item.id, button); $('account-list').append(button);
    }
    accountVersion = data.snapshotId;
  }
  for (const item of accounts) {
    const card = cards.get(item.id); if (!card) continue;
    card.querySelector('.code').textContent = item.code.length === 6 ? item.code.slice(0, 3) + ' ' + item.code.slice(3) : item.code;
    card.querySelector('.seconds').textContent = `${item.remaining}s`;
    const progress = card.querySelector('progress'); progress.max = item.period; progress.value = item.remaining;
    card.classList.toggle('urgent', item.remaining <= 5); card.setAttribute('aria-label', `${item.issuer} ${item.name}，点击复制验证码`);
  }
  filter();
}
async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    state = await send('STATUS'); render();
    if (state.unlocked) {
      drawAccounts(await send('CODES'));
      if (wantsImport) { wantsImport = false; openImport(); }
    }
  } catch (error) { message(error.message); }
  finally { refreshing = false; }
}
function renderPreview() {
  const ready = Boolean(preview);
  $('import-preview').hidden = !ready; $('import-password-field').hidden = ready; $('import-password').required = !ready; $('import-password').disabled = ready;
  $('decrypt-import').hidden = ready; $('commit-import').hidden = !ready; $('import-again').hidden = !ready;
  if (!ready) return;
  $('preview-summary').textContent = `${preview.source} · ${preview.count} 个账户`;
  $('preview-replace').textContent = `确认后，电脑现有 ${preview.currentCount} 个账户将整体替换为文件中的 ${preview.count} 个账户。`;
  $('preview-examples').replaceChildren(...preview.examples.map(item => { const li = document.createElement('li'); li.textContent = [item.issuer, item.name].filter(Boolean).join(' · ') || '未命名账户'; return li; }));
  $('preview-more').textContent = preview.count > preview.examples.length ? `另有 ${preview.count - preview.examples.length} 个账户` : '';
  $('empty-confirm-row').hidden = preview.count !== 0;
  $('commit-import').disabled = busy || (preview.count === 0 && !$('empty-confirm').checked);
}
function resetPreview() {
  importRevision++;
  const old = preview; preview = null;
  if (old) void send('IMPORT_CANCEL', { token: old.token }).catch(() => {});
  $('import-error').textContent = ''; $('empty-confirm').checked = false; renderPreview();
}
function openImport() {
  closeSettings();
  if (popup) { chrome.tabs.create({ url: chrome.runtime.getURL('vault.html?import=1') }); return; }
  resetPreview(); $('import-dialog').showModal();
}
$('auth-form').addEventListener('submit', event => {
  event.preventDefault();
  void action(async () => {
    const first = !state.exists, password = $('password').value;
    if (first && $('setup-lock').checked && password !== $('confirm').value) throw new Error('两次输入的电脑密码不一致');
    try { state = await send(first ? 'SETUP' : 'UNLOCK', { password, lockEnabled: first && $('setup-lock').checked }); }
    finally { $('password').value = ''; $('confirm').value = ''; }
    if (first) wantsImport = true;
  });
});
$('setup-lock').onchange = render;
$('lock').onclick = () => action(async () => { await send('LOCK'); message(''); });
$('settings-open').onclick = () => { if (!$('settings-dialog').open) $('settings-dialog').showModal(); };
$('settings-close').onclick = closeSettings;
$('import-open').onclick = openImport; $('import-empty').onclick = openImport;
$('expand').onclick = () => chrome.tabs.create({ url: chrome.runtime.getURL('vault.html') });
$('privacy').onclick = () => { closeSettings(); chrome.tabs.create({ url: chrome.runtime.getURL('privacy.html') }); };
$('search').oninput = filter;
async function downloadBackup(password) {
  const data = await send('BACKUP', { password }), url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
  const link = document.createElement('a'); link.href = url; link.download = `秘匣电脑加密备份-${new Date().toISOString().slice(0, 10)}.mixia.json`; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 10000); message(state.lockEnabled ? '加密备份已导出，恢复需要导出时的电脑解锁密码。' : '加密备份已导出，恢复需要这次设置的备份密码。', true);
}
function openSecurity(purpose) {
  closeSettings();
  securityAction = purpose; $('security-error').textContent = ''; $('security-form').reset();
  $('security-title').textContent = purpose === 'lock' ? '开启锁屏密码' : '设置加密备份密码';
  $('security-copy').textContent = purpose === 'lock' ? '开启后，五分钟无操作或浏览器重启时需要此密码。' : '此密码只用于保护导出的文件，不会开启锁屏。恢复备份时需要输入。';
  $('security-submit').textContent = purpose === 'lock' ? '开启锁屏密码' : '导出备份';
  $('security-dialog').showModal(); $('security-password').focus();
}
$('backup').onclick = () => { closeSettings(); return state.lockEnabled ? action(() => downloadBackup()) : openSecurity('backup'); };
$('lock-enabled').onchange = () => {
  if ($('lock-enabled').checked) { $('lock-enabled').checked = false; openSecurity('lock'); }
  else void action(async () => { await send('SET_LOCK', { enabled: false }); message('锁屏密码已关闭，之后可直接查看验证码。', true); });
};
$('security-cancel').onclick = () => $('security-dialog').close();
$('security-dialog').addEventListener('close', () => { $('security-form').reset(); $('security-error').textContent = ''; if (state) render(); });
$('security-form').addEventListener('submit', event => {
  event.preventDefault();
  void action(async () => {
    try {
      const password = $('security-password').value;
      if (password !== $('security-confirm').value) throw new Error('两次输入的密码不一致');
      if (securityAction === 'lock') { state = await send('SET_LOCK', { enabled: true, password }); message('锁屏密码已开启。', true); }
      else await downloadBackup(password);
      $('security-dialog').close();
    } catch (error) { $('security-error').textContent = error.message; }
    finally { $('security-password').value = ''; $('security-confirm').value = ''; }
  });
});
$('import-cancel').onclick = () => $('import-dialog').close();
$('import-dialog').addEventListener('close', () => { resetPreview(); $('import-password').value = ''; $('import-file').value = ''; });
$('import-file').onchange = () => { resetPreview(); $('import-password').value = ''; };
$('import-again').onclick = () => { resetPreview(); $('import-password').focus(); };
$('empty-confirm').onchange = renderPreview;
$('import-form').addEventListener('submit', event => {
  event.preventDefault();
  void action(async () => {
    $('import-error').textContent = ''; const revision = importRevision;
    $('decrypt-import').textContent = '正在解密…';
    try {
      const file = $('import-file').files[0];
      if (!file || !file.size || file.size > 10 * 1024 * 1024) throw new Error('请选择不超过 10 MiB 的加密备份文件');
      const password = $('import-password').value; $('import-password').value = '';
      const result = await send('IMPORT_PREVIEW', { text: await file.text(), password });
      if (!$('import-dialog').open || revision !== importRevision) { await send('IMPORT_CANCEL', { token: result.token }); return; }
      preview = result; renderPreview();
    } catch (error) { if ($('import-dialog').open) $('import-error').textContent = error.message; }
    finally { $('import-password').value = ''; $('decrypt-import').textContent = '解密并预览'; }
  });
});
$('commit-import').onclick = () => action(async () => {
  if (!preview) return;
  try {
    state = await send('IMPORT_COMMIT', { token: preview.token, allowEmpty: preview.count === 0 && $('empty-confirm').checked });
    const count = state.count; $('import-dialog').close(); message(`导入完成，电脑现有 ${count} 个账户。`, true);
  } catch (error) { $('import-error').textContent = error.message; }
});
let lastTouch = 0;
for (const event of ['pointerdown', 'keydown', 'input']) document.addEventListener(event, () => {
  if (state?.unlocked && Date.now() - lastTouch > 10000) { lastTouch = Date.now(); void send('TOUCH').catch(() => {}); }
}, { passive: true });
void refresh();
setInterval(() => { if (!document.hidden && !busy) void refresh(); }, 1000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) void refresh(); });
