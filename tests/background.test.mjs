import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { password } from './fixtures.mjs';
import { randomB64, deriveVaultKey, sealVault, decryptJson } from '../extension/lib/crypto.js';
import { snapshot } from './fixtures.mjs';
const fixture = async name => readFile(new URL(`fixtures/${name}.mixia`, import.meta.url), 'utf8');
const id = 'test-extension', store = {}; let listener, failWrite = false;
globalThis.chrome = {
  storage: { local: { async get(key) { return structuredClone({ [key]: store[key] }); }, async set(value) { if (failWrite) throw new Error('quota exceeded'); Object.assign(store, structuredClone(value)); } } },
  runtime: { id, getURL: value => `chrome-extension://${id}/${value}`, onMessage: { addListener(fn) { listener = fn; } } },
  alarms: { create() {}, onAlarm: { addListener() {} } }
};
await import('../extension/background.js');
const sender = { id, url: `chrome-extension://${id}/vault.html` };
const request = (type, extra = {}) => new Promise(resolve => listener({ type, ...extra }, sender, resolve));
async function ok(type, extra) { const value = await request(type, extra); assert.equal(value.ok, true, value.error); return value.data; }
async function preview(name = 'mixia-pin6', filePassword = '012345') { return ok('IMPORT_PREVIEW', { text: await fixture(name), password: filePassword }); }
test('offline import is previewed, confirmed and atomic; cancellation, locking and recovery protect the old vault', async () => {
  try {
    assert.equal((await ok('STATUS')).exists, false);
    assert.equal((await request('SETUP', { password: 'short', lockEnabled: true })).ok, false);
    await ok('SETUP', { password, lockEnabled: true });
    const initial = structuredClone(store.vault), first = await preview();
    assert.equal(first.count, 3); assert.deepEqual(store.vault, initial);
    assert.ok(!JSON.stringify(first).includes('GEZDGNBV'));
    assert.equal((await request('IMPORT_COMMIT', { token: 'wrong-token' })).ok, false);
    await ok('IMPORT_CANCEL', { token: first.token });
    assert.equal((await request('IMPORT_COMMIT', { token: first.token })).ok, false);
    const second = await preview(); await ok('IMPORT_COMMIT', { token: second.token });
    assert.equal((await ok('CODES')).accounts.length, 3);
    const backup = await ok('BACKUP'), saved = structuredClone(store.vault);
    assert.ok(!JSON.stringify(store).includes('GEZDGNBV')); assert.ok(!JSON.stringify(store).includes(password));
    assert.equal((await request('IMPORT_PREVIEW', { text: await fixture('mixia-pin6'), password: 'wrong' })).ok, false);
    assert.equal((await request('IMPORT_PREVIEW', { text: await fixture('mixia-hotp'), password: '012345' })).ok, false);
    assert.deepEqual(store.vault, saved);
    const empty = await preview('mixia-empty');
    assert.equal((await request('IMPORT_COMMIT', { token: empty.token })).ok, false); assert.deepEqual(store.vault, saved);
    const one = await preview('mixia-one'); failWrite = true;
    assert.equal((await request('IMPORT_COMMIT', { token: one.token })).ok, false); assert.deepEqual(store.vault, saved);
    failWrite = false; await ok('IMPORT_COMMIT', { token: one.token });
    assert.deepEqual((await ok('CODES')).accounts.map(item => item.id), ['fixture-two']);
    const restore = await ok('IMPORT_PREVIEW', { text: JSON.stringify(backup), password });
    assert.equal(restore.count, 3); await ok('IMPORT_COMMIT', { token: restore.token });
    assert.equal((await ok('CODES')).accounts.length, 3);
    const older = await preview(), newer = await preview('mixia-one');
    await ok('IMPORT_CANCEL', { token: older.token });
    assert.equal((await request('IMPORT_COMMIT', { token: older.token })).ok, false);
    await ok('IMPORT_COMMIT', { token: newer.token });
    const expiring = await preview(); const clock = Date.now; Date.now = () => clock() + 121000;
    try { assert.equal((await request('IMPORT_COMMIT', { token: expiring.token })).ok, false); } finally { Date.now = clock; }
    const pending = request('IMPORT_PREVIEW', { text: await fixture('mixia-pin6'), password: '012345' });
    await new Promise(resolve => setTimeout(resolve, 5)); await ok('LOCK');
    assert.equal((await pending).ok, false); assert.equal((await request('CODES')).ok, false);
    const pendingUnlock = request('UNLOCK', { password });
    await new Promise(resolve => setTimeout(resolve, 5)); await ok('LOCK'); assert.equal((await pendingUnlock).ok, false);
    await ok('UNLOCK', { password }); assert.equal((await ok('CODES')).accounts.length, 1);
    const clearing = await preview('mixia-empty'); await ok('IMPORT_COMMIT', { token: clearing.token, allowEmpty: true });
    assert.equal((await ok('CODES')).accounts.length, 0);
    const now = Date.now; Date.now = () => now() + 301000;
    try { assert.equal((await ok('STATUS')).unlocked, false); } finally { Date.now = now; }
    assert.equal((await request('ADD_ACCOUNT')).ok, false); assert.equal((await request('PAIR_START')).ok, false);
    assert.equal(listener({ type: 'STATUS' }, { id: 'other', url: 'https://evil.test' }, () => {}), false);
  } finally { failWrite = false; await request('LOCK'); }
});
test('lock is opt-in, persists across worker restarts, and exports remain independently password-encrypted', async () => {
  delete store.vault;
  await import('../extension/background.js?password-free');
  let state = await ok('SETUP');
  assert.equal(state.lockEnabled, false); assert.equal(state.unlocked, true);
  const first = await preview(); await ok('IMPORT_COMMIT', { token: first.token });
  const saved = structuredClone(store.vault);
  assert.equal(saved.format, 'mixia-local-vault');
  assert.ok(!JSON.stringify(saved).includes('GEZDGNBV'));
  assert.equal((await request('LOCK')).ok, false);
  const clock = Date.now; Date.now = () => clock() + 301000;
  try { assert.equal((await ok('STATUS')).unlocked, true); assert.equal((await ok('CODES')).accounts.length, 3); } finally { Date.now = clock; }
  await import('../extension/background.js?password-free-restart');
  assert.equal((await ok('STATUS')).unlocked, true);
  assert.equal((await ok('CODES')).accounts.length, 3);
  assert.equal((await request('BACKUP')).ok, false);
  const file = await ok('BACKUP', { password });
  assert.equal(file.format, 'mixia-desktop-vault'); assert.equal(file.localKey, undefined);
  assert.ok(!JSON.stringify(file).includes(store.vault.localKey));
  assert.equal((await decryptJson(await deriveVaultKey(password, file.salt), file, 'mixia-vault/v1')).accounts.length, 3);
  assert.equal((await ok('STATUS')).lockEnabled, false);
  failWrite = true;
  try { assert.equal((await request('SET_LOCK', { enabled: true, password })).ok, false); assert.deepEqual(store.vault, saved); } finally { failWrite = false; }
  assert.equal((await request('SET_LOCK', { enabled: true, password: 'short' })).ok, false);
  state = await ok('SET_LOCK', { enabled: true, password });
  assert.equal(state.lockEnabled, true); assert.equal(store.vault.localKey, undefined);
  assert.ok(!JSON.stringify(store.vault).includes(password));
  await ok('LOCK'); assert.equal((await request('CODES')).ok, false);
  assert.equal((await request('UNLOCK', { password: 'incorrect-password' })).ok, false);
  await ok('UNLOCK', { password });
  await import('../extension/background.js?password-protected-restart');
  assert.equal((await ok('STATUS')).unlocked, false);
  await ok('UNLOCK', { password });
  const protectedVault = structuredClone(store.vault);
  failWrite = true;
  try { assert.equal((await request('SET_LOCK', { enabled: false })).ok, false); assert.deepEqual(store.vault, protectedVault); } finally { failWrite = false; }
  await ok('SET_LOCK', { enabled: false });
  await import('../extension/background.js?disabled-restart');
  assert.equal((await ok('STATUS')).unlocked, true); assert.equal((await ok('CODES')).accounts.length, 3);
  assert.equal((await ok('STATUS')).lockEnabled, false);
});
test('existing vaults require one old-password authentication before migrating without losing accounts', async () => {
  const salt = randomB64(16);
  store.vault = await sealVault(await deriveVaultKey(password, salt), salt, snapshot());
  const old = structuredClone(store.vault);
  await import('../extension/background.js?legacy-migration');
  assert.equal((await ok('STATUS')).needsMigration, true);
  assert.equal((await request('CODES')).ok, false);
  assert.equal((await request('UNLOCK', { password: 'incorrect-password' })).ok, false);
  assert.deepEqual(store.vault, old);
  failWrite = true;
  try { assert.equal((await request('UNLOCK', { password })).ok, false); assert.deepEqual(store.vault, old); } finally { failWrite = false; }
  const state = await ok('UNLOCK', { password });
  assert.equal(state.needsMigration, false); assert.equal(state.lockEnabled, false);
  const ids = (await ok('CODES')).accounts.map(item => item.id);
  await import('../extension/background.js?legacy-migration-restart');
  assert.equal((await ok('STATUS')).unlocked, true);
  assert.deepEqual((await ok('CODES')).accounts.map(item => item.id), ids);
});
