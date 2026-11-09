import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { decryptMixiaBackup, parseBackupFile, MAX_FILE_BYTES } from '../extension/lib/mixia-backup.js';
const fixture = async name => readFile(new URL(`fixtures/${name}.mixia`, import.meta.url), 'utf8');
test('unchanged original Mixia export: leading-zero PIN, Unicode labels, algorithms and no notes retained', async () => {
  const value = await decryptMixiaBackup(parseBackupFile(await fixture('mixia-pin6')), '012345');
  assert.equal(value.accounts.length, 3); assert.equal(value.accounts[0].name, '测试用户@example.test');
  assert.equal(value.accounts[1].algorithm, 'SHA256'); assert.equal(value.accounts[1].period, 60);
  assert.ok(!JSON.stringify(value).includes('测试备注')); assert.equal(value.allowEmpty, false);
});
test('legacy passwords and absent mode remain compatible; BOM from file transfer accepted', async () => {
  const value = parseBackupFile('\uFEFF' + await fixture('mixia-legacy')); delete value.mode;
  assert.equal((await decryptMixiaBackup(value, 'legacy-test-password')).accounts.length, 3);
});
test('empty export previews safely and HOTP rejects the whole file', async () => {
  assert.equal((await decryptMixiaBackup(parseBackupFile(await fixture('mixia-empty')), '012345')).accounts.length, 0);
  await assert.rejects(decryptMixiaBackup(parseBackupFile(await fixture('mixia-hotp')), '012345'), /HOTP/);
});
test('wrong password, damaged wrapping and damaged database never produce accounts', async () => {
  const original = parseBackupFile(await fixture('mixia-pin6'));
  await assert.rejects(decryptMixiaBackup(original, '12345'), /密码/);
  for (const field of ['wrapped_key', 'db']) {
    const copy = structuredClone(original); copy[field] = (copy[field][0] === 'A' ? 'B' : 'A') + copy[field].slice(1);
    await assert.rejects(decryptMixiaBackup(copy, '012345'), /损坏/);
  }
});
test('device-bound, unsupported and malicious KDF envelopes rejected before decryption', async () => {
  const original = parseBackupFile(await fixture('mixia-pin6'));
  for (const mode of ['device', 'biometric', 'unknown']) await assert.rejects(decryptMixiaBackup({ ...original, mode }, '012345'));
  for (const iterations of [0, -1, 99999, 2000001, Infinity, '600000']) await assert.rejects(decryptMixiaBackup({ ...original, kdf: { ...original.kdf, iterations } }, '012345'));
  await assert.rejects(decryptMixiaBackup({ ...original, version: 2 }, '012345'));
  await assert.rejects(decryptMixiaBackup({ ...original, wrapped_key_nonce: 'AAAA' }, '012345'));
});
test('plaintext, oversized and invalid file data rejected', () => {
  for (const value of ['', 'otpauth://totp/example', 'null', '[]', 'invalid', 'a'.repeat(MAX_FILE_BYTES + 1), '密'.repeat(Math.floor(MAX_FILE_BYTES / 3) + 1)]) assert.throws(() => parseBackupFile(value));
});
