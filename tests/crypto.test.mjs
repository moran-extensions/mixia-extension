import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hotp, totp, decodeBase32 } from '../extension/lib/otp.js';
import { randomB64, encryptJson, decryptJson, deriveVaultKey, sealVault, validateVaultEnvelope, MAX_BYTES, b64, unb64, createLocalKey, sealLocalVault, openLocalVault } from '../extension/lib/crypto.js';
import { validateSnapshot } from '../extension/lib/snapshot.js';
import { account, snapshot, password } from './fixtures.mjs';
function base32(bytes) { let bits = 0, value = 0, text = ''; for (const byte of bytes) { value = (value << 8) | byte; bits += 8; while (bits >= 5) { bits -= 5; text += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[(value >>> bits) & 31]; } } if (bits) text += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[(value << (5 - bits)) & 31]; return text; }
test('RFC 4226: ten standard HOTP vectors for the shared TOTP engine', async () => {
  const secret = base32(Buffer.from('12345678901234567890'));
  for (const [counter, code] of ['755224','287082','359152','969429','338314','254676','287922','162583','399871','520489'].entries()) assert.equal(await hotp(secret, counter), code);
});
for (const [algorithm, length, codes] of [
  ['SHA1',20,['94287082','07081804','14050471','89005924','69279037','65353130']],
  ['SHA256',32,['46119246','68084774','67062674','91819424','90698825','77737706']],
  ['SHA512',64,['90693936','25091201','99943326','93441116','38618901','47863826']]
]) test(`RFC 6238: ${algorithm}, six standard timestamps`, async () => {
  const secret = base32(Buffer.from('1234567890'.repeat(7).slice(0, length)));
  for (const [i, time] of [59,1111111109,1111111111,1234567890,2000000000,20000000000].entries()) assert.equal((await totp({ secret, algorithm, digits: 8, period: 30 }, time * 1000)).code, codes[i]);
});
test('countdown, rollover and one-second period match phone parameters', async () => {
  assert.equal((await totp(account(), 59000)).remaining, 1); assert.equal((await totp(account(), 60000)).remaining, 30);
  assert.equal(validateSnapshot(snapshot([{ ...account(), period: 1 }])).accounts[0].period, 1);
  for (const value of ['', 'A', 'ABC', 'MZ', '1234']) assert.throws(() => decodeBase32(value));
});
test('snapshot validation rejects duplicate IDs, bad parameters and unsupported account types', () => {
  for (const values of [[account(), account()], [{ ...account(), type: 'hotp' }], [{ ...account(), period: 0 }], [{ ...account(), digits: 5 }], [{ ...account(), secret: 'MZ' }]]) assert.throws(() => validateSnapshot(snapshot(values)));
});
test('vault encryption, tampering, bounded KDF and password-independent file recovery', async () => {
  const salt = randomB64(16), key = await deriveVaultKey(password, salt), value = snapshot();
  const vault = validateVaultEnvelope(await sealVault(key, salt, value));
  assert.ok(!JSON.stringify(vault).includes(account().secret));
  assert.deepEqual(await decryptJson(await deriveVaultKey(password, salt), vault, 'mixia-vault/v1'), value);
  await assert.rejects(decryptJson(await deriveVaultKey('wrong-test-password', salt), vault, 'mixia-vault/v1'));
  await assert.rejects(decryptJson(key, vault, 'wrong-context'));
  assert.throws(() => validateVaultEnvelope({ ...vault, iterations: 999999999 }));
  await assert.rejects(deriveVaultKey('012345', salt));
  await assert.rejects(encryptJson(key, { text: 'a'.repeat(MAX_BYTES) }, 'oversized'));
});
test('large Base64 uses bounded memory-friendly chunks and rejects malformed data', () => {
  const value = new Uint8Array(700000).fill(255); assert.deepEqual(unb64(b64(value)), value);
  for (const text of ['A', 'AAAA=', 'AA=A', '*===']) assert.throws(() => unb64(text));
});
test('password-free profile storage restores non-extractable keys and rejects corrupted envelopes', async () => {
  const { key, localKey } = await createLocalKey();
  assert.equal(key.extractable, false);
  const value = snapshot(), stored = await sealLocalVault(key, localKey, value);
  assert.deepEqual((await openLocalVault(stored)).snapshot, value);
  await assert.rejects(openLocalVault({ ...stored, localKey: b64(new Uint8Array(32)) }));
  await assert.rejects(openLocalVault({ ...stored, localKey: b64(new Uint8Array(16)) }));
  await assert.rejects(openLocalVault({ ...stored, v: 2 }));
});
