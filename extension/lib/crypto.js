const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
export const ITERATIONS = 600000;
export const MAX_BYTES = 6 * 1024 * 1024;
export function b64(bytes) {
  const value = new Uint8Array(bytes), chunks = [];
  for (let offset = 0; offset < value.length; offset += 32768) chunks.push(String.fromCharCode(...value.subarray(offset, offset + 32768)));
  return btoa(chunks.join(''));
}
export function unb64(text, max = MAX_BYTES + 16) {
  if (typeof text !== 'string' || text.length > Math.ceil(max / 3) * 4 || text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) throw new Error('加密数据格式错误');
  const bytes = Uint8Array.from(atob(text), c => c.charCodeAt(0));
  if (bytes.length > max) throw new Error('数据超过大小限制');
  return bytes;
}
export function randomB64(length) { return b64(crypto.getRandomValues(new Uint8Array(length))); }
export async function encryptJson(key, value, aad) {
  const plain = encoder.encode(JSON.stringify(value));
  if (plain.byteLength > MAX_BYTES) { plain.fill(0); throw new Error('账户数据超过 6 MiB 限制'); }
  const iv = crypto.getRandomValues(new Uint8Array(12));
  try {
    const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(aad), tagLength: 128 }, key, plain);
    return { iv: b64(iv), ciphertext: b64(data) };
  } finally { plain.fill(0); }
}
export async function decryptJson(key, envelope, aad) {
  if (!envelope || typeof envelope !== 'object') throw new Error('缺少加密数据');
  const iv = unb64(envelope.iv, 12);
  const data = unb64(envelope.ciphertext);
  if (iv.length !== 12 || data.length < 16) throw new Error('加密数据格式错误');
  let plain;
  try {
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(aad), tagLength: 128 }, key, data));
    return JSON.parse(decoder.decode(plain));
  } finally { plain?.fill(0); }
}
export function validateVaultEnvelope(value) {
  if (!value || value.format !== 'mixia-desktop-vault' || value.v !== 1 || value.kdf !== 'PBKDF2-SHA256' || value.iterations !== ITERATIONS || unb64(value.salt, 16).length !== 16) throw new Error('不支持的保险库格式');
  if (unb64(value.iv, 12).length !== 12 || unb64(value.ciphertext).length < 16) throw new Error('保险库已损坏');
  return value;
}
export async function deriveVaultKey(password, salt) {
  if (typeof password !== 'string' || password.length < 10 || password.length > 1024) throw new Error('电脑解锁密码需为 10–1024 个字符');
  const bytes = encoder.encode(password);
  try {
    const base = await crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveKey']);
    return await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: unb64(salt, 16), iterations: ITERATIONS }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } finally { bytes.fill(0); }
}
export async function sealVault(key, salt, snapshot) {
  return { format: 'mixia-desktop-vault', v: 1, kdf: 'PBKDF2-SHA256', iterations: ITERATIONS, salt, ...await encryptJson(key, snapshot, 'mixia-vault/v1') };
}
// In password-free mode the browser profile holds the key. This is convenience
// storage, not password protection; exported backups always use a separate password.
export async function createLocalKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  try {
    return { key: await crypto.subtle.importKey('raw', bytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']), localKey: b64(bytes) };
  } finally { bytes.fill(0); }
}
export async function sealLocalVault(key, localKey, snapshot) {
  return { format: 'mixia-local-vault', v: 1, localKey, ...await encryptJson(key, snapshot, 'mixia-local-vault/v1') };
}
export async function openLocalVault(vault) {
  if (vault?.format !== 'mixia-local-vault' || vault.v !== 1) throw new Error('不支持的本机账户格式');
  const bytes = unb64(vault.localKey, 32);
  try {
    if (bytes.length !== 32) throw new Error('本机账户密钥已损坏');
    const key = await crypto.subtle.importKey('raw', bytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    return { key, localKey: vault.localKey, snapshot: await decryptJson(key, vault, 'mixia-local-vault/v1') };
  } finally { bytes.fill(0); }
}
