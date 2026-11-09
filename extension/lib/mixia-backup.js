import { unb64, MAX_BYTES } from './crypto.js';
import { validateSnapshot } from './snapshot.js';

export const MAX_FILE_BYTES = 10 * 1024 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
export function parseBackupFile(text) {
  if (typeof text !== 'string' || !text.length || text.length > MAX_FILE_BYTES || encoder.encode(text).length > MAX_FILE_BYTES) throw new Error('备份文件为空或超过 10 MiB');
  let value;
  try { value = JSON.parse(text.replace(/^\uFEFF/, '')); } catch { throw new Error('备份文件格式错误，请选择秘匣导出的加密备份'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('备份文件格式错误');
  return value;
}
function bytes(value, size) {
  const result = unb64(value, size);
  if (result.length !== size) throw new Error('备份加密参数无效');
  return result;
}
async function decryptPart(key, ciphertext, nonce, tag) {
  const sealed = new Uint8Array(ciphertext.length + tag.length);
  sealed.set(ciphertext); sealed.set(tag, ciphertext.length);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: new Uint8Array(), tagLength: 128 }, key, sealed));
}
export async function decryptMixiaBackup(value, password) {
  if (value.mode === 'device' || value.mode === 'biometric') throw new Error('这是手机设备加密库，请在秘匣“设置 → 导出加密备份”导出可迁移文件');
  if (value.version !== 1 || (value.mode !== undefined && value.mode !== 'password') || value.kdf?.type !== 'PBKDF2' || value.kdf?.hash !== 'SHA256' || value.cipher?.algo !== 'AES-256-GCM') throw new Error('不支持的秘匣备份格式');
  const iterations = value.kdf.iterations;
  if (!Number.isInteger(iterations) || iterations < 100000 || iterations > 2000000) throw new Error('备份密码派生参数无效');
  const salt = bytes(value.kdf.salt, 32);
  const wrapped = bytes(value.wrapped_key, 32), wrapIv = bytes(value.wrapped_key_nonce, 12), wrapTag = bytes(value.wrapped_key_tag, 16);
  const db = unb64(value.db, MAX_FILE_BYTES), dbIv = bytes(value.cipher.nonce, 12), dbTag = bytes(value.cipher.tag, 16);
  if (!db.length) throw new Error('备份数据为空');
  if (typeof password !== 'string' || !password.length || password.length > 1024) throw new Error('请输入导出文件时设置的备份密码');
  const passwordBytes = encoder.encode(password);
  let masterBytes, plainBytes, content;
  try {
    const base = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveKey']);
    const derived = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    masterBytes = await decryptPart(derived, wrapped, wrapIv, wrapTag);
    if (masterBytes.length !== 32) throw new Error('invalid master key');
    const master = await crypto.subtle.importKey('raw', masterBytes, 'AES-GCM', false, ['decrypt']);
    masterBytes.fill(0);
    plainBytes = await decryptPart(master, db, dbIv, dbTag);
    content = JSON.parse(decoder.decode(plainBytes));
  } catch { throw new Error('备份密码不正确，或文件已损坏'); }
  finally { passwordBytes.fill(0); masterBytes?.fill(0); plainBytes?.fill(0); }
  if (!content || content.version !== 1 || !Array.isArray(content.entries) || content.entries.length > 2000) throw new Error('不支持的账户内容格式，最多支持 2000 个账户');
  const accounts = content.entries.map(entry => {
    if (!entry || entry.type !== 'totp') throw new Error('备份含 HOTP 计次账户或其他不支持的类型，当前版本仅支持 TOTP，电脑数据未更改');
    if (!entry.info || typeof entry.info !== 'object') throw new Error('备份账户信息不完整');
    return { id: entry.uuid, type: entry.type, name: entry.name, issuer: entry.issuer, secret: entry.info.secret, algorithm: entry.info.algo, digits: entry.info.digits, period: entry.info.period ?? 30 };
  });
  const snapshot = validateSnapshot({ format: 'mixia-snapshot', v: 1, id: crypto.randomUUID(), deviceName: '秘匣手机备份', createdAt: Date.now(), allowEmpty: false, accounts }, { initial: true });
  if (encoder.encode(JSON.stringify(snapshot)).length > MAX_BYTES) throw new Error('账户数据超过当前 6 MiB 上限，电脑数据未更改');
  return snapshot;
}
