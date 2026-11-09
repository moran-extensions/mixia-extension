export function decodeBase32(value) {
  if (typeof value !== 'string' || value.length > 1024) throw new Error('账户密钥格式错误');
  const clean = value.replace(/[\s-]/g, '').toUpperCase();
  if (!/^[A-Z2-7]+={0,6}$/.test(clean)) throw new Error('账户密钥不是有效的 Base32');
  const text = clean.replace(/=+$/, '');
  if (![0, 2, 4, 5, 7].includes(text.length % 8)) throw new Error('账户密钥长度错误');
  let bits = 0, buffer = 0;
  const result = [];
  for (const char of text) {
    buffer = (buffer << 5) | 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(char);
    bits += 5;
    if (bits >= 8) { bits -= 8; result.push((buffer >>> bits) & 255); }
  }
  if (!result.length || result.length > 128 || (bits && (buffer & ((1 << bits) - 1)))) throw new Error('账户密钥内容错误');
  return new Uint8Array(result);
}
export async function hotp(secret, counter, algorithm = 'SHA1', digits = 6) {
  if (!Number.isSafeInteger(counter) || counter < 0 || ![6, 7, 8, 9, 10].includes(digits)) throw new Error('验证码参数无效');
  const raw = decodeBase32(secret);
  let key;
  try { key = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' }[algorithm] }, false, ['sign']); }
  finally { raw.fill(0); }
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(counter), false);
  const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, bytes));
  const offset = signature[signature.length - 1] & 15;
  const binary = new DataView(signature.buffer).getUint32(offset, false) & 0x7fffffff;
  return String(binary % (10 ** digits)).padStart(digits, '0');
}
export async function totp(account, now = Date.now()) {
  const seconds = Math.floor(now / 1000);
  return { code: await hotp(account.secret, Math.floor(seconds / account.period), account.algorithm, account.digits), remaining: account.period - (seconds % account.period), period: account.period };
}
