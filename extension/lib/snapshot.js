import { decodeBase32 } from './otp.js';
function text(value, label, max, empty = false) {
  if (typeof value !== 'string' || value.length > max || (!empty && !value.trim()) || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value)) throw new Error(`${label}无效`);
  return value;
}
export function validateSnapshot(value, { initial = false } = {}) {
  if (!value || value.format !== 'mixia-snapshot' || value.v !== 1 || !Array.isArray(value.accounts) || value.accounts.length > 2000) throw new Error('不支持的账户数据，最多支持 2000 个账户');
  const id = text(value.id, '快照编号', 128);
  const deviceName = text(value.deviceName, '手机名称', 128, true);
  if (!Number.isSafeInteger(value.createdAt) || value.createdAt < 0) throw new Error('快照时间无效');
  if (!value.accounts.length && !initial && value.allowEmpty !== true) throw new Error('请明确确认空备份将清空电脑账户');
  const seen = new Set();
  const accounts = value.accounts.map(item => {
    if (!item || item.type !== 'totp') throw new Error('当前版本仅支持 TOTP 时间验证码，未覆盖电脑数据');
    const uuid = text(item.id, '账户编号', 128);
    if (seen.has(uuid)) throw new Error('同步包含重复账户编号');
    seen.add(uuid);
    if (!['SHA1', 'SHA256', 'SHA512'].includes(item.algorithm) || ![6, 7, 8, 9, 10].includes(item.digits) || !Number.isSafeInteger(item.period) || item.period < 1) throw new Error('账户验证码参数无效');
    decodeBase32(item.secret).fill(0);
    return { id: uuid, type: 'totp', name: text(item.name, '账户名称', 512, true), issuer: text(item.issuer, '发行方', 512, true), secret: item.secret.replace(/[\s=-]/g, '').toUpperCase(), algorithm: item.algorithm, digits: item.digits, period: item.period };
  });
  return { format: 'mixia-snapshot', v: 1, id, createdAt: value.createdAt, deviceName, allowEmpty: value.allowEmpty === true, accounts };
}
export function emptySnapshot() {
  return { format: 'mixia-snapshot', v: 1, id: crypto.randomUUID(), createdAt: Date.now(), deviceName: '', allowEmpty: true, accounts: [] };
}
