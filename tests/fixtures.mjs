export const password = 'test-only-desktop-password';
export const account = (id = 'test-account-1') => ({ id, type: 'totp', name: '测试用户@example.test', issuer: 'Example 测试', secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', algorithm: 'SHA1', digits: 6, period: 30 });
export const snapshot = (accounts = [account()]) => ({ format: 'mixia-snapshot', v: 1, id: crypto.randomUUID(), createdAt: Date.now(), deviceName: '测试秘匣手机', allowEmpty: false, accounts });
