import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, readdir, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import os from 'node:os';
import { password, account, snapshot } from './fixtures.mjs';
import { randomB64, deriveVaultKey, sealVault } from '../extension/lib/crypto.js';
import { totp } from '../extension/lib/otp.js';
const root = path.resolve(import.meta.dirname, '..');
const artifacts = path.join(root, '.artifacts/offline'); await mkdir(artifacts, { recursive: true });
const puppeteer = (await import(process.env.PUPPETEER_MODULE || 'puppeteer')).default;
const profile = await mkdtemp(path.join(os.tmpdir(), 'mixia-offline-'));
const downloads = path.join(profile, 'downloads'); await mkdir(downloads);
const manifest = JSON.parse(await readFile(path.join(root, 'extension/manifest.json'), 'utf8'));
assert.deepEqual([...manifest.permissions].sort(), ['alarms', 'clipboardWrite', 'storage']);
assert.equal(manifest.host_permissions, undefined);
const id = [...createHash('sha256').update(Buffer.from(manifest.key, 'base64')).digest().subarray(0, 16)].flatMap(byte => [byte >> 4, byte & 15]).map(n => String.fromCharCode(97 + n)).join('');
const origin = `chrome-extension://${id}`;
let browser; const results = [], errors = [], requests = [];
const record = value => { results.push(value); console.log('PASS ' + value); };
const send = (page, type, extra = {}) => page.evaluate(async message => { const response = await chrome.runtime.sendMessage(message); if (!response.ok) throw new Error(response.error); return response.data; }, { type, ...extra });
async function launch() {
  browser = await puppeteer.launch({ executablePath: process.env.CHROME_EXECUTABLE || undefined, headless: true, userDataDir: profile, args: [`--disable-extensions-except=${path.join(root, 'extension')}`, `--load-extension=${path.join(root, 'extension')}`, '--no-first-run', '--disable-default-apps', '--disable-background-networking', '--no-proxy-server'] });
  await browser.waitForTarget(target => target.type() === 'service_worker' && target.url() === `${origin}/background.js`, { timeout: 15000 });
  const page = await browser.newPage(); page.on('pageerror', error => errors.push(error.message));
  page.on('request', request => { if (/^https?:/.test(request.url())) requests.push(request.url()); });
  await page.setOfflineMode(true); await page.setViewport({ width: 1040, height: 900 }); await page.goto(`${origin}/vault.html`);
  return page;
}
async function choose(page, name, filePassword = '012345', open = true) {
  if (open) { const hasAccounts = (await send(page, 'STATUS')).count > 0; if (hasAccounts) await settings(page); await page.click(hasAccounts ? '#import-open' : '#import-empty'); }
  await page.waitForSelector('#import-dialog[open]');
  await (await page.$('#import-file')).uploadFile(path.isAbsolute(name) ? name : path.join(root, 'tests/fixtures', name + '.mixia'));
  await page.type('#import-password', filePassword); await page.click('#decrypt-import');
}
async function settings(page) {
  if (!await page.$eval('#settings-dialog', node => node.open)) await page.click('#settings-open');
  await page.waitForSelector('#settings-dialog[open]');
}
async function previewReady(page, count) {
  await page.waitForFunction(count => !document.getElementById('import-preview').hidden && document.getElementById('preview-summary').textContent.includes(`${count} 个账户`), {}, count);
  assert.equal(await page.$eval('#import-password', node => node.value), '');
}
async function commit(page, count) {
  await page.click('#commit-import');
  await page.waitForFunction(count => !document.getElementById('import-dialog').open && document.querySelectorAll('.account').length === count, {}, count);
}
try {
  let page = await launch();
  await page.waitForFunction(() => !document.getElementById('auth').hidden);
  assert.equal(await page.$eval('#setup-lock', node => node.checked), false);
  assert.equal(await page.$eval('#auth-password-fields', node => node.hidden), true);
  await page.click('#auth-submit');
  record('new installation defaults to password-free access without requiring a computer password');
  await page.waitForSelector('#import-dialog[open]');
  await choose(page, 'mixia-pin6', '012345', false); await previewReady(page, 3);
  assert.equal((await send(page, 'CODES')).accounts.length, 0);
  await page.screenshot({ path: path.join(artifacts, 'import-preview.png'), fullPage: true });
  await page.click('#import-cancel'); assert.equal((await send(page, 'CODES')).accounts.length, 0);
  record('real Chrome decrypts unchanged Mixia backup while offline; preview and cancellation do not write accounts');
  await choose(page, 'mixia-pin6'); await previewReady(page, 3); await commit(page, 3);
  const codes = (await send(page, 'CODES')).accounts;
  const candidates = await Promise.all([-1000, 0, 1000].map(offset => totp(account(), Date.now() + offset)));
  assert.ok(candidates.some(value => value.code === codes[0].code));
  assert.equal(await page.$$eval('.account img', nodes => nodes.length), 0);
  const stored = await page.evaluate(() => chrome.storage.local.get(null));
  assert.ok(!JSON.stringify(stored).includes(account().secret)); assert.ok(!JSON.stringify(stored).includes('测试用户'));
  await page.screenshot({ path: path.join(artifacts, 'accounts.png'), fullPage: true });
  record('confirmed import displays correct independent TOTP codes and saves only encrypted account data');
  await page.type('#search', 'GitHub'); assert.equal(await page.$$eval('.account:not([hidden])', nodes => nodes.length), 1);
  await page.$eval('#search', node => { node.value = ''; node.dispatchEvent(new Event('input')); });
  await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { async writeText(text) { globalThis.__testCopied = text; } } }));
  await page.click('.account'); await page.waitForFunction(() => /^\d{6}$/.test(globalThis.__testCopied));
  record('search, text-safe labels and click-to-copy flow work; OS clipboard effect is isolated in the test');
  const old = await page.evaluate(() => chrome.storage.local.get('vault'));
  await choose(page, 'mixia-pin6', 'wrong-password');
  await page.waitForFunction(() => document.getElementById('import-error').textContent.includes('密码'));
  assert.deepEqual(await page.evaluate(() => chrome.storage.local.get('vault')), old);
  await page.click('#import-cancel');
  record('wrong backup password leaves the existing encrypted vault unchanged');
  await choose(page, 'mixia-one'); await previewReady(page, 1); await commit(page, 1);
  assert.deepEqual((await send(page, 'CODES')).accounts.map(item => item.id), ['fixture-two']);
  record('next import completely replaces prior accounts without merging');
  const cdp = await browser.target().createCDPSession(); await cdp.send('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: downloads });
  await settings(page);
  await page.click('#backup');
  await page.waitForSelector('#security-dialog[open]');
  await page.type('#security-password', password); await page.type('#security-confirm', password); await page.click('#security-submit');
  let backupPath;
  for (let i = 0; i < 100; i++) { const files = (await readdir(downloads)).filter(name => name.endsWith('.mixia.json')); if (files.length) { backupPath = path.join(downloads, files[0]); break; } await new Promise(resolve => setTimeout(resolve, 50)); }
  assert.ok(backupPath); const backupText = await readFile(backupPath, 'utf8'); assert.equal(JSON.parse(backupText).format, 'mixia-desktop-vault'); assert.ok(!backupText.includes(account().secret));
  assert.equal(JSON.parse(backupText).localKey, undefined); assert.equal((await send(page, 'STATUS')).lockEnabled, false);
  await choose(page, 'mixia-empty'); await previewReady(page, 0); assert.equal(await page.$eval('#commit-import', node => node.disabled), true);
  await page.click('#empty-confirm'); await commit(page, 0);
  assert.equal(await page.$eval('#empty', node => node.hidden), false);
  await page.screenshot({ path: path.join(artifacts, 'empty.png'), fullPage: true });
  await choose(page, backupPath, password); await previewReady(page, 1); await commit(page, 1);
  record('empty backup requires explicit clearing confirmation; actual downloaded encrypted desktop backup restores correctly');
  await choose(page, 'mixia-legacy', 'legacy-test-password'); await previewReady(page, 3); await commit(page, 3);
  await page.setViewport({ width: 375, height: 800 }); assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await page.screenshot({ path: path.join(artifacts, 'narrow.png'), fullPage: true });
  await page.emulateMediaFeatures([{ name: 'prefers-color-scheme', value: 'dark' }, { name: 'prefers-reduced-motion', value: 'reduce' }]);
  await page.screenshot({ path: path.join(artifacts, 'dark.png'), fullPage: true });
  await page.emulateMediaFeatures([{ name: 'prefers-color-scheme', value: 'light' }]);
  record('legacy mobile passwords, 375px layout, dark mode and reduced-motion are supported');
  await settings(page); await page.click('#lock-enabled'); await page.waitForSelector('#security-dialog[open]');
  await page.click('#security-cancel'); assert.equal((await send(page, 'STATUS')).lockEnabled, false);
  await settings(page); await page.click('#lock-enabled'); await page.waitForSelector('#security-dialog[open]');
  await page.type('#security-password', password); await page.type('#security-confirm', password); await page.click('#security-submit');
  await page.waitForFunction(() => !document.getElementById('security-dialog').open && document.getElementById('lock-enabled').checked);
  record('lock password is enabled only after explicitly switching it on and confirming a password');
  await choose(page, 'mixia-pin6'); await previewReady(page, 3); await send(page, 'LOCK');
  await page.waitForFunction(() => !document.getElementById('auth').hidden && !document.getElementById('import-dialog').open);
  assert.equal(await page.$$eval('.account', nodes => nodes.length), 0); assert.equal(await page.$eval('#import-file', node => node.value), '');
  await browser.close(); browser = null;
  page = await launch(); await page.waitForFunction(() => !document.getElementById('auth').hidden);
  assert.equal((await send(page, 'STATUS')).unlocked, false);
  await page.type('#password', password); await page.click('#auth-submit'); await page.waitForSelector('.account');
  assert.equal((await send(page, 'CODES')).accounts.length, 3);
  record('locking removes previews and displayed codes; browser restart requires the independent computer password');
  await settings(page); await page.click('#lock-enabled');
  await page.waitForFunction(() => !document.getElementById('lock-enabled').checked && document.getElementById('lock').hidden);
  await browser.close(); browser = null; page = await launch(); await page.waitForSelector('.account');
  assert.equal((await send(page, 'STATUS')).lockEnabled, false);
  assert.equal((await send(page, 'CODES')).accounts.length, 3);
  record('turning lock off preserves accounts and reopens directly after a full browser restart');
  const popup = await browser.newPage(); popup.on('pageerror', error => errors.push(error.message));
  await popup.setViewport({ width: 420, height: 600 }); await popup.goto(`${origin}/popup.html`); await popup.waitForSelector('.account');
  await popup.screenshot({ path: path.join(artifacts, 'popup.png'), fullPage: true });
  const opened = browser.waitForTarget(target => target.url() === `${origin}/vault.html?import=1`);
  await settings(popup); await popup.click('#import-open'); const importPage = await (await opened).page(); await importPage.waitForSelector('#import-dialog[open]'); await importPage.close();
  const demoAccounts = Array.from({ length: 14 }, (_, i) => ({ ...account(), id: `demo-${i}`, issuer: `示例账户 ${String(i + 1).padStart(2, '0')}`, name: `account-${String(i + 1).padStart(2, '0')}@example.test` }));
  const salt = randomB64(16), legacy = await sealVault(await deriveVaultKey(password, salt), salt, snapshot(demoAccounts));
  await page.evaluate(vault => chrome.storage.local.set({ vault }), legacy);
  await browser.close(); browser = null; page = await launch();
  await page.waitForFunction(() => document.getElementById('auth-title').textContent.includes('升级'));
  await page.type('#password', password); await page.click('#auth-submit'); await page.waitForSelector('.account');
  assert.equal((await send(page, 'STATUS')).needsMigration, false); assert.equal((await send(page, 'STATUS')).lockEnabled, false);
  await browser.close(); browser = null; page = await launch(); await page.waitForSelector('.account');
  assert.equal((await send(page, 'CODES')).accounts.length, 14);
  record('older password-protected vault migrates once with its original password and then opens directly');
  const compact = await browser.newPage(); compact.on('pageerror', error => errors.push(error.message));
  await compact.setViewport({ width: 420, height: 600 }); await compact.goto(`${origin}/popup.html`); await compact.waitForSelector('.account');
  const layout = await compact.evaluate(() => {
    const rows = [...document.querySelectorAll('.account')].map(node => node.getBoundingClientRect());
    return { top: rows[0].top, fullyVisible: rows.filter(rect => rect.top >= 0 && rect.bottom <= innerHeight).length, searchTop: document.getElementById('search').getBoundingClientRect().top, overflow: document.documentElement.scrollWidth > innerWidth };
  });
  assert.ok(layout.top <= 130); assert.ok(layout.fullyVisible >= 4); assert.equal(layout.overflow, false);
  await compact.$eval('#account-list', node => { node.scrollTop = node.scrollHeight; });
  assert.equal(await compact.$eval('#search', node => node.getBoundingClientRect().top), layout.searchTop);
  await compact.type('#search', 'account-14');
  assert.equal(await compact.$$eval('.account:not([hidden])', nodes => nodes.length), 1);
  await compact.$eval('#search', node => { node.value = ''; node.dispatchEvent(new Event('input')); });
  await compact.$eval('#account-list', node => { node.scrollTop = 0; });
  await compact.screenshot({ path: path.join(artifacts, 'popup-dense.png') });
  await settings(compact); await compact.screenshot({ path: path.join(artifacts, 'settings.png') });
  await compact.keyboard.press('Escape');
  assert.equal(await compact.$eval('#settings-dialog', node => node.open), false);
  assert.equal(await compact.evaluate(() => document.activeElement.id), 'settings-open');
  record('14-account popup keeps search fixed, shows at least four whole accounts at 420x600, and settings closes with Escape');
  assert.deepEqual(errors, []); assert.deepEqual(requests, []);
  record('popup import opens a stable full page; no helper, network host permissions, HTTP requests or uncaught errors');
  await writeFile(path.join(artifacts, 'browser-results.json'), JSON.stringify({ version: manifest.version, passed: results, sourceFixtures: 'Generated by unchanged original Mixia export code using host native API adapters', realPhoneExportTested: false }, null, 2));
} catch (error) {
  if (browser) for (const page of await browser.pages()) if (page.url().startsWith(origin)) {
    await page.screenshot({ path: path.join(artifacts, 'failure.png'), fullPage: true }).catch(() => {});
    console.error('UI state:', await page.evaluate(() => ({ message: document.getElementById('message')?.textContent, importError: document.getElementById('import-error')?.textContent })));
  }
  throw error;
} finally { if (browser) await browser.close(); await rm(profile, { recursive: true, force: true }); }
