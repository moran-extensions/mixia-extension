import { readFile, readdir } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
const root = path.resolve(import.meta.dirname, '..');
async function walk(dir) { const result = []; for (const item of await readdir(dir, { withFileTypes: true })) { const p = path.join(dir, item.name); result.push(...item.isDirectory() ? await walk(p) : [p]); } return result; }
const manifest = JSON.parse(await readFile(path.join(root, 'extension/manifest.json'), 'utf8'));
if (manifest.host_permissions || manifest.content_scripts || manifest.externally_connectable) throw new Error('Unexpected webpage/network access');
if (JSON.stringify([...manifest.permissions].sort()) !== JSON.stringify(['alarms', 'clipboardWrite', 'storage'])) throw new Error('Offline extension must only request storage, alarms and clipboardWrite');
if (!manifest.content_security_policy.extension_pages.includes("connect-src 'none'")) throw new Error('External connections must be blocked by CSP');
for (const name of await walk(path.join(root, 'extension'))) {
  if (!name.endsWith('.js')) continue;
  if (/__mixiaTest|connectNative|new WebSocket|\bfetch\s*\(|XMLHttpRequest/.test(await readFile(name, 'utf8'))) throw new Error('Unexpected network/helper code in offline extension');
  const result = spawnSync(process.execPath, ['--check', name], { encoding: 'utf8' });
  if (result.status !== 0) throw new Error(result.stderr);
}
console.log('Extension syntax and minimal permission checks passed.');
