"""Build public archives from an explicit allowlist, never from local data folders."""
from pathlib import Path
import json
import zipfile

ROOT = Path(__file__).resolve().parents[1]
EXTENSION_FILES = (
    'extension/manifest.json', 'extension/background.js', 'extension/app.js',
    'extension/popup.html', 'extension/vault.html', 'extension/privacy.html',
    'extension/ui.css', 'extension/icons/icon128.png', 'extension/lib/crypto.js',
    'extension/lib/otp.js', 'extension/lib/snapshot.js', 'extension/lib/mixia-backup.js',
)
SOURCE_FILES = EXTENSION_FILES + (
    'scripts/build.mjs', 'scripts/check.mjs', 'scripts/package.py',
    'tests/background.test.mjs', 'tests/backup.test.mjs', 'tests/crypto.test.mjs',
    'tests/browser.mjs', 'tests/fixtures.mjs', 'tests/fixtures/README.md',
    'tests/fixtures/mixia-pin6.mixia', 'tests/fixtures/mixia-one.mixia',
    'tests/fixtures/mixia-empty.mixia', 'tests/fixtures/mixia-hotp.mixia',
    'tests/fixtures/mixia-legacy.mixia',
    'README.md', 'PRIVACY.md', 'VALIDATION.md', 'CHANGELOG.md', 'RELEASE-NOTES.md',
    'docs/preview.png',
    'package.json', 'package-lock.json', '.gitignore',
)

def build_archive(target, files, prefix, strip_extension=False):
    with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED) as output:
        for name in files:
            file = ROOT / name
            if file.is_symlink() or not file.is_file():
                raise ValueError('Public package file missing or symlink: ' + name)
            relative = str(Path(name).relative_to('extension')) if strip_extension else name
            output.write(file, prefix + relative)

def main():
    manifest = json.loads((ROOT / 'extension/manifest.json').read_text())
    version = manifest['version']
    (ROOT / 'dist').mkdir(exist_ok=True)
    archive = ROOT / f'dist/mixia-extension-{version}.zip'
    source = ROOT / f'dist/mixia-extension-source-{version}.zip'
    build_archive(archive, EXTENSION_FILES, '', strip_extension=True)
    build_archive(source, SOURCE_FILES, 'mixia-extension/')
    print('Built extension and source ZIPs using the public-file allowlist; local data excluded.')

if __name__ == '__main__':
    main()
