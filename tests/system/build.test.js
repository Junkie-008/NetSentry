/**
 * System tests: packaging & structural validation.
 *
 * Verifies that the extension is internally consistent: manifest references,
 * JS syntax, permissions, and that the build script produces a loadable
 * package containing every required file.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..', '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const exists = (p) => fs.existsSync(path.join(ROOT, p));

describe('system: manifest & structure', () => {
  const manifest = JSON.parse(read('manifest.json'));

  it('is a valid Manifest V3 extension manifest', () => {
    assert.equal(manifest.manifest_version, 3);
    assert.ok(manifest.name);
    assert.ok(/^\d+\.\d+(\.\d+)?$/.test(manifest.version), 'version must be x.y[.z]');
    assert.ok(manifest.description);
  });

  it('every file referenced by the manifest exists', () => {
    const referenced = [];

    referenced.push(manifest.background.service_worker);
    for (const cs of manifest.content_scripts) {
      referenced.push(...cs.js, ...cs.css);
    }
    referenced.push(manifest.action.default_popup);
    Object.values(manifest.action.default_icon).forEach((p) => referenced.push(p));
    Object.values(manifest.icons).forEach((p) => referenced.push(p));
    for (const war of manifest.web_accessible_resources) {
      for (const res of war.resources) {
        if (!res.includes('*')) referenced.push(res);
      }
    }

    for (const file of referenced) {
      assert.ok(exists(file), `manifest references missing file: ${file}`);
    }
  });

  it('does not reference files that do not exist (regression: warning.html)', () => {
    const raw = read('manifest.json');
    assert.ok(!raw.includes('warning.html'), 'manifest must not reference missing warning.html');
  });

  it('loads detector.js before content.js in the content script list', () => {
    const js = manifest.content_scripts[0].js;
    assert.equal(js[0], 'detector.js');
    assert.equal(js[1], 'content.js');
  });

  it('popup loads detector.js before popup.js', () => {
    const html = read('popup.html');
    const detectorIdx = html.indexOf('src="detector.js"');
    const popupIdx = html.indexOf('src="popup.js"');
    assert.ok(detectorIdx >= 0, 'popup must load detector.js');
    assert.ok(popupIdx > detectorIdx, 'detector.js must load before popup.js');
  });

  it('only requests permissions it actually uses', () => {
    const allowed = new Set(['activeTab', 'tabs', 'storage', 'webNavigation', 'scripting']);
    for (const perm of manifest.permissions) {
      assert.ok(allowed.has(perm), `unused permission declared: ${perm}`);
    }
    // Regression guard: these were declared but never used
    assert.ok(!manifest.permissions.includes('webRequest'));
    assert.ok(!manifest.permissions.includes('declarativeContent'));
  });

  it('content script is injected into every frame (iframe phishing kits)', () => {
    assert.equal(manifest.content_scripts[0].all_frames, true);
  });

  it('all shipped JavaScript passes a syntax check', () => {
    for (const file of ['detector.js', 'background.js', 'content.js', 'popup.js', 'blocked.js']) {
      assert.doesNotThrow(() => {
        execFileSync(process.execPath, ['--check', path.join(ROOT, file)], {
          stdio: 'pipe'
        });
      }, `syntax error in ${file}`);
    }
  });

  it('manifest and shipped JSON parse cleanly', () => {
    assert.doesNotThrow(() => JSON.parse(read('manifest.json')));
    assert.doesNotThrow(() => JSON.parse(read('package.json')));
  });

  it('no source file calls out to external network endpoints (privacy)', () => {
    const files = ['detector.js', 'background.js', 'content.js', 'popup.js'];
    const forbidden = [
      /\bfetch\s*\(/,
      /XMLHttpRequest/,
      /WebSocket\s*\(/,
      /sendBeacon/,
      /importScripts\s*\(\s*['"]https?:/
    ];
    for (const file of files) {
      const src = read(file);
      for (const re of forbidden) {
        assert.ok(!re.test(src), `${file} matches forbidden network pattern: ${re}`);
      }
    }
  });
});

describe('system: build pipeline', () => {
  it('build.sh produces a complete build directory and zip package', () => {
    // build.sh needs a POSIX shell (git-bash / WSL / Linux / macOS)
    let status = 0;
    try {
      execFileSync('bash', [path.join(ROOT, 'build.sh')], {
        cwd: ROOT,
        stdio: 'pipe'
      });
    } catch (err) {
      status = err.status === undefined ? 1 : err.status;
      if (err.message.includes('ENOENT')) {
        // No bash on this machine - skip rather than fail
        return;
      }
      assert.equal(status, 0, `build.sh failed: ${err.stderr || err.message}`);
    }

    const buildFiles = [
      'manifest.json', 'detector.js', 'background.js', 'content.js',
      'popup.html', 'popup.js', 'blocked.html', 'blocked.js',
      'styles.css', 'README.md', 'LICENSE'
    ];
    for (const f of buildFiles) {
      assert.ok(
        fs.existsSync(path.join(ROOT, 'build', f)),
        `build/ is missing ${f}`
      );
    }

    assert.ok(fs.existsSync(path.join(ROOT, 'build', 'icons', 'icon128.png')));

    // Build manifest must itself be loadable (same checks as source)
    const built = JSON.parse(fs.readFileSync(path.join(ROOT, 'build', 'manifest.json'), 'utf8'));
    assert.equal(built.manifest_version, 3);
    assert.ok(built.content_scripts[0].js.includes('detector.js'));

    const zipPath = path.join(ROOT, 'netsentry-extension.zip');
    assert.ok(fs.existsSync(zipPath), 'zip package missing');
    assert.ok(fs.statSync(zipPath).size > 5000, 'zip package suspiciously small');
  });
});
