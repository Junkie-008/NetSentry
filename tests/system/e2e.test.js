/**
 * End-to-end system test: loads the real extension into headless Chrome,
 * serves local fixture pages, and verifies the three user-facing outcomes:
 *   - safe page  -> nothing happens
 *   - medium risk -> warning banner appears
 *   - high risk  -> full-page block screen replaces the site
 *
 * Skips automatically when Chrome/Chromium is not available on this machine.
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');

const ROOT = path.join(__dirname, '..', '..');

function findChrome() {
  if (process.env.CHROME_PATH && fs.existsSync(process.env.CHROME_PATH)) {
    return process.env.CHROME_PATH;
  }
  const candidates = [];
  for (const base of [
    process.env['PROGRAMFILES'],
    process.env['PROGRAMFILES(X86)'],
    process.env.LOCALAPPDATA]
  ) {
    if (base) {
      candidates.push(path.join(base, 'Google', 'Chrome', 'Application', 'chrome.exe'));
      candidates.push(path.join(base, 'Chromium', 'Application', 'chrome.exe'));
    }
  }
  candidates.push(
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
  );
  return candidates.find((p) => fs.existsSync(p)) || null;
}

const chromePath = findChrome();

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------
// Score budget (see detector.js):
//   warn: 2 phishing phrases (40) + long URL (10) = 50  -> medium (41-70)
//   phish: 4 phishing phrases (80) + long URL (10) = 90 -> high  (>70, blocked)
const WARN_QUERY =
  'a=limited time&b=click here immediately&pad=' + 'x'.repeat(60);
const PHISH_QUERY =
  'a=update payment&b=verify identity&c=urgent action required' +
  '&d=suspicious activity&pad=' + 'x'.repeat(40);

function fixturePages() {
  return {
    safe: '<!DOCTYPE html><html><body><h1>Safe page</h1><p>Just some normal content.</p></body></html>',
    warn: '<!DOCTYPE html><html><body><h1>Mildly odd page</h1><p>Some content here.</p></body></html>',
    phish: '<!DOCTYPE html><html><body><h1>Login</h1><form><input type="password"></form></body></html>'
  };
}

function startServer() {
  const pages = fixturePages();
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/safe.html') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(pages.safe);
    } else if (url.pathname === '/warn.html') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(pages.warn);
    } else if (url.pathname === '/phish.html') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(pages.phish);
    } else if (url.pathname === '/frames.html') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!DOCTYPE html><html><body><h1>Parent page</h1>' +
        '<iframe src="/frame-phish.html" width="600" height="250"></iframe>' +
        '</body></html>');
    } else if (url.pathname === '/frame-phish.html') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!DOCTYPE html><html><body><h2>Frame login</h2>' +
        '<form action="/steal" method="post"><input type="password" name="p"><button>Sign in</button></form>' +
        '</body></html>');
    } else {
      res.writeHead(404, { 'Content-Type': 'text/html' });
      res.end('<html><body>not found</body></html>');
    }
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({ server, port: server.address().port });
    });
  });
}

describe('e2e: extension in headless Chrome', { skip: !chromePath && 'Chrome not found' }, () => {
  let browser;
  let serverInfo;
  let base;
  let swTargetUrl;

  before(async () => {
    // Refuse to run against a stale build: the extension root must be valid
    JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));

    serverInfo = await startServer();
    base = `http://127.0.0.1:${serverInfo.port}`;

    const puppeteer = require('puppeteer-core');
    browser = await puppeteer.launch({
      executablePath: chromePath,
      headless: true,
      enableExtensions: [ROOT],
      args: [
        '--no-sandbox',
        '--disable-gpu',
        '--disable-dev-shm-usage'
      ],
      timeout: 30000
    });

    const swTarget = await browser.waitForTarget(
      (t) => t.type() === 'service_worker',
      { timeout: 20000 }
    );
    swTargetUrl = swTarget.url();
    assert.match(swTargetUrl, /^chrome-extension:\/\//, 'service worker must be an extension');
  }, { timeout: 40000 });

  after(async () => {
    if (browser) await browser.close();
    if (serverInfo) await new Promise((r) => serverInfo.server.close(r));
  });

  it('safe page: no warning, no block', async () => {
    const page = await browser.newPage();
    try {
      await page.goto(`${base}/safe.html`, { waitUntil: 'domcontentloaded' });
      await new Promise((r) => setTimeout(r, 2000));
      const html = await page.evaluate(() => document.body.innerHTML);
      assert.ok(!html.includes('phishing-warning'), 'no warning banner expected');
      assert.ok(!html.includes('PHISHING SITE BLOCKED'), 'no block page expected');
    } finally {
      await page.close();
    }
  }, { timeout: 40000 });

  it('medium-risk page: warning banner appears and is dismissible', async () => {
    const page = await browser.newPage();
    try {
      await page.goto(`${base}/warn.html?${WARN_QUERY}`, { waitUntil: 'domcontentloaded' });
      await page.waitForFunction(
        () => !!document.querySelector('#phishing-warning'),
        { timeout: 15000 }
      );

      const info = await page.evaluate(() => {
        const el = document.querySelector('#phishing-warning');
        return {
          className: el.className,
          text: el.innerText,
          hasDismiss: !!el.querySelector('.dismiss-btn')
        };
      });

      assert.ok(info.className.includes('phishing-warning-overlay'));
      assert.ok(info.text.includes('SUSPICIOUS SITE DETECTED'));
      assert.ok(info.text.includes('risk 50/100'), `banner text: ${info.text}`);
      assert.ok(info.hasDismiss);

      // Dismiss works
      await page.evaluate(() => document.querySelector('.dismiss-btn').click());
      const gone = await page.evaluate(() => !document.querySelector('#phishing-warning'));
      assert.equal(gone, true);
    } finally {
      await page.close();
    }
  }, { timeout: 40000 });

  it('content script analyses IFrames too (all_frames hardening)', async () => {
    // qwen3.5 finding #2: a credential-harvesting form inside an iframe was
    // invisible because content scripts only ran in the top frame.
    const page = await browser.newPage();
    try {
      await page.goto(`${base}/frames.html`, { waitUntil: 'networkidle0' });
      await new Promise((r) => setTimeout(r, 700));

      const iframe = page.frames().find((f) => f.url().includes('frame-phish.html'));
      assert.ok(iframe, 'iframe should have loaded');

      const marked = await iframe.evaluate(() => {
        const form = document.querySelector('form');
        return {
          insecure: !!form && form.classList.contains('phishing-detector-insecure-form'),
          flagged: !!form && form.dataset.pdMarked === '1'
        };
      });
      assert.equal(marked.insecure, true, 'insecure form inside iframe must be marked');
      assert.equal(marked.flagged, true, 'iframe form must carry the duplicate-guard flag');

      // The top frame has no sensitive form itself -> stays untouched
      const topMarks = await page.evaluate(
        () => document.querySelectorAll('.phishing-detector-suspicious').length
      );
      assert.equal(topMarks, 0);
    } finally {
      await page.close();
    }
  }, { timeout: 40000 });

  it('high-risk page: full block screen replaces the site', async () => {
    const page = await browser.newPage();
    try {
      await page.goto(`${base}/phish.html?${PHISH_QUERY}`, { waitUntil: 'domcontentloaded' });
      await page.waitForFunction(
        () => document.body && document.body.innerText.includes('PHISHING SITE BLOCKED'),
        { timeout: 15000 }
      );

      const info = await page.evaluate(() => ({
        text: document.body.innerText,
        html: document.body.innerHTML
      }));

      assert.ok(info.text.includes('PHISHING SITE BLOCKED'));
      assert.ok(/90/.test(info.text), `risk score shown: ${info.text}`);
      assert.ok(info.html.includes('Why this was blocked'), 'block reasons shown');
      assert.ok(info.html.includes('Go Back'), 'escape button shown');

      // HARDENING: the tab must end up on the extension's blocked.html so the
      // malicious document and its JavaScript are fully unloaded.
      await new Promise((r) => setTimeout(r, 500));
      assert.ok(
        page.url().includes('blocked.html'),
        `tab should be redirected to blocked.html, got ${page.url()}`
      );
      const finalUrl = new URL(page.url());
      assert.equal(finalUrl.searchParams.get('score'), '90');
      assert.ok(finalUrl.searchParams.getAll('r').length > 0, 'reasons in URL');
    } finally {
      await page.close();
    }
  }, { timeout: 40000 });

  it('popup page loads without errors and shows updated stats', async () => {
    const extId = new URL(swTargetUrl).hostname;
    const page = await browser.newPage();
    const pageErrors = [];
    page.on('pageerror', (err) => pageErrors.push(String(err)));

    try {
      await page.goto(`chrome-extension://${extId}/popup.html`, {
        waitUntil: 'domcontentloaded'
      });
      await page.waitForFunction(
        () => {
          const content = document.getElementById('content');
          const loading = document.getElementById('loading');
          return content && loading && loading.style.display === 'none';
        },
        { timeout: 10000 }
      );

      const state = await page.evaluate(() => ({
        title: document.querySelector('.title') && document.querySelector('.title').textContent,
        blocked: document.getElementById('sites-blocked').textContent,
        statusMessage: document.getElementById('status-message').textContent,
        hasGauge: !!document.getElementById('risk-bar-fill'),
        statTiles: document.querySelectorAll('.stat').length
      }));

      assert.equal(pageErrors.length, 0, `popup errors: ${pageErrors.join('; ')}`);
      assert.ok(state.title.includes('NetSentry'));
      assert.equal(state.blocked, '1', 'block stat from the previous test');
      assert.ok(state.hasGauge, 'risk gauge rendered');
      assert.equal(state.statTiles, 3, 'three stat tiles');
      // Popup opened as a tab (no active analysis) -> graceful empty state
      assert.ok(state.statusMessage.length > 0);
    } finally {
      await page.close();
    }
  }, { timeout: 40000 });
});
