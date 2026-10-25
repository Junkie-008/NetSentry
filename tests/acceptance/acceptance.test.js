/**
 * Acceptance tests: verify the project's documented promises against the
 * actual implementation.
 *
 * Sources of truth:
 *  - README.md           (risk bands, thresholds, privacy claim)
 *  - test_sites.md       (expected results table, manual test scenarios)
 *  - test_paypal_detection.html (concrete score expectations)
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..', '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

const Detector = require('../../detector.js');
const { createMockChrome, flush } = require('../helpers/chrome-mock');

require('../../detector.js'); // global Detector for background.js

function loadBackground(activeUrl) {
  const mock = createMockChrome({ activeUrl });
  global.chrome = mock.chrome;
  delete require.cache[require.resolve('../../background.js')];
  require('../../background.js');
  return mock;
}

describe('acceptance: README documented behavior', () => {
  const readme = read('README.md');

  it('documented warning threshold matches the engine (40 points)', () => {
    const m = readme.match(/Warning threshold: (\d+) points/);
    assert.ok(m, 'README must document a warning threshold');
    assert.equal(Number(m[1]), Detector.RISK_THRESHOLDS.WARN);
  });

  it('documented blocking threshold matches the engine (70 points)', () => {
    const m = readme.match(/Blocking threshold: (\d+) points/);
    assert.ok(m, 'README must document a blocking threshold');
    assert.equal(Number(m[1]), Detector.RISK_THRESHOLDS.BLOCK);
  });

  it('README "score > 70 blocks" claim matches the engine', () => {
    const m = readme.match(/blocks high-risk sites \(score > (\d+)\)/);
    assert.ok(m, 'README must document the blocking rule');
    assert.equal(Number(m[1]), Detector.RISK_THRESHOLDS.BLOCK);
    assert.equal(Detector.shouldBlock(71), true);
    assert.equal(Detector.shouldBlock(70), false);
  });

  it('README risk band table (0-20/21-40/41-70/71-100) matches getRiskLevel', () => {
    const bands = [...readme.matchAll(/\*\*(\d+)-(\d+)\*\*:.*$/gm)].map((m) => [
      Number(m[1]),
      Number(m[2])
    ]);
    assert.deepEqual(bands, [[0, 20], [21, 40], [41, 70], [71, 100]]);

    const expectations = ['safe', 'low', 'medium', 'high'];
    bands.forEach(([lo, hi], i) => {
      assert.equal(Detector.getRiskLevel(lo), expectations[i], `band ${lo}-${hi}`);
      assert.equal(Detector.getRiskLevel(hi), expectations[i], `band ${lo}-${hi}`);
      assert.equal(Detector.getRiskLevel(hi + 1), expectations[i + 1] || 'high');
    });
  });

  it('README privacy claim holds: no external network calls in source', () => {
    assert.ok(/No External Calls|no data sent to remote servers/i.test(readme));
    for (const f of ['detector.js', 'background.js', 'content.js', 'popup.js']) {
      const src = read(f);
      assert.ok(!/\bfetch\s*\(/.test(src), `${f} uses fetch()`);
      assert.ok(!/XMLHttpRequest/.test(src), `${f} uses XMLHttpRequest`);
      assert.ok(!/navigator\.sendBeacon/.test(src), `${f} uses sendBeacon`);
    }
  });
});

describe('acceptance: test_sites.md expected results', () => {
  const doc = read('test_sites.md');

  it('every documented safe site scores within 0-20', () => {
    const section = doc.split('## ✅ Safe Sites')[1].split('##')[0];
    const urls = [...section.matchAll(/-(\s*)(https?:\/\/\S+)/g)].map((m) => m[2]);
    assert.ok(urls.length >= 6, `expected >=6 safe sites, found ${urls.length}`);
    for (const url of urls) {
      const report = Detector.analyzeUrl(url);
      assert.ok(
        report.score <= 20,
        `${url} scored ${report.score}, documented safe band is 0-20`
      );
    }
  });

  it('documented brand impersonation cases are blocked (71-100)', () => {
    const cases = ['paypal-security.com', 'amazon-verification.net', 'google-accounts.info'];
    for (const domain of cases) {
      const report = Detector.analyzeUrl(`https://${domain}/`);
      assert.ok(
        Detector.shouldBlock(report.score),
        `${domain} scored ${report.score}; docs promise it is blocked`
      );
      assert.ok(report.score >= 71 && report.score <= 100);
    }
  });

  it('documented suspicious TLD domains trigger a warning (41-70)', () => {
    // test_sites.md: suspicious TLDs contribute +45 and warn on their own
    for (const domain of ['example.tk', 'test.ml', 'suspicious.ga']) {
      const report = Detector.analyzeUrl(`https://${domain}/`);
      assert.ok(
        Detector.shouldWarn(report.score),
        `${domain} scored ${report.score}, expected a warning`
      );
      assert.ok(!Detector.shouldBlock(report.score), `${domain} should warn, not block`);
    }
  });

  it('documented medium/high result bands are consistent with the engine', () => {
    assert.match(doc, /Risk Score: 0-20/);
    assert.match(doc, /Risk Score: 41-70/);
    assert.match(doc, /Risk Score: 71-100/);
    assert.equal(Detector.getRiskLevel(41), 'medium');
    assert.equal(Detector.getRiskLevel(70), 'medium');
    assert.equal(Detector.getRiskLevel(71), 'high');
  });
});

describe('acceptance: test_paypal_detection.html expectations', () => {
  const doc = read('test_paypal_detection.html');

  it('documents the same blocking threshold as the engine', () => {
    const m = doc.match(/threshold > (\d+)/);
    assert.ok(m, 'test page must document the blocking threshold');
    assert.equal(Number(m[1]), Detector.RISK_THRESHOLDS.BLOCK);
  });

  it('paypa1-login.com: PayPal variant scores exactly 80 points', () => {
    const brand = Detector.checkBrandImpersonation('paypa1-login.com');
    assert.equal(brand.score, 80);
    assert.ok(/80 points/.test(doc));
  });

  it('paypa1-login.com: HTTP + login keyword scores exactly 40 points', () => {
    const structure = Detector.analyzeUrlStructure(new URL('http://paypa1-login.com/login'));
    assert.equal(structure.score, 40);
    assert.ok(/40 points/.test(doc));
  });

  it('paypa1-login.com: mixed letters/numbers scores exactly 10 points', () => {
    const domain = Detector.analyzeDomain('paypa1-login.com');
    const mixed = domain.reasons.find((r) => r.label.includes('Digits mixed'));
    assert.ok(mixed && mixed.points === 10);
    assert.ok(/10 points/.test(doc));
  });

  it('paypa1-login.com: totals 130+ capped at 100 and is blocked', () => {
    const report = Detector.analyzeUrl('http://paypa1-login.com/login');
    assert.equal(report.score, 100); // capped
    assert.ok(Detector.shouldBlock(report.score));
    assert.ok(/capped at 100/.test(doc));
  });

  it('paypal.com is safe (score 0)', () => {
    assert.equal(Detector.analyzeUrl('https://www.paypal.com/').score, 0);
    assert.equal(Detector.analyzeUrl('https://paypal.com/').score, 0);
  });
});

describe('acceptance: manual test scenarios from test_sites.md', () => {
  it('Test Case 4 (Phishing Site Block): high-risk page gets the block screen', async () => {
    const mock = loadBackground('http://paypa1-login.com/login');
    mock.emit.tabUpdated(1, 'http://paypa1-login.com/login');
    await flush();

    assert.equal(mock.calls.executeScript.length, 1);
    const fn = mock.calls.executeScript[0].func.toString();
    assert.ok(fn.includes('PHISHING SITE BLOCKED'), 'block page shown');
    assert.ok(fn.includes('Go Back'), 'Go Back action available');
    assert.ok(fn.includes('Close Tab'), 'Close Tab action available');

    // v1.1 hardening: tab is also redirected to the extension's blocked.html
    // (unloads the malicious document and its JavaScript)
    assert.equal(mock.calls.tabsUpdate.length, 1);
    assert.ok(mock.calls.tabsUpdate[0].url.includes('blocked.html'));
  });

  it('Test Case 5 (Whitelist Functionality): score becomes 0 after trusting', async () => {
    const mock = loadBackground('http://free-prize1.tk/win');

    const before = await mock.emit.message({ action: 'getAnalysis' });
    assert.ok(before.riskScore > 0, 'site is risky before whitelisting');

    await mock.writeStorage({ whitelistedDomains: ['free-prize1.tk'] });

    const after = await mock.emit.message({ action: 'getAnalysis' });
    assert.equal(after.riskScore, 0, 'risk score must become 0');
    assert.equal(after.level, 'safe');
  });

  it('Test Case 1 (Safe Site Navigation): no warnings for safe pages', async () => {
    const mock = loadBackground('https://google.com/');
    mock.emit.tabUpdated(1, 'https://google.com/');
    await flush();

    assert.equal(mock.calls.executeScript.length, 0, 'no warning/block overlay');
    const analysis = mock.data['analysis_1'];
    assert.equal(analysis.riskScore, 0);
    assert.equal(analysis.level, 'safe');
  });

  it('Test Case 6 (Popup): analysis carries score + reasons the popup renders', async () => {
    const mock = loadBackground('http://free-prize1.tk/win');
    const analysis = await mock.emit.message({ action: 'getAnalysis' });

    assert.equal(typeof analysis.riskScore, 'number');
    assert.ok(analysis.reasons.length > 0, 'popup Risk Factors section gets data');
    for (const r of analysis.reasons) {
      assert.ok(typeof r.label === 'string' && typeof r.points === 'number');
    }

    const popupHtml = read('popup.html');
    assert.ok(popupHtml.includes('risk-bar'), 'popup has the risk gauge');
    assert.ok(popupHtml.includes('reasons-list'), 'popup renders risk factors');
    assert.ok(popupHtml.includes('sites-reported'), 'popup shows reported count');
  });

  it('Test Case 3 (Form Security): insecure login form is flagged by content script', async () => {
    // Full DOM check lives in tests/integration/content.test.js; here we
    // verify the shared inputs the acceptance scenario depends on.
    const content = read('content.js');
    assert.ok(content.includes("input[type=\"password\"]"));
    assert.ok(content.includes('phishing-detector-insecure-form'));
    assert.ok(content.includes('Non-HTTPS site collecting sensitive information'));
  });
});
