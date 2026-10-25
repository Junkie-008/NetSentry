/**
 * Unit tests for the shared detection engine (detector.js).
 *
 * Coverage: positive, negative, boundary, and edge cases.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const Detector = require('../../detector.js');

const {
  analyzeUrl,
  analyzeDomain,
  analyzeUrlStructure,
  analyzePatterns,
  checkBrandImpersonation,
  detectPayPalImpersonation,
  detectCharacterSubstitution,
  detectHomograph,
  getRiskLevel,
  shouldWarn,
  shouldBlock,
  isWhitelisted,
  RISK_THRESHOLDS
} = Detector;

const u = (s) => new URL(s);

// ---------------------------------------------------------------------------
// POSITIVE cases: known phishing patterns must be flagged
// ---------------------------------------------------------------------------
describe('positive: phishing URLs are detected', () => {
  it('blocks PayPal character-substitution domain (paypa1-login.com)', () => {
    const report = analyzeUrl('http://paypa1-login.com/login');
    assert.equal(report.score, 100); // 80 + 40 + 10, capped at 100
    assert.equal(report.level, 'high');
    assert.equal(shouldBlock(report.score), true);
  });

  it('blocks fake PayPal brand domain (paypal-security.com)', () => {
    const report = analyzeUrl('https://paypal-security.com/');
    // 'paypal-' is a dedicated PayPal impersonation variant: 80 points
    assert.equal(report.score, 80);
    assert.equal(report.level, 'high');
    assert.ok(shouldBlock(report.score));
  });

  it('blocks fake Amazon brand domain (amazon-verification.net)', () => {
    const report = analyzeUrl('https://amazon-verification.net');
    assert.ok(report.score >= 70, `expected >=70, got ${report.score}`);
    assert.ok(shouldBlock(report.score));
  });

  it('blocks fake Google brand domain (google-accounts.info)', () => {
    const report = analyzeUrl('https://google-accounts.info');
    assert.ok(report.score >= 70, `expected >=70, got ${report.score}`);
    assert.ok(shouldBlock(report.score));
  });

  it('blocks deceptive subdomain chain (secure-login.paypal.com.evil.com)', () => {
    const report = analyzeUrl('http://secure-login.paypal.com.evil.com/');
    assert.ok(shouldBlock(report.score), `score was ${report.score}`);
    assert.ok(report.reasons.some((r) => r.label.includes('Brand impersonation')));
  });

  it('flags punycode homograph domain', () => {
    const report = analyzeUrl('https://xn--ggle-55da.com/');
    assert.equal(detectHomograph('xn--ggle-55da.com'), true);
    assert.ok(report.score >= 40, `score was ${report.score}`);
    assert.ok(report.reasons.some((r) => r.label.includes('Homograph')));
  });

  it('flags raw non-ASCII (Cyrillic) homograph input', () => {
    // "gооgle.com" with Cyrillic о characters
    const report = analyzeUrl('http://gооgle.com/');
    assert.ok(report.score >= 40, `score was ${report.score}`);
    assert.equal(report.domain.startsWith('xn--'), true);
  });

  it('warns on suspicious TLD + mixed digits (free-prize1.tk)', () => {
    const report = analyzeUrl('http://free-prize1.tk/win');
    assert.equal(report.score, 55); // 45 TLD + 10 mixed
    assert.equal(report.level, 'medium');
    assert.ok(shouldWarn(report.score));
    assert.equal(shouldBlock(report.score), false);
  });

  it('warns on shortener + redirect + phishing phrase', () => {
    const report = analyzeUrl('https://bit.ly/x?a=limited%20time&redirect=1');
    assert.equal(report.score, 60); // 25 shortener + 15 redirect + 20 pattern
    assert.equal(report.level, 'medium');
  });

  it('adds 80 points for previously-reported domains', () => {
    const report = analyzeUrl('https://bad-example.com/', {
      suspiciousDomains: ['bad-example.com']
    });
    assert.equal(report.score, 80);
    assert.ok(report.reasons.some((r) => r.label.includes('reported')));
  });

  it('flags character-substituted google (g00gle.com)', () => {
    const brand = checkBrandImpersonation('g00gle.com');
    assert.equal(brand.score, 75);
    assert.equal(detectCharacterSubstitution('g00gle.com'), true);
  });

  it('detects every documented PayPal variant', () => {
    for (const variant of Detector.PAYPAL_VARIANTS) {
      assert.equal(
        detectPayPalImpersonation(`${variant}-login.com`),
        true,
        `variant "${variant}" should be detected`
      );
    }
  });

  it('flags HTTP on a security-related host (+40)', () => {
    const result = analyzeUrlStructure(u('http://my-bank.example/'));
    assert.equal(result.score, 40);
  });

  it('flags all 8 phishing URL patterns (+20 each)', () => {
    const samples = [
      'https://x.test/secure-to-verify',
      'https://x.test/account-is-suspended-now',
      'https://x.test/click-here-immediately',
      'https://x.test/urgent-action-required',
      'https://x.test/verify-your-identity',
      'https://x.test/update-your-payment',
      'https://x.test/suspicious-activity-alert',
      'https://x.test/limited-time-offer'
    ];
    samples.forEach((s) => {
      assert.equal(analyzePatterns(s).score, 20, `pattern should match: ${s}`);
    });
  });

  it('flags brand hidden in URL userinfo (@ trick)', () => {
    // Browser connects to evil.example while the URL reads "paypal.com@..."
    const report = analyzeUrl('http://paypal.com@evil.example/');
    assert.ok(report.score >= 75, `score was ${report.score}`);
    assert.equal(shouldBlock(report.score), true);
    assert.ok(report.reasons.some((r) => r.label.includes('userinfo')));
  });

  it('accumulates reasons that sum to the score (before cap)', () => {
    const report = analyzeUrl('http://free-prize1.tk/win');
    const sum = report.reasons.reduce((acc, r) => acc + r.points, 0);
    assert.equal(sum, report.score);
    for (const r of report.reasons) {
      assert.equal(typeof r.label, 'string');
      assert.equal(typeof r.points, 'number');
      assert.ok(r.points > 0);
    }
  });
});

// ---------------------------------------------------------------------------
// NEGATIVE cases: legitimate URLs must NOT be flagged
// ---------------------------------------------------------------------------
describe('negative: legitimate URLs score 0 / low risk', () => {
  const safeUrls = [
    'https://google.com/',
    'https://www.google.com/search?q=cats',
    'https://github.com/user/repo',
    'https://stackoverflow.com/questions/123',
    'https://en.wikipedia.org/wiki/Phishing',
    'https://microsoft.com/en-us',
    'https://amazon.com/gp/bestbooks',
    'https://example.com/blog/post',
    'https://blog.example.org/2024/post',
    'https://mail.google.com/inbox',
    'https://news.ycombinator.com/',
    'https://developer.mozilla.org/en-US/docs/Web'
  ];

  for (const url of safeUrls) {
    it(`scores ${url} as safe`, () => {
      const report = analyzeUrl(url);
      assert.equal(report.score, 0, `score was ${report.score} for ${url}`);
      assert.equal(report.level, 'safe');
      assert.equal(shouldWarn(report.score), false);
      assert.equal(shouldBlock(report.score), false);
    });
  }

  it('does not flag microsoftonline.com (old substring false positive)', () => {
    assert.equal(checkBrandImpersonation('microsoftonline.com').score, 0);
    assert.equal(analyzeUrl('https://microsoftonline.com/login').score, 0);
  });

  it('does not flag pineapple.com (brand substring false positive)', () => {
    assert.equal(analyzeUrl('https://pineapple.com/').score, 0);
  });

  it('does not flag official PayPal domains', () => {
    assert.equal(analyzeUrl('https://www.paypal.com/signin').score, 0);
    assert.equal(detectPayPalImpersonation('paypal.com'), false);
    assert.equal(checkBrandImpersonation('paypal.com').score, 0);
  });

  it('does not flag official country-domain variants (paypal.com.br)', () => {
    assert.equal(checkBrandImpersonation('paypal.com.br').score, 0);
  });

  it('does not flag microsoft official subdomains', () => {
    assert.equal(checkBrandImpersonation('login.microsoft.com').score, 0);
    assert.equal(checkBrandImpersonation('outlook.office365.com').score, 0);
  });

  it('does not match whitelist via concatenation (notgoogle.com)', () => {
    assert.equal(isWhitelisted('notgoogle.com', ['google.com']), false);
    assert.equal(analyzeUrl('https://notgoogle.com/', { whitelistedDomains: ['google.com'] }).whitelisted, false);
  });

  it('does not flag brand names that only appear in the URL path', () => {
    // Wikipedia-style article URLs must not trigger the userinfo rule
    assert.equal(analyzeUrl('https://example.org/wiki/PayPal').score, 0);
  });

  it('returns 0 for a clean path on an unbranded domain', () => {
    assert.equal(analyzeUrl('https://example.com/about').score, 0);
  });

  it('does not treat HTTPS login pages as insecure', () => {
    assert.equal(analyzeUrlStructure(u('https://secure-login.example/')).score, 0);
  });
});

// ---------------------------------------------------------------------------
// BOUNDARY cases: exact threshold behavior
// ---------------------------------------------------------------------------
describe('boundary: thresholds and limits', () => {
  it('risk level bands: 20/21, 40/41, 70/71', () => {
    assert.equal(getRiskLevel(0), 'safe');
    assert.equal(getRiskLevel(20), 'safe');
    assert.equal(getRiskLevel(21), 'low');
    assert.equal(getRiskLevel(40), 'low');
    assert.equal(getRiskLevel(41), 'medium');
    assert.equal(getRiskLevel(70), 'medium');
    assert.equal(getRiskLevel(71), 'high');
    assert.equal(getRiskLevel(100), 'high');
  });

  it('warn/block decisions are strictly greater-than', () => {
    assert.equal(shouldWarn(RISK_THRESHOLDS.WARN), false);    // 40
    assert.equal(shouldWarn(RISK_THRESHOLDS.WARN + 1), true); // 41
    assert.equal(shouldBlock(RISK_THRESHOLDS.BLOCK), false);    // 70
    assert.equal(shouldBlock(RISK_THRESHOLDS.BLOCK + 1), true); // 71
  });

  it('score exactly 40 does not trigger a warning', () => {
    // 25 shortener + 15 redirect = 40
    const report = analyzeUrl('https://bit.ly/x?redirect=https://evil.example');
    assert.equal(report.score, 40);
    assert.equal(shouldWarn(report.score), false);
    assert.equal(report.level, 'low');
  });

  it('score just above 41 does trigger a warning', () => {
    assert.equal(shouldWarn(41), true);
    // 25 shortener + 15 redirect + 10 (URL > 100 chars) = 50
    const long =
      'https://bit.ly/x?redirect=1&pad=' + 'x'.repeat(80);
    const report = analyzeUrl(long);
    assert.equal(report.score, 50);
    assert.ok(report.score > RISK_THRESHOLDS.WARN);
    assert.equal(report.level, 'medium');
  });

  it('domain length boundary: 30 chars no penalty, 31 chars +15', () => {
    const d30 = 'a'.repeat(26) + '.com'; // 30 chars
    const d31 = 'a'.repeat(27) + '.com'; // 31 chars
    assert.equal(d30.length, 30);
    assert.equal(d31.length, 31);
    assert.equal(analyzeDomain(d30).score, 0);
    assert.equal(analyzeDomain(d31).score, 15);
  });

  it('subdomain boundary: 3 subdomains no penalty, 4 +45', () => {
    assert.equal(analyzeDomain('a.b.c.example.com').score, 0);    // 3 subdomains
    assert.equal(analyzeDomain('a.b.c.d.example.com').score, 45); // 4 subdomains
  });

  it('URL length boundary: 100 chars no penalty, 101 chars +10', () => {
    const prefix = 'https://example.com/?a='; // 23 chars
    const url100 = prefix + 'x'.repeat(100 - prefix.length);
    const url101 = prefix + 'x'.repeat(101 - prefix.length);
    assert.equal(url100.length, 100);
    assert.equal(url101.length, 101);
    assert.equal(analyzeUrl(url100).score, 0);
    assert.equal(analyzeUrl(url101).score, 10);
  });

  it('score never exceeds 100', () => {
    const report = analyzeUrl('http://paypa1-login.com/login');
    assert.equal(report.score, 100);
    const report2 = analyzeUrl('http://paypa1-login.tk/');
    assert.equal(report2.score, 100);
  });

  it('whitelist matches subdomains of trusted domains', () => {
    assert.equal(isWhitelisted('www.google.com', ['google.com']), true);
    assert.equal(isWhitelisted('a.b.google.com', ['google.com']), true);
    assert.equal(isWhitelisted('google.com', new Set(['google.com'])), true);
    assert.equal(isWhitelisted('google.com.evil.net', ['google.com']), false);
  });

  it('empty whitelist trusts nothing', () => {
    assert.equal(isWhitelisted('google.com', []), false);
    assert.equal(isWhitelisted('google.com', undefined), false);
  });
});

// ---------------------------------------------------------------------------
// EDGE cases: malformed, unusual, or hostile inputs
// ---------------------------------------------------------------------------
describe('edge: unusual inputs never throw', () => {
  it('rejects invalid URLs gracefully', () => {
    for (const bad of ['not a url', '', 'http://', '://broken', '???']) {
      const report = analyzeUrl(bad);
      assert.equal(report.score, 0);
      assert.equal(report.error, 'invalid-url');
      assert.equal(report.level, 'safe');
    }
  });

  it('handles null/undefined/non-string input', () => {
    for (const bad of [null, undefined, 42, {}, []]) {
      const report = analyzeUrl(bad);
      assert.equal(report.score, 0);
      assert.equal(report.error, 'invalid-url');
    }
  });

  it('skips non-http(s) schemes', () => {
    for (const url of [
      'chrome://extensions',
      'about:blank',
      'file:///etc/passwd',
      'data:text/html,<script>alert(1)</script>',
      'javascript:alert(1)',
      'chrome-extension://abcdef/popup.html'
    ]) {
      const report = analyzeUrl(url);
      assert.equal(report.skipped, true, `should skip ${url}`);
      assert.equal(report.score, 0);
      assert.equal(shouldBlock(report.score), false);
    }
  });

  it('handles uppercase schemes and hosts (URL normalization)', () => {
    const report = analyzeUrl('HTTPS://WWW.GOOGLE.COM/Search');
    assert.equal(report.score, 0);
    assert.equal(report.domain, 'www.google.com');
  });

  it('scores an IP-address host without crashing', () => {
    const report = analyzeUrl('http://192.168.1.1/login');
    // security hints match the HOSTNAME only, so an IP host scores 0
    assert.equal(report.score, 0);
    assert.equal(report.level, 'safe');
    assert.equal(analyzeDomain('192.168.1.1').score, 0); // no letters -> no mixed penalty
    // but the same hint on a named host does score
    assert.equal(analyzeUrlStructure(u('http://192.168.1.1/')).score, 0);
    assert.equal(analyzeUrlStructure(u('http://login.example/')).score, 40);
  });

  it('handles localhost with a port', () => {
    assert.equal(analyzeUrl('http://localhost:3000/').score, 0);
    assert.equal(analyzeUrl('https://localhost:8443/app').score, 0);
  });

  it('benign userinfo without a brand adds no points', () => {
    const report = analyzeUrl('http://user@example.com/');
    assert.equal(report.score, 0);
    assert.equal(shouldWarn(report.score), false);
  });

  it('handles a 10 KB URL without crashing', () => {
    const long = 'https://example.com/?q=' + 'a'.repeat(10 * 1024);
    const report = analyzeUrl(long);
    assert.ok(report.score <= 100);
    assert.equal(report.error, null);
  });

  it('handles URL fragments and ports', () => {
    assert.equal(analyzeUrl('https://example.com:8080/page#section').score, 0);
  });

  it('handles suspicious TLDs at the exact boundary', () => {
    assert.equal(analyzeDomain('site.tk').score, 45);
    assert.equal(analyzeDomain('site.tkk').score, 0);
    assert.equal(analyzeDomain('site.com.tk').score, 45);
  });

  it('pattern matching is bounded to 2000 chars', () => {
    const url = 'https://example.com/?pad=' + 'a'.repeat(5000) + '&verify identity';
    const result = analyzePatterns(url);
    // "verify identity" sits beyond the 2000-char cap and must not match
    assert.equal(result.score, 0);
  });

  it('homograph detection ignores plain ASCII', () => {
    assert.equal(detectHomograph('google.com'), false);
    assert.equal(detectHomograph('xn--ggle-55da.com'), true);
    assert.equal(detectHomograph('gооgle.com'), true); // Cyrillic о
    assert.equal(detectHomograph('paypa1-login.com'), false);
  });
});
