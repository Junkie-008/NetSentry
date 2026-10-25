/**
 * Performance tests for the detection engine.
 *
 * Guards against regressions such as catastrophic regex backtracking
 * (the old /secure.*verify/i pattern took ~870ms on a 120KB pathological
 * input; the bounded pattern must stay fast).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { performance } = require('node:perf_hooks');

const Detector = require('../../detector.js');

const now = () => performance.now();

describe('performance', () => {
  it('analyzes 10,000 mixed URLs in under 2 seconds', () => {
    const urls = [];
    for (let i = 0; i < 10000; i++) {
      const kind = i % 5;
      if (kind === 0) urls.push(`https://site-${i}.example.com/page?id=${i}`);
      else if (kind === 1) urls.push(`http://paypa${(i % 10) ? '1' : 'l'}-login.com/login`);
      else if (kind === 2) urls.push(`https://bit.ly/x?redirect=${i}`);
      else if (kind === 3) urls.push(`http://free-prize${i}.tk/win`);
      else urls.push(`https://www.google.com/search?q=test${i}`);
    }

    // Warm-up
    for (let i = 0; i < 100; i++) Detector.analyzeUrl(urls[i]);

    const start = now();
    for (const url of urls) Detector.analyzeUrl(url);
    const elapsed = now() - start;

    const avgMs = elapsed / urls.length;
    assert.ok(
      elapsed < 2000,
      `10k URLs took ${elapsed.toFixed(0)}ms (avg ${avgMs.toFixed(4)}ms/URL)`
    );
    console.log(`    -> 10k URLs in ${elapsed.toFixed(0)}ms (avg ${avgMs.toFixed(4)}ms)`);
  });

  it('pattern matching stays fast on 120KB pathological input', () => {
    // Old patterns with unbounded .* took ~870ms here.
    const evil = 'secure'.repeat(20000); // 120,000 chars, no "verify"
    const start = now();
    const result = Detector.analyzePatterns(evil);
    const elapsed = now() - start;

    assert.equal(result.score, 0);
    assert.ok(elapsed < 100, `pathological input took ${elapsed.toFixed(1)}ms (limit 100ms)`);
    console.log(`    -> 120KB pathological patterns in ${elapsed.toFixed(1)}ms`);
  });

  it('analyzes a 50KB URL in under 50ms', () => {
    const url = 'https://example.com/?data=' + 'a'.repeat(50 * 1024);
    const start = now();
    const report = Detector.analyzeUrl(url);
    const elapsed = now() - start;

    assert.equal(report.error, null);
    assert.ok(elapsed < 50, `50KB URL took ${elapsed.toFixed(1)}ms (limit 50ms)`);
  });

  it('analyzes 1,000 worst-case URLs in under 1 second', () => {
    const urls = [];
    for (let i = 0; i < 1000; i++) {
      urls.push(
        'http://secure-login.paypal.com.evil' + i +
        '.com/update-payment?redirect=https://evil.example/' + 'x'.repeat(60)
      );
    }

    const start = now();
    for (const url of urls) Detector.analyzeUrl(url);
    const elapsed = now() - start;

    assert.ok(elapsed < 1000, `1k worst-case URLs took ${elapsed.toFixed(0)}ms`);
    console.log(`    -> 1k worst-case URLs in ${elapsed.toFixed(0)}ms`);
  });

  it('whitelist lookups stay fast with 1,000 trusted domains', () => {
    const whitelist = [];
    for (let i = 0; i < 1000; i++) whitelist.push(`trusted${i}.example.com`);

    const start = now();
    for (let i = 0; i < 1000; i++) {
      Detector.analyzeUrl(`https://trusted${i}.example.com/page`, { whitelistedDomains: whitelist });
    }
    const elapsed = now() - start;

    assert.ok(elapsed < 1000, `1k whitelist lookups took ${elapsed.toFixed(0)}ms`);
  });

  it('memory footprint of a report stays small', () => {
    const report = Detector.analyzeUrl('http://paypa1-login.com/login');
    const reasonsJson = JSON.stringify(report.reasons);
    assert.ok(reasonsJson.length < 5000, `reasons payload was ${reasonsJson.length} bytes`);
    assert.ok(report.reasons.length <= 12, `unexpectedly many reasons: ${report.reasons.length}`);
  });
});
