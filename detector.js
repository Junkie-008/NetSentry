/**
 * NetSentry Browser Extension - Shared Detection Engine
 *
 * Pure, side-effect-free URL/content analysis logic shared by:
 *  - background.js (service worker, via importScripts)
 *  - content.js    (content script, listed before content.js in the manifest)
 *  - popup.js      (popup UI, via <script src="detector.js">)
 *  - Node.js tests (via module.exports)
 *
 * No Chrome APIs are used here so the logic stays unit-testable.
 *
 * @author ABHISHEK
 * @version 1.1
 */

const Detector = (function () {
  'use strict';

  // ---------------------------------------------------------------------------
  // Configuration (single source of truth for thresholds used everywhere)
  // ---------------------------------------------------------------------------
  const RISK_THRESHOLDS = {
    WARN: 40,  // score > 40  => warning banner + "medium" level
    BLOCK: 70  // score > 70  => block page + "high" level
  };

  const DEFAULT_WHITELIST = [
    'google.com', 'facebook.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'github.com', 'stackoverflow.com', 'wikipedia.org'
  ];

  const SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq'];

  const URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly'];

  // Patterns are bounded ({0,N}) instead of using .* so they cannot
  // backtrack catastrophically on long/pathological URLs.
  const PHISHING_PATTERNS = [
    /secure.{0,80}verify/i,
    /account.{0,80}suspended/i,
    /click.{0,60}here.{0,60}immediately/i,
    /urgent.{0,60}action.{0,60}required/i,
    /verify.{0,80}identity/i,
    /update.{0,80}payment/i,
    /suspicious.{0,80}activity/i,
    /limited.{0,60}time/i
  ];

  const PHISHING_KEYWORDS = [
    'verify your account',
    'suspended account',
    'click here immediately',
    'urgent action required',
    'limited time offer',
    'congratulations you have won',
    'update payment information',
    'suspicious activity detected'
  ];

  const POPULAR_BRANDS = [
    'paypal', 'amazon', 'google', 'facebook', 'microsoft',
    'apple', 'netflix', 'instagram', 'twitter', 'linkedin',
    'ebay', 'walmart', 'target', 'chase', 'wellsfargo'
  ];

  const SECURITY_HOST_HINTS = ['login', 'secure', 'account', 'bank', 'paypal', 'paypa'];

  const PAYPAL_VARIANTS = [
    'paypa1',     // 1 instead of l
    'paypaI',     // capital I instead of l
    'payp4l',     // 4 instead of a
    'p4ypal',     // 4 instead of a
    'payp@l',     // @ instead of a
    'paypai',     // i instead of l
    'papyal',     // transposed letters
    'payapl',     // transposed letters
    'paipal',     // i instead of y
    'paypal1',    // with number
    'paypal-'     // with dash
  ];

  const CHARACTER_SUBSTITUTIONS = [
    { original: 'o', fake: '0' },
    { original: 'l', fake: '1' },
    { original: 'l', fake: 'I' },
    { original: 'a', fake: '@' },
    { original: 'a', fake: '4' },
    { original: 'e', fake: '3' },
    { original: 's', fake: '5' },
    { original: 'g', fake: '9' }
  ];

  const OFFICIAL_TLDS = ['.com', '.org'];

  // Cap how much of a URL we run pattern matching against (huge query strings,
  // data: URLs etc.) to keep analysis time bounded.
  const MAX_PATTERN_TEXT_LENGTH = 2000;

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /** Parse a URL, returning null instead of throwing on invalid input. */
  function parseUrl(url) {
    if (typeof url !== 'string' || url.length === 0) return null;
    try {
      return new URL(url);
    } catch (e) {
      return null;
    }
  }

  /**
   * Whitelist matching with subdomain support:
   * "google.com" also trusts "www.google.com" and "mail.google.com".
   */
  function isWhitelisted(domain, whitelist) {
    if (!domain) return false;
    const set = whitelist instanceof Set ? whitelist : new Set(whitelist || []);
    if (set.has(domain)) return true;
    for (const entry of set) {
      if (entry && domain.endsWith('.' + entry)) return true;
    }
    return false;
  }

  /** Map a numeric risk score to a level: safe | low | medium | high. */
  function getRiskLevel(score) {
    const s = Number(score);
    if (!Number.isFinite(s) || s <= 20) return 'safe';
    if (s <= RISK_THRESHOLDS.WARN) return 'low';
    if (s <= RISK_THRESHOLDS.BLOCK) return 'medium';
    return 'high';
  }

  function shouldWarn(score) {
    return Number(score) > RISK_THRESHOLDS.WARN;
  }

  function shouldBlock(score) {
    return Number(score) > RISK_THRESHOLDS.BLOCK;
  }

  function makeReason(label, points) {
    return { label, points };
  }

  // ---------------------------------------------------------------------------
  // Domain analysis (0-35 normal points, more for strong signals)
  // ---------------------------------------------------------------------------

  function isSuspiciousTld(domain) {
    return SUSPICIOUS_TLDS.some((tld) => domain.endsWith(tld));
  }

  /**
   * Homograph detection.
   *
   * BUG FIX: the URL parser converts non-ASCII hosts to punycode
   * (e.g. "gооgle.com" becomes "xn--ggle-55da.com"), so the old
   * Cyrillic/Greek character regex never matched a parsed hostname.
   * We now detect punycode labels ("xn--") as well as any raw
   * non-ASCII characters that survive parsing.
   */
  function detectHomograph(domain) {
    const labels = domain.split('.');
    if (labels.some((label) => label.toLowerCase().startsWith('xn--'))) {
      return true;
    }
    const suspiciousChars = /[\u0400-\u04FF\u0370-\u03FF\u0500-\u052F]/;
    return suspiciousChars.test(domain);
  }

  /**
   * Brand impersonation detection.
   *
   * A brand only counts as impersonated when it appears on label
   * boundaries (e.g. "paypal-security.com", "secure-paypal.net",
   * "paypal.evil.com") AND the host is not the official domain.
   * This fixes false positives like "microsoftonline.com" (brand
   * followed by a letter) that the old substring check flagged.
   */
  function brandAppearsAtBoundary(domain, brand) {
    // Boundary on both sides: start/end of the string or a non-alphanumeric
    // character (which includes "." between labels).
    const pattern = new RegExp(
      '(^|[^a-z0-9])' + brand.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '($|[^a-z0-9])',
      'i'
    );
    return pattern.test(domain);
  }

  function isOfficialDomain(domain, brand) {
    // Official: "paypal.com", "www.paypal.com", "paypal.com.br" (country
    // variant), but NOT "paypal.com.evil.net" (deceptive subdomain chain).
    return OFFICIAL_TLDS.some((tld) =>
      new RegExp('(^|\\.)' + brand + tld + '(\\.[a-z]{2})?$', 'i').test(domain)
    );
  }

  function detectPayPalImpersonation(domain) {
    for (const variant of PAYPAL_VARIANTS) {
      if (domain.includes(variant)) return true;
    }
    return false;
  }

  function detectCharacterSubstitution(domain) {
    for (const brand of POPULAR_BRANDS) {
      for (const sub of CHARACTER_SUBSTITUTIONS) {
        const fakeBrand = brand.replace(new RegExp(sub.original, 'g'), sub.fake);
        if (fakeBrand !== brand && domain.includes(fakeBrand)) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Returns { score, reason } for brand-related signals.
   * Strongest signals block on their own (score > 70).
   */
  function checkBrandImpersonation(domain) {
    // PayPal-specific variants: near-certain phishing.
    if (detectPayPalImpersonation(domain)) {
      return { score: 80, reason: 'PayPal impersonation pattern detected' };
    }
    // Generic character substitution ("g00gle.com", "m1crosoft.com").
    if (detectCharacterSubstitution(domain)) {
      return { score: 75, reason: 'Character-substituted brand name detected' };
    }
    for (const brand of POPULAR_BRANDS) {
      if (isOfficialDomain(domain, brand)) continue;
      if (brandAppearsAtBoundary(domain, brand)) {
        return { score: 75, reason: `Brand impersonation: "${brand}" in non-official domain` };
      }
    }
    return { score: 0, reason: null };
  }

  function analyzeDomain(domain) {
    let score = 0;
    const reasons = [];

    if (isSuspiciousTld(domain)) {
      score += 45;
      reasons.push(makeReason('Suspicious TLD (free/abused domain)', 45));
    }

    if (domain.length > 30) {
      score += 15;
      reasons.push(makeReason('Unusually long domain name', 15));
    }

    // Excessive subdomains (e.g. a.b.c.d.example.com)
    const subdomains = domain.split('.').length - 2;
    if (subdomains > 3) {
      score += 45;
      reasons.push(makeReason(`Excessive subdomains (${subdomains})`, 45));
    }

    if (/\d/.test(domain) && /[a-z]/.test(domain)) {
      score += 10;
      reasons.push(makeReason('Digits mixed with letters in domain', 10));
    }

    if (detectHomograph(domain)) {
      score += 40;
      reasons.push(makeReason('Homograph / punycode attack suspected', 40));
    }

    const brand = checkBrandImpersonation(domain);
    if (brand.score > 0) {
      score += brand.score;
      reasons.push(makeReason(brand.reason, brand.score));
    }

    return { score, reasons };
  }

  // ---------------------------------------------------------------------------
  // URL structure analysis (0-30 points)
  // ---------------------------------------------------------------------------

  function analyzeUrlStructure(urlObj) {
    let score = 0;
    const reasons = [];
    const hostname = urlObj.hostname.toLowerCase();

    // Plaintext HTTP on a security-related host.
    if (
      urlObj.protocol === 'http:' &&
      SECURITY_HOST_HINTS.some((hint) => hostname.includes(hint))
    ) {
      score += 40;
      reasons.push(makeReason('Insecure HTTP on a login/security-related host', 40));
    }

    if (URL_SHORTENERS.includes(hostname)) {
      score += 25;
      reasons.push(makeReason('URL shortener hides the real destination', 25));
    }

    if (urlObj.pathname.includes('..')) {
      score += 30;
      reasons.push(makeReason('Path traversal pattern in URL', 30));
    }

    if (urlObj.href.length > 100) {
      score += 10;
      reasons.push(makeReason('Very long URL', 10));
    }

    if (urlObj.search.includes('redirect') || urlObj.search.includes('url=')) {
      score += 15;
      reasons.push(makeReason('Redirect indicator in query string', 15));
    }

    // Brand hidden in the userinfo component ("http://paypal.com@evil.tk/"):
    // the browser connects to evil.tk while casual readers see "paypal.com".
    // Legitimate services never put brand names before the "@", so this is a
    // high-confidence, low-false-positive signal.
    const userinfo = (urlObj.username + ':' + urlObj.password).toLowerCase();
    if (userinfo !== ':') {
      const brand = POPULAR_BRANDS.find(
        (b) => userinfo.includes(b) && !isOfficialDomain(urlObj.hostname.toLowerCase(), b)
      );
      if (brand) {
        score += 75;
        reasons.push(makeReason(`Brand name hidden in URL userinfo (@ trick): "${brand}"`, 75));
      }
    }

    return { score, reasons };
  }

  // ---------------------------------------------------------------------------
  // Pattern analysis on the full URL (0-35+ points)
  // ---------------------------------------------------------------------------

  function analyzePatterns(url) {
    let score = 0;
    const reasons = [];
    const text = String(url).slice(0, MAX_PATTERN_TEXT_LENGTH);

    const labels = [
      'Phishing phrase: secure...verify',
      'Phishing phrase: account suspended',
      'Phishing phrase: click here immediately',
      'Phishing phrase: urgent action required',
      'Phishing phrase: verify identity',
      'Phishing phrase: update payment',
      'Phishing phrase: suspicious activity',
      'Phishing phrase: limited time'
    ];

    PHISHING_PATTERNS.forEach((pattern, i) => {
      if (pattern.test(text)) {
        score += 20;
        reasons.push(makeReason(labels[i] || 'Phishing phrase detected', 20));
      }
    });

    return { score, reasons };
  }

  // ---------------------------------------------------------------------------
  // Main entry point
  // ---------------------------------------------------------------------------

  /**
   * Analyze a URL and return a full risk report.
   *
   * @param {string} url
   * @param {object} [options]
   * @param {Set|string[]} [options.whitelistedDomains]
   * @param {Set|string[]} [options.suspiciousDomains]
   * @returns {{url: string, domain: string, score: number, level: string,
   *            reasons: Array<{label:string, points:number}>,
   *            whitelisted: boolean, skipped: boolean, error: string|null}}
   */
  function analyzeUrl(url, options) {
    const opts = options || {};
    const base = {
      url: typeof url === 'string' ? url : '',
      domain: '',
      score: 0,
      level: 'safe',
      reasons: [],
      whitelisted: false,
      skipped: false,
      error: null
    };

    const urlObj = parseUrl(url);
    if (!urlObj) {
      return Object.assign(base, { error: 'invalid-url' });
    }

    base.domain = urlObj.hostname.toLowerCase();

    // Only http(s) pages can be phishing sites; chrome://, about:, data:
    // and file: URLs are skipped.
    if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
      return Object.assign(base, { skipped: true });
    }

    if (isWhitelisted(base.domain, opts.whitelistedDomains)) {
      return Object.assign(base, { whitelisted: true });
    }

    let score = 0;
    const reasons = [];

    const suspiciousSet =
      opts.suspiciousDomains instanceof Set
        ? opts.suspiciousDomains
        : new Set(opts.suspiciousDomains || []);

    if (suspiciousSet.has(base.domain)) {
      score += 80;
      reasons.push(makeReason('Domain previously reported as phishing', 80));
    }

    const domainResult = analyzeDomain(base.domain);
    score += domainResult.score;
    reasons.push(...domainResult.reasons);

    const structureResult = analyzeUrlStructure(urlObj);
    score += structureResult.score;
    reasons.push(...structureResult.reasons);

    const patternResult = analyzePatterns(urlObj.href);
    score += patternResult.score;
    reasons.push(...patternResult.reasons);

    score = Math.min(score, 100);

    return Object.assign(base, {
      score,
      level: getRiskLevel(score),
      reasons
    });
  }

  return {
    RISK_THRESHOLDS,
    DEFAULT_WHITELIST,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
    PHISHING_PATTERNS,
    PHISHING_KEYWORDS,
    POPULAR_BRANDS,
    PAYPAL_VARIANTS,
    MAX_PATTERN_TEXT_LENGTH,
    parseUrl,
    isWhitelisted,
    getRiskLevel,
    shouldWarn,
    shouldBlock,
    detectHomograph,
    detectPayPalImpersonation,
    detectCharacterSubstitution,
    checkBrandImpersonation,
    analyzeDomain,
    analyzeUrlStructure,
    analyzePatterns,
    analyzeUrl
  };
})();

// Expose for browser contexts (service worker, content script, popup).
if (typeof globalThis !== 'undefined') {
  globalThis.Detector = Detector;
}

// Expose for Node.js tests.
if (typeof module !== 'undefined' && module.exports) {
  module.exports = Detector;
}
