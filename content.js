/**
 * NetSentry Browser Extension - Content Script
 *
 * Real-time page analysis and form monitoring.
 * Keywords/shortener lists come from the shared detector.js engine.
 *
 * @author ABHISHEK
 * @version 1.1
 */

/* global Detector */

// Content script for real-time page analysis
class PageAnalyzer {
  constructor() {
    this.suspiciousElements = [];
    this.formSubmissions = [];
    this.init();
  }

  init() {
    // Wait for DOM to be ready before the first full analysis.
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => this.analyzePage());
    } else {
      this.analyzePage();
    }

    // Monitor form submissions
    this.monitorForms();

    // Monitor dynamic content changes.
    // BUG FIX: at document_start, document.body can still be null, which made
    // observer.observe(document.body) throw and killed mutation monitoring.
    this.observeMutations();
  }

  analyzePage() {
    this.analyzeLinks();
    this.analyzeForms();
    this.analyzeImages();
    this.analyzeText();
    this.checkSSL();
  }

  analyzeLinks() {
    const links = document.querySelectorAll('a[href]');

    links.forEach((link) => {
      const href = link.href;

      // Check for suspicious link patterns
      if (this.isSuspiciousLink(href)) {
        this.markSuspiciousElement(link, 'Suspicious link detected');
      }

      // Check for misleading display text
      if (this.isMisleadingLink(link)) {
        this.markSuspiciousElement(link, 'Misleading link text');
      }
    });
  }

  analyzeForms() {
    const forms = document.querySelectorAll('form');

    forms.forEach((form) => {
      // Check for password/sensitive input fields
      const hasPasswordField = form.querySelector('input[type="password"]');
      const hasEmailField = form.querySelector('input[type="email"], input[name*="email"]');
      const hasCreditCardField = form.querySelector('input[name*="card"], input[name*="credit"]');

      if (hasPasswordField || hasEmailField || hasCreditCardField) {
        const isSecure = window.location.protocol === 'https:';

        if (!isSecure) {
          this.markSuspiciousElement(form, 'Insecure form collecting sensitive data');
        }

        // Check form action URL
        const action = form.action || window.location.href;
        if (this.isSuspiciousUrl(action)) {
          this.markSuspiciousElement(form, 'Form submits to suspicious URL');
        }
      }
    });
  }

  analyzeImages() {
    const images = document.querySelectorAll('img');

    images.forEach((img) => {
      if (this.isSuspiciousImage(img)) {
        this.markSuspiciousElement(img, 'Suspicious image detected');
      }
    });
  }

  analyzeText() {
    const body = document.body;
    if (!body) return;

    const textNodes = this.getTextNodes(body);
    const fullText = textNodes.join(' ').toLowerCase();

    // Check for phishing keywords (shared list from detector.js)
    Detector.PHISHING_KEYWORDS.forEach((keyword) => {
      if (fullText.includes(keyword)) {
        this.addSuspiciousFlag(`Phishing keyword detected: "${keyword}"`);
      }
    });
  }

  checkSSL() {
    if (window.location.protocol !== 'https:' && this.hasSensitiveContent()) {
      this.addSuspiciousFlag('Non-HTTPS site collecting sensitive information');
    }
  }

  isSuspiciousLink(href) {
    try {
      const url = new URL(href, window.location.href);

      // Check for URL shorteners (shared list from detector.js)
      if (Detector.URL_SHORTENERS.includes(url.hostname)) {
        return true;
      }

      // Check for suspicious patterns
      if (url.href.includes('..') || url.href.length > 100) {
        return true;
      }

      return false;
    } catch {
      return true; // Invalid URL
    }
  }

  isMisleadingLink(link) {
    const displayText = link.textContent.toLowerCase().trim();
    const actualUrl = link.href.toLowerCase();

    // Check if display text suggests one domain but link goes to another
    const domains = ['paypal', 'amazon', 'google', 'facebook', 'microsoft', 'apple'];

    for (const domain of domains) {
      if (displayText.includes(domain) && !actualUrl.includes(domain)) {
        return true;
      }
    }

    return false;
  }

  isSuspiciousUrl(url) {
    try {
      const urlObj = new URL(url, window.location.href);
      const domain = urlObj.hostname.toLowerCase();

      // Basic suspicious domain patterns
      if (domain.includes('secure') && domain.includes('verify')) {
        return true;
      }

      if (domain.split('.').length > 4) {
        // Too many subdomains
        return true;
      }

      return false;
    } catch {
      return true;
    }
  }

  isSuspiciousImage(img) {
    // Check if image source is from a different domain
    if (img.src && img.src.startsWith('http')) {
      try {
        const imgDomain = new URL(img.src).hostname;
        const pageDomain = window.location.hostname;

        if (imgDomain !== pageDomain && !this.isKnownCDN(imgDomain)) {
          return true;
        }
      } catch {
        return true;
      }
    }

    return false;
  }

  isKnownCDN(domain) {
    const cdns = [
      'cloudfront.net', 'cloudflare.com', 'fastly.com',
      'jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com'
    ];

    return cdns.some((cdn) => domain.includes(cdn));
  }

  hasSensitiveContent() {
    const forms = document.querySelectorAll('form');

    for (const form of forms) {
      if (form.querySelector('input[type="password"], input[type="email"], input[name*="card"]')) {
        return true;
      }
    }

    return false;
  }

  markSuspiciousElement(element, reason) {
    if (element.dataset && element.dataset.pdMarked === '1') return; // avoid duplicates
    this.suspiciousElements.push({ element, reason });
    if (element.dataset) element.dataset.pdMarked = '1';

    // Visual indicator using the shared styles.css classes (!important, so page
    // styles cannot hide them) instead of per-element inline styles.
    element.classList.add('phishing-detector-suspicious');
    if (reason === 'Insecure form collecting sensitive data') {
      element.classList.add('phishing-detector-insecure-form');
    }
    element.title = `⚠️ ${reason}`;

    // Add click warning for links
    if (element.tagName === 'A') {
      element.addEventListener('click', (e) => {
        if (!confirm(`Warning: ${reason}\n\nDo you want to continue?`)) {
          e.preventDefault();
        }
      });
    }
  }

  addSuspiciousFlag(reason) {
    // Store for popup display
    if (!window.phishingFlags) {
      window.phishingFlags = [];
    }
    if (!window.phishingFlags.includes(reason)) {
      window.phishingFlags.push(reason);
    }
  }

  monitorForms() {
    document.addEventListener('submit', (e) => {
      const form = e.target;

      if (form.tagName === 'FORM') {
        const hasPassword = form.querySelector('input[type="password"]');
        const hasEmail = form.querySelector('input[type="email"], input[name*="email"]');

        if ((hasPassword || hasEmail) && window.location.protocol !== 'https:') {
          if (!confirm('Warning: You are about to submit sensitive information over an insecure connection. Continue?')) {
            e.preventDefault();
          }
        }

        // Log form submission for analysis
        this.formSubmissions.push({
          action: form.action || window.location.href,
          timestamp: Date.now(),
          hasPassword: !!hasPassword,
          hasEmail: !!hasEmail
        });
      }
    });
  }

  observeMutations() {
    // BUG FIX: document.body may be null when this runs at document_start.
    const root = document.documentElement || document;
    if (!root) return;

    let reanalyzeTimer = null;
    const observer = new MutationObserver((mutations) => {
      let shouldReanalyze = false;

      mutations.forEach((mutation) => {
        if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              // Check if new forms or links were added
              if (
                (node.querySelector && node.querySelector('form, a[href]')) ||
                node.tagName === 'FORM' ||
                node.tagName === 'A'
              ) {
                shouldReanalyze = true;
              }
            }
          });
        }
      });

      if (shouldReanalyze) {
        // Debounced so rapid DOM churn triggers a single re-analysis.
        if (reanalyzeTimer) clearTimeout(reanalyzeTimer);
        reanalyzeTimer = setTimeout(() => this.analyzePage(), 100);
      }
    });

    observer.observe(root, {
      childList: true,
      subtree: true
    });
  }

  getTextNodes(element) {
    const textNodes = [];
    const walker = document.createTreeWalker(
      element,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode(node) {
          // Skip script/style/noscript content so code strings do not
          // produce false phishing-keyword matches.
          const parent = node.parentElement;
          if (parent) {
            const tag = parent.tagName;
            if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'NOSCRIPT') {
              return NodeFilter.FILTER_REJECT;
            }
          }
          return NodeFilter.FILTER_ACCEPT;
        }
      },
      false
    );

    let node;
    while ((node = walker.nextNode())) {
      textNodes.push(node.textContent);
    }

    return textNodes;
  }
}

// Initialize page analyzer on http(s) pages only.
if (
  typeof Detector !== 'undefined' &&
  typeof document !== 'undefined' &&
  (document.location.protocol === 'http:' || document.location.protocol === 'https:')
) {
  new PageAnalyzer();
}

// Expose for debugging / re-analysis (mirrors Detector's global exposure).
if (typeof globalThis !== 'undefined') {
  globalThis.PageAnalyzer = PageAnalyzer;
}

// Export for Node tests.
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { PageAnalyzer };
}
