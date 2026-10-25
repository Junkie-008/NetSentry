/**
 * NetSentry Browser Extension - Background Service Worker
 *
 * Real-time URL analysis and phishing detection engine.
 * All scoring logic lives in detector.js (shared, unit-tested).
 *
 * @author ABHISHEK
 * @version 1.1
 */

/* global Detector */

// Load the shared detection engine (browser path).
if (typeof importScripts === 'function') {
  importScripts('detector.js');
}

// Background service worker for phishing detection
class PhishingDetector {
  constructor() {
    this.suspiciousDomains = new Set();
    this.whitelistedDomains = new Set(Detector.DEFAULT_WHITELIST);
    // Dedupe map: tabId -> { url, time } so a URL analyzed once (tabs.onUpdated
    // AND webNavigation.onBeforeNavigate both fire) does not double-count stats.
    this.recentlyAnalyzed = new Map();
    this.init();
  }

  init() {
    if (typeof chrome === 'undefined' || !chrome.tabs) return;

    // Listen for tab updates
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (changeInfo.status === 'complete' && tab.url) {
        this.analyzeUrl(tab.url, tabId);
      }
    });

    // Listen for web navigation. This fires BEFORE the tab commits to the new
    // page (the tab may still show about:blank), so it only refreshes the
    // analysis - injection side effects run on tabs.onUpdated 'complete'.
    if (chrome.webNavigation && chrome.webNavigation.onBeforeNavigate) {
      chrome.webNavigation.onBeforeNavigate.addListener((details) => {
        if (details.frameId === 0) {
          this.analyzeUrl(details.url, details.tabId, { sideEffects: false });
        }
      });
    }

    // Clean up per-tab analysis data when a tab closes.
    if (chrome.tabs.onRemoved) {
      chrome.tabs.onRemoved.addListener((tabId) => {
        this.recentlyAnalyzed.delete(tabId);
        if (chrome.storage && chrome.storage.local && chrome.storage.local.remove) {
          Promise.resolve(chrome.storage.local.remove(`analysis_${tabId}`)).catch(() => {});
        }
      });
    }

    // Keep whitelist/suspicious lists in sync with storage writes (e.g. the
    // popup's "Trust Site" button).
    if (chrome.storage && chrome.storage.onChanged) {
      chrome.storage.onChanged.addListener((changes, area) => {
        if (area !== 'local') return;
        if (changes.whitelistedDomains && changes.whitelistedDomains.newValue) {
          this.whitelistedDomains = new Set([
            ...Detector.DEFAULT_WHITELIST,
            ...changes.whitelistedDomains.newValue
          ]);
        }
        if (changes.suspiciousDomains && changes.suspiciousDomains.newValue) {
          this.suspiciousDomains = new Set(changes.suspiciousDomains.newValue);
        }
      });
    }

    // Load persisted lists from storage
    this.loadStoredLists();
  }

  async loadStoredLists() {
    try {
      const result = await chrome.storage.local.get([
        'suspiciousDomains',
        'whitelistedDomains'
      ]);
      if (result.suspiciousDomains) {
        this.suspiciousDomains = new Set(result.suspiciousDomains);
      }
      if (result.whitelistedDomains) {
        this.whitelistedDomains = new Set([
          ...Detector.DEFAULT_WHITELIST,
          ...result.whitelistedDomains
        ]);
      }
    } catch (error) {
      console.error('NetSentry: error loading stored lists:', error);
    }
  }

  async saveSuspiciousDomains() {
    try {
      await chrome.storage.local.set({
        suspiciousDomains: Array.from(this.suspiciousDomains)
      });
    } catch (error) {
      console.error('NetSentry: error saving suspicious domains:', error);
    }
  }

  /** Full risk report for a URL using current whitelist/suspicious lists. */
  getReport(url) {
    return Detector.analyzeUrl(url, {
      whitelistedDomains: this.whitelistedDomains,
      suspiciousDomains: this.suspiciousDomains
    });
  }

  isDuplicate(tabId, url) {
    const last = this.recentlyAnalyzed.get(tabId);
    if (!last) return false;
    return last.url === url && Date.now() - last.time < 5000;
  }

  analyzeUrl(url, tabId, options) {
    // sideEffects=false is used for pre-navigation signals, where the tab has
    // not committed yet and chrome.scripting cannot touch its contents.
    const sideEffects = !options || options.sideEffects !== false;
    try {
      const report = this.getReport(url);
      if (report.error || report.skipped) {
        // chrome://, about:, invalid URLs etc. - just reset the badge.
        // Exception: our own blocked.html keeps the red "!" badge so the
        // protection stays visible while the user reads it.
        const isBlockedPage =
          typeof url === 'string' && url.indexOf('/blocked.html') !== -1;
        this.updateBadge(tabId, isBlockedPage ? 100 : 0);
        return report;
      }

      if (sideEffects) {
        const duplicate = this.isDuplicate(tabId, url);
        this.recentlyAnalyzed.set(tabId, { url, time: Date.now() });

        if (!duplicate) {
          if (Detector.shouldBlock(report.score)) {
            this.blockPhishingSite(tabId, report);
            this.incrementStat('sitesBlocked');
            this.incrementStat('threatsDetected');
          } else if (Detector.shouldWarn(report.score)) {
            this.warnUser(tabId, report);
            this.incrementStat('threatsDetected');
          }
        }
      }

      // Update badge based on risk
      this.updateBadge(tabId, report.score);

      // Store analysis result for the popup
      chrome.storage.local.set({
        [`analysis_${tabId}`]: {
          url,
          domain: report.domain,
          riskScore: report.score,
          level: report.level,
          reasons: report.reasons,
          timestamp: Date.now()
        }
      });

      return report;
    } catch (error) {
      console.error('NetSentry: error analyzing URL:', error);
      return null;
    }
  }

  /**
   * Serialized read-modify-write: two rapid increments (e.g. sitesBlocked and
   * threatsDetected on the same block) must not race and lose an update.
   */
  incrementStat(key) {
    this._statQueue = (this._statQueue || Promise.resolve())
      .then(async () => {
        const result = await chrome.storage.local.get(['stats']);
        const stats = result.stats || { sitesBlocked: 0, threatsDetected: 0, sitesReported: 0 };
        stats[key] = (stats[key] || 0) + 1;
        await chrome.storage.local.set({ stats });
      })
      .catch((error) => {
        console.error('NetSentry: error updating stats:', error);
      });
    return this._statQueue;
  }

  async blockPhishingSite(tabId, report) {
    try {
      // Remember the domain so future visits are flagged immediately.
      if (report.domain) {
        this.suspiciousDomains.add(report.domain);
        await this.saveSuspiciousDomains();
      }

      const reasons = (report.reasons || [])
        .slice(0, 5)
        .map((r) => `<li>${escapeHtml(r.label)} (+${r.points})</li>`);

      // Inject blocking page using modern scripting API
      await chrome.scripting.executeScript({
        target: { tabId: tabId },
        func: (riskScore, domain, reasonItems) => {
          document.documentElement.innerHTML = `
            <style>
              * { box-sizing: border-box; margin: 0; padding: 0; }
              body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: radial-gradient(circle at 20% 20%, #1b263b 0%, #0d1b2a 70%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                color: #e0e1dd;
              }
              .pd-card {
                background: rgba(27, 38, 59, 0.75);
                border: 1px solid rgba(65, 90, 119, 0.7);
                backdrop-filter: blur(14px);
                border-radius: 20px;
                padding: 40px 36px;
                max-width: 620px;
                width: calc(100% - 40px);
                text-align: center;
                box-shadow: 0 24px 60px rgba(0, 0, 0, 0.55);
              }
              .pd-icon { font-size: 64px; margin-bottom: 14px; animation: pd-shake 0.6s ease-in-out infinite alternate; }
              @keyframes pd-shake { from { transform: translateX(-4px); } to { transform: translateX(4px); } }
              h1 { font-size: 26px; letter-spacing: 0.5px; color: #e0e1dd; margin-bottom: 10px; }
              p { font-size: 14px; line-height: 1.6; color: #778da9; margin-bottom: 10px; }
              .pd-domain {
                display: inline-block;
                font-family: 'SFMono-Regular', Consolas, monospace;
                font-size: 13px;
                background: rgba(65, 90, 119, 0.45);
                border: 1px solid #778da9;
                color: #e0e1dd;
                padding: 6px 14px;
                border-radius: 999px;
                margin: 8px 0 16px;
                word-break: break-all;
              }
              .pd-score { font-size: 34px; font-weight: 800; color: #e0e1dd; margin: 6px 0 16px; }
              .pd-score small { font-size: 15px; color: #778da9; font-weight: 500; }
              .pd-reasons {
                text-align: left;
                background: rgba(13, 27, 42, 0.8);
                border: 1px solid rgba(65, 90, 119, 0.8);
                border-radius: 12px;
                padding: 14px 18px;
                margin: 0 auto 20px;
                max-width: 460px;
                font-size: 13px;
                color: #e0e1dd;
              }
              .pd-reasons ul { margin: 6px 0 0 18px; }
              .pd-reasons li { margin-bottom: 4px; }
              .pd-actions { display: flex; gap: 12px; justify-content: center; flex-wrap: wrap; }
              .pd-actions button {
                background: linear-gradient(135deg, #415a77, #778da9);
                color: #0d1b2a;
                border: none;
                padding: 12px 26px;
                border-radius: 999px;
                cursor: pointer;
                font-size: 14px;
                font-weight: 700;
                transition: transform 0.15s ease, box-shadow 0.15s ease;
                box-shadow: 0 8px 20px rgba(65, 90, 119, 0.5);
              }
              .pd-actions button.secondary { background: rgba(119, 141, 169, 0.2); border: 1px solid rgba(224, 225, 221, 0.4); color: #e0e1dd; box-shadow: none; }
              .pd-actions button:hover { transform: translateY(-2px); box-shadow: 0 10px 24px rgba(119, 141, 169, 0.5); }
              .pd-footer { margin-top: 18px; font-size: 11px; color: #778da9; }
              @media (max-width: 640px) {
                .pd-card { padding: 28px 20px; }
                h1 { font-size: 21px; }
              }
            </style>
            <body>
              <div class="pd-card">
                <div class="pd-icon">🐊</div>
                <h1>PHISHING SITE BLOCKED</h1>
                <p><strong>This website has been identified as a potential phishing site.</strong></p>
                <div class="pd-domain">${window.location.hostname}</div>
                <div class="pd-score">${riskScore}<small>/100 risk</small></div>
                ${
                  reasonItems && reasonItems.length
                    ? `<div class="pd-reasons"><strong>Why this was blocked:</strong><ul>${reasonItems.join('')}</ul></div>`
                    : ''
                }
                <p>This site appears to be impersonating a legitimate service to steal your personal information. Access has been blocked by NetSentry.</p>
                <div class="pd-actions">
                  <button onclick="history.back()">← Go Back</button>
                  <button class="secondary" onclick="window.close()">Close Tab</button>
                </div>
                <div class="pd-footer">NetSentry · local analysis · nothing ever leaves your browser</div>
              </div>
            </body>
          `;
        },
        args: [report.score, report.domain, reasons]
      });

      // HARDENING: the injected screen shares the document with the malicious
      // page's own JavaScript, which could rewrite the DOM back. Navigating
      // the tab to our extension page unloads that document completely -
      // its scripts stop running and forms die with it.
      try {
        const blockedUrl = new URL(chrome.runtime.getURL('blocked.html'));
        blockedUrl.searchParams.set('score', String(report.score));
        blockedUrl.searchParams.set('domain', report.domain || '');
        (report.reasons || [])
          .slice(0, 5)
          .forEach((r) => blockedUrl.searchParams.append('r', `${r.label} (+${r.points})`));
        await chrome.tabs.update(tabId, { url: blockedUrl.toString() });
        // Clear the dedupe marker so navigating back to the phishing URL
        // (within the 5s window) triggers a fresh block instead of being
        // skipped as a duplicate.
        this.recentlyAnalyzed.delete(tabId);
      } catch (error) {
        console.error('NetSentry: redirect to blocked page failed:', error);
        // The injected block screen remains in place as fallback.
      }
    } catch (error) {
      console.error('NetSentry: error blocking phishing site:', error);
    }
  }

  async warnUser(tabId, report) {
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tabId },
        func: (riskScore, hostname) => {
          if (!document.querySelector('#phishing-warning')) {
            const warning = document.createElement('div');
            warning.id = 'phishing-warning';
            warning.className = 'phishing-warning-overlay';
            warning.innerHTML = `
              <span class="warning-icon">⚠️</span>
              <strong>SUSPICIOUS SITE DETECTED</strong>
              <br>
              <small>${hostname} · risk ${riskScore}/100</small>
              <button class="dismiss-btn" type="button">Dismiss</button>
            `;
            const dismiss = warning.querySelector('.dismiss-btn');
            if (dismiss) {
              dismiss.addEventListener('click', () => warning.remove());
            }
            (document.body || document.documentElement).appendChild(warning);

            // Auto-dismiss after 10 seconds
            setTimeout(() => {
              const el = document.querySelector('#phishing-warning');
              if (el) el.remove();
            }, 10000);
          }
        },
        args: [report.score, report.domain]
      });
    } catch (error) {
      console.error('NetSentry: error showing warning:', error);
    }
  }

  updateBadge(tabId, riskScore) {
    if (!chrome.action || !chrome.action.setBadgeText) return;

    let badgeText = '';
    let badgeColor = '#415a77'; // slate for safe/cleared

    if (Detector.shouldBlock(riskScore)) {
      badgeText = '!';
      badgeColor = '#e0e1dd'; // brightest = highest risk
    } else if (Detector.shouldWarn(riskScore)) {
      badgeText = '?';
      badgeColor = '#778da9'; // mid slate = warning
    }

    chrome.action.setBadgeText({ text: badgeText, tabId });
    chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId });
    if (chrome.action.setBadgeTextColor) {
      chrome.action.setBadgeTextColor({ color: '#0d1b2a', tabId });
    }
  }

  /**
   * Fresh report for the active tab, recomputed with the current whitelist so
   * the popup reflects "Trust Site" clicks immediately.
   */
  async getActiveAnalysis() {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const tab = tabs[0];
      if (!tab || !tab.url) return null;

      const stored = await chrome.storage.local.get([`analysis_${tab.id}`]);
      const existing = stored[`analysis_${tab.id}`] || null;
      const url = existing ? existing.url : tab.url;

      const report = this.getReport(url);
      if (report.error || report.skipped) return existing;

      const analysis = {
        url,
        domain: report.domain,
        riskScore: report.score,
        level: report.level,
        reasons: report.reasons,
        timestamp: Date.now()
      };
      await chrome.storage.local.set({ [`analysis_${tab.id}`]: analysis });
      return analysis;
    } catch (error) {
      console.error('NetSentry: error getting analysis:', error);
      return null;
    }
  }
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Initialize the phishing detector (browser only; skipped in Node tests).
let phishingDetector = null;
if (typeof chrome !== 'undefined' && chrome.runtime) {
  phishingDetector = new PhishingDetector();

  // Handle messages from popup
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getAnalysis') {
      phishingDetector.getActiveAnalysis().then(sendResponse);
      return true; // keep the message channel open for the async response
    }

    if (request.action === 'reportPhishing') {
      try {
        const domain = new URL(request.url).hostname.toLowerCase();
        phishingDetector.suspiciousDomains.add(domain);
        phishingDetector.saveSuspiciousDomains();
        phishingDetector.incrementStat('sitesReported');
        sendResponse({ success: true });
      } catch (e) {
        sendResponse({ success: false });
      }
      return false;
    }

    return false;
  });
}

// Export for Node tests.
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { PhishingDetector, escapeHtml };
}
