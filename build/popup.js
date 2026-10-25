/**
 * NetSentry Browser Extension - Popup Interface
 *
 * User interface for displaying security analysis and controls.
 * Risk levels come from the shared detector.js engine so the popup,
 * badge and blocking logic can never disagree.
 *
 * @author ABHISHEK
 * @version 1.1
 */

/* global Detector */

// Popup script for displaying phishing analysis results
class PopupController {
  constructor() {
    this.currentAnalysis = null;
    this.init();
  }

  async init() {
    await this.loadAnalysis();
    this.setupEventListeners();
    this.loadStats();
  }

  async loadAnalysis() {
    try {
      // Get current tab analysis (background recomputes it with the latest
      // whitelist, so "Trust Site" takes effect immediately).
      const response = await chrome.runtime.sendMessage({ action: 'getAnalysis' });
      this.currentAnalysis = response;

      if (this.currentAnalysis) {
        this.displayAnalysis();
      } else {
        this.displayNoAnalysis();
      }

      // Hide loading, show content
      document.getElementById('loading').style.display = 'none';
      document.getElementById('content').style.display = 'block';
    } catch (error) {
      console.error('Error loading analysis:', error);
      this.displayError();
    }
  }

  displayAnalysis() {
    const { domain, riskScore, reasons } = this.currentAnalysis;

    // Update domain info
    document.getElementById('current-domain').textContent = domain;

    // Update status based on risk score (shared thresholds)
    this.updateStatus(riskScore);

    // Update risk score display + gauge
    document.getElementById('risk-score').innerHTML =
      `${riskScore}<small>/100</small>`;
    document.getElementById('risk-bar-fill').style.width = `${riskScore}%`;

    // Risk factor breakdown
    this.displayReasons(reasons || []);

    // Load and display any security flags from the content script
    this.loadSecurityFlags();
  }

  updateStatus(riskScore) {
    const statusCard = document.getElementById('status');
    const statusIcon = document.getElementById('status-icon');
    const statusMessage = document.getElementById('status-message');

    // Remove existing status classes
    statusCard.classList.remove('status-safe', 'status-low', 'status-warning', 'status-danger');

    const level = Detector.getRiskLevel(riskScore);
    const content = {
      safe: { cls: 'status-safe', icon: '✅', msg: 'Safe Site' },
      low: { cls: 'status-low', icon: '🔒', msg: 'Low Risk' },
      medium: { cls: 'status-warning', icon: '⚠️', msg: 'Medium Risk — Be Cautious' },
      high: { cls: 'status-danger', icon: '🚫', msg: 'High Risk — Potential Phishing' }
    }[level];

    statusCard.classList.add(content.cls);
    statusIcon.textContent = content.icon;
    statusMessage.textContent = content.msg;
  }

  displayNoAnalysis() {
    document.getElementById('current-domain').textContent = 'No analysis available';
    document.getElementById('status-icon').textContent = '❓';
    document.getElementById('status-message').textContent = 'Unable to analyze';
    document.getElementById('risk-score').innerHTML = `--<small>/100</small>`;
    document.getElementById('risk-bar-fill').style.width = '0%';
  }

  displayError() {
    document.getElementById('loading').style.display = 'none';
    const content = document.getElementById('content');
    content.style.display = 'block';
    content.innerHTML = `
      <div class="status-card status-warning">
        <div class="status-text">
          <span class="status-icon">❌</span>
          Error loading analysis
        </div>
      </div>
    `;
  }

  displayReasons(reasons) {
    const reasonsContainer = document.getElementById('reasons');
    const reasonsList = document.getElementById('reasons-list');

    if (!reasonsContainer || !reasonsList) return;

    if (reasons.length === 0) {
      reasonsContainer.style.display = 'none';
      reasonsList.innerHTML = '';
      return;
    }

    reasonsList.innerHTML = '';
    reasons.forEach((reason) => {
      const el = document.createElement('div');
      el.className = 'reason';

      const label = document.createElement('span');
      label.textContent = reason.label;

      const pts = document.createElement('span');
      pts.className = 'pts';
      pts.textContent = `+${reason.points}`;

      el.appendChild(label);
      el.appendChild(pts);
      reasonsList.appendChild(el);
    });

    reasonsContainer.style.display = 'block';
  }

  async loadSecurityFlags() {
    try {
      // Try to get flags from content script
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

      if (tab) {
        // allFrames: true - the content script runs in every frame (iframe
        // phishing kits), so merge flags from the top page and all iframes.
        const results = await chrome.scripting.executeScript({
          target: { tabId: tab.id, allFrames: true },
          func: () => window.phishingFlags || []
        });

        const flags = [];
        for (const frame of results || []) {
          for (const flag of (frame && frame.result) || []) {
            if (!flags.includes(flag)) flags.push(flag);
          }
        }

        if (flags.length > 0) {
          this.displayFlags(flags);
        }
      }
    } catch (error) {
      // Cannot inject into chrome:// pages etc. - not an error worth showing.
    }
  }

  displayFlags(flags) {
    const flagsContainer = document.getElementById('flags');
    const flagsList = document.getElementById('flags-list');

    if (flags.length > 0) {
      flagsList.innerHTML = '';
      flags.forEach((flag) => {
        const flagElement = document.createElement('div');
        flagElement.className = 'flag';
        flagElement.textContent = flag;
        flagsList.appendChild(flagElement);
      });

      flagsContainer.style.display = 'block';
    }
  }

  setupEventListeners() {
    // Report phishing button
    document.getElementById('report-btn').addEventListener('click', async () => {
      if (this.currentAnalysis) {
        try {
          await chrome.runtime.sendMessage({
            action: 'reportPhishing',
            url: this.currentAnalysis.url
          });

          this.showNotification('Site reported as phishing', 'success');
          this.loadStats();
        } catch (error) {
          this.showNotification('Error reporting site', 'error');
        }
      }
    });

    // Whitelist button
    document.getElementById('whitelist-btn').addEventListener('click', async () => {
      if (this.currentAnalysis) {
        try {
          // Add to whitelist in storage; the background worker picks the
          // change up via chrome.storage.onChanged.
          const domain = this.currentAnalysis.domain;
          const result = await chrome.storage.local.get(['whitelistedDomains']);
          const whitelist = result.whitelistedDomains || [];

          if (!whitelist.includes(domain)) {
            whitelist.push(domain);
            await chrome.storage.local.set({ whitelistedDomains: whitelist });
            this.showNotification('Site added to trusted list', 'success');

            // Re-fetch: background recomputes with the fresh whitelist.
            setTimeout(() => {
              this.loadAnalysis();
            }, 300);
          } else {
            this.showNotification('Site already trusted', 'info');
          }
        } catch (error) {
          this.showNotification('Error adding to whitelist', 'error');
        }
      }
    });
  }

  async loadStats() {
    try {
      const result = await chrome.storage.local.get(['stats']);
      const stats = result.stats || { sitesBlocked: 0, threatsDetected: 0, sitesReported: 0 };

      document.getElementById('sites-blocked').textContent = stats.sitesBlocked || 0;
      document.getElementById('threats-detected').textContent = stats.threatsDetected || 0;
      document.getElementById('sites-reported').textContent = stats.sitesReported || 0;
    } catch (error) {
      console.error('Error loading stats:', error);
    }
  }

  showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 10px;
      left: 50%;
      transform: translateX(-50%);
      background: #e0e1dd;
      color: #0d1b2a;
      padding: 8px 16px;
      border-radius: 999px;
      z-index: 1000;
      font-size: 12px;
      font-weight: 700;
      box-shadow: 0 8px 20px rgba(13, 27, 42, 0.6);
      opacity: 0;
      transition: opacity 0.3s ease;
    `;
    const icons = { success: '✓', error: '✕', info: 'ℹ' };
    notification.textContent = `${icons[type] || 'ℹ'} ${message}`;

    document.body.appendChild(notification);

    // Fade in
    setTimeout(() => {
      notification.style.opacity = '1';
    }, 100);

    // Remove after 3 seconds
    setTimeout(() => {
      notification.style.opacity = '0';
      setTimeout(() => {
        if (notification.parentNode) {
          notification.parentNode.removeChild(notification);
        }
      }, 300);
    }, 3000);
  }
}

// Initialize popup when DOM is ready (skipped when loaded under Node tests)
if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', () => {
    new PopupController();
  });
}

// Export for Node tests.
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { PopupController };
}
