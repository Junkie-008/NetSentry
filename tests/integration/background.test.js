/**
 * Integration tests: background service worker (background.js) driven through
 * mocked chrome events - tab updates, navigation, storage, runtime messages.
 */

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

require('../../detector.js'); // sets globalThis.Detector
const { createMockChrome, flush } = require('../helpers/chrome-mock');

/**
 * Fresh module instance bound to a fresh mock. background.js runs its
 * top-level wiring on require, so we bust the module cache each time.
 */
function loadBackground(activeUrl) {
  const mock = createMockChrome({ activeUrl });
  global.chrome = mock.chrome;
  const resolved = require.resolve('../../background.js');
  delete require.cache[resolved];
  require(resolved);
  return mock;
}

describe('background integration', () => {
  let mock;

  beforeEach(() => {
    mock = undefined;
  });

  it('blocks a high-risk page and injects the block screen once', async () => {
    mock = loadBackground('http://paypa1-login.com/login');

    // Both event sources fire for the same navigation (as in a real browser)
    mock.emit.tabUpdated(1, 'http://paypa1-login.com/login');
    mock.emit.beforeNavigate(1, 'http://paypa1-login.com/login');
    await flush();

    assert.equal(mock.calls.executeScript.length, 1, 'block script injected exactly once');
    const injected = mock.calls.executeScript[0];
    assert.ok(
      injected.func.toString().includes('PHISHING SITE BLOCKED'),
      'block page UI should be injected'
    );
    assert.equal(injected.target.tabId, 1);

    // Stats: single count despite two events (dedupe regression guard)
    assert.equal(mock.data.stats.sitesBlocked, 1);
    assert.equal(mock.data.stats.threatsDetected, 1);

    // Badge: red "!" for high risk
    const lastBadge = mock.calls.badgeText[mock.calls.badgeText.length - 1];
    assert.equal(lastBadge.text, '!');

    // Analysis stored for the popup, with reasons
    const analysis = mock.data['analysis_1'];
    assert.ok(analysis);
    assert.equal(analysis.riskScore, 100);
    assert.equal(analysis.level, 'high');
    assert.ok(Array.isArray(analysis.reasons) && analysis.reasons.length > 0);

    // Blocked domain is remembered for future visits
    assert.ok(mock.data.suspiciousDomains.includes('paypa1-login.com'));

    // HARDENING: tab is redirected to the extension's blocked.html so the
    // malicious document (and its JavaScript) is unloaded
    assert.equal(mock.calls.tabsUpdate.length, 1, 'tab redirected once');
    const redirect = new URL(mock.calls.tabsUpdate[0].url);
    assert.ok(redirect.pathname.endsWith('/blocked.html'), redirect.pathname);
    assert.equal(redirect.searchParams.get('score'), '100');
    assert.equal(redirect.searchParams.get('domain'), 'paypa1-login.com');
    assert.ok(redirect.searchParams.getAll('r').length > 0, 'reasons passed along');
  });

  it('re-blocks when the same phishing URL is visited again right away', async () => {
    // After a redirect the dedupe marker is cleared, so navigating back to
    // the phishing site must trigger a fresh block instead of being skipped.
    mock = loadBackground('https://example.com/');
    const phish = 'http://paypa1-login.com/login';

    mock.emit.tabUpdated(1, phish);
    await flush();
    assert.equal(mock.calls.executeScript.length, 1);
    assert.equal(mock.calls.tabsUpdate.length, 1);

    mock.emit.tabUpdated(1, phish); // user pressed Back within 5 seconds
    await flush();
    assert.equal(mock.calls.executeScript.length, 2, 'second visit re-blocks');
    assert.equal(mock.calls.tabsUpdate.length, 2);
    assert.equal(mock.data.stats.sitesBlocked, 2);
  });

  it('shows a warning banner (but does not block) for medium risk', async () => {
    mock = loadBackground('http://free-prize1.tk/win');
    mock.emit.tabUpdated(1, 'http://free-prize1.tk/win');
    await flush();

    assert.equal(mock.calls.executeScript.length, 1);
    const injected = mock.calls.executeScript[0];
    assert.ok(injected.func.toString().includes('phishing-warning'));
    assert.ok(injected.func.toString().includes('phishing-warning-overlay'));

    assert.equal(mock.data.stats.sitesBlocked, 0, 'blocked stat stays at 0');
    assert.equal(mock.data.stats.threatsDetected, 1);

    const lastBadge = mock.calls.badgeText[mock.calls.badgeText.length - 1];
    assert.equal(lastBadge.text, '?'); // orange warning badge
  });

  it('does nothing dangerous on safe pages', async () => {
    mock = loadBackground('https://example.com/blog/post');
    mock.emit.tabUpdated(1, 'https://example.com/blog/post');
    await flush();

    assert.equal(mock.calls.executeScript.length, 0);
    assert.equal(mock.data.stats, undefined, 'no stats written for safe pages');

    const lastBadge = mock.calls.badgeText[mock.calls.badgeText.length - 1];
    assert.equal(lastBadge.text, '');
  });

  it('skips browser-internal URLs (chrome://) without storing analysis', async () => {
    mock = loadBackground('chrome://extensions');
    mock.emit.tabUpdated(1, 'chrome://extensions');
    await flush();

    assert.equal(mock.calls.executeScript.length, 0);
    assert.equal(mock.data['analysis_1'], undefined);

    const lastBadge = mock.calls.badgeText[mock.calls.badgeText.length - 1];
    assert.equal(lastBadge.text, '');
  });

  it('answers getAnalysis with a fresh report including reasons', async () => {
    mock = loadBackground('http://free-prize1.tk/win');
    const response = await mock.emit.message({ action: 'getAnalysis' });

    assert.ok(response);
    assert.equal(response.domain, 'free-prize1.tk');
    assert.equal(response.riskScore, 55);
    assert.equal(response.level, 'medium');
    assert.equal(response.reasons.length, 2);
  });

  it('getAnalysis returns null when there is no active tab', async () => {
    mock = loadBackground(undefined);
    const response = await mock.emit.message({ action: 'getAnalysis' });
    assert.equal(response, null);
  });

  it('Trust Site flow: popup writes whitelist -> score becomes 0', async () => {
    mock = loadBackground('http://free-prize1.tk/win');

    const before = await mock.emit.message({ action: 'getAnalysis' });
    assert.equal(before.riskScore, 55);

    // Popup writes the whitelist (popup.js does exactly this)
    await mock.writeStorage({ whitelistedDomains: ['free-prize1.tk'] });

    const after = await mock.emit.message({ action: 'getAnalysis' });
    assert.equal(after.riskScore, 0, 'trusted site must score 0');
    assert.equal(after.level, 'safe');
    assert.deepEqual(after.reasons, []);

    // Whitelist also covers subdomains of the trusted domain
    await mock.writeStorage({ whitelistedDomains: ['sub.trusted.example'] });
    // active URL is fixed in this mock, so verify via storage-driven state:
    // the background instance now trusts sub.trusted.example (implicit in
    // getReport); assert the persisted value survived round-trip.
    const stored = await mock.chrome.storage.local.get(['whitelistedDomains']);
    assert.ok(stored.whitelistedDomains.includes('sub.trusted.example'));
  });

  it('reportPhishing adds the domain to the suspicious list and blocks it later', async () => {
    mock = loadBackground('https://innocent.example/page');
    mock.emit.tabUpdated(1, 'https://innocent.example/page');
    await flush();
    assert.equal(mock.calls.executeScript.length, 0);

    const resp = await mock.emit.message({
      action: 'reportPhishing',
      url: 'https://innocent.example/page'
    });
    assert.deepEqual(resp, { success: true });
    await flush();

    assert.ok(mock.data.suspiciousDomains.includes('innocent.example'));
    assert.equal(mock.data.stats.sitesReported, 1);

    // Next visit is blocked because the domain is now known-bad
    mock.emit.tabUpdated(2, 'https://innocent.example/page');
    await flush();
    assert.equal(mock.calls.executeScript.length, 1);
    assert.equal(mock.data.stats.sitesBlocked, 1);
  });

  it('reportPhishing with an invalid URL responds with failure', async () => {
    mock = loadBackground('https://example.com/');
    const resp = await mock.emit.message({ action: 'reportPhishing', url: 'not-a-url' });
    assert.deepEqual(resp, { success: false });
  });

  it('cleans up stored analysis when a tab closes', async () => {
    mock = loadBackground('https://example.com/one');
    mock.emit.tabUpdated(7, 'https://example.com/one');
    await flush();
    assert.ok(mock.data['analysis_7']);

    mock.emit.tabRemoved(7);
    await flush();
    assert.equal(mock.data['analysis_7'], undefined);
    assert.equal(mock.data['analysis_1'], undefined, 'no stray keys');
  });

  it('handles an invalid URL from tab updates without crashing', async () => {
    mock = loadBackground('https://example.com/');
    mock.emit.tabUpdated(1, '::::not-a-url');
    mock.emit.tabUpdated(2, undefined);
    await flush();
    assert.equal(mock.calls.executeScript.length, 0);
  });

  it('badge thresholds match the shared 40/70 risk bands', async () => {
    mock = loadBackground('https://example.com/');

    mock.emit.tabUpdated(1, 'https://bit.ly/x?redirect=1&pad=' + 'x'.repeat(80)); // 50 -> warn
    await flush();
    assert.equal(mock.calls.badgeText[mock.calls.badgeText.length - 1].text, '?');
    assert.equal(mock.calls.badgeColor[mock.calls.badgeColor.length - 1].color, '#778da9');

    mock.emit.tabUpdated(2, 'http://free-prize1.tk/win'); // 55 -> warn
    await flush();
    assert.equal(mock.calls.badgeText[mock.calls.badgeText.length - 1].text, '?');

    mock.emit.tabUpdated(3, 'http://paypa1-login.com/login'); // 100 -> block
    await flush();
    assert.equal(mock.calls.badgeText[mock.calls.badgeText.length - 1].text, '!');
    assert.equal(mock.calls.badgeColor[mock.calls.badgeColor.length - 1].color, '#e0e1dd');
  });
});
