/**
 * NetSentry - Blocked page controller.
 *
 * Reads ?score=&domain=&r=reason params set by background.js and renders
 * the block screen. All values are inserted with textContent (never
 * innerHTML) so query params cannot inject markup.
 */

(function () {
  'use strict';

  const params = new URLSearchParams(window.location.search);

  const rawScore = Number.parseInt(params.get('score'), 10);
  const score = Number.isFinite(rawScore) ? Math.min(100, Math.max(0, rawScore)) : 0;

  const domain = params.get('domain') || window.location.hostname;
  const reasons = params.getAll('r').slice(0, 5);

  document.getElementById('pd-score').textContent = String(score);
  document.getElementById('pd-domain').textContent = domain;

  if (reasons.length > 0) {
    const list = document.getElementById('pd-reasons');
    reasons.forEach((text) => {
      const li = document.createElement('li');
      li.textContent = text; // safe: no markup interpretation
      list.appendChild(li);
    });
    document.getElementById('pd-reasons-box').hidden = false;
  }

  document.getElementById('pd-back').addEventListener('click', () => {
    window.history.back();
  });

  document.getElementById('pd-close').addEventListener('click', () => {
    window.close();
  });
})();
