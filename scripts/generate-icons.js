/**
 * Generates the NetSentry alligator icons.
 *
 *   node scripts/generate-icons.js
 *
 * Writes icons/icon{16,32,48,128}.svg and rasterizes icons/icon{16,32,48,128}.png
 * using headless Chrome (same engine the E2E tests use).
 *
 * Design: an alligator head in profile - an ambush predator that waits just
 * beneath the surface, the perfect mascot for a phishing lure detector.
 * Palette: #0D1B2A bg / #1B263B sheen / #415A77 lower jaw / #778DA9 head /
 * #E0E1DD teeth + eye.
 */

const puppeteer = require('puppeteer-core');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const ICONS = path.join(ROOT, 'icons');
const SIZES = [16, 32, 48, 128];

const CHROME = process.env.CHROME_PATH ||
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';

function svgMarkup(size) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 128 128">
  <!-- NetSentry Extension Icon - alligator "lurks beneath the surface" -->
  <defs>
    <radialGradient id="bg" cx="35%" cy="28%" r="95%">
      <stop offset="0%" stop-color="#1B263B"/>
      <stop offset="100%" stop-color="#0D1B2A"/>
    </radialGradient>
  </defs>

  <!-- deep-water background tile -->
  <rect x="0" y="0" width="128" height="128" rx="28" ry="28" fill="url(#bg)"/>

  <!-- upper jaw -->
  <path d="M28 58 C28 45, 40 37, 56 41 L104 53 L115 59 L104 65 L56 67 L30 66 Z"
        fill="#778DA9"/>
  <!-- upper teeth -->
  <path d="M60 65 L68 65 L64 74 Z M74 65 L82 65 L78 74 Z M88 65 L96 65 L92 74 Z M100 65 L107 65 L103.5 73 Z"
        fill="#E0E1DD"/>
  <!-- lower jaw -->
  <path d="M34 74 L58 71 L106 80 L100 89 L46 88 Z"
        fill="#415A77"/>
  <!-- lower teeth -->
  <path d="M64 72.1 L72 73.6 L68 65.6 Z M78 74.7 L86 76.2 L82 68.2 Z M92 77.3 L100 78.8 L96 70.8 Z"
        fill="#E0E1DD"/>
  <!-- nostril -->
  <circle cx="109" cy="58.5" r="2.2" fill="#0D1B2A"/>
  <!-- eye -->
  <circle cx="48" cy="53" r="6.5" fill="#E0E1DD"/>
  <circle cx="50" cy="53" r="3" fill="#0D1B2A"/>
  <!-- brow ridge -->
  <path d="M40 44.5 L57 47.5" stroke="#415A77" stroke-width="3.5" stroke-linecap="round"/>
  <!-- scale ridges along the snout -->
  <path d="M70 47.5 L74 49 M82 50.5 L86 52 M94 53.5 L98 55"
        stroke="#415A77" stroke-width="3" stroke-linecap="round"/>
</svg>`;
}

async function main() {
  if (!fs.existsSync(ICONS)) fs.mkdirSync(ICONS, { recursive: true });

  // 1. Write the SVG sources
  for (const size of SIZES) {
    fs.writeFileSync(path.join(ICONS, `icon${size}.svg`), svgMarkup(size));
  }
  console.log(`wrote ${SIZES.length} SVG sources`);

  // 2. Rasterize to PNG through headless Chrome
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: 'new',
    args: ['--no-sandbox', '--disable-gpu']
  });
  try {
    for (const size of SIZES) {
      const page = await browser.newPage();
      await page.setViewport({ width: size, height: size, deviceScaleFactor: 1 });
      await page.setContent(
        `<!DOCTYPE html><html><body style="margin:0;padding:0;background:transparent">
           ${svgMarkup(size)}
         </body></html>`,
        { waitUntil: 'load' }
      );
      const out = path.join(ICONS, `icon${size}.png`);
      await page.screenshot({ path: out, omitBackground: true, clip: { x: 0, y: 0, width: size, height: size } });
      await page.close();
      console.log(`rendered icons/icon${size}.png`);
    }
  } finally {
    await browser.close();
  }
}

main().catch((err) => { console.error(err); process.exit(1); });
