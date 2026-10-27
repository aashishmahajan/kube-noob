// Render the brand images from their HTML and SVG sources, at high resolution.
//   node docs/brand/render.js [out-dir]      (default: write next to the sources, in docs/brand)
//
// Each page is laid out at the size the platform recommends and rendered at 2x or 3x that, so it stays sharp on
// high-density screens; platforms scale it down themselves. Uploads with a size cap get their own copy.
// Needs: Node with the `playwright` package and Chromium.
'use strict';
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const HERE = __dirname;
const JOBS = [
  // source, layout size, scale, output name (relative to the out dir), screenshot options
  ['linkedin/profile.html', [800, 800], 3, 'linkedin/profile.png'],
  ['linkedin/banner.html', [1584, 396], 2, 'linkedin/banner.png'],
  ['linkedin/post.html', [1200, 627], 2, 'linkedin/post.png'],
  ['social-preview.html', [1280, 640], 2, 'social-preview.png'],
  // GitHub's social preview upload is capped at 1 MB: the 1x copy is for Settings > Social preview.
  ['social-preview.html', [1280, 640], 1, 'social-preview-github.png'],
];
const ICON_SIZES = [1024, 2048];

async function main() {
  const out = path.resolve(process.argv[2] || HERE);
  const browser = await chromium.launch();
  for (const [src, [w, h], scale, name] of JOBS) {
    const page = await browser.newPage({ viewport: { width: w, height: h }, deviceScaleFactor: scale });
    await page.goto('file://' + path.join(HERE, src));
    await page.evaluate(() => document.fonts.ready);
    await page.waitForFunction(() => [...document.images].every(i => i.complete));
    const file = path.join(out, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    await page.screenshot({ path: file });
    console.log(`${file} ${w * scale}x${h * scale}`);
    await page.close();
  }
  const svg = fs.readFileSync(path.join(HERE, 'kube-noob-icon.svg'), 'utf8');
  for (const size of ICON_SIZES) {
    const page = await browser.newPage({ viewport: { width: size, height: size }, deviceScaleFactor: 1 });
    await page.setContent(`<html><body style="margin:0;background:transparent">${svg.replace('<svg ', `<svg width="${size}" height="${size}" `)}</body></html>`);
    const file = path.join(out, `kube-noob-${size}.png`);
    await page.screenshot({ path: file, omitBackground: true, clip: { x: 0, y: 0, width: size, height: size } });
    console.log(`${file} ${size}x${size}`);
    await page.close();
  }
  await browser.close();
}

main().catch(e => { console.error(e); process.exit(1); });
