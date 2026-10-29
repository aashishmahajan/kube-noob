// Render the YouTube thumbnail: node thumbnail.js <dir>   (reads <dir>/thumbnail.html)
// Laid out at 1280x720 and rendered at 2x: youtube-thumbnail.png (2560x1440 master) and youtube-thumbnail.jpg,
// the upload copy, kept under YouTube's 2 MB thumbnail limit. Fonts, colours, the tagline and the icon come from
// docs/brand (brand.js); the render stops if the brand fonts did not load.
'use strict';
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');
const { applyBrand, verifyBrand } = require('./brand');

(async () => {
  const dir = path.resolve(process.argv[2]);
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 1280, height: 720 }, deviceScaleFactor: 2 });
  const errors = [];
  p.on('pageerror', e => errors.push(String(e)));
  await applyBrand(p);
  await p.goto('file://' + path.join(dir, 'thumbnail.html'));
  await p.evaluate(() => window.__ready);
  await verifyBrand(p);
  if (errors.length) throw new Error(`thumbnail.html: ${errors[0]}`);
  await p.screenshot({ path: path.join(dir, 'youtube-thumbnail.png') });
  for (const quality of [95, 92, 88, 84, 80]) {
    const jpg = await p.screenshot({ type: 'jpeg', quality });
    if (jpg.length < 2 * 1024 * 1024 || quality === 80) {
      fs.writeFileSync(path.join(dir, 'youtube-thumbnail.jpg'), jpg);
      console.log(`youtube-thumbnail.jpg 2560x1440 quality ${quality}, ${(jpg.length / 1024 / 1024).toFixed(2)} MB`);
      break;
    }
  }
  await b.close();
})().catch(e => { console.error(e.message || e); process.exit(1); });
