// Render the YouTube thumbnail: node thumbnail.js <dir>   (reads <dir>/thumbnail.html)
// Laid out at 1280x720 and rendered at 2x: youtube-thumbnail.png (2560x1440 master) and youtube-thumbnail.jpg,
// the upload copy, kept under YouTube's 2 MB thumbnail limit.
const fs = require('fs');
const { chromium } = require('playwright');
(async () => {
  const dir = process.argv[2];
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 1280, height: 720 }, deviceScaleFactor: 2 });
  await p.goto('file://' + dir + '/thumbnail.html');
  await p.evaluate(() => document.fonts.ready);
  await p.screenshot({ path: dir + '/youtube-thumbnail.png' });
  for (const quality of [95, 92, 88, 84, 80]) {
    const jpg = await p.screenshot({ type: 'jpeg', quality });
    if (jpg.length < 2 * 1024 * 1024 || quality === 80) {
      fs.writeFileSync(dir + '/youtube-thumbnail.jpg', jpg);
      console.log(`youtube-thumbnail.jpg 2560x1440 quality ${quality}, ${(jpg.length / 1024 / 1024).toFixed(2)} MB`);
      break;
    }
  }
  await b.close();
})();
