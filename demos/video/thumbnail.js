const { chromium } = require('playwright');
(async () => {
  const dir = process.argv[2];
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 1280, height: 720 } });
  await p.goto('file://' + dir + '/thumbnail.html');
  await p.screenshot({ path: dir + '/youtube-thumbnail.png' });
  await b.close();
})();
