const { chromium } = require('playwright');
(async () => {
  const dir = process.argv[2];
  const browser = await chromium.launch();
  const context = await browser.newContext({ viewport: { width: 1920, height: 1080 }, recordVideo: { dir, size: { width: 1920, height: 1080 } } });
  const page = await context.newPage();
  await page.goto('file://' + dir + '/walkthrough.html');
  await page.waitForTimeout(4600);
  await page.screenshot({ path: dir + '/thumbnail.png' });
  await page.waitForFunction(() => window.__done === true, null, { timeout: 400000, polling: 500 });
  const video = page.video();
  await context.close();
  console.log(await video.path());
  await browser.close();
})();
