// Capture a page that animates with timers and CSS (player.html) as a smooth high-resolution video:
//   node capture_page.js <dir> <page.html> <out.mp4> [--scale 2] [--fps 30] [--frames png|jpeg] [--stills t1,t2]
//
// The page's clock is replaced with a virtual one (Date, performance.now, setTimeout, setInterval,
// requestAnimationFrame) and its CSS animations and transitions are paused and driven from that clock. Time then
// advances exactly one frame between screenshots, so every frame is on time however slow 4K rendering is. The page
// is laid out at 1920x1080 and captured at --scale times that (default 2: 3840x2160), encoded as H.264 High (x264
// preset slow, CRF 16, tuned for animation). Capture stops one second after the page sets window.__done, and a still
// of the title card is written next to the video as <page>-title.png, and the scene marks as <page>-marks.json.
// Fonts, colours and the icon come from docs/brand (brand.js); the capture stops if the brand fonts did not load.
// Needs: Node with the `playwright` package and Chromium, ffmpeg on PATH.
'use strict';
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { chromium } = require('playwright');
const { applyBrand, verifyBrand } = require('./brand');

const VIRTUAL_CLOCK = () => {
  const realSetTimeout = window.setTimeout.bind(window);
  const RealDate = window.Date;
  const origin = RealDate.now();
  let now = 0;
  let seq = 1;
  const timers = new Map();
  const frames = new Map();
  const started = new WeakMap();
  const add = (fn, ms, args, every) => {
    const id = seq++;
    timers.set(id, { t: now + Math.max(0, Number(ms) || 0), fn, args, every });
    return id;
  };
  window.setTimeout = (fn, ms, ...args) => add(fn, ms, args, 0);
  window.setInterval = (fn, ms, ...args) => add(fn, ms, args, Math.max(1, Number(ms) || 0));
  window.clearTimeout = window.clearInterval = id => { timers.delete(id); };
  window.requestAnimationFrame = fn => { const id = seq++; frames.set(id, fn); return id; };
  window.cancelAnimationFrame = id => { frames.delete(id); };
  performance.now = () => now;
  class VirtualDate extends RealDate {
    constructor(...a) { if (a.length) super(...a); else super(origin + now); }
    static now() { return origin + now; }
  }
  window.Date = VirtualDate;
  const settle = () => new Promise(r => realSetTimeout(r, 0));
  window.__advance = async ms => {
    const target = now + ms;
    for (;;) {
      let pick = null;
      for (const [id, tm] of timers) {
        if (tm.t <= target && (!pick || tm.t < pick[1].t || (tm.t === pick[1].t && id < pick[0]))) pick = [id, tm];
      }
      if (!pick) break;
      const [id, tm] = pick;
      now = Math.max(now, tm.t);
      if (tm.every) tm.t += tm.every; else timers.delete(id);
      try { tm.fn(...tm.args); } catch (e) { console.error(e); }
      await settle();
    }
    now = target;
    const due = [...frames.values()];
    frames.clear();
    for (const fn of due) { try { fn(now); } catch (e) { console.error(e); } }
    await settle();
    for (const a of document.getAnimations()) {
      if (!started.has(a)) { started.set(a, now); a.pause(); }
      a.currentTime = now - started.get(a);
    }
  };
};

function args(argv) {
  const out = { pos: [], scale: 2, fps: 30, frames: 'jpeg', stills: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--scale') out.scale = Number(argv[++i]);
    else if (argv[i] === '--fps') out.fps = Number(argv[++i]);
    else if (argv[i] === '--frames') out.frames = argv[++i];
    else if (argv[i] === '--stills') out.stills = argv[++i].split(',').map(Number).sort((x, y) => x - y);
    else out.pos.push(argv[i]);
  }
  const usage = 'usage: node capture_page.js <dir> <page.html> <out.mp4> [--scale 2] [--fps 30] [--frames png|jpeg] '
    + '[--stills t1,t2]';
  if (out.pos.length !== 3 || !['png', 'jpeg'].includes(out.frames)) throw new Error(usage);
  if (out.stills && out.stills.some(t => !(t >= 0))) throw new Error(`--stills takes seconds: ${usage}`);
  return out;
}

async function main() {
  const a = args(process.argv.slice(2));
  const [dir, pageName, outFile] = a.pos;
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: a.scale });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await applyBrand(page);
  await page.addInitScript(VIRTUAL_CLOCK);
  await page.goto('file://' + path.resolve(dir, pageName));
  await page.evaluate(() => window.__ready);
  await verifyBrand(page);
  const cdp = await page.context().newCDPSession(page);
  const clip = { x: 0, y: 0, width: 1920, height: 1080, scale: a.scale };
  const grab = async format => Buffer.from(
    (await cdp.send('Page.captureScreenshot', { format, clip, quality: format === 'jpeg' ? 100 : undefined })).data,
    'base64');
  const base = pageName.replace(/\.html$/, '');
  const step = 1000 / a.fps;
  const limit = 20 * 60 * a.fps;
  if (a.stills) {
    // Advance the virtual clock without encoding and save a PNG at each requested time: a quick check of a layout.
    const want = [...a.stills];
    for (let f = 0; f < limit && want.length; f++) {
      await page.evaluate(ms => window.__advance(ms), f === 0 ? 0 : step);
      if (errors.length) throw new Error(`page error at frame ${f}: ${errors[0]}`);
      while (want.length && f >= Math.round(want[0] * a.fps)) {
        const file = path.join(dir, `still-${base}-${want.shift().toFixed(2)}.png`);
        fs.writeFileSync(file, await grab('png'));
        console.log(file);
      }
      if (await page.evaluate(() => window.__done === true) && want.length) {
        throw new Error(`the page ended at ${(f / a.fps).toFixed(2)} s, before the still at ${want[0]} s`);
      }
    }
    await browser.close();
    return;
  }
  // JPEG frames at quality 100 by default: after the CRF 16 encode they measure 51.8 dB PSNR against lossless PNG
  // frames, at three times the speed in 4K. --frames png for lossless.
  // ffmpeg writes a partial file that is renamed only when the encode succeeded.
  const partial = path.join(path.dirname(outFile), `.${path.basename(outFile, '.mp4')}.partial.mp4`);
  const ff = spawn('ffmpeg', [
    '-y', '-v', 'error', '-f', 'image2pipe', '-framerate', String(a.fps), '-c:v', a.frames === 'png' ? 'png' : 'mjpeg', '-i', '-',
    '-c:v', 'libx264', '-preset', 'slow', '-crf', '16', '-tune', 'animation', '-x264-params', 'rc-lookahead=20', '-profile:v', 'high', '-level', '5.1',
    '-pix_fmt', 'yuv420p', '-r', String(a.fps), '-color_primaries', 'bt709', '-color_trc', 'bt709', '-colorspace', 'bt709',
    '-an', '-movflags', '+faststart', partial,
  ], { stdio: ['pipe', 'inherit', 'inherit'] });
  const done = new Promise((res, rej) => ff.on('close', c => (c === 0 ? res() : rej(new Error(`ffmpeg exited ${c}`)))));
  const titleAt = Math.round(4.6 * a.fps);
  let tail = -1;
  const started = Date.now();
  try {
    for (let f = 0; f < limit; f++) {
      await page.evaluate(ms => window.__advance(ms), f === 0 ? 0 : step);
      if (errors.length) throw new Error(`page error at frame ${f}: ${errors[0]}`);
      const buf = await grab(a.frames);
      if (!ff.stdin.write(buf)) await new Promise(r => ff.stdin.once('drain', r));
      if (f === titleAt) fs.writeFileSync(path.join(dir, base + '-title.png'), a.frames === 'png' ? buf : await grab('png'));
      if (tail < 0 && await page.evaluate(() => window.__done === true)) tail = a.fps;
      if (tail >= 0 && tail-- === 0) break;
      if (f === limit - 1) throw new Error(`the page did not finish within ${limit / a.fps} s`);
      if (f % (a.fps * 10) === 0) {
        process.stderr.write(`frame ${f} (${(f / Math.max(1, (Date.now() - started) / 1000)).toFixed(1)} fps)\n`);
      }
    }
    ff.stdin.end();
    await done;
  } catch (e) {
    ff.stdin.destroy();
    ff.kill('SIGKILL');
    fs.rmSync(partial, { force: true });
    throw e;
  }
  fs.renameSync(partial, outFile);
  // Scene marks (virtual milliseconds) for audio_kit.py score, which lays narration and music on them.
  const marks = await page.evaluate(() => window.__marks || []);
  fs.writeFileSync(path.join(dir, base + '-marks.json'), JSON.stringify(marks, null, 1));
  await browser.close();
  console.log(outFile);
}

main().catch(e => { console.error(e.message || e); process.exit(1); });
