// Render one animated video frame by frame:
//   node capture.js <out-dir> [--scale 2] [--stills t1,t2,...] [--from s] [--to s] [--check] [--frames png|jpeg]
//
// Reads <out-dir>/timeline.json and <out-dir>/audio.wav (written by voiceover.py), loads stage.html in Chromium,
// calls renderAt(t) for every frame at the timeline's fps, screenshots it and pipes the frames to ffmpeg, which
// muxes the audio (normalised to the brand loudness by voiceover.py; audio_kit.py verify checks the result) into
// <out-dir>/kube-noob-<video>.mp4. Frames are JPEG at quality 100 (after the CRF 16 encode they measure 51.8 dB PSNR
// against lossless PNG frames, at three times the speed in 4K; --frames png for lossless), and the mp4 appears only
// when the encode succeeded.
// The stage is laid out at 1920x1080 and rendered at --scale times that (default 2: 3840x2160, 4K UHD), encoded as
// H.264 High (x264 preset slow, CRF 16, tuned for animation) with 320 kb/s AAC.
// --stills writes PNG frames at the given times instead (for checking), --from/--to render a time range, and --check
// renders every frame without encoding and fails if a frame breaks a brand layout rule (stage.html layoutIssues()).
// Needs: Node with the `playwright` package and Chromium, ffmpeg on PATH.
'use strict';
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { chromium } = require('playwright');
const { applyBrand, verifyBrand } = require('../brand');

function args(argv) {
  const out = { dir: null, stills: null, from: 0, to: null, scale: 2, check: false, frames: 'jpeg' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--stills') out.stills = argv[++i].split(',').map(Number);
    else if (a === '--from') out.from = Number(argv[++i]);
    else if (a === '--to') out.to = Number(argv[++i]);
    else if (a === '--scale') out.scale = Number(argv[++i]);
    else if (a === '--check') out.check = true;
    else if (a === '--frames') out.frames = argv[++i];
    else if (!out.dir) out.dir = path.resolve(a);
    else throw new Error(`unexpected argument ${a}`);
  }
  if (!out.dir || !['png', 'jpeg'].includes(out.frames)) {
    throw new Error('usage: node capture.js <out-dir> [--stills t1,t2] [--from s] [--to s] [--check] [--frames png|jpeg]');
  }
  return out;
}

function sceneAt(tl, t) {
  const sc = tl.scenes.find(s => t >= s.start && t < s.start + s.dur) || tl.scenes[tl.scenes.length - 1];
  return sc.kind;
}

async function main() {
  const a = args(process.argv.slice(2));
  const tl = JSON.parse(fs.readFileSync(path.join(a.dir, 'timeline.json'), 'utf8'));
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: a.scale });
  const cdp = await page.context().newCDPSession(page);
  // An explicit clip with scale is what makes CDP capture at device resolution (3840x2160 at --scale 2).
  const clip = { x: 0, y: 0, width: 1920, height: 1080, scale: a.scale };
  const grab = async format => Buffer.from(
    (await cdp.send('Page.captureScreenshot', { format, clip, quality: format === 'jpeg' ? 100 : undefined })).data,
    'base64');
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await applyBrand(page); // fonts and colours from docs/brand, before the stage's own script runs
  await page.addInitScript(t => { window.__TIMELINE__ = t; }, tl);
  await page.goto('file://' + path.join(__dirname, 'stage.html'));
  await page.waitForFunction(() => window.stageReady === true, null, { timeout: 30000 });
  await verifyBrand(page); // stops the render when a brand font did not load
  const shot = async t => {
    await page.evaluate(x => window.renderAt(x), t);
    if (errors.length) throw new Error(`stage error at t=${t}: ${errors[0]}`);
  };

  if (a.check) {
    const issues = new Map(); // issue -> [first, last] time
    const frames = Math.round(tl.duration * tl.fps);
    for (let f = 0; f < frames; f++) {
      const t = f / tl.fps;
      await shot(t);
      for (const issue of await page.evaluate(() => window.layoutIssues())) {
        const key = `${sceneAt(tl, t)}: ${issue.replace(/ \(\d+ px²\)/, '')}`;
        const span = issues.get(key) || [t, t];
        span[1] = t;
        issues.set(key, span);
      }
    }
    await browser.close();
    if (issues.size) {
      const lines = [...issues].map(([k, [a0, a1]]) => `  ${k} at ${a0.toFixed(2)}-${a1.toFixed(2)} s`);
      throw new Error(`${tl.video}: ${issues.size} layout problem(s):\n${lines.join('\n')}`);
    }
    console.log(`${tl.video}: ${frames} frames, layout OK`);
    return;
  }

  if (a.stills) {
    for (const t of a.stills) {
      await shot(t);
      const file = path.join(a.dir, `still-${tl.video}-${t.toFixed(2)}.png`);
      fs.writeFileSync(file, await grab('png'));
      console.log(file);
    }
    await browser.close();
    return;
  }

  const fps = tl.fps;
  const end = a.to ?? tl.duration;
  const first = Math.round(a.from * fps), last = Math.round(end * fps);
  const out = path.join(a.dir, `kube-noob-${tl.video}${a.from || a.to ? `-${a.from}-${end}` : ''}.mp4`);
  const partial = path.join(a.dir, `.${path.basename(out, '.mp4')}.partial.mp4`);
  const ff = spawn('ffmpeg', [
    '-y', '-v', 'error',
    '-f', 'image2pipe', '-framerate', String(fps), '-c:v', a.frames === 'png' ? 'png' : 'mjpeg', '-i', '-',
    '-ss', String(a.from), '-t', String(end - a.from), '-i', path.join(a.dir, 'audio.wav'),
    '-map', '0:v', '-map', '1:a',
    '-c:v', 'libx264', '-preset', 'slow', '-crf', '16', '-tune', 'animation', '-x264-params', 'rc-lookahead=20', '-profile:v', 'high', '-level', '5.1',
    '-pix_fmt', 'yuv420p', '-r', String(fps), '-color_primaries', 'bt709', '-color_trc', 'bt709', '-colorspace', 'bt709',
    '-c:a', 'aac', '-b:a', '320k', '-ar', '48000',
    '-shortest', '-movflags', '+faststart', partial,
  ], { stdio: ['pipe', 'inherit', 'inherit'] });
  const done = new Promise((res, rej) => ff.on('close', c => (c === 0 ? res() : rej(new Error(`ffmpeg exited ${c}`)))));
  const started = Date.now();
  try {
    for (let f = first; f < last; f++) {
      await shot(f / fps);
      const buf = await grab(a.frames);
      if (!ff.stdin.write(buf)) await new Promise(r => ff.stdin.once('drain', r));
      if ((f - first) % (fps * 5) === 0) {
        const done_ = f - first, rate = done_ / Math.max(1, (Date.now() - started) / 1000);
        process.stderr.write(`frame ${f}/${last} (${rate.toFixed(1)} fps)\n`);
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
  fs.renameSync(partial, out);
  await browser.close();
  console.log(out);
}

main().catch(e => { console.error(e.message || e); process.exit(1); });
