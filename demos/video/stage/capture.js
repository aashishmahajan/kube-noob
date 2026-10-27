// Render one animated video frame by frame: node capture.js <out-dir> [--stills t1,t2,...] [--from s] [--to s]
//
// Reads <out-dir>/timeline.json and <out-dir>/audio.wav (written by voiceover.py), loads stage.html in Chromium,
// calls renderAt(t) for every frame at the timeline's fps, screenshots it and pipes the JPEG frames to ffmpeg, which
// muxes the audio (loudness-normalised to -16 LUFS) into <out-dir>/kube-noob-<video>.mp4 (H.264, 1920x1080).
// --stills writes PNG frames at the given times instead (for checking), --from/--to render a time range.
// Needs: Node with the `playwright` package and Chromium, ffmpeg on PATH.
'use strict';
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { chromium } = require('playwright');

function args(argv) {
  const out = { dir: null, stills: null, from: 0, to: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--stills') out.stills = argv[++i].split(',').map(Number);
    else if (a === '--from') out.from = Number(argv[++i]);
    else if (a === '--to') out.to = Number(argv[++i]);
    else if (!out.dir) out.dir = path.resolve(a);
    else throw new Error(`unexpected argument ${a}`);
  }
  if (!out.dir) throw new Error('usage: node capture.js <out-dir> [--stills t1,t2] [--from s] [--to s]');
  return out;
}

async function main() {
  const a = args(process.argv.slice(2));
  const tl = JSON.parse(fs.readFileSync(path.join(a.dir, 'timeline.json'), 'utf8'));
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 1 });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await page.addInitScript(t => { window.__TIMELINE__ = t; }, tl);
  await page.goto('file://' + path.join(__dirname, 'stage.html'));
  await page.waitForFunction(() => window.stageReady === true, null, { timeout: 30000 });
  const shot = async t => {
    await page.evaluate(x => window.renderAt(x), t);
    if (errors.length) throw new Error(`stage error at t=${t}: ${errors[0]}`);
  };

  if (a.stills) {
    for (const t of a.stills) {
      await shot(t);
      const file = path.join(a.dir, `still-${tl.video}-${t.toFixed(2)}.png`);
      await page.screenshot({ path: file });
      console.log(file);
    }
    await browser.close();
    return;
  }

  const fps = tl.fps;
  const end = a.to ?? tl.duration;
  const first = Math.round(a.from * fps), last = Math.round(end * fps);
  const out = path.join(a.dir, `kube-noob-${tl.video}${a.from || a.to ? `-${a.from}-${end}` : ''}.mp4`);
  const ff = spawn('ffmpeg', [
    '-y', '-v', 'error',
    '-f', 'image2pipe', '-framerate', String(fps), '-c:v', 'mjpeg', '-i', '-',
    '-ss', String(a.from), '-t', String(end - a.from), '-i', path.join(a.dir, 'audio.wav'),
    '-map', '0:v', '-map', '1:a',
    '-c:v', 'libx264', '-preset', 'veryfast', '-crf', '20', '-pix_fmt', 'yuv420p', '-r', String(fps),
    '-af', 'loudnorm=I=-16:TP=-1.5:LRA=11', '-c:a', 'aac', '-b:a', '192k', '-ar', '48000',
    '-shortest', '-movflags', '+faststart', out,
  ], { stdio: ['pipe', 'inherit', 'inherit'] });
  const done = new Promise((res, rej) => ff.on('close', c => (c === 0 ? res() : rej(new Error(`ffmpeg exited ${c}`)))));
  const started = Date.now();
  for (let f = first; f < last; f++) {
    await shot(f / fps);
    const buf = await page.screenshot({ type: 'jpeg', quality: 92 });
    if (!ff.stdin.write(buf)) await new Promise(r => ff.stdin.once('drain', r));
    if ((f - first) % (fps * 5) === 0) {
      const done_ = f - first, rate = done_ / Math.max(1, (Date.now() - started) / 1000);
      process.stderr.write(`frame ${f}/${last} (${rate.toFixed(1)} fps)\n`);
    }
  }
  ff.stdin.end();
  await done;
  await browser.close();
  console.log(out);
}

main().catch(e => { console.error(e.message || e); process.exit(1); });
