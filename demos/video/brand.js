// The kube-noob brand for every rendered video frame and image (stage/capture.js, capture_page.js, thumbnail.js).
//
// Fonts come from docs/brand/fonts and are injected as data: URLs under their own family names ("KN Sans",
// "KN Mono"), so a machine's installed fonts can never stand in for them; colours and words come from
// docs/brand/tokens.json. verifyBrand() is the gate: it loads every face the brand needs and fails the render when one
// is missing. document.fonts.check() cannot be that gate, because it also answers true for a family that was never
// declared at all.
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// KN_BRAND_DIR points at another copy of docs/brand (the tests use it to check that a changed font is refused).
const BRAND_DIR = path.resolve(process.env.KN_BRAND_DIR || path.join(__dirname, '..', '..', 'docs', 'brand'));
const FONT_DIR = path.join(BRAND_DIR, 'fonts');

function tokens() {
  return JSON.parse(fs.readFileSync(path.join(BRAND_DIR, 'tokens.json'), 'utf8'));
}

// Every bundled file must match the SHA-256 in PROVENANCE.json: a swapped or truncated font fails here, not on screen.
function fontBytes(file) {
  const prov = JSON.parse(fs.readFileSync(path.join(FONT_DIR, 'PROVENANCE.json'), 'utf8'));
  const entry = prov.sources.map(s => s.files[file]).find(Boolean);
  if (!entry) throw new Error(`brand font ${file} is not listed in docs/brand/fonts/PROVENANCE.json`);
  const data = fs.readFileSync(path.join(FONT_DIR, file));
  const sha = crypto.createHash('sha256').update(data).digest('hex');
  if (sha !== entry.sha256) throw new Error(`brand font ${file}: sha256 ${sha} does not match PROVENANCE.json`);
  return data;
}

function hexToRgb(hex) {
  const m = /^#([0-9a-f]{6})$/i.exec(hex);
  if (!m) throw new Error(`tokens.json colour ${hex} is not #RRGGBB`);
  const n = parseInt(m[1], 16);
  return `${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}`;
}

// CSS for the page: @font-face rules plus custom properties (--sans, --mono, --kn-<colour>, --kn-<colour>-rgb).
function brandCSS(t = tokens()) {
  const faces = t.fonts.faces.map(f => {
    const data = fontBytes(f.file).toString('base64');
    return `@font-face { font-family: "${f.family}"; src: url(data:font/woff2;base64,${data}) format("woff2"); ` +
      `font-weight: ${f.weight}; font-style: normal; font-display: block; }`;
  });
  const vars = [`--sans: "${t.fonts.sans}", sans-serif;`, `--mono: "${t.fonts.mono}", monospace;`];
  for (const [name, hex] of Object.entries(t.colors)) {
    const key = name.replace(/[A-Z]/g, c => `-${c.toLowerCase()}`);
    vars.push(`--kn-${key}: ${hex};`, `--kn-${key}-rgb: ${hexToRgb(hex)};`);
  }
  return `${faces.join('\n')}\n:root { ${vars.join(' ')} }`;
}

// What a page script needs, before any page script runs: window.__KN_BRAND__ = { tokens, rgb: {green: "r, g, b"}, icon },
// icon being docs/brand/kube-noob-icon.svg as a data: URL, so a page works from any folder.
function brandGlobal(t = tokens()) {
  const rgb = Object.fromEntries(Object.entries(t.colors).map(([k, hex]) => [k, hexToRgb(hex)]));
  const icon = 'data:image/svg+xml;base64,' + fs.readFileSync(path.join(BRAND_DIR, 'kube-noob-icon.svg')).toString('base64');
  return { tokens: t, rgb, icon };
}

// Make the brand part of every document the page loads: window.__KN_BRAND__ exists before the page's own scripts run,
// and the brand <style> is the first child of <head>. The pages declare none of the brand variables themselves, so
// the order of styles cannot matter.
async function applyBrand(page, t = tokens()) {
  const css = brandCSS(t);
  await page.addInitScript(({ css, brand }) => {
    Object.defineProperty(window, '__KN_BRAND__', { value: Object.freeze(brand), writable: false });
    const add = () => {
      if (!document.head || document.getElementById('kn-brand')) return Boolean(document.head);
      const s = document.createElement('style');
      s.id = 'kn-brand';
      s.textContent = css;
      document.head.prepend(s);
      return true;
    };
    if (!add()) {
      const mo = new MutationObserver(() => { if (add()) mo.disconnect(); });
      mo.observe(document, { childList: true, subtree: true });
    }
  }, { css, brand: brandGlobal(t) });
}

// Load every face the brand needs and check that each one is a bundled face that really loaded.
async function verifyBrand(page, t = tokens()) {
  const results = await page.evaluate(async ({ specs, families }) => {
    await document.fonts.ready;
    const out = [];
    for (const spec of specs) {
      let faces = [];
      try {
        faces = await document.fonts.load(spec, 'kube-noob 0123 No AI inside.');
      } catch (e) {
        out.push({ spec, ok: false, why: String(e) });
        continue;
      }
      const ours = faces.filter(f => families.includes(f.family.replace(/^"|"$/g, '')) && f.status === 'loaded');
      out.push({ spec, ok: ours.length > 0, why: ours.length ? '' : `no bundled face loaded (got ${faces.length})` });
    }
    return out;
  }, { specs: t.fonts.check, families: [t.fonts.sans, t.fonts.mono] });
  const bad = results.filter(r => !r.ok);
  if (bad.length) {
    throw new Error(`brand fonts did not load, refusing to render: ${bad.map(b => `${b.spec} (${b.why})`).join('; ')}`);
  }
  return results;
}

module.exports = { tokens, brandCSS, brandGlobal, applyBrand, verifyBrand, BRAND_DIR };
