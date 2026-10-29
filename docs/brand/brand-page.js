// Fills a brand image page from the brand (window.__KN_BRAND__, injected by demos/video/brand.js through render.js):
// every <img> gets the icon, every [data-kn="<token>"] gets that token's text. window.__ready resolves when the
// icon has decoded. A page opened without render.js says so instead of rendering in the wrong fonts.
(() => {
  const KN = window.__KN_BRAND__;
  if (!KN) throw new Error('kube-noob brand missing: render this page with docs/brand/render.js');
  for (const el of document.querySelectorAll('[data-kn]')) el.textContent = KN.tokens[el.dataset.kn];
  const imgs = [...document.querySelectorAll('img')];
  for (const img of imgs) img.src = KN.icon;
  window.__ready = Promise.all(imgs.map(i => i.decode()));
})();
