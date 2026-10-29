// Every page: theme toggle, mobile menu, site search (a static index, searched in the browser), mermaid diagrams.
const root = document.documentElement;
const THEME_SLOT = "kube-noob-theme";

function storedTheme() {
  try {
    return localStorage.getItem(THEME_SLOT);
  } catch {
    return null;
  }
}

function applyTheme(theme) {
  if (theme === "light" || theme === "dark") root.dataset.theme = theme;
  else delete root.dataset.theme;
  const button = document.getElementById("theme-toggle");
  if (button) button.textContent = theme === "dark" ? "Light" : theme === "light" ? "Dark" : "Theme";
}

applyTheme(storedTheme());

document.getElementById("theme-toggle")?.addEventListener("click", () => {
  const dark = root.dataset.theme
    ? root.dataset.theme === "dark"
    : matchMedia("(prefers-color-scheme: dark)").matches;
  const next = dark ? "light" : "dark";
  try {
    localStorage.setItem(THEME_SLOT, next);
  } catch {
    // Storage blocked: the choice lasts for this page only.
  }
  applyTheme(next);
});

const menu = document.getElementById("menu-toggle");
menu?.addEventListener("click", () => {
  const nav = document.getElementById("main-nav");
  const open = nav.classList.toggle("open");
  menu.setAttribute("aria-expanded", String(open));
});

// Search
let index = null;
const input = document.getElementById("site-search");
const results = document.getElementById("search-results");

async function loadIndex() {
  index ??= fetch("/search-index.json").then((r) => r.json());
  return index;
}

function score(doc, terms) {
  const title = doc.t.toLowerCase();
  const head = doc.h.toLowerCase();
  const body = doc.b.toLowerCase();
  let s = 0;
  for (const term of terms) {
    if (!body.includes(term) && !title.includes(term) && !head.includes(term)) return 0;
    if (title.includes(term)) s += 10;
    if (head.includes(term)) s += 4;
    s += Math.min(5, body.split(term).length - 1);
  }
  return s;
}

function snippet(text, term) {
  const i = text.toLowerCase().indexOf(term);
  if (i < 0) return text.slice(0, 120);
  return `${i > 40 ? "..." : ""}${text.slice(Math.max(0, i - 40), i + 100)}...`;
}

input?.addEventListener("input", async () => {
  const q = input.value.trim().toLowerCase();
  if (q.length < 2) {
    results.classList.remove("open");
    return;
  }
  const terms = q.split(/\s+/).filter(Boolean);
  const docs = await loadIndex();
  const hits = docs
    .map((d) => [score(d, terms), d])
    .filter(([s]) => s > 0)
    .sort((a, b) => b[0] - a[0])
    .slice(0, 8);
  results.replaceChildren();
  if (!hits.length) {
    const none = document.createElement("small");
    none.textContent = "No pages match.";
    none.style.padding = "8px 10px";
    results.append(none);
  }
  for (const [, d] of hits) {
    const a = document.createElement("a");
    a.href = d.u;
    a.textContent = d.t;
    const small = document.createElement("small");
    small.textContent = snippet(d.b, terms[0]);
    a.append(small);
    results.append(a);
  }
  results.classList.add("open");
});
input?.addEventListener("keydown", (e) => {
  if (e.key === "Escape") results.classList.remove("open");
  if (e.key === "Enter") results.querySelector("a")?.click();
});
document.addEventListener("click", (e) => {
  if (results && !results.contains(e.target) && e.target !== input) results.classList.remove("open");
});

// Mermaid diagrams, loaded only on pages that have one.
if (document.querySelector("pre.mermaid")) {
  const script = document.createElement("script");
  script.src = "/assets/mermaid.min.js";
  script.onload = () => {
    const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    window.mermaid.initialize({ startOnLoad: false, theme: dark ? "dark" : "neutral", securityLevel: "strict" });
    window.mermaid.run({ querySelector: "pre.mermaid" });
  };
  document.head.append(script);
}
