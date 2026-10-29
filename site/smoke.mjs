// Smoke test of a built kube-noob.com in Chromium: `node smoke.mjs http://127.0.0.1:8765`.
// Fails on any console error or CSP violation, runs every playground tool for real (Pyodide in the page), and drives
// the Ask page through a full tool-use round trip against a stubbed api.anthropic.com (no key, nothing billed).
import { chromium } from "playwright";

const base = process.argv[2] ?? "http://127.0.0.1:8765";
const failures = [];
const fail = (msg) => { failures.push(msg); console.log(`FAIL ${msg}`); };
const pass = (msg) => console.log(`ok   ${msg}`);

const browser = await chromium.launch();
const context = await browser.newContext();

async function open(path, { expectErrors = false } = {}) {
  const page = await context.newPage();
  const errors = [];
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(String(e)));
  const res = await page.goto(base + path, { waitUntil: "load" });
  if (!res || res.status() !== 200) fail(`${path} returned ${res?.status()}`);
  page.errors = errors;
  return page;
}

function noErrors(page, path) {
  const real = page.errors.filter((e) => !/favicon/.test(e));
  if (real.length) fail(`${path} console errors: ${real.join(" | ").slice(0, 600)}`);
  else pass(`${path} loads without console errors`);
}

// Static pages
for (const path of ["/", "/journey/", "/docs/overview/", "/docs/architecture/", "/reference/mcp/", "/reference/cli/",
  "/reference/rules/", "/reference/playbooks/", "/reference/knowledge/", "/reference/known-issues/",
  "/reference/helm-values/", "/insights/", "/videos/"]) {
  const page = await open(path);
  if (path === "/docs/architecture/") {
    await page.waitForSelector("pre.mermaid svg", { timeout: 20000 }).then(
      () => pass("architecture diagram renders"), () => fail("mermaid diagram did not render"));
  }
  if (path === "/videos/") {
    const n = await page.locator("video").count();
    n >= 3 ? pass(`videos page has ${n} videos`) : fail(`videos page has ${n} videos`);
  }
  noErrors(page, path);
  await page.close();
}

// Search
{
  const page = await open("/");
  await page.fill("#site-search", "known issues");
  await page.waitForSelector("#search-results.open a", { timeout: 5000 }).then(
    () => pass("search returns results"), () => fail("search returned nothing"));
  await page.close();
}

// Playground: every tab, real tools in Pyodide
{
  const page = await open("/playground/");
  await page.waitForFunction(() => /running in your browser/.test(document.getElementById("kn-status").textContent),
    null, { timeout: 120000 }).then(() => pass("runtime starts in the browser"), () => fail("runtime did not start"));
  const expect = {
    audit: /Score \d+/,
    diagnose: /confidence/,
    known: /OCPBUGS-\d+/,
    denied: /SecurityContextConstraints/,
    reach: /ALLOWED|DENIED/,
  };
  for (const [id, re] of Object.entries(expect)) {
    await page.click(`#kn-tabs button[data-id="${id}"]`);
    await page.click("#kn-panel form button[type=submit]");
    const out = page.locator("#kn-panel .out");
    try {
      await page.waitForFunction(([sel, src]) => new RegExp(src).test(document.querySelector(sel).textContent),
        ["#kn-panel .out", re.source], { timeout: 60000 });
      const text = await out.textContent();
      if (/undefined|\[object Object\]/.test(text)) fail(`playground ${id} shows undefined or [object Object]`);
      else pass(`playground ${id}: ${text.replace(/\s+/g, " ").slice(0, 110)}`);
    } catch {
      fail(`playground ${id} output: ${(await out.textContent()).slice(0, 300)}`);
    }
  }
  noErrors(page, "/playground/");
  await page.close();
}

// Ask: stubbed Messages API, real SDK tool runner, real in-browser tools
{
  const page = await open("/ask/");
  const requests = [];
  await page.route("https://api.anthropic.com/**", async (route) => {
    const req = route.request();
    const cors = {
      "access-control-allow-origin": "*",
      "access-control-allow-headers": "*",
      "access-control-allow-methods": "POST, OPTIONS",
    };
    if (req.method() === "OPTIONS") return route.fulfill({ status: 204, headers: cors });
    const body = JSON.parse(req.postData());
    requests.push({ headers: req.headers(), body });
    const base = { id: `msg_${requests.length}`, type: "message", role: "assistant", model: body.model,
      stop_sequence: null, usage: { input_tokens: 10, output_tokens: 10 } };
    const reply = requests.length === 1
      ? { ...base, stop_reason: "tool_use", content: [
          { type: "text", text: "Checking the release-note index." },
          { type: "tool_use", id: "toolu_1", name: "kube_noob_known_issues",
            input: { text: "could not find any suitable subnets for creating the ELB", version: "4.20.8" } }] }
      : { ...base, stop_reason: "end_turn", content: [{ type: "text", text: "That matches a reported issue." }] };
    return route.fulfill({ status: 200, headers: { ...cors, "content-type": "application/json" }, body: JSON.stringify(reply) });
  });
  await page.fill("#ask-key", "sk-ant-test-not-a-real-key");
  await page.fill("#ask-input", "Is this a known bug on 4.20.8: could not find any suitable subnets for creating the ELB");
  await page.click("#ask-send");
  try {
    await page.waitForFunction(() => /That matches a reported issue/.test(document.getElementById("ask-chat").textContent),
      null, { timeout: 120000 });
    const second = requests[1]?.body;
    const toolResult = JSON.stringify(second?.messages?.at(-1) ?? {});
    const first = requests[0];
    const checks = [
      [requests.length === 2, `two API calls (got ${requests.length})`],
      [/OCPBUGS-\d+/.test(toolResult), "tool result sent back holds the matched OCPBUGS id"],
      [first.headers["anthropic-dangerous-direct-browser-access"] === "true", "browser-access header sent"],
      [first.headers["x-api-key"] === "sk-ant-test-not-a-real-key", "key sent only as x-api-key"],
      [first.body.model === "claude-opus-5-5", "default model is claude-opus-5-5"],
      [first.body.fallbacks === "default", "server-side fallback requested"],
      [(first.headers["anthropic-beta"] ?? "").includes("server-side-fallback-2026-07-01"), "fallback beta header"],
      [first.body.tools.length >= 10 && first.body.tools.every((t) => t.name.startsWith("kube_noob_")), "kube-noob tools offered"],
      [await page.locator("#ask-chat details.tool-trace").count() === 1, "tool call shown in the trace"],
    ];
    for (const [ok, what] of checks) ok ? pass(`ask: ${what}`) : fail(`ask: ${what}`);
  } catch {
    fail(`ask round trip did not finish: ${await page.locator("#ask-status").textContent()}`);
  }
  const stored = await page.evaluate(() => [localStorage.length, sessionStorage.getItem("kube-noob-anthropic-key")]);
  stored[0] === 0 && stored[1] === null ? pass("ask: key not stored without consent") : fail(`ask: storage ${stored}`);
  noErrors(page, "/ask/");
  await page.close();
}

await browser.close();
if (failures.length) {
  console.log(`\n${failures.length} failure(s)`);
  process.exit(1);
}
console.log("\nall smoke checks passed");
