// The playground: kube-noob's real tools, running in this browser tab. No model, no network, no account.
import * as kn from "./kn-client.js";

const examples = JSON.parse(document.getElementById("kn-examples").textContent);

const el = (tag, attrs = {}, ...children) => {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) if (c != null) node.append(c);
  return node;
};
const sev = (s) => el("span", { class: `sev ${s}`, text: s });
const list = (items) => el("ul", {}, ...items.map((i) => el("li", { text: String(i) })));
const step = (s) => {
  if (typeof s === "string") return el("li", {}, el("code", { text: s }));
  if (s.command) return el("li", {}, el("code", { text: s.command }), s.why ? ` ${s.why}` : "");
  return el("li", { text: `${s.change ?? JSON.stringify(s)}${s.requiresApproval ? " (needs approval)" : ""}` });
};
const cmdList = (steps) => el("ul", {}, ...steps.map(step));
const raw = (obj) => el("details", {}, el("summary", { text: "Full JSON result" }), el("pre", { text: JSON.stringify(obj, null, 2) }));

const PLATFORMS = ["kubernetes", "openshift", "rosa-classic", "rosa-hcp"];

const TOOLS = [
  {
    id: "audit",
    label: "Audit YAML",
    tool: "kube_noob_audit_manifests",
    intro: "60 rules, strict schemas and removed-API checks. Findings name the RHACS policy and NIST controls.",
    fields: [
      { name: "manifests", kind: "textarea", value: examples.audit },
      { name: "platform", kind: "select", options: PLATFORMS, value: "openshift" },
      { name: "version", kind: "text", value: "4.22", placeholder: "4.22" },
    ],
    render(r) {
      const c = r.summary.counts;
      const out = [
        el("h4", { text: `Score ${r.summary.score} / 100 on ${r.platform} (Kubernetes ${r.kubernetesVersion})` }),
        el("p", { text: `critical ${c.critical} · high ${c.high} · medium ${c.medium} · low ${c.low}` }),
      ];
      const rows = r.findings.map((f) =>
        el("tr", {}, el("td", {}, sev(f.severity)), el("td", {}, el("code", { text: f.ruleId })),
          el("td", { text: `${f.resource}${f.line ? ` L${f.line}` : ""}` }), el("td", { text: `${f.message} ${f.remediation}` })),
      );
      out.push(el("div", { class: "table-wrap" }, el("table", {},
        el("thead", {}, el("tr", {}, ...["Severity", "Rule", "Where", "Finding and fix"].map((h) => el("th", { text: h })))),
        el("tbody", {}, ...rows))));
      return out;
    },
  },
  {
    id: "diagnose",
    label: "Diagnose",
    tool: "kube_noob_diagnose",
    intro: "Paste events, describe output or logs. You get the likely cause and read-only steps first.",
    fields: [
      { name: "text", kind: "textarea", value: examples.diagnose },
      { name: "platform", kind: "select", options: ["", ...PLATFORMS], value: "openshift" },
      { name: "version", kind: "text", value: "", placeholder: "4.21.4 (optional)" },
    ],
    render(r) {
      const out = [el("p", { text: r.approach })];
      for (const d of r.diagnoses) {
        out.push(el("h4", { text: `${d.title} (${d.id}, confidence ${d.confidence})` }));
        out.push(el("p", { text: "Likely causes:" }), list(d.rootCauses));
        if (d.readOnlyNextSteps?.length) out.push(el("p", { text: "Read-only next steps:" }), cmdList(d.readOnlyNextSteps));
        if (d.proposedChanges?.length) out.push(el("p", { text: "Changes (need approval):" }), cmdList(d.proposedChanges));
      }
      const issues = Array.isArray(r.knownIssues) ? r.knownIssues : r.knownIssues?.matches ?? [];
      if (issues.length) out.push(el("h4", { text: "Reported issues" }), list(issues.map((m) => `${m.id}: ${m.status}`)));
      return out;
    },
  },
  {
    id: "known",
    label: "Known bug?",
    tool: "kube_noob_known_issues",
    intro: "Match an error against the issues in the OpenShift release notes, with the fix version.",
    fields: [
      { name: "text", kind: "textarea", value: examples.known, rows: 4 },
      { name: "version", kind: "text", value: "4.20.8", placeholder: "4.20.8" },
    ],
    render(r) {
      if (!r.matches.length) return [el("p", { text: r.note ?? "No reported issue matches this text closely." })];
      return r.matches.flatMap((m) => [
        el("h4", {}, el("a", { href: m.url, rel: "noopener", target: "_blank", text: m.id }), ` ${m.status}`),
        el("p", { text: m.summary }),
        m.workaround ? el("p", { text: `Workaround: ${m.workaround}` }) : null,
      ]);
    },
  },
  {
    id: "denied",
    label: "Why denied?",
    tool: "kube_noob_explain_denial",
    intro: "Kyverno, Gatekeeper, ValidatingAdmissionPolicy, Pod Security, SCC, RHACS, quota, LimitRange and RBAC.",
    fields: [
      { name: "text", kind: "textarea", value: examples.denied },
      { name: "platform", kind: "select", options: ["", ...PLATFORMS], value: "openshift" },
    ],
    render(r) {
      const out = [el("p", { text: r.summary ?? r.approach })];
      for (const d of r.denials) {
        out.push(el("h4", { text: `${d.engineName}: ${d.message}` }), el("p", { text: d.meaning }));
        if (d.readOnlyNextSteps?.length) out.push(el("p", { text: "Read-only steps:" }), cmdList(d.readOnlyNextSteps));
        if (d.fix) out.push(el("p", { text: `Fix: ${typeof d.fix === "string" ? d.fix : JSON.stringify(d.fix)}` }));
      }
      return out;
    },
  },
  {
    id: "reach",
    label: "Can A reach B?",
    tool: "kube_noob_check_network_policy",
    intro: "Evaluates NetworkPolicies the way Kubernetes does, names the deciding rule and proposes the smallest fix.",
    fields: [
      { name: "manifests", kind: "textarea", value: examples.reach },
      { name: "source", kind: "text", value: "shop/orders-api" },
      { name: "destination", kind: "text", value: "shop/payments" },
      { name: "port", kind: "text", value: "9090" },
    ],
    coerce: (a) => ({ ...a, port: /^\d+$/.test(a.port) ? Number(a.port) : a.port }),
    render(r) {
      const out = [
        el("h4", {}, el("span", { class: r.verdict === "allowed" ? "ok" : "no", text: r.verdict.toUpperCase() }), ` ${r.source} to ${r.destination}:${r.port}`),
        el("p", { text: r.summary }),
        el("p", { text: `Egress: ${r.egress.reason ?? (r.egress.allowed ? "allowed" : "denied")}` }),
        el("p", { text: `Ingress: ${r.ingress.reason ?? (r.ingress.allowed ? "allowed" : "denied")}` }),
      ];
      if (r.suggestedPolicy) out.push(el("p", { text: "Smallest policy that allows it:" }), el("pre", { text: r.suggestedPolicy }));
      return out;
    },
  },
];

async function buildRawTab(panel) {
  const status = document.getElementById("kn-status");
  const defs = await kn.tools();
  const select = el("select", { id: "raw-tool" }, ...defs.map((d) => el("option", { value: d.name, text: `${d.name} - ${d.title}` })));
  const args = el("textarea", { id: "raw-args", spellcheck: "false" });
  const describe = el("p", { class: "status" });
  const fill = () => {
    const d = defs.find((x) => x.name === select.value);
    describe.textContent = d.description;
    const props = d.input_schema.properties ?? {};
    const sample = {};
    for (const k of d.input_schema.required ?? []) sample[k] = props[k]?.type === "integer" ? 0 : "";
    args.value = JSON.stringify(sample, null, 2);
  };
  select.addEventListener("change", fill);
  fill();
  const run = el("button", { class: "btn primary", type: "button", text: "Run tool" });
  const out = el("div", { class: "out" });
  run.addEventListener("click", async () => {
    let parsed;
    try { parsed = JSON.parse(args.value || "{}"); } catch (e) { out.replaceChildren(el("p", { class: "no", text: `Arguments are not JSON: ${e.message}` })); return; }
    status.textContent = `Running ${select.value} in your browser...`;
    const res = await kn.call(select.value, parsed);
    status.textContent = "";
    out.replaceChildren(res.ok ? el("pre", { text: JSON.stringify(res.result, null, 2) }) : el("p", { class: "no", text: res.error }));
  });
  panel.replaceChildren(
    el("div", {}, el("label", { for: "raw-tool", text: "Tool" }), select, describe, el("label", { for: "raw-args", text: "Arguments (JSON)" }), args, el("p", {}, run)),
    out,
  );
}

function buildTab(spec, panel) {
  const form = el("form", {});
  form.append(el("p", { class: "status", text: spec.intro }));
  for (const f of spec.fields) {
    const id = `${spec.id}-${f.name}`;
    form.append(el("label", { for: id, text: f.name }));
    let input;
    if (f.kind === "textarea") {
      input = el("textarea", { id, name: f.name, spellcheck: "false" });
      if (f.rows) input.style.minHeight = `${f.rows * 1.6}em`;
      input.value = f.value ?? "";
    } else if (f.kind === "select") {
      input = el("select", { id, name: f.name }, ...f.options.map((o) => el("option", { value: o, text: o || "(not set)" })));
      input.value = f.value;
    } else {
      input = el("input", { id, name: f.name, type: "text", placeholder: f.placeholder ?? "" });
      input.value = f.value ?? "";
    }
    form.append(input);
  }
  const button = el("button", { class: "btn primary", type: "submit", text: `Run ${spec.label}` });
  form.append(el("p", {}, button));
  const out = el("div", { class: "out", "aria-live": "polite" }, el("p", { class: "status", text: "Results appear here." }));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(form).entries());
    for (const k of Object.keys(data)) if (data[k] === "") delete data[k];
    const args = spec.coerce ? spec.coerce(data) : data;
    button.disabled = true;
    const status = document.getElementById("kn-status");
    status.textContent = "Running in your browser (the first run loads the Python runtime, about 15 MB)...";
    const started = performance.now();
    try {
      const res = await kn.call(spec.tool, args);
      if (!res.ok) out.replaceChildren(el("p", { class: "no", text: res.error }));
      else out.replaceChildren(...spec.render(res.result), el("p", { class: "status", text: res.result.knowledgeAsOf ?? "" }), raw(res.result));
      status.textContent = `Done in ${Math.round(performance.now() - started)} ms, on your device.`;
    } catch (e) {
      out.replaceChildren(el("p", { class: "no", text: String(e.message ?? e) }));
      status.textContent = "";
    } finally {
      button.disabled = false;
    }
  });
  panel.replaceChildren(form, out);
}

function main() {
  const tabs = document.getElementById("kn-tabs");
  const panel = document.getElementById("kn-panel");
  const all = [...TOOLS, { id: "raw", label: "Any tool (JSON)" }];
  const select = (spec) => {
    for (const b of tabs.children) b.setAttribute("aria-selected", String(b.dataset.id === spec.id));
    if (spec.id === "raw") buildRawTab(panel).catch((e) => panel.replaceChildren(el("p", { class: "no", text: e.message })));
    else buildTab(spec, panel);
    history.replaceState(null, "", `#${spec.id}`);
  };
  for (const spec of all) {
    const b = el("button", { type: "button", role: "tab", "data-id": spec.id, text: spec.label });
    b.addEventListener("click", () => select(spec));
    tabs.append(b);
  }
  select(all.find((s) => `#${s.id}` === location.hash) ?? all[0]);
  const status = document.getElementById("kn-status");
  status.textContent = "Loading kube-noob into your browser...";
  kn.info()
    .then((i) => { status.textContent = `kube-noob ${i.version} is running in your browser. ${i.knowledgeAsOf}.`; })
    .catch((e) => { status.textContent = `Could not start the in-browser runtime: ${e.message}`; });
}

main();
