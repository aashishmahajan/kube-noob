// Ask with your own Claude key. Claude runs the conversation; kube-noob's tools run in this tab (Pyodide worker).
// The key and the conversation go from this browser straight to api.anthropic.com and nowhere else. The key is kept
// in memory, or in this tab's sessionStorage only if the visitor ticks the box; never in localStorage, never logged.
import Anthropic from "@anthropic-ai/sdk";
import { betaTool } from "@anthropic-ai/sdk/helpers/beta/json-schema";
import * as kn from "./kn-client.js";

const KEY_SLOT = "kube-noob-anthropic-key";
const MAX_RESULT_CHARS = 60000;
const SYSTEM = [
  "You are answering questions from a visitor on kube-noob.com about Kubernetes, OpenShift, ROSA HCP, Helm and",
  "RHACS/StackRox. The kube_noob_* tools are kube-noob's deterministic rules, playbooks, release-note issue index and",
  "cited local knowledge, running in the visitor's browser with no network and no cluster access.",
  "Use the tools for facts about manifests, errors, denials, NetworkPolicies, rules and known issues, and say which",
  "rule ids, playbook ids, issue ids or knowledge chunk ids ([kn:<doc>#<n>]) your answer rests on. Put read-only",
  "commands before anything that changes a cluster, and mark changes as needing the owner's approval. When a tool",
  "result carries knowledgeAsOf, mention how current that knowledge is if it matters to the answer.",
].join(" ");

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};

let toolDefs = null;
let history = [];
let busy = false;

function readKey() {
  const typed = $("ask-key").value.trim();
  if (typed) {
    if ($("ask-remember").checked) sessionStorage.setItem(KEY_SLOT, typed);
    return typed;
  }
  return sessionStorage.getItem(KEY_SLOT) ?? "";
}

function addMessage(who, text, cls) {
  const box = el("div", `msg ${cls}`);
  box.append(el("div", "who", who), el("div", "body", text));
  $("ask-chat").append(box);
  box.scrollIntoView({ block: "end", behavior: "smooth" });
  return box;
}

function addTrace(name, input, output) {
  const d = el("details", "tool-trace");
  d.append(el("summary", null, `kube-noob tool: ${name}`));
  d.append(el("pre", null, `input:\n${JSON.stringify(input, null, 2)}\n\nresult:\n${output}`));
  $("ask-chat").append(d);
}

async function runnableTools() {
  toolDefs ??= await kn.tools();
  return toolDefs.map((def) =>
    betaTool({
      name: def.name,
      description: def.description,
      inputSchema: def.input_schema,
      run: async (input) => {
        const res = await kn.call(def.name, input);
        const text = res.ok ? JSON.stringify(res.result) : JSON.stringify({ error: res.error });
        addTrace(def.name, input, text.length > 4000 ? `${text.slice(0, 4000)}...` : text);
        if (!res.ok) throw new Error(res.error); // the runner returns it to Claude as an is_error tool result
        return text.length > MAX_RESULT_CHARS ? `${text.slice(0, MAX_RESULT_CHARS)} [truncated]` : text;
      },
    }),
  );
}

function explain(error) {
  if (error instanceof Anthropic.AuthenticationError) return "The API key was rejected. Check it in the Claude Console.";
  if (error instanceof Anthropic.PermissionDeniedError) return "This key is not allowed to use that model.";
  if (error instanceof Anthropic.RateLimitError) return "Rate limited by the API. Wait a moment and try again.";
  if (error instanceof Anthropic.APIConnectionError) return "Could not reach api.anthropic.com from this browser.";
  if (error instanceof Anthropic.APIError) return `The API returned an error (${error.status ?? "?"}): ${error.message}`;
  return String(error?.message ?? error);
}

async function send(event) {
  event.preventDefault();
  if (busy) return;
  const question = $("ask-input").value.trim();
  if (!question) return;
  const apiKey = readKey();
  if (!apiKey) {
    $("ask-status").textContent = "Paste an Anthropic API key first. It stays in this browser.";
    return;
  }
  busy = true;
  $("ask-send").disabled = true;
  $("ask-input").value = "";
  addMessage("You", question, "user");
  $("ask-status").textContent = "Starting kube-noob in your browser...";
  try {
    const tools = await runnableTools();
    const client = new Anthropic({ apiKey, dangerouslyAllowBrowser: true });
    const runner = client.beta.messages.toolRunner({
      model: $("ask-model").value,
      max_tokens: 16000,
      system: SYSTEM,
      tools,
      messages: [...history, { role: "user", content: question }],
      output_config: { effort: $("ask-effort").value },
      betas: ["server-side-fallback-2026-07-01"],
      fallbacks: "default",
      max_iterations: 12,
    });
    $("ask-status").textContent = "Claude is working; kube-noob tools run here in your tab...";
    let last = null;
    for await (const message of runner) {
      last = message;
      const text = message.content.filter((b) => b.type === "text").map((b) => b.text).join("\n").trim();
      if (text) addMessage(`Claude (${message.model})`, text, "assistant");
    }
    if (last?.stop_reason === "refusal") {
      const why = last.stop_details?.explanation ?? "The request was declined.";
      addMessage("Claude", `Declined: ${why}`, "assistant");
    } else if (last?.stop_reason === "max_tokens") {
      addMessage("Claude", "The answer hit the length limit. Ask for a shorter answer or a narrower question.", "assistant");
    }
    // The runner appends every assistant turn and tool result to its messages, the final turn included, so the
    // history stays append-only for the next question.
    history = [...runner.params.messages];
    $("ask-status").textContent = "";
  } catch (error) {
    $("ask-status").textContent = explain(error);
  } finally {
    busy = false;
    $("ask-send").disabled = false;
  }
}

function main() {
  if (sessionStorage.getItem(KEY_SLOT)) {
    $("ask-key").placeholder = "Using the key saved in this tab";
    $("ask-remember").checked = true;
  }
  $("ask-form").addEventListener("submit", send);
  $("ask-forget").addEventListener("click", () => {
    sessionStorage.removeItem(KEY_SLOT);
    $("ask-key").value = "";
    $("ask-key").placeholder = "sk-ant-...";
    $("ask-remember").checked = false;
    history = [];
    $("ask-chat").replaceChildren();
    $("ask-status").textContent = "Key and conversation cleared from this tab.";
  });
  for (const b of document.querySelectorAll("[data-ask]")) {
    b.addEventListener("click", () => {
      $("ask-input").value = b.dataset.ask;
      $("ask-input").focus();
    });
  }
}

main();
