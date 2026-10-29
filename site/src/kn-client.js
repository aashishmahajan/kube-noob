// Talks to the kube-noob Web Worker. One worker per page, started on first use.
let worker = null;
let seq = 0;
const pending = new Map();

function failAll(message) {
  for (const { reject } of pending.values()) reject(new Error(message));
  pending.clear();
}

function ensureWorker() {
  if (worker) return worker;
  worker = new Worker(new URL("/assets/kn-worker.js", location.href), { type: "module" });
  worker.onmessage = (event) => {
    const { id, ok, json, error } = event.data;
    const p = pending.get(id);
    if (!p) return;
    pending.delete(id);
    if (ok) p.resolve(JSON.parse(json));
    else p.reject(new Error(error));
  };
  worker.onerror = (event) => {
    failAll(event.message || "the kube-noob worker stopped");
    worker = null;
  };
  return worker;
}

function request(op, name, args) {
  return new Promise((resolve, reject) => {
    const id = ++seq;
    pending.set(id, { resolve, reject });
    ensureWorker().postMessage({ id, op, name, args });
  });
}

/** Start the runtime; resolves to {version, knowledgeAsOf, tools}. */
export const info = () => request("info");
/** Tool definitions: [{name, title, description, input_schema}]. */
export const tools = () => request("tools");
/** Run one tool: resolves to {ok: true, result} or {ok: false, error}. */
export const call = (name, args) => request("call", name, args);
