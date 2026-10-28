"""Prompt-injection hygiene for text that came from outside: a cluster, a must-gather, a ticket, a memory entry, a
pasted payload or a web page.

Defence in depth, not a guarantee. kube-noob calls no model itself, but the model that calls kube-noob reads its
results, so text shaped to steer that model is found and neutralised before a result leaves the MCP server:

- invisible characters are removed: Unicode tag characters (U+E0000 to U+E007F), bidirectional overrides and isolates
  (U+202A to U+202E, U+2066 to U+2069) and zero-width characters (U+200B to U+200D, U+2060, U+FEFF);
- chat-template and role markers (``<|im_start|>``, ``[INST]``, ``<<SYS>>``, ``### System:``, ``</system>``,
  ``<system-reminder>``, and ``Human:`` / ``Assistant:`` lines when both appear), tool-call shapes
  (``<tool_call>``, ``<function_calls>``, ``"tool_calls":``, ``{"name": ..., "arguments": ...}``) and instruction
  phrases aimed at a model ("ignore previous instructions", "you are now in developer mode", "do not tell the user",
  "send the kubeconfig to https://...") are replaced by a visible marker;
- Markdown images with a remote address and Markdown links whose address carries a query string (the usual way to
  make a renderer send data out) lose the address.

Detection runs after invisible characters are removed, so a zero-width space inside "ignore" does not hide it. Every
rule is deterministic and bounded. The eval in ``tests/fixtures/injection.yaml`` (kept out of the package and the
plugin, since it holds attack text) gates detection at 95% or better and false positives at zero, and a test runs
every rule over all bundled text (playbooks, rules, lessons, signals, known issues, example events and logs)
expecting no finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

MAX_SIGNALS = 20
MAX_DEPTH = 40
MAX_SCAN = 4_000_000  # characters of one string scanned; the rest is kept as is (results are bounded upstream)
MARKER = "[removed: {what}]"

_KINDS_OF_INVISIBLE = (
    (re.compile("[\U000e0000-\U000e007f]"), "unicode-tags"),
    (re.compile("[\u202a-\u202e\u2066-\u2069]"), "bidi-override"),
    (re.compile("[\u200b-\u200d\u2060\ufeff]"), "zero-width"),
)
_INVISIBLE = re.compile("[\U000e0000-\U000e007f\u202a-\u202e\u2066-\u2069\u200b-\u200d\u2060\ufeff]")

_MODEL = (
    r"(?:AI|A\.I\.|assistant|LLM|large\s+language\s+model|language\s+model|chatbot|copilot|Claude|ChatGPT|GPT(?:-\d)?|"
    r"Gemini|Lightspeed|AI\s+agent|coding\s+agent)"
)
_SENSITIVE = (
    r"(?:secrets?|credentials?|tokens?|api\s+keys?|passwords?|environment\s+variables|env\s+vars|kubeconfigs?|"
    r"ssh\s+keys?|private\s+keys?|service\s*account\s+tokens?)"
)

_ROLE = re.compile(
    r"<\|(?:im_start|im_end|im_sep|system|user|assistant|begin_of_text|end_of_text|start_header_id|end_header_id|"
    r"eot_id|endoftext)\|>"
    r"|\[/?INST\]|<</?SYS>>|<start_of_turn>|<end_of_turn>"
    r"|^[ \t]*#{2,4}[ \t]*(?:system|instruction|instructions|human|assistant)[ \t]*:"
    r"|</?(?:system|assistant)[-_](?:reminder|prompt|message|instructions?)(?:\s[^<>]{0,40})?>"
    r"|</(?:system|assistant)>|<assistant(?:\s[^<>]{0,40})?>",
    re.MULTILINE | re.IGNORECASE,
)
_TOOL_CALL = re.compile(
    r"</?(?:tool_call|tool_use|tool_result|function_calls?|invoke|antml:[a-z_]{1,30})(?:\s[^<>]{0,120})?>"
    r"|\"(?:function_call|tool_calls|tool_use)\"\s*:"
    r"|\{\s*\"name\"\s*:\s*\"[\w.-]{1,80}\"\s*,\s*\"(?:arguments|parameters)\"\s*:",
    re.IGNORECASE,
)
_INSTRUCTION = re.compile(
    r"\b(?:"
    r"(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|the\s+|your\s+|every\s+)?(?:of\s+)?"
    r"(?:the\s+|your\s+|these\s+|those\s+)?(?:previous|prior|above|earlier|preceding|original|system|initial|safety)\s+"
    r"(?:instructions?|prompts?|messages?|directions?|rules|guidelines|guardrails|context|constraints)"
    r"|forget\s+(?:everything|all)\s+(?:you\s+(?:were|have\s+been)\s+told|above|before\s+this)"
    r"|you\s+are\s+now\s+(?:a|an|in|the)\s+(?:[\w-]+\s+){0,2}(?:" + _MODEL + r"|DAN|mode|jailbroken|unrestricted|"
    r"unfiltered)\b"
    r"|(?:new|updated|real|actual|hidden|secret|override)\s+(?:system\s+)?instructions?\s*:"
    r"|system\s+prompt\s*:"
    r"|(?:reveal|print|show|repeat|output|leak|dump)\s+(?:me\s+)?(?:your\s+(?:system\s+|hidden\s+|initial\s+|"
    r"original\s+)?|the\s+(?:system|hidden|initial|original)\s+)(?:prompt|instructions)\b"
    r"|do\s+not\s+(?:tell|inform|alert|warn|notify|show|mention\s+(?:this\s+)?to)\s+(?:the\s+)?(?:user|human|"
    r"operator|admin(?:istrator)?)\b"
    r"|without\s+(?:telling|informing|asking|alerting|notifying)\s+the\s+(?:user|human|operator)\b"
    r"|(?:act|behave|respond|pretend)\s+(?:as\s+if\s+you\s+are|as|like)\s+(?:a|an)\s+(?:unrestricted|jailbroken|"
    r"unfiltered|uncensored|evil)\b"
    r"|(?:developer|DAN|god)\s+mode\s+(?:is\s+)?(?:enabled|activated|on)\b"
    r"|(?:note|message|instructions?|reminder)\s+(?:to|for)\s+(?:the\s+|any\s+|all\s+)?" + _MODEL + r"s?\b"
    r"|(?:note|message|instructions?|reminder)\s+(?:to|for)\s+(?:the\s+|any\s+|all\s+)?(?:models?|agents?)\s*:"
    r"|if\s+you\s+are\s+(?:a|an)\s+(?:[\w-]+\s+)?" + _MODEL + r"\b"
    r"|(?:attention|important|note)\s*[,:!-]\s*(?:all\s+|any\s+)?" + _MODEL + r"s?\b"
    r"|(?:attention|important|note)\s+(?:to\s+)?(?:all\s+|any\s+)?" + _MODEL + r"s?\s*[,:!]"
    r"|(?:any|every|all)\s+(?:AI\s+)?(?:models?|agents?)\s+(?:reading|processing|summari[sz]ing|parsing)\s+this\b"
    r"|" + _MODEL + r"s?\s+(?:reading|processing|summari[sz]ing|parsing)\s+this\b"
    r"|the\s+(?:assistant|model|AI|agent|LLM)\s+(?:must|should|shall|will)\s+(?:now|immediately|silently)\b"
    r"|(?:send|post|upload|exfiltrate|forward|e-?mail|leak|copy)\s+(?:all\s+|the\s+|your\s+|any\s+|every\s+)?"
    r"(?:of\s+the\s+)?" + _SENSITIVE + r"\s+to\s+(?:https?://|\S+@\S+\.\w+|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b)"
    r")",
    re.IGNORECASE,
)
_TRANSCRIPT_LINE = re.compile(r"^[ \t]*(?:Human|Assistant|User)[ \t]*:[ \t]+(?=\S)", re.MULTILINE)
_HUMAN_LINE = re.compile(r"^[ \t]*(?:Human|User)[ \t]*:[ \t]+\S", re.MULTILINE)
_ASSISTANT_LINE = re.compile(r"^[ \t]*Assistant[ \t]*:[ \t]+\S", re.MULTILINE)
_MD_IMAGE = re.compile(r"!\[([^\]\n]{0,200})\]\(\s*(?:https?:)?//[^)\s]{1,2000}(?:\s+\"[^\"\n]{0,200}\")?\s*\)")
_MD_LINK_QUERY = re.compile(r"(?<!!)\[([^\]\n]{1,200})\]\(\s*(?:https?:)?//[^)\s?]{1,1000}\?[^)\s]{1,2000}\s*\)")


@dataclass(frozen=True)
class Finding:
    kind: str
    excerpt: str
    field: str = ""

    def as_dict(self) -> dict[str, str]:
        out = {"kind": self.kind, "excerpt": self.excerpt}
        if self.field:
            out["field"] = self.field
        return out


_DEFANG = str.maketrans(dict.fromkeys('<>|[]{}"`*#'))


def _excerpt(s: str) -> str:
    """A preview that cannot carry the instruction back into the result: the first word, defanged, and the length."""
    words = " ".join(s.split()).translate(_DEFANG).split()
    first = words[0][:20] if words else ""
    return f"{first}... ({len(s)} characters)"


def clean(text: str, field: str = "") -> tuple[str, list[Finding]]:
    """``text`` with invisible characters removed and injection shapes neutralised, and what was found."""
    if not text:
        return text, []
    head, tail = (text, "") if len(text) <= MAX_SCAN else (text[:MAX_SCAN], text[MAX_SCAN:])
    findings: list[Finding] = []
    for rx, kind in _KINDS_OF_INVISIBLE:
        n = len(rx.findall(head))
        if n:
            findings.append(Finding(kind, f"{n} character(s) removed", field))
    head = _INVISIBLE.sub("", head)

    def sub(rx: re.Pattern[str], kind: str, repl: Any) -> None:
        nonlocal head

        def one(m: re.Match[str]) -> str:
            findings.append(Finding(kind, _excerpt(m.group(0)), field))
            return str(repl(m) if callable(repl) else repl)

        head = rx.sub(one, head)

    sub(_ROLE, "role-marker", MARKER.format(what="role marker"))
    if _HUMAN_LINE.search(head) and _ASSISTANT_LINE.search(head):  # a scripted conversation, not one stray label
        sub(_TRANSCRIPT_LINE, "role-marker", MARKER.format(what="role marker") + " ")
    sub(_TOOL_CALL, "tool-call", MARKER.format(what="tool-call marker"))
    sub(_INSTRUCTION, "instruction", MARKER.format(what="instruction-like text"))
    sub(_MD_IMAGE, "markdown-image", lambda m: f"[image: {m.group(1)}] " + MARKER.format(what="remote image address"))
    sub(_MD_LINK_QUERY, "markdown-link", lambda m: f"{m.group(1)} " + MARKER.format(what="link with a query string"))
    return head + tail, findings


def detect(text: str) -> list[Finding]:
    """What :func:`clean` would find in ``text``."""
    return clean(text)[1]


def result(value: Any) -> Any:
    """Clean every string (and mapping key) in a tool result: dicts, lists and strings, depth-bounded. When anything
    was found, a dict result carries ``untrusted: true`` and ``injectionSignals`` (where, what kind, an excerpt; at
    most 20, the count of the rest in ``injectionSignalsTruncated``)."""
    found: list[Finding] = []

    def walk(v: Any, path: str, depth: int) -> Any:
        if depth > MAX_DEPTH:
            return v
        if isinstance(v, str):
            cleaned, f = clean(v, path)
            found.extend(f)
            return cleaned
        if isinstance(v, dict):
            out: dict[Any, Any] = {}
            for k, x in v.items():
                key = k
                if isinstance(k, str):
                    key, f = clean(k, f"{path}.<key>" if path else "<key>")
                    found.extend(f)
                    while key in out:
                        key = f"{key} (duplicate)"
                out[key] = walk(x, f"{path}.{key}" if path else str(key), depth + 1)
            return out
        if isinstance(v, list | tuple):
            return [walk(x, f"{path}[{i}]", depth + 1) for i, x in enumerate(v)]
        return v

    cleaned = walk(value, "", 0)
    if found and isinstance(cleaned, dict):
        seen: set[tuple[str, str, str]] = set()
        signals: list[dict[str, str]] = []
        for f in found:
            key = (f.kind, f.excerpt, f.field)
            if key not in seen:
                seen.add(key)
                signals.append(f.as_dict())
        cleaned["untrusted"] = True
        cleaned["injectionSignals"] = signals[:MAX_SIGNALS]
        if len(signals) > MAX_SIGNALS:
            cleaned["injectionSignalsTruncated"] = len(signals) - MAX_SIGNALS
    return cleaned
