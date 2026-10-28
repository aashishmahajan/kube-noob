"""One entry point for anything pasted: ``kube-noob insight`` and the ``kubenoob_insight`` tool.

``recognise`` names what the input is (several kinds at once are normal: events next to a denial next to a manifest)
by rules, with the evidence for each kind. ``insight`` then runs every analyser that applies, each on its own size
budget: diagnosis with reported issues, team memory and policy denials (events, pod status, logs, alerts, build
logs, tickets, questions), the audit with its schema and removed-API checks (manifests), the documentation index
(questions) and the denial explainer. Kinds whose analyser is still to come (Containerfile, SBOM and scanner reports,
packet captures, must-gather paths) are named with what to run today. The answer merges every finding with its
source, the read-only next steps, and what was skipped and why. Rules only: no model, deterministic.
"""

from __future__ import annotations

import functools
import json
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

MAX_TEXT = 2_000_000
ANALYSER_TEXT = 200_000  # characters each text analyser reads (the end of the input, where failures usually are)

KINDS = (
    "alert-payload",
    "events",
    "pod-status",
    "logs",
    "ticket",
    "manifests",
    "helm-chart",
    "policy-denial",
    "build-log",
    "containerfile",
    "sbom",
    "scanner-report",
    "packet-capture",
    "must-gather",
    "question",
)
PENDING = {
    "packet-capture": "packet capture analysis (queue N2) is not built yet; tcpdump text is read as logs",
    "must-gather": "a list of must-gather paths is not the must-gather itself: kube-noob must-gather analyze <dir or "
    ".tar.gz> opens it safely and ranks what is wrong (the MCP tool is queue G5); paste the pod's events and logs "
    "for a diagnosis",
}
UNREAD = {  # recognised, but in a form the vulnerability reader does not take
    "sbom": "only JSON SBOMs are read: export SPDX 2.3 or CycloneDX JSON (syft -o spdx-json, trivy image -f "
    "cyclonedx) and run kube-noob vuln report -r <file>",
    "scanner-report": "scanner tables are not read here: give the JSON (trivy image -f json "
    "--list-all-pkgs, grype -o json) to kube-noob vuln report -r <file>",
}

# Every line pattern starts with [ \t]* (never \s*, which crosses newlines and backtracks quadratically on blank lines)
_EVENT_TABLE = re.compile(
    r"^[ \t]*(?:Type[ \t]+Reason[ \t]+Age[ \t]+From[ \t]+Message|LAST SEEN[ \t]+TYPE[ \t]+REASON[ \t]+OBJECT|"
    r"NAMESPACE[ \t]+LAST SEEN[ \t]+TYPE[ \t]+REASON)",
    re.M,
)
_EVENT_LINE = re.compile(r"^[ \t]*(?:\S+[ \t]+){0,2}(?:Normal|Warning)[ \t]+[A-Z][A-Za-z]+[ \t]+\S+", re.M)
_POD_TABLE = re.compile(r"^(?:NAMESPACE[ \t]+)?NAME[ \t]+READY[ \t]+STATUS[ \t]+RESTARTS[ \t]+AGE\b", re.M)
_POD_ROW = re.compile(
    r"^[ \t]*(?:[a-z0-9][-a-z0-9]*[ \t]+)?[a-z0-9][-a-z0-9.]*[ \t]+\d+/\d+[ \t]+(?:Running|Pending|Completed|"
    r"CrashLoopBackOff|ImagePullBackOff|ErrImagePull|Error|OOMKilled|ContainerCreating|Terminating|Init:[\w/:]+|"
    r"CreateContainerConfigError|Evicted|Unknown)\b",
    re.M,
)
_DESCRIBE_POD = re.compile(r"^(?:Name|Namespace|Node|Status|Containers|Conditions|Controlled By):", re.M)
_CONTAINER_STATE = re.compile(r"(?:Last State|State):\s+(?:Waiting|Terminated|Running)|Reason:\s+[A-Z][A-Za-z]+", re.M)
_LOG_LINE = re.compile(
    r"^[ \t]*(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|[IWEF]\d{4} \d{2}:\d{2}:\d{2}\.\d+|time=\"?\d{4}-|"
    r"level=(?:info|warn|warning|error|fatal|debug)|\{\"(?:level|ts|time|msg)\"|"
    r"[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2})",
    re.M,
)
_STACK = re.compile(r"^(?:Traceback \(most recent call last\):|[ \t]+at [\w.$]+\(|panic: |goroutine \d+ \[)", re.M)
_TICKET = re.compile(
    r"\b(?:[A-Z][A-Z0-9_]{1,15}-\d{1,7}|INC\d{7}|RITM\d{7}|CHG\d{7})\b.{0,200}?(?:Summary|Description|Status|"
    r"short_description|Priority|Assignee|Resolution)\b|\"(?:issues|short_description|fields)\"\s*:|"
    r"^(?:Issue key|Summary|number),",
    re.S | re.M,
)
_DENIAL = re.compile(
    r"admission webhook \".{1,200}\" denied|(?:would )?violate[s]? PodSecurity|"
    r"unable to validate against any security context constraint|exceeded quota|\[denied by |"
    r"ValidatingAdmissionPolicy .{1,120} denied|is forbidden: |"
    r"policy .{1,120} (?:blocked|violation)",
    re.I,
)
_BUILD = re.compile(
    r"^(?:\d{4}-\d{2}-\d{2}T[\d:.]+Z[ \t])?(?:STEP \d+/\d+: |Step \d+/\d+ : |#\d+ \[[\w.-]+(?: \d+/\d+)?\]|"
    r"\[Pipeline\]|##\[(?:error|group|warning)\]|Cloning \"https?://|error building image|Pushing image |"
    r"error: build error|\[step-[\w-]+\]|\[[\w-]+ : [\w-]+\] |Run actions/|Error: Process completed with exit code|"
    r"\[INFO\] BUILD FAILURE|BUILD FAILED|npm ERR! |\[\+\] Building \d)",
    re.M,
)
_DOCKER_INSTRUCTION = re.compile(  # instructions are case-insensitive in Dockerfiles and Containerfiles
    r"^(?:FROM|RUN|COPY|ADD|USER|ENTRYPOINT|CMD|WORKDIR|ENV|ARG|EXPOSE|LABEL|HEALTHCHECK|VOLUME)[ \t]", re.M | re.I
)
_SBOM_TEXT = re.compile(r"^SPDXVersion: SPDX-\d|<bom [^>]{0,200}xmlns=\"http://cyclonedx\.org", re.M)
_ACCESS_LOG = re.compile(r"^\S+ \S+ \S+ \[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] \"", re.M)
_YAML_HEAD = re.compile(r"^(?:---\n)?(?:#.*\n)*apiVersion: [\w./-]+\nkind: [A-Z]\w+\n", re.M)
_TECH = re.compile(
    r"\b(?:pods?|nodes?|deploy\w*|crash\w*|errors?|fail\w*|oom\w*|images?|pull\w*|routes?|ingress\w*|services?|"
    r"namespaces?|pvcs?|volumes?|helm|operators?|clusters?|etcd|upgrad\w*|rbac|forbidden|denied|timeouts?|timed out|"
    r"certificat\w*|x509|dns|network\w*|containers?|kube\w*|kubectl|oc|openshift|rosa|rhacs|stackrox|secrets?|"
    r"configmaps?|probes?|restart\w*|pending|evict\w*|quota|scc|webhooks?|api|tls|memory|cpu|disk|storage|latency|"
    r"[45]\d\d)\b",
    re.I,
)
_ASKED_LINE = re.compile(  # a line of words that asks something, next to a paste
    r"^(?![ \t]*[$#>|{\[])[^\n]{0,240}?\b(?:how|why|what|when|where|which|can|could|should|would|is|are|does|do|did|"
    r"will|has|have|anyone|any idea)\b[^\n]{0,240}\?[ \t]*$",
    re.M | re.I,
)
_CAMEL = re.compile(r"\b[A-Z][a-z]+(?:[A-Z][a-z0-9]*)+\b")
_ASKED_SENTENCE = re.compile(  # "Is there a way to use kubectl to ...?" inside a paragraph
    r"(?i)\b(?:how (?:do|can|to|should)|is there (?:a|any) way|can (?:i|you|we)|is it possible|does anyone|"
    r"what is the (?:best|right|correct) way)\b[^.?!\n]{0,200}\?"
)
_TCPDUMP = re.compile(  # tcpdump (any -t format, interface prefix) and tshark summary lines
    r"^(?:\d{4}-\d{2}-\d{2} )?\d{2}:\d{2}:\d{2}\.\d+[ \t]+(?:\S+[ \t]+(?:In|Out|P|M)[ \t]+)?(?:IP6?|ARP),?[ \t]+"
    r"\S+ > \S+: |^[ \t]*\d+[ \t]+\d+\.\d{6,9}[ \t]+\S+[ \t]+(?:→|->)[ \t]+\S+[ \t]+[A-Z][A-Z0-9v.]{1,10}[ \t]+\d+",
    re.M,
)
_SCANNER_TABLE = re.compile(
    r"Total: \d+ \((?:UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL)|"
    r"^NAME[ \t]+INSTALLED[ \t]+FIXED[- ]IN[ \t]+TYPE[ \t]+VULNERABILITY|"
    r"(?:Library|COMPONENT|PACKAGE)[ \t│|]+(?:Vulnerability|VERSION|INSTALLED)",
    re.M | re.I,
)
_CVE_ROW = re.compile(r"CVE-\d{4}-\d{4,7}.{0,120}?\b(?:CRITICAL|HIGH|MEDIUM|LOW|Important|Moderate|Critical)\b", re.M)
_ALERT_TEXT = re.compile(r"\[FIRING:\d+\]|\[RESOLVED\]|\balertname=\w+|^ALERTS\{alertname=", re.M)
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
SAMPLE = 200_000  # characters from each end of a long paste the line patterns read
_MUST_GATHER = re.compile(
    r"must-gather\.local\.|cluster-scoped-resources/|namespaces/openshift-[\w-]+/pods/|"
    r"^\[must-gather[\w -]*\] (?:OUT|POD) |"
    r"quay-io-openshift-release-dev-ocp-v4-0-art-dev-sha256-",
    re.M,
)
_EVENT_FIELDS = re.compile(
    r"\"type\":\s{0,4}\"(?:Warning|Normal)\"[^{}]{0,400}?\"reason\":\s{0,4}\"[A-Z][A-Za-z]+\"|"
    r"\"reason\":\s{0,4}\"[A-Z][A-Za-z]+\"[^{}]{0,400}?\"type\":\s{0,4}\"(?:Warning|Normal)\""
)
_QUESTION = re.compile(r"^(?:how|why|what|when|where|which|can|could|should|is|are|does|do|will|my|i )\b", re.I)
_WORD = re.compile(r"[A-Za-z]{3}")
_HELM = re.compile(
    r"\{\{-?\s*(?:\.Values|\.Release|include |template |if |range )|^apiVersion: v2\n(?:.*\n){0,6}name: ", re.M
)


@dataclass(frozen=True)
class Kind:
    kind: str
    evidence: str

    def as_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "evidence": self.evidence}


def _json(text: str) -> Any:
    """The JSON document the paste is, or starts with after a line or two of words ("got paged for this:"), read
    up to its end even when log lines follow it."""
    s = text.lstrip()
    if not s.startswith(("{", "[")):
        start = s.find("{", 0, 2000)
        if start < 0 or "\n" not in s[:start]:
            return None
        s = s[start:]
    try:
        return json.JSONDecoder().raw_decode(s)[0]
    except (ValueError, RecursionError):
        return None


def _yaml_docs(text: str) -> list[Any]:
    """The documents, through the audit's guarded loader (size, count, depth and alias budgets); [] if not YAML."""
    if "apiVersion" not in text or "kind" not in text:
        return []
    from kube_noob.errors import ManifestError
    from kube_noob.yamlio import load_documents

    try:
        docs = [d.data for d in load_documents(text)]
    except ManifestError:
        return []
    return docs if all(isinstance(d, dict) for d in docs) else []


_YAMLISH = re.compile(r"^(?:\s|-\s|-$|#|---|\.\.\.|[A-Za-z_][\w./-]*:(?:\s|$))")
_YAML_START = re.compile(r"^(?:apiVersion|kind):\s*\S")
MAX_SEGMENTS = 50


def manifest_segments(text: str) -> list[str]:
    """The Kubernetes YAML inside a mixed paste (events, then a manifest, then a denial): each run of lines that
    starts with ``apiVersion:`` or ``kind:`` at the margin, continues while lines look like YAML, and parses as
    documents that all carry apiVersion and kind. Shrinks a run to its last blank line or ``---`` when the whole run
    does not parse."""
    lines = text.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines) and len(out) < MAX_SEGMENTS:
        if not _YAML_START.match(lines[i]):
            i += 1
            continue
        start = i - 1 if i and lines[i - 1].strip() == "---" else i
        j = i + 1
        while j < len(lines) and (not lines[j].strip() or _YAMLISH.match(lines[j])):
            j += 1
        ends = [j] + [k for k in range(j - 1, i, -1) if not lines[k].strip() or lines[k].strip() == "---"][:20]
        for end in ends:
            chunk = "\n".join(lines[start:end]).strip("\n")
            docs = _yaml_docs(chunk)
            if docs and all("apiVersion" in d and "kind" in d for d in docs):
                out.append(chunk)
                break
        i = j
    return out


def normalise(text: str) -> str:
    """Terminal colour codes and CRLF line ends removed: pastes from kubecolor, Windows terminals and CI logs."""
    return _ANSI.sub("", text.replace("\r\n", "\n").replace("\r", "\n")) if ("\x1b" in text or "\r" in text) else text


def recognise(text: str) -> list[Kind]:
    """Every kind the input looks like, with the evidence; empty for text that is none of them. Structured parses
    read the whole input (each with its own caps); line patterns read the first and last ``SAMPLE`` characters, so
    the time stays linear in the input whatever it holds."""
    text = normalise(text[:MAX_TEXT])
    found: dict[str, str] = {}
    doc = _json(text)
    s = text.lstrip()
    if isinstance(doc, dict):
        if "spdxVersion" in doc or doc.get("bomFormat") == "CycloneDX":
            found["sbom"] = "SPDX or CycloneDX document"
        if ("Results" in doc and "SchemaVersion" in doc) or ("matches" in doc and "descriptor" in doc):
            found["scanner-report"] = "Trivy or Grype report"
        runs = doc.get("runs")
        sarif_schema = "sarif" in str(doc.get("$schema", "")).lower()
        # $schema is optional in SARIF 2.1.0: version "2.1.0" with runs[].tool.driver is enough
        sarif_shape = (
            str(doc.get("version", "")) == "2.1.0"
            and isinstance(runs, list)
            and any(
                isinstance(r, dict) and isinstance(r.get("tool"), dict) and "driver" in r["tool"] for r in runs[:20]
            )
        )
        if "runs" in doc and (sarif_schema or sarif_shape):
            found["scanner-report"] = "SARIF report"
        if isinstance(doc.get("scan"), dict) and isinstance(doc["scan"].get("components"), list):
            found["scanner-report"] = "RHACS image scan"
        if doc.get("kind") in {"EventList", "Event"}:
            found["events"] = f"{doc.get('kind')} JSON"
        if doc.get("kind") == "Pod" and "status" in doc:
            found["pod-status"] = "Pod JSON with status"
        if doc.get("kind") == "Status" and isinstance(doc.get("message"), str):  # what the API server answered
            found["policy-denial" if _DENIAL.search(doc["message"]) else "logs"] = "an API server Status response"
        if "issues" in doc or "fields" in doc or "short_description" in s[:5000]:
            found["ticket"] = "ticket export JSON"
        items = doc.get("items")
        if (
            doc.get("kind") in {"List", "EventList"}
            and isinstance(items, list)
            and items
            and all(isinstance(i, dict) and (i.get("kind") == "Event" or "involvedObject" in i) for i in items[:50])
        ):
            found["events"] = f"{len(items)} events (JSON list)"
    from kube_noob.signals import alertmanager

    if alertmanager.parse(text) is not None or (
        isinstance(doc, (dict, list)) and alertmanager._alerts(doc) is not None
    ):
        found["alert-payload"] = "Alertmanager webhook or API alerts"
    docs = _yaml_docs(text) if not found else []
    whole = bool(docs) and all("apiVersion" in d and "kind" in d for d in docs)
    if not whole and not found:
        docs = [d for seg in manifest_segments(text) for d in _yaml_docs(seg)]
    if docs and all(d.get("kind") == "Status" for d in docs):
        docs = []  # an API response, not a manifest
    if docs and all(d.get("kind") == "Event" for d in docs):
        found.setdefault("events", f"{len(docs)} Event objects")
        docs = []
    if not docs and not found and _YAML_HEAD.search(text[:5000]):
        found["manifests"] = "Kubernetes YAML that does not parse (cut short or mis-indented)"
    if docs and all("apiVersion" in d and "kind" in d for d in docs):
        where = "" if whole else " inside the paste"
        found["manifests"] = (
            f"{len(docs)} Kubernetes document(s){where}: {', '.join(sorted({str(d['kind']) for d in docs}))}"
        )
        if any(d.get("kind") == "Pod" and isinstance(d.get("status"), dict) for d in docs):
            found["pod-status"] = "Pod with status"
        if any(d.get("kind") == "EventList" for d in docs):
            found["events"] = "EventList"
    whole_text = text
    if len(text) > 2 * SAMPLE:
        text = text[:SAMPLE] + "\n" + text[-SAMPLE:]
    if _HELM.search(text):
        found["helm-chart"] = "Helm template or Chart.yaml"
        found.pop("manifests", None)
    if _EVENT_TABLE.search(text) or _EVENT_LINE.search(text):
        found.setdefault("events", "event lines (Normal or Warning with a reason)")
    elif _EVENT_FIELDS.search(text):
        found.setdefault("events", "event fields in JSON (type and reason)")
    if len(_DESCRIBE_POD.findall(text)) >= 3 or _CONTAINER_STATE.search(text):
        found.setdefault("pod-status", "pod status or describe output")
    if _POD_TABLE.search(text) or len(_POD_ROW.findall(text)) >= 2:
        found.setdefault("pod-status", "a get pods table")
    if _ALERT_TEXT.search(text):
        found.setdefault("alert-payload", "alert notification text")
    if _SCANNER_TABLE.search(text) or len(_CVE_ROW.findall(text)) >= 2:
        found.setdefault("scanner-report", "scanner table (Trivy, Grype or roxctl)")
    if len(_LOG_LINE.findall(text)) >= 2 or _STACK.search(text) or len(_ACCESS_LOG.findall(text)) >= 2:
        found["logs"] = "timestamped log lines or a stack trace"
    if _TICKET.search(text[:20_000]):
        found.setdefault("ticket", "ticket key with ticket fields")
    if _DENIAL.search(text):
        found["policy-denial"] = "an admission or authorization denial"
    if _BUILD.search(text):
        found["build-log"] = "build or pipeline steps"
        if not _STACK.search(text):
            found.pop("logs", None)  # CI timestamps make a build log look like logs; it is read as one either way
    if _SBOM_TEXT.search(text):
        found["sbom"] = "SPDX tag-value or CycloneDX XML"
    instructions = _DOCKER_INSTRUCTION.findall(text)
    if len(instructions) >= 2 and re.match(r"(?:[ \t\n]*#.*\n|[ \t\n]*ARG\s.*\n)*[ \t\n]*FROM\s", text, re.I):
        found["containerfile"] = f"{len(instructions)} Containerfile instructions"
    if len(_TCPDUMP.findall(text)) >= 2:
        found["packet-capture"] = "tcpdump text"
    if _MUST_GATHER.search(text):
        found["must-gather"] = "must-gather paths"
    stripped = whole_text.strip()
    one_line = "\n" not in stripped and 3 <= len(stripped) <= 300 and bool(_WORD.search(stripped))
    asked = stripped.endswith("?") or bool(_QUESTION.match(stripped))
    technical = bool(_TECH.search(stripped[:300]) or _CAMEL.search(stripped[:300]))
    # A forum post: a title line that asks, then the body (asked by its title or by a line that asks).
    title = stripped.split("\n", 1)[0].strip()
    posted = (
        not found
        and "\n" in stripped
        and technical
        and (
            title.endswith("?")
            or bool(_QUESTION.match(title))
            or bool(_ASKED_LINE.search(stripped[:3000]))
            or bool(_ASKED_SENTENCE.search(stripped[:1000]))
        )
    )
    if (not found and (asked or (one_line and technical) or posted)) or (
        asked and one_line and set(found) <= {"policy-denial", "ticket"}
    ):
        found["question"] = "a question or symptom in words"
    elif found and _ASKED_LINE.search(stripped[:3000]):
        found["question"] = "a question next to what was pasted"
    keys = _ticket_keys(stripped[:20_000])
    if keys and "ticket" not in found:
        found["ticket"] = f"Red Hat Jira key {keys[0]}"
    return [Kind(k, found[k]) for k in KINDS if k in found]


def recognise_bytes(data: bytes) -> list[Kind]:
    """For a file: packet captures by their magic number, else the text inside."""
    if data[:4] in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}:
        return [Kind("packet-capture", "pcap file")]
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        return [Kind("packet-capture", "pcapng file")]
    if b"\x00" in data[:8192]:
        return []  # some other binary file: nothing to read as text
    return recognise(data.decode("utf-8", errors="replace"))


_SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
BUDGET_SECONDS = 20.0  # each analyser's time budget; one that runs longer is reported as skipped
MAX_TICKETS = 5
ALONE = {
    "diagnose": "kube-noob diagnose -f <file>",
    "search": "kube-noob search '<question>'",
    "audit": "kube-noob audit -f <file>",
    "tickets": "kube-noob ticket <KEY>",
}
GATHER = (
    ("{cli} get pods -n {ns} -o wide", "which pods are not Running or not Ready, and on which node"),
    ("{cli} describe pod <pod> -n {ns}", "the State, Last State and Events sections name the reason"),
    ("{cli} get events -n {ns} --sort-by=.lastTimestamp", "recent warnings in the namespace"),
    ("{cli} logs <pod> -n {ns} --previous --tail=200", "the last run's logs when the container restarted"),
)
GATHER_NOTE = " Nothing here was evidence enough to diagnose: run the steps and paste what they print."
NOT_YET: dict[str, str] = {}


def gather_steps(platform: str | None, namespace: str | None) -> list[dict[str, str]]:
    """Read-only commands that collect the evidence a diagnosis needs, for input that carries none yet."""
    from kube_noob.catalog import OPENSHIFT_FAMILY

    cli = "oc" if platform in OPENSHIFT_FAMILY else "kubectl"
    ns = namespace or "<namespace>"
    return [{"command": c.format(cli=cli, ns=ns), "why": why} for c, why in GATHER]


class _Budget:
    """Runs each analyser in a worker thread and stops waiting after ``BUDGET_SECONDS``. A late analyser's result
    is dropped and the answer says so; the size limits already bound how long any of them can take."""

    def __init__(self, skipped: list[dict[str, str]], ran: list[str]) -> None:
        self.skipped, self.ran = skipped, ran

    def run(self, name: str, fn: Any) -> Any:
        import concurrent.futures

        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"insight-{name}")
        future = pool.submit(fn)
        try:
            out = future.result(timeout=BUDGET_SECONDS)
        except concurrent.futures.TimeoutError:
            self.skipped.append(
                {"kind": name, "why": f"took longer than {BUDGET_SECONDS:g} s; run it alone: {ALONE.get(name, name)}"}
            )
            return None
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        self.ran.append(name)
        return out


def _ticket_keys(text: str) -> list[str]:
    from kube_noob.jira_catalog import DEFAULT_PROJECTS

    projects = "|".join(sorted(DEFAULT_PROJECTS, key=len, reverse=True))
    keys = re.findall(rf"\b(?:{projects})-\d{{1,9}}\b", text[:ANALYSER_TEXT])
    return list(dict.fromkeys(keys))[:MAX_TICKETS]


def _ticket_findings(kit: Any, keys: list[str], version: str | None) -> list[dict[str, Any]]:
    from kube_noob import known_issues as ki
    from kube_noob import toolkit as tk

    out: list[dict[str, Any]] = []
    index = {i.id: i for i in ki.get_index(kit.settings.data_dir).issues}
    for key in keys:
        t = kit.ticket(tk.TicketIn(key=key, version=version))
        if t.get("found"):
            out.append(
                {
                    "source": "ticket",
                    "id": key,
                    "title": t.get("title"),
                    "verdict": t.get("verdict") or t.get("status"),
                    "url": t.get("url"),
                    "rank": 3,
                }
            )
        elif key in index:
            issue = index[key]
            out.append(
                {
                    "source": "reported-issue",
                    "id": key,
                    "title": issue.summary,
                    "verdict": issue.status(version),
                    "url": issue.url,
                    "rank": 3,
                }
            )
        else:
            out.append(
                {
                    "source": "ticket",
                    "id": key,
                    "title": "not in the local copy or the release notes",
                    "verdict": t.get("note"),
                    "rank": 40,
                }
            )
    return out


def _vulnerabilities(kit: Any, text: str) -> dict[str, Any] | str:
    from pydantic import ValidationError

    from kube_noob import toolkit as tk

    try:
        return dict(kit.vuln_report(tk.VulnReportIn(reports=[text[: tk.MAX_SCAN_REPORT]], top=10)))
    except (ValueError, ValidationError) as exc:
        return f"not read: {str(exc).splitlines()[0][:300]}"


def _code(kit: Any, text: str) -> dict[str, Any] | str:
    from pydantic import ValidationError

    from kube_noob import toolkit as tk

    try:
        return dict(kit.code_report(tk.CodeReportIn(sarif=[text[: tk.MAX_SCAN_REPORT]], top=10)))
    except (ValueError, ValidationError) as exc:
        return f"not read: {str(exc).splitlines()[0][:300]}"


def _containerfile(kit: Any, text: str) -> dict[str, Any] | str:
    from kube_noob import toolkit as tk

    try:
        return dict(kit.containerfile_audit(tk.ContainerfileIn(containerfile=text[: tk.MAX_MANIFEST_CHARS])))
    except ValueError as exc:
        return f"not audited: {str(exc).splitlines()[0][:300]}"


# A document is offered for a pasted post only when it shares at least this many specific words with it (base forms,
# not everyday English or everyday Kubernetes words, not version numbers): measured on 25,292 community questions
# (scripts/eval_questions.py), documents sharing one incidental word answered almost none of them. A one-line question
# typed to kube-noob needs one shared word that is not everyday English ("why does my pod stay Pending?" -> pending).
MIN_DOC_TERMS = 2
_STOP = frozenset(
    """
    the and for with from that this these those there their they them what when where which while does doing done
    have having would could should will shall about into onto your yours just only also some such each other more
    most than then very
    """.split()  # noqa: SIM905 - a word list reads better as text
)


_ROSA_ONLY = frozenset({"rosa-classic", "rosa-hcp"})
# Products with their own documentation that kube-noob does not carry. A question that names one is about it: a
# document that never mentions that product does not answer it, however many Kubernetes words they share (measured on
# the community-questions eval: Istio, Argo CD and Trivy questions drew Ingress, scheduling and RHACS documents).
_OTHER_TOOLS = re.compile(
    r"(?i)\b(istio|argo ?cd|argo-cd|argocd|argo workflows|trivy|karpenter|flux ?cd|fluxcd|flux2|flux|helmrelease|"
    r"helm-controller|chart\.js|chartjs|aws lambda|lambda function|terraform|talos|"
    r"rancher|rke2|k3s|microk8s|minikube|kind cluster|docker desktop|docker compose|docker-compose|podman|"
    r"traefik|cilium|calico|envoy|keda|vault|jenkins|gitlab|github actions|tekton|skaffold|helmfile|metallb|"
    r"cert-manager|external-secrets|crossplane|longhorn|openebs|velero|knative|linkerd|kong|haproxy|"
    r"spring boot|django|laravel|wordpress|grafana|loki)\b"
)


class _DocFit:
    """Whether a knowledge doc may answer this text, beyond shared words. With no platform given, a doc written only
    for OpenShift or ROSA needs the text to say it is OpenShift or ROSA (the playbooks' rule, G83); with a platform
    given, the doc must cover it. A doc's ``requires`` groups each need one of their words in the text, and a text
    that names another product (Istio, Argo CD, Trivy...) is answered only by a doc that mentions it."""

    def __init__(self, text: str, platform: str | None) -> None:
        self.platform = platform
        self._text = text
        self._ctx: tuple[bool, bool] | None = None
        self.tools = {re.sub(r"[\s-]", "", m.lower()) for m in _OTHER_TOOLS.findall(text[:2_000])}

    def _context(self) -> tuple[bool, bool]:
        if self._ctx is None:
            from kube_noob.debug.diagnose import _ROSA_CONTEXT
            from kube_noob.known_issues import openshift_context

            self._ctx = (openshift_context(self._text), bool(_ROSA_CONTEXT.search(self._text[:200_000])))
        return self._ctx

    def __call__(self, chunk: Any, words: set[str]) -> bool:
        if chunk is None:
            return True
        extra = getattr(chunk, "extra", None) or {}
        plats = {str(p) for p in extra.get("platforms") or []}
        if plats and self.platform and self.platform not in plats:
            return False
        if plats and not self.platform and "kubernetes" not in plats:
            openshift, rosa = self._context()
            if not (rosa if plats <= _ROSA_ONLY else openshift or rosa):
                return False
        if self.tools:
            body = re.sub(r"[\s-]", "", f"{getattr(chunk, 'title', '')} {getattr(chunk, 'text', '')}".lower())
            if not any(t in body for t in self.tools):
                return False  # the question is about a product this document never mentions
        return all(any(w in words for w in group) for group in extra.get("requires") or [])


def _closest(options: list[str], text: str, hint: str = "") -> str:
    """The option that shares the most specific words with ``text``, then with ``hint`` at half weight (the first on
    a tie): a playbook lists every cause and fix it knows, and the finding should show the one this input points at.
    Each shared word counts by how rare it is across all playbook text ("minikube" says much, "pull" little)."""
    if not options:
        return ""
    df = _playbook_word_counts()
    want = _specific_terms(text, kubernetes_words=True)
    also = _specific_terms(hint, kubernetes_words=True) - want if hint else set()

    def score(option: str) -> float:
        ts = _specific_terms(option, kubernetes_words=True)
        return sum(1.0 / df.get(t, 1) for t in want & ts) + sum(0.5 / df.get(t, 1) for t in also & ts)

    scores = [score(o) for o in options]
    return options[max(range(len(options)), key=lambda n: (scores[n], -n))]


@functools.lru_cache(maxsize=1)
def _playbook_word_counts() -> dict[str, int]:
    """In how many playbook causes, checks and fixes each specific word appears."""
    from kube_noob.debug.playbooks import PLAYBOOKS

    counts: Counter[str] = Counter()
    for pb in PLAYBOOKS:
        for line in (*pb.root_causes, *pb.checks, *pb.fixes):
            counts.update(_specific_terms(line, kubernetes_words=True))
    return dict(counts)


def _specific_terms(text: str, *, kubernetes_words: bool = False) -> set[str]:
    """Words of ``text`` in base form that carry meaning: not stop words or everyday English and, unless
    ``kubernetes_words``, not everyday Kubernetes words either (pod, node, error, pending)."""
    from kube_noob.knowledge.store import tokenize
    from kube_noob.known_issues import EVERYDAY_WORDS, _forms
    from kube_noob.tickets import GENERIC_WORDS

    out: set[str] = set()
    for t in tokenize(text[:20_000]):
        if len(t) <= 3 or not any(ch.isalpha() for ch in t):
            continue
        forms = _forms(t)
        if any(f in _STOP or f in EVERYDAY_WORDS or (not kubernetes_words and f in GENERIC_WORDS) for f in forms):
            continue
        out.add(min(forms, key=len))
    return out


def insight(kit: Any, text: str, platform: str | None = None, version: str | None = None) -> dict[str, Any]:
    """Recognise the input, run every analyser that applies (each on its own size and time budget) and merge
    what they found into one answer."""
    from kube_noob import toolkit as tk

    text = text[:MAX_TEXT]
    kinds = recognise(text)
    names = {k.kind for k in kinds}
    findings: list[dict[str, Any]] = []
    steps: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    ran: list[str] = []
    budget = _Budget(skipped, ran)
    tail = text[-ANALYSER_TEXT:]
    textual = {"alert-payload", "events", "pod-status", "logs", "ticket", "build-log", "question", "policy-denial"}
    context: dict[str, Any] = {}
    signals: list[Any] = []

    doc = _json(text)
    if isinstance(doc, dict) and doc.get("kind") == "Status" and isinstance(doc.get("message"), str):
        tail = f"{doc['message']}\n{tail}"  # the denial as the API server wrote it, quotes unescaped
    if names & textual or not names:
        d = budget.run(
            "diagnose", lambda: kit.diagnose(tk.DiagnoseIn(text=tail, platform=platform, version=version, limit=5))
        )
        d = d or {}
        signals = list(d.get("signals") or [])
        for i, x in enumerate(d.get("diagnoses", [])[:3]):
            likely = _closest(x.get("rootCauses") or [], tail)
            findings.append(
                {
                    "source": "playbook",
                    "id": x["id"],
                    "title": x["title"],
                    "confidence": x["confidence"],
                    "cause": likely,
                    "fix": _closest([c.get("change", "") for c in x.get("proposedChanges") or []], tail, likely),
                    "rank": 10 + i,
                }
            )
            if i == 0:
                steps += x.get("readOnlyNextSteps", [])[:6]
        for m in d.get("knownIssues", [])[:3]:
            findings.append(
                {
                    "source": "reported-issue",
                    "id": m.get("id"),
                    "title": m.get("title") or m.get("summary"),
                    "verdict": m.get("verdict") or m.get("status"),
                    "url": m.get("url"),
                    "rank": 20,
                }
            )
        for m in d.get("memory", [])[:3]:
            findings.append(
                {
                    "source": "team-memory",
                    "id": m.get("id"),
                    "title": m.get("symptom"),
                    "cite": m.get("citation"),
                    "rank": 5,
                }
            )
        for den in d.get("policyDenials", [])[:3]:
            findings.append(
                {
                    "source": "policy",
                    "id": "/".join(str(x) for x in (den.get("engine"), den.get("policy"), den.get("rule")) if x),
                    "title": den.get("meaning") or den.get("message"),
                    # every change the requester can make; exceptions and new permissions stay with the policy owner
                    "fix": " ".join(
                        str(c.get("change", ""))
                        for c in (den.get("proposedChanges") or [])[:4]
                        if not c.get("needsPolicyOwner")
                    )[:800],
                    "rank": 1,
                }
            )
            steps = [*den.get("readOnlyNextSteps", [])[:3], *steps]
        context = d.get("context") or {}
    if "build-log" in names:
        b = budget.run(
            "build",
            lambda: kit.build_diagnose(
                tk.BuildDiagnoseIn(log=text[-tk.MAX_BUILD_LOG :], platform=platform, version=version)
            ),
        )
        if b:
            cause = b.get("cause") or {}
            step = b.get("failingStep") or {}
            findings.append(
                {
                    "source": "build",
                    "id": cause.get("class") or "build-failure",
                    "title": f"{b['system']}: step {step.get('name', '?')} failed"
                    + (f": {cause['meaning']}" if cause else ""),
                    "confidence": cause.get("confidence"),
                    "evidence": [e["text"] for e in b.get("evidence", [])[:2]],
                    "fix": b.get("fix", [])[:3],
                    "rank": 2,
                }
            )
            for m in b.get("knownIssues", [])[:2]:
                if m.get("id") not in {f.get("id") for f in findings}:
                    findings.append(
                        {
                            "source": "reported-issue",
                            "id": m.get("id"),
                            "title": m.get("title") or m.get("summary"),
                            "verdict": m.get("verdict") or m.get("status"),
                            "url": m.get("url"),
                            "rank": 20,
                        }
                    )
            steps = [{"command": c, "why": "read the failed run"} for c in b.get("readOnlyNextSteps", [])[:3]] + steps
    if "containerfile" in names:
        rep = budget.run(
            "containerfile",
            lambda: _containerfile(kit, text),
        )
        if isinstance(rep, str):
            ran.remove("containerfile")
            skipped.append({"kind": "containerfile", "why": rep})
        elif rep:
            for f in rep["findings"][:10]:
                findings.append(
                    {
                        "source": "rule",
                        "id": f["ruleId"],
                        "title": f["message"],
                        "severity": f["severity"],
                        "resource": f"Containerfile line {f['line']}" if f.get("line") else "Containerfile",
                        "rank": 15 - _SEVERITY.get(str(f.get("severity")), 0),
                    }
                )
    vuln_kinds = names & {"sbom", "scanner-report"}
    unread = set(vuln_kinds)
    is_sarif = isinstance(doc, dict) and isinstance(doc.get("runs"), list) and "Results" not in doc
    if "scanner-report" in vuln_kinds and is_sarif:
        vuln_kinds = vuln_kinds - {"scanner-report"}
        unread.discard("scanner-report")
        rep_code = budget.run("code", lambda: _code(kit, text))
        if isinstance(rep_code, str):
            ran.remove("code")
            skipped.append({"kind": "scanner-report", "why": rep_code})
        elif rep_code:
            for r in rep_code["ranking"]["ranked"][:10]:
                f = r["finding"]
                loc = f["location"]
                findings.append(
                    {
                        "source": "code",
                        "id": f["cwe"][0] if f["cwe"] else f["sources"][0]["ruleId"],
                        "title": f"{f['title'][:120]} ({', '.join(f['tools'])})",
                        "severity": f["severity"],
                        "resource": f"{loc['path']}:{loc.get('line', '?')}",
                        "rank": 12 - _SEVERITY.get(str(f["severity"]), 0),
                    }
                )
            c = rep_code["counts"]
            context["code"] = {k: c[k] for k in ("results", "findings", "excluded", "quality")}
    if vuln_kinds and isinstance(doc, dict):
        rep = budget.run("vulnerabilities", lambda: _vulnerabilities(kit, text))
        if isinstance(rep, str):
            ran.remove("vulnerabilities")
            for k in sorted(vuln_kinds):
                skipped.append({"kind": k, "why": rep})
            unread = set()
        elif rep:
            unread = set()
            for r in rep["ranking"]["ranked"][:10]:
                f = r["finding"]
                findings.append(
                    {
                        "source": "vulnerability",
                        "id": f["cve"],
                        "title": f"{f['package']['name']} {f['package']['version']}: "
                        + (f"fixed in {f['fixVersion']}" if f["fixVersion"] else "no fix yet")
                        + (" (known exploited)" if f["knownExploited"] else ""),
                        "severity": {"negligible": "info", "unknown": "medium"}.get(f["severity"], f["severity"]),
                        "resource": r["image"],
                        "rank": 12 - _SEVERITY.get(str(f["severity"]), 0) - (2 if f["knownExploited"] else 0),
                    }
                )
            c = rep["counts"]
            context["vulnerabilities"] = {k: c[k] for k in ("reported", "excludedByVex", "findings", "fixable")}
    for k in sorted(unread):
        skipped.append({"kind": k, "why": UNREAD[k]})
    keys = _ticket_keys(text)
    if keys:
        known = {f["id"] for f in findings}
        fresh = [k for k in keys if k not in known]
        if fresh:
            findings += budget.run("tickets", lambda: _ticket_findings(kit, fresh, version)) or []
    if "question" in names:
        from kube_noob.knowledge.store import tokenize
        from kube_noob.known_issues import _forms

        query = text.strip()[:500]
        res = budget.run("search", lambda: kit.search(tk.SearchIn(query=query, limit=8)))
        seen: set[str] = set()
        typed = "\n" not in query  # a question typed to kube-noob, not a pasted post
        asked = _specific_terms(query, kubernetes_words=typed)
        words = {f for t in tokenize(query) for f in _forms(t)}
        need = MIN_DOC_TERMS
        store = kit.store()
        if typed:
            from kube_noob.known_issues import EVERYDAY_WORDS

            unknown = [
                t
                for t in tokenize(query)
                if len(t) > 3
                and t.isalpha()
                and not any(f in _STOP or f in EVERYDAY_WORDS for f in _forms(t))
                and all(store.doc_frequency(f) == 0 for f in _forms(t))  # "quotas" is known as "quota"
            ]
            if unknown:
                # It names something the knowledge has never seen ("Talos", "batchMaxDuration", "Trivy"): it is
                # about that, and a document sharing two of its other words ("node", "pool") is not.
                need = MIN_DOC_TERMS + 1
            elif len(asked) <= 2:
                need = 1  # a short question needs one shared word
        fits = _DocFit(text, platform)
        for h in (res or {}).get("results", []):
            doc = h["chunkId"].split("#", 1)[0]
            if doc in seen or len(seen) == 3:
                continue
            chunk = store.get(h["chunkId"])
            body = chunk.text if chunk is not None else h.get("text") or ""  # the whole chunk: search results are cut
            shared = asked & _specific_terms(f"{h.get('title') or ''} {body}", kubernetes_words=typed)
            if len(shared) < need:  # a document that shares one incidental word with a post does not answer it
                continue
            if not fits(chunk, words):
                continue
            seen.add(doc)
            findings.append(
                {
                    "source": "doc",
                    "id": h["chunkId"],
                    "title": h.get("title"),
                    "sharedTerms": sorted(shared)[:6],
                    "rank": 30 + len(seen),
                }
            )
    if "manifests" in names:
        from kube_noob.errors import ManifestError

        docs = _yaml_docs(text)
        manifests = text if docs and all("apiVersion" in x and "kind" in x for x in docs) else None
        manifests = manifests or "\n---\n".join(manifest_segments(text)) or text  # YAML that does not parse: the
        # audit's loader says why
        where = {k: v for k, v in (("platform", platform), ("version", version)) if v}

        def audit() -> Any:
            try:
                return kit.audit(tk.AuditIn(manifests=manifests[: tk.MAX_MANIFEST_CHARS], **where))
            except (ManifestError, ValueError) as exc:
                return ManifestError(str(exc).splitlines()[0][:300])

        rep = budget.run("audit", audit)
        if isinstance(rep, ManifestError):
            ran.remove("audit")
            skipped.append({"kind": "manifests", "why": f"not audited: {rep}"})
            rep = None
        ordered = sorted((rep or {}).get("findings", []), key=lambda f: -_SEVERITY.get(str(f.get("severity")), 0))
        for f in ordered[:10]:
            findings.append(
                {
                    "source": "rule",
                    "id": f["ruleId"],
                    "title": f["message"],
                    "severity": f["severity"],
                    "resource": f.get("resource"),
                    "rank": 15 - _SEVERITY.get(str(f.get("severity")), 0),
                }
            )
        if re.search(r"^kind:\s*NetworkPolicy\s*$", manifests, re.M):
            skipped.append(
                {
                    "kind": "network-policy",
                    "why": "reachability needs a source, a destination and a port: kube-noob policy reach --from "
                    "<ns>/<workload> --to <ns>/<workload> --port <port> -f <file>",
                }
            )
    if "helm-chart" in names:
        skipped.append(
            {
                "kind": "helm-chart",
                "why": "templates are audited after rendering: helm template <release> <chart> | kube-noob audit -f -",
            }
        )
    for k in sorted(names & (set(PENDING) | set(NOT_YET))):
        skipped.append({"kind": k, "why": PENDING.get(k) or NOT_YET[k]})
    evidence = {
        "playbook",
        "policy",
        "rule",
        "ticket",
        "reported-issue",
        "team-memory",
        "build",
        "vulnerability",
        "code",
    }
    if not steps and not any(f["source"] in evidence for f in findings) and (names & textual or not names):
        ns = context.get("namespace")
        steps = gather_steps(platform, ns if isinstance(ns, str) else None)
        ran.append("gather")
    findings.sort(key=lambda f: (f["rank"], str(f.get("id"))))
    for f in findings:
        f.pop("rank", None)
    return {
        "kinds": [k.as_dict() for k in kinds] or [{"kind": "unknown", "evidence": "nothing recognised"}],
        "ran": ran,
        "findings": findings,
        "signals": signals,
        "readOnlyNextSteps": steps[:8],
        "context": context,
        "skipped": skipped,
        "approach": "Read-only first: every step listed here only reads; changes come from the playbook or rule "
        "with a person's approval." + (GATHER_NOTE if "gather" in ran else ""),
    }
