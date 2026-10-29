"""Build failure diagnosis (requirements R4.1): which step failed, the error line and its template, the cause class,
and the fix, for OpenShift BuildConfig builds, Tekton (``tkn``), GitHub Actions and Jenkins logs.

The log formats are the ones each system writes (sources checked 2026-10-28):

- GitHub Actions: each step opens with ``##[group]Run <name>``; a failed step ends with ``##[error]Process completed
  with exit code N.``, a step timeout with ``##[error]The action '<name>' has timed out after N minutes.``
  (actions/runner ``Handlers/ScriptHandler.cs``, ``StepsRunner.cs``). Downloaded logs prefix every line with a UTC
  timestamp.
- Jenkins Pipeline: ``[Pipeline] { (<stage>)`` opens a stage, ``Stage "<name>" skipped due to earlier failure(s)``
  marks one that did not run, ``ERROR: script returned exit code N`` (workflow-durable-task-step) and ``Finished:
  FAILURE`` (core ``BuildListener``) close the run; ``Cancelling nested steps due to timeout`` and ``Timeout has been
  exceeded`` come from the ``timeout`` step (workflow-basic-steps).
- Tekton: ``tkn`` prefixes each line with ``[<task> : <step>]`` (tektoncd/cli ``pkg/log/writer.go``); a failed task
  reads ``task <task> failed: "step-<step>" exited with code N`` (tektoncd/pipeline ``pkg/pod/status.go``,
  ``tkn`` ``task_reader.go``); a timeout ``TaskRun "<run>" failed to finish within "<d>"``.
- OpenShift builds: ``Cloning "<url>" ...``, buildah's ``STEP n/m: <instruction>`` (``[s/t] STEP`` in multi-stage
  builds), ``Pushing image <ref> ...`` and ``error: build error: <cause>`` (openshift/builder, containers/buildah
  ``building at STEP "<instruction>": ...``).

Tool error lines (npm, pip, Maven, Gradle, Go, compilers, test runners, registries, the API server's quota and SCC
messages) decide the cause. Output is deterministic and bounded; secrets in quoted lines are redacted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from kube_noob.debug.cluster import redact_text
from kube_noob.signals.core import normalise_error

MAX_INPUT = 5_000_000
MAX_LINES = 100_000
MAX_LINE = 4_000
MAX_EVIDENCE = 5
EXCERPT = 300

SYSTEMS = ("github-actions", "jenkins", "tekton", "openshift-build", "unknown")
CLASSES: dict[str, str] = {
    "dependency-fetch": "a dependency, base image or source could not be downloaded or resolved",
    "compile": "the code did not compile or bundle",
    "test": "tests failed",
    "image-push": "the image could not be pushed to the registry",
    "registry-auth": "a registry or Git host refused the credentials",
    "quota": "a quota or limit stopped it: ResourceQuota or LimitRange, node capacity, a registry rate limit, disk "
    "space",
    "timeout": "the job, step or build ran past its time limit",
    "out-of-memory": "a process ran out of memory or was OOM-killed",
    "permissions": "file permissions, the user the build runs as, an SCC or RBAC refused it",
}

_ANSI = re.compile(r"\x1b\[[0-9;?]{0,20}[A-Za-z]|\x1b\][^\x07]{0,200}\x07")
_GHA_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z ")
_JENKINS_TIME = re.compile(r"^(?:\[\d{4}-\d{2}-\d{2}T[\d:.]{8,20}Z\] |\d{2}:\d{2}:\d{2}(?:\.\d{1,3})? {1,2})")

# -- step structure ---------------------------------------------------------------------------------------------
_GHA_STEP = re.compile(r"^##\[group\]Run (.{1,300})$")
_GHA_MARK = re.compile(r"^##\[(?:group|endgroup|error|warning|notice|debug)\]")
_GHA_FATAL = re.compile(
    r"^##\[error\](?:Process completed with exit code (\d{1,3})\.|The action '.{1,300}' has timed out after \d{1,5} "
    r"minutes\.|The job running on runner .{1,300} has exceeded the maximum execution time of \d{1,6} minutes\.|"
    r"The operation was canceled\.)"
)
_JENKINS_STAGE = re.compile(r"^\[Pipeline\] \{ \((.{1,200})\)$")
_JENKINS_SKIPPED = re.compile(r'^Stage "(.{1,200})" skipped due to ')
_JENKINS_MARK = re.compile(
    r"^(?:\[Pipeline\] |Started by |Finished: (?:SUCCESS|FAILURE|UNSTABLE|ABORTED)$|"
    r"Build step '.{1,100}' marked build as failure$)"
)
_JENKINS_FREESTYLE = re.compile(r"^\[[\w.@-]{1,200}\] \$ (.{1,300})$")
_JENKINS_FREESTYLE_FAIL = re.compile(r"^Build step '(.{1,100})' marked build as failure$")
_JENKINS_EXIT = re.compile(r"^ERROR: script returned exit code (\d{1,3})$")
_JENKINS_END = re.compile(r"^\[Pipeline\] End of Pipeline$")
_TEKTON_PREFIX = re.compile(r"^\[([a-z0-9][a-z0-9-]{0,62}) : ([a-z0-9][a-z0-9-]{0,62})\] ?(.*)$")
_TEKTON_FAILED = re.compile(
    r"^(?:Error: )?task ([a-z0-9][a-z0-9-]{0,62}) failed: (?:\"step-([a-z0-9][a-z0-9-]{0,62})\" exited (?:with code "
    r"(\d{1,3})|because the step exceeded)|.{0,300})"
)
_TEKTON_EXITED = re.compile(
    r'"step-([a-z0-9][a-z0-9-]{0,62})" exited (?:with code (\d{1,3})|because the step exceeded)'
)
_OCP_CLONE = re.compile(r'^Cloning "(?:https?|ssh|git)://')
_OCP_STEP = re.compile(r"^(?:\[\d{1,3}/\d{1,3}\] )?STEP \d{1,4}(?:/\d{1,4})?: (.{1,300})$")
_OCP_PUSH = re.compile(r"^Pushing image .{1,400} \.\.\.$")
_OCP_ERROR = re.compile(r"^error: build error: (.{0,2000})$")
_OCP_AT_STEP = re.compile(r'building at STEP "(.{1,300}?)": ')

# -- causes: (class, weight, pattern) ---------------------------------------------------------------------------
# Weights: 5 says the cause outright, 3-4 is strong, 1-2 needs company. Every pattern is bounded (no nested
# quantifiers, explicit lengths), so a hostile line cannot make matching slow.
_P: tuple[tuple[str, int, str], ...] = (
    # timeout: the CI system's own limit
    ("timeout", 6, r"^##\[error\]The action '.{1,300}' has timed out after \d{1,5} minutes"),
    ("timeout", 6, r"has exceeded the maximum execution time of \d{1,6} minutes"),
    ("timeout", 6, r"^Cancelling nested steps due to timeout$"),
    ("timeout", 6, r"^Timeout has been exceeded$"),
    ("timeout", 6, r'failed to finish within "'),
    ("timeout", 6, r"exited because the step exceeded the specified timeout limit"),
    ("timeout", 6, r"Pod was active on the node longer than the specified deadline"),
    ("timeout", 3, r"\bDeadlineExceeded\b"),
    ("timeout", 1, r"^##\[error\]The operation was canceled\."),
    # out of memory
    ("out-of-memory", 6, r"\bOOMKilled\b|\bOutOfMemoryKilled\b"),
    ("out-of-memory", 6, r"JavaScript heap out of memory|Reached heap limit Allocation failed"),
    ("out-of-memory", 6, r"java\.lang\.OutOfMemoryError|GC overhead limit exceeded"),
    ("out-of-memory", 6, r"fatal error: runtime: out of memory|Killed signal terminated program"),
    ("out-of-memory", 4, r"Expiring Daemon because JVM heap space is exhausted|virtual memory exhausted"),
    ("out-of-memory", 3, r"\bMemoryError\b|[Cc]annot allocate memory"),
    ("out-of-memory", 3, r"exit code 137\b|exited with code 137\b|returned exit code 137$"),
    ("out-of-memory", 2, r"(?:^|\s)Killed(?:\s{1,40}\S.{0,200})?$"),
    # quota and limits
    ("quota", 6, r"exceeded quota: |failed quota: "),
    ("quota", 5, r"ExceededResourceQuota|TaskRun Pod exceeded available resources"),
    ("quota", 5, r"maximum (?:cpu|memory|ephemeral-storage) usage per (?:Container|Pod) is "),
    ("quota", 4, r"must specify (?:limits|requests)\.(?:cpu|memory)"),
    ("quota", 5, r"\btoomanyrequests\b|You have reached your pull rate limit"),
    ("quota", 3, r"(?i)\bAPI rate limit exceeded\b|\brate limit exceeded\b"),
    ("quota", 5, r"[Nn]o space left on device"),
    ("quota", 3, r"\b\d{1,5} Insufficient (?:cpu|memory)\b"),
    # registry and Git authentication
    (
        "registry-auth",
        6,
        r"unauthorized: (?:authentication required|incorrect username or password|access to the "
        r"requested resource is not authorized)",
    ),
    ("registry-auth", 6, r"denied: requested access to the resource is denied|pull access denied for "),
    ("registry-auth", 5, r"npm (?:ERR!|error) code E40[13]\b|ReasonPhrase: ?(?:Unauthorized|Forbidden)"),
    ("registry-auth", 6, r"status code: 40[13], reason phrase: |Not authorized , ReasonPhrase|401 Unauthorized"),
    (
        "registry-auth",
        6,
        r'failed to fetch requested repository ".{1,400}" with provided credentials|unable to '
        r"retrieve auth token",
    ),
    (
        "registry-auth",
        5,
        r"fatal: Authentication failed for |fatal: could not read Username for |Permission denied "
        r"\(publickey",
    ),
    ("registry-auth", 4, r"\b40[13] Client Error: (?:Unauthorized|Forbidden)\b|HTTP error 40[13]\b"),
    ("registry-auth", 3, r"\bauthentication required\b|\binvalid username/password\b"),
    ("registry-auth", 2, r"\bunauthorized\b"),
    # image push
    ("image-push", 4, r"Failed to push image|[Ee]rror pushing image|[Ee]rror: pushing image"),
    (
        "image-push",
        4,
        r"writing blob: |error uploading layer|blob upload (?:unknown|invalid)|manifest blob unknown|"
        r"manifest invalid",
    ),
    ("image-push", 3, r"received unexpected HTTP status: 5\d\d|name unknown: |unknown blob"),
    ("image-push", 2, r"x509: certificate signed by unknown authority"),
    # permissions, SCC, RBAC
    ("permissions", 6, r"unable to validate against any security context constraint"),
    ("permissions", 6, r'is forbidden: User "[^"]{1,300}" cannot '),
    ("permissions", 6, r'cannot set up namespace using "[^"]{0,100}newuidmap"|insufficient UIDs or GIDs available'),
    ("permissions", 4, r"EACCES: permission denied|[Pp]ermission denied$|: [Pp]ermission denied\b"),
    ("permissions", 3, r"[Oo]peration not permitted|Read-only file system"),
    ("permissions", 3, r"sudo: .{0,60}(?:a terminal is required|no tty present|not found)|must be run as root"),
    # dependency fetch (packages, base images, sources)
    (
        "dependency-fetch",
        6,
        r"Could not find a version that satisfies the requirement|No matching distribution "
        r"found for",
    ),
    (
        "dependency-fetch",
        6,
        r"Could not resolve dependencies for project|Could not find artifact |Non-resolvable "
        r"parent POM",
    ),
    ("dependency-fetch", 6, r"Could not resolve all (?:files|dependencies|artifacts) for configuration"),
    (
        "dependency-fetch",
        5,
        r"npm (?:ERR!|error) code (?:E404|ETIMEDOUT|ECONNRESET|ENOTFOUND|EAI_AGAIN|ECONNREFUSED|"
        r"ETARGET|ERESOLVE)\b|npm (?:ERR!|error) 404\b|No matching version found for ",
    ),
    ("dependency-fetch", 5, r"Could not transfer artifact |Failed to read artifact descriptor|ResolutionImpossible"),
    ("dependency-fetch", 5, r"^go: .{1,300}: reading .{1,400}: 404 Not Found|unrecognized import path"),
    ("dependency-fetch", 5, r"Failed to download metadata for repo|No match for argument: |Unable to find a match"),
    (
        "dependency-fetch",
        5,
        r"Unable to locate package |has no installation candidate|ERROR: unable to select "
        r"packages",
    ),
    (
        "dependency-fetch",
        5,
        r"NU1101: Unable to find package|Unable to load the service index for source|Couldn't "
        r"find any versions for ",
    ),
    ("dependency-fetch", 5, r"error: failed to fetch requested repository|fatal: repository '.{1,400}' not found"),
    ("dependency-fetch", 4, r"(?:initializing source|creating build container).{0,300}(?:manifest unknown|not found)"),
    (
        "dependency-fetch",
        4,
        r"Temporary failure resolving |Failed to fetch https?://|Could not resolve host|Temporary "
        r"failure in name resolution",
    ),
    ("dependency-fetch", 3, r"fatal: unable to access '|Could not read from remote repository|Curl error \(\d{1,3}\)"),
    (
        "dependency-fetch",
        3,
        r"SSL: CERTIFICATE_VERIFY_FAILED|unable to get local issuer certificate|self[- ]signed "
        r"certificate in certificate chain|SELF_SIGNED_CERT_IN_CHAIN|UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
    ),
    (
        "dependency-fetch",
        2,
        r"dial tcp: lookup .{1,300}: (?:no such host|i/o timeout)|Failed to establish a new "
        r"connection|Connection timed out|TLS handshake timeout",
    ),
    ("dependency-fetch", 2, r"x509: certificate signed by unknown authority|\bmanifest unknown\b"),
    # compile
    ("compile", 6, r"COMPILATION ERROR|Compilation failed; see the compiler error output|error: could not compile "),
    ("compile", 4, r"Execution failed for task ':[\w:-]{0,100}compile[\w-]{0,40}'"),
    (
        "compile",
        5,
        r"Compilation failure|error: cannot find symbol|error TS\d{4}: |error\[E\d{4}\]|Failed to "
        r"compile\.?$",
    ),
    ("compile", 5, r"Module not found: Error: Can't resolve |undefined reference to "),
    ("compile", 4, r"\.java:\[\d{1,6},\d{1,4}\] |^e: .{1,300}\.kts?:"),
    (
        "compile",
        4,
        r"^[\w./-]{1,300}\.(?:c|cc|cpp|cxx|h|hpp|go|rs|swift|java|scala|ts|tsx|jsx?):\d{1,6}(?::\d{1,4})?:"
        r" (?:fatal )?error",
    ),
    ("compile", 3, r"^[\w./-]{1,300}\.go:\d{1,6}:\d{1,4}: (?:undefined: |cannot use |syntax error)"),
    ("compile", 3, r"make(?:\[\d{1,3}\])?: \*\*\* \[.{1,300}\] Error \d{1,3}|^ERROR in \./|SyntaxError: "),
    # test
    ("test", 6, r"Tests run: \d{1,7}, Failures: [1-9]\d{0,6}|Tests run: \d{1,7}, Failures: \d{1,7}, Errors: [1-9]"),
    ("test", 6, r"There are test failures|There were failing tests|Execution failed for task ':[\w:-]{0,100}test'"),
    (
        "test",
        6,
        r"^=+ .{0,120}\b\d{1,6} failed\b|^FAILED [\w/.\[\]-]{1,300}::|Tests:\s{1,20}\d{1,6} failed|Test "
        r"Suites: \d{1,6} failed",
    ),
    ("test", 6, r"^--- FAIL: |^FAIL\t"),
    ("test", 3, r"\bAssertionError\b|^not ok \d{1,6}\b|^\s{0,10}\d{1,6} failing$"),
)
_PATTERNS = tuple((cls, w, re.compile(rx)) for cls, w, rx in _P)
# A cheap pre-filter: a line with none of these words cannot match any pattern, so most lines skip the patterns.
_HINT = re.compile(
    r"(?i)error|fail|denied|unauthori|authenticat|permission|forbidden|quota|limit|killed|memory|timed out|timeout|"
    r"exceeded|deadline|not found|unable|could not|couldn't|resolve|no space|no match|operation not|read-only|"
    r"sudo|x509|certificate|manifest|blob|push|tests run|failures|failing|not ok|assert|refused|connection|"
    r"lookup|cancel|newuidmap|uids|404|401|403|429|137|toomanyrequests|e: |\*\*\*|^-+ fail|reasonphrase|undefined|"
    r"cannot use|syntax|unknown|symbol"
)
_BOOST = (  # the failing step's name hints at the cause when the lines alone are ambiguous
    ("image-push", 2.0, re.compile(r"(?i)\bpush|publish|\bdeploy image|^push image$")),
    (
        "dependency-fetch",
        1.0,
        re.compile(
            r"(?i)install|restore|download|dependenc|fetch|clone|checkout|setup|"
            r"\bnpm ci\b|\bpip\b|\bgo mod\b|^FROM "
        ),
    ),
    ("test", 1.0, re.compile(r"(?i)\btests?\b|pytest|jest|junit|surefire|verify|\bcheck\b")),
    ("compile", 0.5, re.compile(r"(?i)compile|\bbuild\b|tsc|webpack|\bmake\b|assemble")),
)


@dataclass
class Step:
    name: str
    start: int  # first line index (0-based) of the step
    end: int  # one past the last line
    detail: str = ""  # the command that ran, when the log shows it


@dataclass
class Evidence:
    line: int  # 1-based line number in the input
    text: str  # up to EXCERPT characters around the match, redacted
    cls: str
    weight: int
    full: str = ""  # the whole line, redacted: the error template is made from it


@dataclass
class Diagnosis:
    system: str
    steps: list[Step]
    failing: Step | None
    failing_why: str
    exit_code: int | None
    cause: str | None
    confidence: str
    scores: dict[str, float]
    evidence: list[Evidence]
    notes: list[str] = field(default_factory=list)

    def template(self) -> tuple[str, str] | None:
        return normalise_error(self.evidence[0].full or self.evidence[0].text) if self.evidence else None


def clean_lines(text: str) -> tuple[list[str], list[str]]:
    """The log as lines with colour codes, carriage returns and CI timestamps removed, and notes on what was cut."""
    notes: list[str] = []
    if len(text) > MAX_INPUT:
        text = text[-MAX_INPUT:]
        notes.append(f"read the last {MAX_INPUT:,} characters")
    raw = text.split("\n")
    if len(raw) > MAX_LINES:
        notes.append(f"read the last {MAX_LINES:,} of {len(raw):,} lines")
        raw = raw[-MAX_LINES:]
    lines = []
    for original in raw:
        line = original[:MAX_LINE]
        if "\r" in line:
            line = line.rstrip("\r").rsplit("\r", 1)[-1]  # progress bars redraw with CR: keep the last drawing
        if "\x1b" in line:
            line = _ANSI.sub("", line)
        line = _JENKINS_TIME.sub("", _GHA_TIME.sub("", line, count=1), count=1)
        lines.append(line.rstrip())
    return lines, notes


def detect(lines: list[str]) -> str:
    sample = lines[:2000] + lines[-2000:]
    if any(_GHA_MARK.match(x) for x in sample):
        return "github-actions"
    if sum(1 for x in sample if _TEKTON_PREFIX.match(x)) >= 2 or any(_TEKTON_FAILED.match(x) for x in sample):
        return "tekton"
    if any(_JENKINS_MARK.match(x) for x in sample):
        return "jenkins"
    if any(_OCP_CLONE.match(x) or _OCP_STEP.match(x) or _OCP_ERROR.match(x) or _OCP_PUSH.match(x) for x in sample):
        return "openshift-build"
    return "unknown"


# -- failing step, per system -----------------------------------------------------------------------------------


def _github(lines: list[str]) -> tuple[list[Step], Step | None, str, int | None]:
    steps: list[Step] = []
    for i, line in enumerate(lines):
        m = _GHA_STEP.match(line)
        if m:
            if steps:
                steps[-1].end = i
            elif i:
                steps.append(Step("Set up job", 0, i))
            steps.append(Step(m.group(1).strip(), i, len(lines)))
    if not steps:
        steps = [Step("job", 0, len(lines))]
    for i, line in enumerate(lines):
        m = _GHA_FATAL.match(line)
        if m:
            step = next(s for s in reversed(steps) if s.start <= i)
            code = int(m.group(1)) if m.group(1) else None
            return steps, step, f"line {i + 1}: {line[2:120] if line.startswith('##') else line[:120]}", code
    for i, line in enumerate(lines):
        if line.startswith("##[error]"):
            step = next(s for s in reversed(steps) if s.start <= i)
            return steps, step, f"first ##[error] at line {i + 1}", None
    return steps, None, "no ##[error] line: the log does not show a failed step", None


def _jenkins(lines: list[str]) -> tuple[list[Step], Step | None, str, int | None]:
    steps: list[Step] = []
    skipped: set[str] = set()
    code = None
    for i, line in enumerate(lines):
        m = _JENKINS_STAGE.match(line)
        if m and not m.group(1).startswith("Declarative: Post Actions"):
            if steps and steps[-1].end == len(lines):
                steps[-1].end = i
            steps.append(Step(m.group(1), i, len(lines)))
            continue
        m = _JENKINS_SKIPPED.match(line)
        if m:
            skipped.add(m.group(1))
        m = _JENKINS_EXIT.match(line)
        if m:
            code = int(m.group(1))
        if _JENKINS_END.match(line) and steps and steps[-1].end == len(lines):
            steps[-1].end = i
        if steps and line.startswith("+ ") and steps[-1].start <= i < steps[-1].end:
            steps[-1].detail = line[2:200]
    if not steps:  # a freestyle job: one step per build step
        for i, line in enumerate(lines):
            m = _JENKINS_FREESTYLE.match(line)
            if m:
                if steps:
                    steps[-1].end = i
                steps.append(Step("Execute shell", i, len(lines), m.group(1)[:200]))
            elif steps and line.startswith("+ "):
                steps[-1].detail = line[2:200]
        for i, line in enumerate(lines):
            m = _JENKINS_FREESTYLE_FAIL.match(line)
            if m:
                step = next((s for s in reversed(steps) if s.start <= i), None)
                if step is None:
                    step = Step(m.group(1), 0, len(lines))
                    steps.append(step)
                return steps, step, f"line {i + 1}: Build step '{m.group(1)}' marked build as failure", code
        return steps or [Step("build", 0, len(lines))], (steps[-1] if steps else None), "the last build step", code
    ran = [s for s in steps if s.name not in skipped]
    for s in ran:  # a stage that ran into the timeout step's cancellation
        if any(lines[j] == "Cancelling nested steps due to timeout" for j in range(s.start, s.end)):
            return steps, s, f"stage {s.name!r} was cancelled by its timeout", code
    if not ran:
        return steps, None, "every stage was skipped", code
    why = "the last stage that ran (the stages after it were skipped)" if skipped else "the last stage that ran"
    return steps, ran[-1], why, code


def _tekton(lines: list[str]) -> tuple[list[Step], Step | None, str, int | None]:
    steps: list[Step] = []
    by_key: dict[tuple[str, str], Step] = {}
    for i, line in enumerate(lines):
        m = _TEKTON_PREFIX.match(line)
        if not m:
            continue
        key = (m.group(1), m.group(2))
        if steps and (steps[-1].name == f"{key[0]} : {key[1]}"):
            steps[-1].end = i + 1
            continue
        step = Step(f"{key[0]} : {key[1]}", i, i + 1)
        steps.append(step)
        by_key[key] = step
    for i, line in enumerate(lines):
        m = _TEKTON_FAILED.match(line)
        if not m:
            continue
        task = m.group(1)
        exited = _TEKTON_EXITED.search(line)
        inner = m.group(2) or (exited.group(1) if exited else None)
        code = int(m.group(3)) if m.group(3) else None
        if inner and (task, inner) in by_key:
            return steps, by_key[(task, inner)], f"line {i + 1}: task {task} failed in step {inner}", code
        mine = [s for s in steps if s.name.startswith(f"{task} : ")]
        if mine:
            return steps, mine[-1], f"line {i + 1}: task {task} failed (its last step with output)", code
        step = Step(f"{task} : {inner}" if inner else task, i, i + 1)
        steps.append(step)
        return steps, step, f"line {i + 1}: task {task} failed before printing output", code
    for line in lines:
        m = _TEKTON_EXITED.search(line)
        if m:
            hit = next((s for s in reversed(steps) if s.name.endswith(f" : {m.group(1)}")), None)
            if hit:
                return steps, hit, f'"step-{m.group(1)}" exited', int(m.group(2)) if m.group(2) else None
    if steps:
        return steps, steps[-1], "the last step with output", None
    return [Step("pipeline", 0, len(lines))], None, "no [task : step] lines", None


def _openshift(lines: list[str]) -> tuple[list[Step], Step | None, str, int | None]:
    steps: list[Step] = []

    def start(name: str, i: int) -> None:
        if steps:
            steps[-1].end = i
        steps.append(Step(name, i, len(lines)))

    for i, line in enumerate(lines):
        if _OCP_CLONE.match(line):
            start("fetch source", i)
        elif m := _OCP_STEP.match(line):
            start(m.group(1).strip(), i)
        elif _OCP_PUSH.match(line):
            start("push image", i)
    if not steps:
        steps = [Step("build", 0, len(lines))]
    for i, line in enumerate(lines):
        m = _OCP_ERROR.match(line) or (re.match(r"^Error: (building at STEP .{0,2000})$", line))
        if not m:
            continue
        err = m.group(1)
        at = _OCP_AT_STEP.search(err)
        if at:
            want = at.group(1)
            hit = next((s for s in steps if s.name == want), None)
            if hit is None:
                hit = next((s for s in steps if s.name.startswith(want[:40])), None)
            if hit:
                return steps, hit, f"line {i + 1}: building at STEP {want!r}", _exit(err)
        if err.startswith("Failed to push image"):
            hit = next((s for s in reversed(steps) if s.name == "push image"), None)
            if hit is None:
                hit = Step("push image", i, i + 1)
                steps.append(hit)
            return steps, hit, f"line {i + 1}: Failed to push image", None
        before = [s for s in steps if s.start <= i]
        if before:
            return steps, before[-1], f"line {i + 1}: the step running when the build failed", _exit(err)
    return steps, steps[-1], "the last step in the log", None


def _exit(text: str) -> int | None:
    m = re.search(r"exit status (\d{1,3})\b", text)
    return int(m.group(1)) if m else None


def _generic(lines: list[str]) -> tuple[list[Step], Step | None, str, int | None]:
    return [Step("log", 0, len(lines))], None, "no step structure recognised (not a known CI log format)", None


_SPLITTERS = {
    "github-actions": _github,
    "jenkins": _jenkins,
    "tekton": _tekton,
    "openshift-build": _openshift,
    "unknown": _generic,
}

# -- cause ------------------------------------------------------------------------------------------------------


def _scan(lines: list[str], lo: int, hi: int, factor: float, scores: dict[str, float], ev: list[Evidence]) -> None:
    for i in range(lo, hi):
        line = lines[i]
        if not line or not _HINT.search(line):
            continue
        best: dict[str, tuple[int, int]] = {}
        for cls, w, rx in _PATTERNS:
            if w > best.get(cls, (0, 0))[0] and (m := rx.search(line)):
                best[cls] = (w, m.start())
        if not best:
            continue
        prefixed = _TEKTON_PREFIX.match(line)
        full = redact_text((prefixed.group(3) if prefixed else line).strip())
        for cls, (w, at) in best.items():
            scores[cls] = scores.get(cls, 0.0) + w * factor
            if factor >= 1.0:
                ev.append(Evidence(i + 1, _excerpt(full, at), cls, w, full))


def _excerpt(line: str, at: int) -> str:
    """The part of a long line around the match, so the words that decided the cause are always shown."""
    if len(line) <= EXCERPT:
        return line
    lo = max(0, min(at - 80, len(line) - EXCERPT))
    return ("..." if lo else "") + line[lo : lo + EXCERPT] + ("..." if lo + EXCERPT < len(line) else "")


def diagnose(text: str) -> Diagnosis:
    lines, notes = clean_lines(text)
    system = detect(lines)
    steps, failing, why, code = _SPLITTERS[system](lines)
    scores: dict[str, float] = {}
    evidence: list[Evidence] = []
    if failing is not None:
        lo, hi = failing.start, failing.end
        if system == "jenkins":  # Jenkins prints the error after the pipeline ends
            end = next((i for i, x in enumerate(lines) if _JENKINS_END.match(x)), len(lines))
            _scan(lines, lo, hi, 1.0, scores, evidence)
            _scan(lines, end, len(lines), 1.0, scores, evidence)
            _scan(lines, max(0, lo - 20_000), lo, 0.25, scores, evidence)
        else:
            _scan(lines, lo, hi, 1.0, scores, evidence)
            _scan(lines, max(0, lo - 20_000), lo, 0.25, scores, evidence)
            _scan(lines, hi, min(len(lines), hi + 2_000), 0.5 if system == "tekton" else 0.25, scores, evidence)
        decisive = any(e.weight >= 5 for e in evidence)
        for cls, bonus, rx in _BOOST:  # only when no line in the step names the cause outright
            if not decisive and cls in scores and rx.search(failing.name):
                scores[cls] += bonus
    else:
        lo = max(0, len(lines) - 20_000)
        _scan(lines, lo, len(lines), 1.0, scores, evidence)
    if code == 137 and "timeout" not in scores:
        scores["out-of-memory"] = scores.get("out-of-memory", 0.0) + 3
    ranked = sorted(scores.items(), key=lambda kv: (-kv[1], list(CLASSES).index(kv[0])))
    cause = ranked[0][0] if ranked and ranked[0][1] >= 2 else None
    if cause is None:
        confidence = "none"
    else:
        top = ranked[0][1]
        second = ranked[1][1] if len(ranked) > 1 else 0.0
        confidence = "high" if top >= 5 and top >= 2 * second else ("medium" if top > second else "low")
    chosen = sorted((e for e in evidence if e.cls == cause), key=lambda e: (-e.weight, e.line))[:MAX_EVIDENCE]
    return Diagnosis(
        system=system,
        steps=steps,
        failing=failing,
        failing_why=why,
        exit_code=code,
        cause=cause,
        confidence=confidence,
        scores={k: round(v, 2) for k, v in ranked},
        evidence=sorted(chosen, key=lambda e: e.line),
        notes=notes,
    )


# -- fixes -------------------------------------------------------------------------------------------------------

_FIX: dict[str, dict[str, list[str]]] = {
    "dependency-fetch": {
        "all": [
            "Read the first error line: a name or version that does not exist (404, no matching version) is fixed in "
            "the dependency list; a DNS, connection or TLS error is the build's network path, not the code",
            "Behind a proxy or a private mirror, point the tool at it (npm config registry, pip --index-url, a Maven "
            "mirror in settings.xml, GOPROXY) and give the build the mirror's CA",
            "Pin the base image and dependencies so a moved tag or a yanked release cannot break the next build",
        ],
        "openshift-build": [
            "Cluster-wide build proxy and CA: spec.buildDefaults.defaultProxy and gitProxy in "
            "build.config.openshift.io/cluster; per build: spec.strategy.*.env HTTP_PROXY/HTTPS_PROXY/NO_PROXY",
            "A private Git source needs a source secret: oc set build-secret --source bc/<name> <secret>",
        ],
        "tekton": ["Give the Task's ServiceAccount the registry or Git secret it needs, and the proxy as step env"],
        "github-actions": ["Cache dependencies (actions/cache, setup-node cache) so a registry outage fails less"],
        "jenkins": ["Run the stage on an agent that can reach the registry, or configure the mirror for the agent"],
    },
    "compile": {
        "all": [
            "Fix the first compiler error (file and line in the evidence); later errors usually follow from it",
            "Build with the same toolchain version locally: pin it in the builder image or the setup step",
        ],
    },
    "test": {
        "all": [
            "Run the failing test alone to see whether it fails every time; one that passes and fails on the same "
            "commit is flaky: quarantine it and fix it, do not retry the whole build",
            "Read the assertion in the evidence: expected and actual values name the regression",
        ],
    },
    "image-push": {
        "all": [
            "Check that the target repository exists and the reference is right (registry, namespace, name, tag)",
            "A 5xx or blob upload error is the registry side: check its health and storage, then retry once",
            "A registry with a private CA needs the CA trusted by the build (x509 errors)",
        ],
        "openshift-build": [
            "Read the output reference: oc get bc/<name> -o jsonpath='{.spec.output.to}'",
            "For the internal registry: oc get clusteroperator image-registry (Available, not Degraded)",
            "A registry CA for builds: additionalTrustedCA in image.config.openshift.io/cluster",
        ],
    },
    "registry-auth": {
        "all": [
            "Give the build credentials for that registry or Git host, and check that they are not expired and are "
            "allowed to push (or pull) that repository",
        ],
        "openshift-build": [
            "Push secret: oc set build-secret --push bc/<name> <secret>; pull secret for the builder image: "
            "oc set build-secret --pull bc/<name> <secret>",
            "Pushing to the internal registry in another project needs the system:image-builder role for the "
            "builder ServiceAccount: oc policy add-role-to-user system:image-builder "
            "system:serviceaccount:<build-ns>:builder -n <target-ns>",
        ],
        "tekton": [
            "Link the registry secret to the pipeline's ServiceAccount: oc secrets link pipeline <secret> "
            "--for=pull,mount (or kubectl patch serviceaccount ... imagePullSecrets)",
        ],
        "github-actions": ["Log in before pushing (docker/login-action or podman login) with a token that can push"],
        "jenkins": ["Bind the registry credential to the stage (withCredentials or the registry plugin's login)"],
    },
    "quota": {
        "all": [
            "ResourceQuota or LimitRange: read the numbers in the message, then lower the build's requests and "
            "limits or ask for more quota (oc describe quota -n <ns>, oc describe limitrange -n <ns>)",
            "A registry rate limit (toomanyrequests): authenticate the pulls or use a mirror",
            "No space left on device: remove what the job does not need, or give the build a larger volume",
        ],
        "openshift-build": ["Build resources: spec.resources in the BuildConfig (or buildDefaults.resources)"],
        "tekton": ["Step resources: computeResources on the Task step, or the Pipeline's taskRunSpecs"],
    },
    "timeout": {
        "all": [
            "Find the slow part first (the step durations, a test that hangs, a network wait); raise the limit only "
            "after that",
            "Cache dependencies and images so the build does not download everything each time",
        ],
        "github-actions": ["Step or job limit: timeout-minutes on the step or the job"],
        "jenkins": ["The timeout step around the stage: timeout(time: <n>, unit: 'MINUTES')"],
        "tekton": ["spec.timeouts.pipeline and spec.timeouts.tasks on the PipelineRun, or timeout on the TaskRun"],
        "openshift-build": ["spec.completionDeadlineSeconds in the BuildConfig"],
    },
    "out-of-memory": {
        "all": [
            "Give the build more memory, or cap the tool below the limit: NODE_OPTIONS=--max-old-space-size=<MB>, "
            "MAVEN_OPTS/JAVA_TOOL_OPTIONS -Xmx, GRADLE_OPTS, make -j with fewer jobs",
        ],
        "openshift-build": ["spec.resources.limits.memory in the BuildConfig"],
        "tekton": ["computeResources.limits.memory on the step that was killed"],
        "github-actions": ["A larger runner, or fewer parallel jobs in the step"],
        "jenkins": ["A larger agent (the pod template's memory limit for Kubernetes agents)"],
    },
    "permissions": {
        "all": [
            "A file the build writes must be writable by the user it runs as: on OpenShift that is an arbitrary UID "
            "in group 0, so chgrp -R 0 <dir> && chmod -R g=u <dir> in the Containerfile; write to /tmp or $HOME",
            "An SCC or RBAC refusal names what is missing: kube-noob explain-denial with the message gives the "
            "smallest grant (never privileged or cluster-admin for a build)",
        ],
        "openshift-build": [
            "Docker strategy builds run as the builder ServiceAccount: oc adm policy who-can use scc <scc> shows who "
            "may use which SCC",
        ],
        "tekton": [
            "Rootless buildah in OpenShift Pipelines runs with the pipelines-scc: check the pipeline ServiceAccount "
            "may use it",
        ],
    },
}

_READ_ONLY: dict[str, list[str]] = {
    "github-actions": ["gh run view <run-id> --log-failed", "gh run view <run-id> --json jobs"],
    "jenkins": ["the run's consoleText (<job-url>/<build>/consoleText)", "the stage view of the run"],
    "tekton": ["tkn pipelinerun describe <run> -n <ns>", "tkn taskrun logs <taskrun> -n <ns>"],
    "openshift-build": [
        "oc describe build/<name> -n <ns>",
        "oc logs build/<name> -n <ns>",
        "oc get events -n <ns> --sort-by=.lastTimestamp",
    ],
    "unknown": ["the full job log from the CI system"],
}


def fixes(cause: str | None, system: str) -> list[str]:
    if cause is None:
        return []
    entry = _FIX.get(cause, {})
    return [*entry.get(system, []), *entry.get("all", [])]


def as_dict(d: Diagnosis) -> dict[str, Any]:
    tpl = d.template()
    out: dict[str, Any] = {
        "system": d.system,
        "steps": len(d.steps),
        "failingStep": (
            {
                "name": d.failing.name,
                "lines": [d.failing.start + 1, d.failing.end],
                **({"command": redact_text(d.failing.detail)} if d.failing.detail else {}),
                "why": d.failing_why,
            }
            if d.failing
            else None
        ),
        "exitCode": d.exit_code,
        "cause": ({"class": d.cause, "meaning": CLASSES[d.cause], "confidence": d.confidence} if d.cause else None),
        "evidence": [{"line": e.line, "text": e.text} for e in d.evidence],
        "errorTemplate": {"text": tpl[0], "id": tpl[1]} if tpl else None,
        "scores": d.scores,
        "fix": fixes(d.cause, d.system),
        "readOnlyNextSteps": _READ_ONLY.get(d.system, []),
    }
    if not d.failing:
        out["note"] = d.failing_why
    if d.cause is None:
        out["causeNote"] = "no line names a known cause class; the evidence to read is the failing step's last lines"
    if d.notes:
        out["notes"] = d.notes
    return out
