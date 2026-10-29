"""R3.1 acceptance on a real API server: every generated policy refuses its rule's bad fixture and admits the good one.

Usage (in CI, against a kind cluster): python scripts/policy_kind_test.py --engine vap|kyverno

For each rule with a fixture in tests/fixtures/rules whose policy is generated for the fixture's platform, the script
writes the policy with `kube-noob policy generate --mode enforce`, applies it, waits until a server-side dry-run of the
bad fixture is refused with the rule's id in the message, checks that a server-side dry-run of the good fixture is
admitted, deletes the policy and waits until the bad fixture is no longer refused by it. It also checks audit mode
once (the request is admitted with a warning naming the rule). Results are printed as GitHub annotations.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "rules"
CRDS = ROOT / "scripts" / "policy_kind_crds.yaml"


def _escape(text: str) -> str:
    return " ".join(text.replace("%", "%25").split())[:1500]


def run(args: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


def dry_run(kubectl: str, path: Path) -> tuple[int, str]:
    out = run([kubectl, "apply", "--dry-run=server", "-f", str(path)])
    return out.returncode, out.stdout + out.stderr


def generated(rule: str, platform: str, version: str | None, engine: str, mode: str, out: Path) -> bool:
    args = ["kube-noob", "policy", "generate", "--rule", rule, "--platform", platform, "--mode", mode]
    args += ["--engine", engine, "-o", str(out)] + (["--version", version] if version else [])
    res = run(args)
    if res.returncode != 0:
        raise RuntimeError(f"kube-noob policy generate failed for {rule}: {res.stderr}")
    return any(d for d in yaml.safe_load_all(out.read_text(encoding="utf-8")) if d)


def wait_for(kubectl: str, path: Path, rule: str, refused: bool, seconds: int) -> tuple[bool, str]:
    """Poll a server-side dry-run of ``path`` until the rule's policy refuses it (``refused``) or stops refusing it."""
    deadline = time.monotonic() + seconds
    text = ""
    while time.monotonic() < deadline:
        code, text = dry_run(kubectl, path)
        hit = code != 0 and f"[{rule}]" in text
        if hit == refused:
            return True, text
        time.sleep(2)
    return False, text


def check_rule(kubectl: str, engine: str, data: dict[str, object], tmp: Path) -> list[str]:
    rule = str(data["rule"])
    platform = str(data.get("platform", "kubernetes"))
    version = str(data["version"]) if data.get("version") else None
    policy = tmp / f"{rule}-{engine}.yaml"
    if not generated(rule, platform, version, engine, "enforce", policy):
        return []
    good, bad = tmp / f"{rule}-good.yaml", tmp / f"{rule}-bad.yaml"
    good.write_text(str(data["good"]), encoding="utf-8")
    bad.write_text(str(data["bad"]), encoding="utf-8")
    problems: list[str] = []
    applied = run([kubectl, "apply", "-f", str(policy)])
    if applied.returncode != 0:
        return [f"{rule}: policy not accepted by the cluster: {applied.stderr}"]
    try:
        ok, text = wait_for(kubectl, bad, rule, refused=True, seconds=120)
        if not ok:
            problems.append(f"{rule}: bad fixture not refused within 120 s: {text}")
        code, text = dry_run(kubectl, good)
        if code != 0:
            problems.append(f"{rule}: good fixture refused: {text}")
        if engine == "vap":
            status = run(
                [
                    kubectl,
                    "get",
                    "validatingadmissionpolicy",
                    f"kube-noob-{rule.lower()}",
                    "-o",
                    "jsonpath={.status.typeChecking.expressionWarnings}",
                ]
            )
            if status.stdout.strip() not in {"", "[]"}:
                print(f"::notice title=VAP type checking {rule}::{_escape(status.stdout)}")
    finally:
        run([kubectl, "delete", "-f", str(policy), "--wait=true", "--ignore-not-found"])
        ok, text = wait_for(kubectl, bad, rule, refused=False, seconds=120)
        if not ok:
            problems.append(f"{rule}: still refused 120 s after the policy was deleted: {text}")
    return problems


def check_audit_mode(kubectl: str, engine: str, tmp: Path) -> list[str]:
    data = yaml.safe_load((FIXTURES / "KN-S001.yaml").read_text(encoding="utf-8"))
    policy = tmp / f"audit-{engine}.yaml"
    generated("KN-S001", "kubernetes", None, engine, "audit", policy)
    bad = tmp / "audit-bad.yaml"
    bad.write_text(data["bad"], encoding="utf-8")
    applied = run([kubectl, "apply", "-f", str(policy)])
    if applied.returncode != 0:
        return [f"audit mode: policy not accepted: {applied.stderr}"]
    try:
        deadline = time.monotonic() + 120
        text = ""
        while time.monotonic() < deadline:
            code, text = dry_run(kubectl, bad)
            if code != 0:
                return [f"audit mode refused the request: {text}"]
            if "[KN-S001]" in text:
                print(f"::notice title=audit mode {engine}::{_escape(text)}")
                return []
            time.sleep(2)
        return [f"audit mode: no warning naming KN-S001 within 120 s: {text}"]
    finally:
        run([kubectl, "delete", "-f", str(policy), "--wait=true", "--ignore-not-found"])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", choices=["vap", "kyverno"], required=True)
    ap.add_argument("--kubectl", default="kubectl")
    ap.add_argument("--rule", action="append", default=[], help="only these rules")
    a = ap.parse_args()
    setup = run([a.kubectl, "apply", "-f", str(CRDS)])
    if setup.returncode != 0:
        print(f"::error title=policy kind setup::{_escape(setup.stderr)}")
        return 1
    run([a.kubectl, "wait", "--for=condition=Established", "crd", "--all", "--timeout=60s"])
    run([a.kubectl, "create", "namespace", "shop"])
    problems: list[str] = []
    checked: list[str] = []
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        for path in sorted(FIXTURES.glob("*.yaml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if a.rule and data["rule"] not in a.rule:
                continue
            found = check_rule(a.kubectl, a.engine, data, tmp)
            if (tmp / f"{data['rule']}-good.yaml").exists():
                checked.append(str(data["rule"]))
            problems += found
        problems += check_audit_mode(a.kubectl, a.engine, tmp)
    for p in problems:
        print(f"::error title=policy {a.engine}::{_escape(p)}")
    print(f"::notice title=policy {a.engine}::{len(checked)} rules checked on the API server, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
