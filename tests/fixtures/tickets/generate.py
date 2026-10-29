"""Writes the synthetic ticket exports used by tests/test_memory_import.py (55 tickets per format, deterministic).

Every ticket is invented. Names, emails, phone numbers and account ids are fake and placed where real exports carry
them (caller lines, journal headers, @mentions, comment authors) so the tests can prove none of them survive.
Run: python tests/fixtures/tickets/generate.py
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

HERE = Path(__file__).parent

ISSUES = [
    (
        "orders-api pods OOMKilled during the nightly batch import",
        "Pods restart every night. Last State: Terminated Reason: OOMKilled Exit Code: 137.",
        "Raised the memory limit to 1Gi and changed the import to stream pages of 500 rows.",
        "Root cause: the import loaded the whole catalogue into memory.",
    ),
    (
        "ImagePullBackOff for payments after the registry move",
        "Failed to pull image quay.io/acme/payments:2.3.1: unauthorized: authentication required.",
        "Linked the new pull secret to the default ServiceAccount in payments and restarted the rollout.",
        "Cause was a pull secret that still pointed at the old registry.",
    ),
    (
        "etcd leader changes every few minutes after the 4.21.0 update",
        "etcdHighNumberOfLeaderChanges is firing on all masters; API requests time out.",
        "Updated the cluster to 4.21.1, which fixes the catalog sync I/O on the control plane.",
        "Root cause: catalog sync wrote to the control-plane disks every few seconds.",
    ),
    (
        "Route returns 503 for shop frontend",
        "The router answers 503 Service Unavailable for shop.apps.example.test.",
        "The Service selector used app=front instead of app=frontend; corrected the selector.",
        "Cause: the Service selected no pods.",
    ),
    (
        "PVC stuck Pending for the reporting database",
        "persistentvolumeclaim/report-db is Pending: no persistent volumes available and no storage class.",
        "Set storageClassName gp3-csi on the claim and recreated it.",
        "Root cause was a claim without a storage class on a cluster with no default class.",
    ),
    (
        "Pods rejected by SCC in the batch namespace",
        "unable to validate against any security context constraint: runAsUser 0 is not an allowed user.",
        "Removed runAsUser 0 from the Deployment so restricted-v2 assigns a UID from the namespace range.",
        "Cause: the chart hard-codes runAsUser for vanilla Kubernetes.",
    ),
    (
        "DNS lookups time out from the analytics pods",
        "dial tcp: lookup db.analytics.svc on 172.30.0.10:53: i/o timeout in the logs.",
        "Added an egress NetworkPolicy rule for DNS to openshift-dns on port 5353.",
        "Root cause: a default-deny egress policy blocked DNS.",
    ),
    (
        "Certificate expired on the internal API route",
        "x509: certificate has expired or is not yet valid for api.internal.example.test.",
        "Renewed the certificate in cert-manager and switched the route to reencrypt with the new CA.",
        "Cause was a manually created certificate that nobody renewed.",
    ),
    (
        "Node NotReady after kubelet disk pressure",
        "Node worker-3 NotReady; kubelet reports DiskPressure and evicts pods.",
        "Cleaned unused images and raised the image GC thresholds on the machine config pool.",
        "Root cause: image garbage collection thresholds were too high for the 60 GB disk.",
    ),
    (
        "Quota exceeded when scaling the checkout service",
        "exceeded quota: compute-resources, requested: limits.memory=2Gi, used: limits.memory=15Gi.",
        "Raised the namespace quota after the capacity review and set requests to match real usage.",
        "Cause: limits far above real usage consumed the quota.",
    ),
    (
        "HAProxy router pods restart at maxconn",
        "Router pods restarted by the liveness probe when HAProxy reaches maxconn under load.",
        "Raised maxConnections in the IngressController tuningOptions to 40000.",
        "Root cause: maxconn too low for the client traffic.",
    ),
]
PEOPLE = [
    ("Jane Doe", "jane.doe@example.com", "+1 555 123 4567", "jdoe"),
    ("Raj Patel", "raj.patel@example.org", "(555) 987-6543", "rpatel"),
    ("Ana Lima", "ana.lima@example.net", "+44 20 7946 0958", "alima"),
]


def tickets() -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for n in range(55):
        title, desc, fix, cause = ISSUES[n % len(ISSUES)]
        name, email, phone, handle = PEOPLE[n % len(PEOPLE)]
        kind = "resolved"
        if 30 <= n < 36:
            kind = "workaround"
        elif 36 <= n < 41:
            kind = "open"
        elif 41 <= n < 44:
            kind = "canceled"
        elif 44 <= n < 47:
            kind = "nofix"
        elif 47 <= n < 50:
            kind = "nonotes"
        elif n == 50:
            kind = "logsonly"
        notes = f"{cause} Checked with @{handle}; call {phone} or mail {email} if it comes back."
        resolution = fix
        if n in (51, 52):
            resolution = f"{fix} Rotated the token: password is S3cretValue{n} and the API key is AKIAABCDEFGHIJKLMNOP."
        if kind == "logsonly":
            resolution = "2026-10-01T09:12:41Z kubelet started\n2026-10-01T09:12:42Z kubelet ready"
        out.append(
            {
                "n": n,
                "title": f"{title} (case {n})",
                "description": f"Caller: {name}\n{desc}\nReported by {name} <{email}>.",
                "notes": f"2026-10-0{1 + n % 9} 09:12:41 - {name} (Work notes)\n{notes}",
                "resolution": "" if kind == "nonotes" else resolution,
                "kind": kind,
                "resolved": f"2026-10-{1 + n % 28:02d}",
                "who": (name, email),
            }
        )
    return out


SN_STATE = {
    "resolved": "6",
    "workaround": "7",
    "open": "2",
    "canceled": "8",
    "nofix": "7",
    "nonotes": "6",
    "logsonly": "6",
}
SN_CODE = {
    "resolved": "Solved (Permanently)",
    "workaround": "Solved (Work Around)",
    "open": "",
    "canceled": "",
    "nofix": "Not Solved (Not Reproducible)",
    "nonotes": "Solution provided",
    "logsonly": "Solution provided",
}
JIRA_RES = {
    "resolved": "Done",
    "workaround": "Workaround",
    "open": "",
    "canceled": "Won't Do",
    "nofix": "Cannot Reproduce",
    "nonotes": "Done",
    "logsonly": "Done",
}


def servicenow_records() -> list[dict[str, object]]:
    recs = []
    for t in tickets():
        n = int(t["n"])  # type: ignore[call-overload]
        state = SN_STATE[str(t["kind"])]
        rec: dict[str, object] = {
            "sys_id": f"{n:032x}",
            "number": f"INC{10000 + n:07d}",
            "short_description": t["title"],
            "description": t["description"],
            "state": state
            if n % 2
            else {
                "value": state,
                "display_value": {"6": "Resolved", "7": "Closed", "2": "In Progress", "8": "Canceled"}[state],
            },
            "close_code": SN_CODE[str(t["kind"])],
            "close_notes": t["resolution"],
            "resolved_at": f"{t['resolved']} 10:00:00" if state in {"6", "7"} else "",
            "work_notes": t["notes"],
            "comments": "",
            "caller_id": {"link": "https://example.service-now.com/api/now/table/sys_user/1", "value": "a1b2c3"},
            "assigned_to": t["who"][0],  # type: ignore[index]
            "assignment_group": "Platform Team",
        }
        recs.append(rec)
    return recs


def write() -> None:
    recs = servicenow_records()
    (HERE / "servicenow.json").write_text(json.dumps({"result": recs}, indent=1) + "\n", encoding="utf-8")
    with open(HERE / "servicenow.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(
            [
                "Number",
                "Short description",
                "Description",
                "State",
                "Resolution code",
                "Resolution notes",
                "Resolved",
                "Work notes",
                "Assigned to",
                "Caller",
            ]
        )
        for r in recs:
            st = r["state"]
            label = (
                st["display_value"]
                if isinstance(st, dict)
                else {"6": "Resolved", "7": "Closed", "2": "In Progress", "8": "Canceled"}[str(st)]
            )
            w.writerow(
                [
                    r["number"],
                    r["short_description"],
                    r["description"],
                    label,
                    r["close_code"],
                    r["close_notes"],
                    r["resolved_at"],
                    r["work_notes"],
                    r["assigned_to"],
                    "Jane Doe",
                ]
            )
    issues = []
    rows = []
    for t in tickets():
        n = int(t["n"])  # type: ignore[call-overload]
        key = f"OPS-{100 + n}"
        res = JIRA_RES[str(t["kind"])]
        comments = [str(t["notes"])] + ([str(t["resolution"])] if t["resolution"] else [])
        adf = n % 2 == 0

        def body(text: str, adf: bool = adf) -> object:
            if not adf:
                return text
            return {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": text},
                            {"type": "mention", "attrs": {"id": "557058:abc", "text": "@Jane"}},
                        ],
                    }
                ],
            }

        issues.append(
            {
                "key": key,
                "fields": {
                    "summary": t["title"],
                    "description": body(str(t["description"])),
                    "status": {
                        "name": "Open" if not res else "Done",
                        "statusCategory": {"key": "new" if not res else "done"},
                    },
                    "resolution": {"name": res} if res else None,
                    "resolutiondate": f"{t['resolved']}T10:00:00.000+0000" if res else None,
                    "assignee": {"displayName": t["who"][0], "emailAddress": t["who"][1]},  # type: ignore[index]
                    "comment": {
                        "comments": [{"body": body(c), "author": {"displayName": t["who"][0]}} for c in comments]
                    },  # type: ignore[index]
                },
            }
        )
        rows.append(
            [
                key,
                t["title"],
                t["description"],
                "Done" if res else "Open",
                res,
                f"{int(str(t['resolved'])[-2:]):02d}/Oct/26 10:00 AM" if res else "",
                t["who"][0],
            ]  # type: ignore[index]
            + [
                f"{int(str(t['resolved'])[-2:]):02d}/Oct/26 9:{i:02d} AM;557058:abc{i};{c}"
                for i, c in enumerate(comments)
            ]
        )
    (HERE / "jira.json").write_text(
        json.dumps({"startAt": 0, "maxResults": 100, "total": len(issues), "issues": issues}, indent=1) + "\n",
        encoding="utf-8",
    )
    with open(HERE / "jira.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(
            [
                "Issue key",
                "Summary",
                "Description",
                "Status",
                "Resolution",
                "Resolved",
                "Assignee",
                "Comment",
                "Comment",
            ]
        )
        for r in rows:
            w.writerow(r + [""] * (9 - len(r)))


if __name__ == "__main__":
    write()
