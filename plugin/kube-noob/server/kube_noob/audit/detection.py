"""What a cluster's audit configuration can and cannot record (R4, G244).

Eleven `AUD-*` checks were proposed in the external reviews -- are logs forwarded, is retention long enough,
does anyone review them, is the SIEM healthy -- and every one of them needs a system kube-noob has no
credentials for. A rule that answers "not evaluated" eleven times is coverage theatre. This module answers the
part that IS decidable from a read-only bundle, and says plainly what it cannot answer.

It is a projection, not a rule: it reads the same cluster-scoped `APIServer` singleton `KN-S035` reads
(`config.openshift.io`), and turns `spec.audit` into a statement about categories of API activity. No event, no
request body, nothing about a person is read -- only the configuration.

Every statement here comes from the field documentation of `Audit` in openshift/api `config/v1`
(`types_apiserver.go`, read from master on 2026-11-06), which is the contract the API server's policy is
generated from:

* `Default` -- "MetaData level logging with the exception of events (not logged at all), oauthaccesstokens and
  oauthauthorizetokens (both logged at RequestBody level)".
* `WriteRequestBodies` -- "like 'Default', but logs request and response HTTP payloads for write requests
  (create, update, patch)".
* `AllRequestBodies` -- "like 'WriteRequestBodies', but also logs request and response HTTP payloads for read
  requests (get, list)".
* `None` -- "no requests are logged at all, not even oauthaccesstokens and oauthauthorizetokens".
* Unset -- "the 'Default' profile is used as the default" (`+kubebuilder:default=Default`).
* `customRules` -- "profiles per group. These profile take precedence over the top-level profile field if they
  apply. They are evaluation from top to bottom and the first one that matches, applies."

Two decisions worth stating, because each is a defect taken the other way.

**An unknown profile is `unknown`, not `no`.** The field is a validated enum on a live cluster, but a bundle is
a file and can carry anything, including a profile a later OpenShift adds. Reporting an unrecognised value as
"records nothing" would be a confident wrong answer in the direction that matters; reporting it as "records
everything" would be the absence-read-as-a-pass failure. It is reported as not decidable, naming the value.

**No object means no statement.** On OpenShift the singleton always exists, so its absence from a bundle means
it was not collected. `coverage` returns None and the report carries no block at all, which is why every
existing result is byte-identical unless the object is there.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal

from kube_noob.audit.rules import APISERVER_GROUP, AUDIT_PROFILE_NONE
from kube_noob.yamlio import Document

#: The profiles openshift/api defines, in order of how much each records. A value outside this set is reported
#: as undecidable rather than guessed.
PROFILES: tuple[str, ...] = ("None", "Default", "WriteRequestBodies", "AllRequestBodies")

#: The default when `spec.audit.profile` is unset (`+kubebuilder:default=Default`).
DEFAULT_PROFILE = "Default"

Recorded = Literal["yes", "no", "unknown"]

#: One category of API activity, and the profiles under which it is recorded. `yes_for` is read as "recorded
#: under exactly these profiles"; anything else records it not at all. Each `because` is the field
#: documentation's own statement, because a coverage claim that paraphrases its source stops being checkable.
CATEGORIES: tuple[tuple[str, str, tuple[str, ...], str], ...] = (
    (
        "request-metadata",
        "who made each request, when, with which verb, against which resource, and how the API server answered",
        ("Default", "WriteRequestBodies", "AllRequestBodies"),
        "every profile but None logs at least MetaData level",
    ),
    (
        "write-bodies",
        "what a create, update or patch contained, and what the API server returned for it",
        ("WriteRequestBodies", "AllRequestBodies"),
        "request and response payloads for write requests are logged only from WriteRequestBodies up",
    ),
    (
        "read-bodies",
        "what a get or list returned, so what an exfiltrating reader actually saw",
        ("AllRequestBodies",),
        "payloads for read requests are logged only under AllRequestBodies",
    ),
    (
        "oauth-token-bodies",
        "the bodies of oauthaccesstokens and oauthauthorizetokens requests, which is how a token grant is traced",
        ("Default", "WriteRequestBodies", "AllRequestBodies"),
        "oauthaccesstokens and oauthauthorizetokens are logged at RequestBody level, and under None not at all",
    ),
    (
        "events",
        "API activity on core Event objects, including a deletion that removes the trace of an incident",
        (),
        "events are not logged at all under Default, and the richer profiles are defined as 'like Default'",
    ),
)

#: What no reading of this object can establish. Printed every time, because a coverage statement that lists
#: only what it knows reads as a complete answer. None of these is reachable without a credential for another
#: system, which is the reason the eleven proposed checks were refused rather than stubbed (docs/ideation-review.md).
CANNOT_SAY: tuple[str, ...] = (
    "whether these records leave the cluster or reach a SIEM: the forwarding configuration is not in this "
    "object, and kube-noob has no credentials for the collector",
    "how long they are kept, or whether they survive a node replacement",
    "whether anyone reads them, or whether an alert fires on one (AU-6 is about review, not generation)",
    "anything that is not an API request to the OpenShift-provided API servers: the kubelet, etcd, a node "
    "shell and a process inside a container are all outside this policy",
)


def _records(profile: str, yes_for: tuple[str, ...]) -> Recorded:
    if profile not in PROFILES:
        return "unknown"
    return "yes" if profile in yes_for else "no"


def _statement(profile: str) -> list[dict[str, str]]:
    return [
        {"id": cid, "what": what, "recorded": _records(profile, yes_for), "because": because}
        for cid, what, yes_for, because in CATEGORIES
    ]


def _sentence(profile: str, assumed: bool, group: str | None = None) -> str:
    """The one honest sentence the roadmap item asked for, for the cluster or for one group."""
    whose = "requests" if group is None else f"requests from {group}"
    for_every = "every request" if group is None else f"every request from {group}"
    if profile not in PROFILES:
        where = f"customRules entry for {group}" if group else "spec.audit.profile"
        return (
            f"The {where} is {profile!r}, which is not a profile this build knows "
            f"({', '.join(PROFILES)}), so what is recorded for {whose} cannot be stated from it."
        )
    if profile == AUDIT_PROFILE_NONE:
        scope = f"No request from {group} is recorded" if group else "No API request is recorded"
        for_what = (
            f"there is no audit evidence for what anyone in {group} does"
            if group
            else "there is no audit evidence for anything that happens on this cluster"
        )
        return f"{scope} at all, not even an OAuth token grant, so {for_what}."
    where = f"profile {profile}" + (" (unset, so the API server's default)" if assumed else "")
    bodies = {
        "Default": "what a request contained is not recorded, except an OAuth token grant",
        "WriteRequestBodies": (
            "what a create, update or patch contained is recorded; what a get or list returned is not"
        ),
        "AllRequestBodies": "what every request contained and what it returned are recorded as well",
    }[profile]
    return (
        f"Under {where}, who did what to which object is recorded for {for_every}, {bodies}, and API "
        "activity on Event objects is not recorded at all."
    )


def coverage(docs: Sequence[Document]) -> dict[str, Any] | None:
    """A detection-coverage statement from the cluster audit configuration, or None when it was not collected.

    Only the `config.openshift.io` APIServer is read: an `APIServer` kind in another group is a different
    resource that happens to share a name. The first such document decides, and any further one is named, so a
    bundle carrying two does not get a verdict from whichever sorted first.
    """
    found = [d for d in docs if d.kind == "APIServer" and d.api_version.split("/", 1)[0] == APISERVER_GROUP]
    if not found:
        return None
    doc = found[0]
    spec = doc.data.get("spec") if isinstance(doc.data, dict) else None
    audit = spec.get("audit") if isinstance(spec, dict) else None
    audit = audit if isinstance(audit, dict) else {}
    raw = audit.get("profile")
    assumed = raw is None or raw == ""
    profile = DEFAULT_PROFILE if assumed else str(raw)
    out: dict[str, Any] = {
        "from": doc.ref(),
        "profile": profile,
        "profileAssumed": assumed,
        "statement": _sentence(profile, assumed),
        "records": _statement(profile),
        "controls": ["AU-2", "AU-12"],
        "cannotSay": list(CANNOT_SAY),
    }
    groups: list[dict[str, Any]] = []
    rules = audit.get("customRules")
    for i, entry in enumerate(rules if isinstance(rules, list) else []):
        if not isinstance(entry, dict):
            continue
        g_raw = entry.get("profile")
        g_profile = DEFAULT_PROFILE if g_raw is None or g_raw == "" else str(g_raw)
        groups.append(
            {
                "group": str(entry.get("group") or "(unnamed group)"),
                "precedence": i,
                "profile": g_profile,
                "statement": _sentence(
                    g_profile, g_raw is None or g_raw == "", str(entry.get("group") or "(unnamed group)")
                ),
                "records": _statement(g_profile),
            }
        )
    if groups:
        out["groups"] = groups
        # Precedence is a fact about the list, not about any one entry, and it is the part a reader gets wrong:
        # a user in two of these groups is covered by whichever entry is listed first, not by the stricter one.
        out["cannotSay"] = [
            *out["cannotSay"],
            "which entry applies to a user in several of these groups beyond the order they are listed in: "
            "the first match applies, and group membership is not in this object",
        ]
    if len(found) > 1:
        out["alsoPresent"] = [d.ref() for d in found[1:]]
    return out


def render_text(cov: dict[str, Any]) -> str:
    """The block `kube-noob audit --format text` prints. Short on purpose: the detail is in the JSON."""
    lines = [f"Detection coverage (from {cov['from']}, spec.audit.profile: {cov['profile']})", ""]
    lines.append(f"  {cov['statement']}")
    lines.append("")
    mark = {"yes": "recorded", "no": "NOT recorded", "unknown": "cannot say"}
    for row in cov["records"]:
        lines.append(f"  {mark[row['recorded']]:>12}: {row['what']}")
    for g in cov.get("groups", ()):
        lines.append("")
        lines.append(f"  group {g['group']} (customRules[{g['precedence']}], profile {g['profile']}) overrides it:")
        lines.append(f"    {g['statement']}")
    lines.append("")
    lines.append("  This says nothing about:")
    lines.extend(f"    - {w}" for w in cov["cannotSay"])
    return "\n".join(lines) + "\n"
