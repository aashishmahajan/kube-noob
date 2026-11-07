"""Which CNI enforces the admin tier, and which silently ignores it.

``kube_noob.debug.anp`` evaluates ``AdminNetworkPolicy`` and ``BaselineAdminNetworkPolicy`` with the semantics
OVN-Kubernetes implements. That is only the answer on a cluster whose CNI enforces them, and one widely deployed
CNI no longer does: Calico removed support in 3.32 in favour of ``ClusterNetworkPolicy``, and "Calico does not
enforce them from 3.32 onward, so they stop taking effect silently" (Tigera upgrade notes). On such a cluster the
tier kube-noob trusts first is the one doing nothing, so a ``Deny`` it reports is a deny that is not happening and
an ``Allow`` it reports is permission nobody granted.

Three answers, never two:

- ``enforced`` -- upstream lists the CNI as implementing the v1alpha1 standard fields, so the tier decides.
- ``not-enforced`` -- the CNI is documented as not enforcing it. The tier is dropped and each policy in it is
  reported as inert, which is the finding worth having: the operator believes those policies protect them.
- ``unknown`` -- nothing upstream states either way. Evaluating the tier guesses enforcement and dropping it
  guesses the reverse, so an admin policy present under an unknown CNI makes the verdict ``undetermined``.

Sources, both retrieved 2026-11-05:

- https://network-policy-api.sigs.k8s.io/implementations/ (page updated 21 April 2026) lists the implementations
  of ``AdminNetworkPolicy``/``BaselineAdminNetworkPolicy`` v1alpha1 -- OVN-Kubernetes, Antrea, Kube-OVN,
  kube-network-policies and "Calico v3.29, v3.30, and v3.31" -- and, for ``ClusterNetworkPolicy``, "Calico v3.32"
  with standard support and Kube-OVN as experimental. Cilium appears with a tracking issue and no stated support.
- https://docs.tigera.io/calico/latest/operations/upgrading/upgrade-notes -- "3.32 removed support for both in
  favor of ``ClusterNetworkPolicy``"; the upgrade note applies to clusters coming from 3.31 that hold those
  resources, and says to replace each one with an equivalent ``ClusterNetworkPolicy`` or remove it.

A CNI absent from the table is ``unknown``, not enforced: a tool that guesses in its owner's favour here reports
protection that does not exist.
"""

from __future__ import annotations

import re
from typing import Literal

Support = Literal["enforced", "not-enforced", "unknown"]

ADMIN_TIER_SOURCES: tuple[tuple[str, str], ...] = (
    ("https://network-policy-api.sigs.k8s.io/implementations/", "2026-11-05"),
    ("https://docs.tigera.io/calico/latest/operations/upgrading/upgrade-notes", "2026-11-05"),
)

#: The replacement Calico points at. Named on every inert finding so the fix is not left as an exercise.
REPLACEMENT = "ClusterNetworkPolicy"

#: Upstream lists these with "Has implemented standard fields of the API" and states no version, so every version
#: is taken as enforcing. A CNI whose support is version-dependent is in :data:`_VERSIONED` instead.
#:
#: ``kube-network-policies`` is deliberately NOT here. Upstream links a conformance report for it and states no
#: support level, and the rule this table keeps is to answer only where upstream does -- so it is unknown, like
#: any CNI the page does not characterise.
_ENFORCING = frozenset({"ovn-kubernetes", "antrea", "kube-ovn"})

#: name -> (first version upstream lists as implementing it, first version that dropped it). Below the first the
#: answer is unknown rather than no: upstream simply does not say. A version with fewer components than these
#: bounds cannot be compared against them -- see :func:`admin_tier_support`.
_VERSIONED: dict[str, tuple[tuple[int, ...], tuple[int, ...]]] = {"calico": ((3, 29), (3, 32))}

#: Listed upstream with a tracking issue and no stated support. Kept by name so the reason can say which it is.
_NO_STATED_SUPPORT = frozenset({"cilium"})

_NAME = re.compile(r"^[a-z0-9]([-a-z0-9]{0,38}[a-z0-9])?\Z")
_VERSION = re.compile(r"^v?(\d{1,4})(?:\.(\d{1,4}))?(?:\.(\d{1,4}))?\Z")


def parse_cni(raw: str) -> tuple[str, str | None]:
    """``calico:3.32`` or ``calico`` -> a lower-case name and a version without its ``v``.

    Raises ``ValueError`` on anything else rather than reading an unrecognisable value as a CNI with no version,
    which would silently get the ``unknown`` answer and look like a supported input.
    """
    if raw.count(":") > 1:
        raise ValueError(f"bad --cni {raw!r}: use NAME or NAME:VERSION")
    name, _, version = raw.partition(":")
    name, version = name.strip().lower(), version.strip()
    if not _NAME.match(name):
        raise ValueError(f"bad CNI name {name!r}: lower-case letters, digits and dashes, up to 40 characters")
    if ":" in raw and not version:
        raise ValueError(f"bad --cni {raw!r}: a trailing ':' with no version")
    if version and not _VERSION.match(version):
        raise ValueError(f"bad CNI version {version!r}: expected 3.32, v3.32 or 3.32.1")
    return name, version.lstrip("v") or None


def _tuple(version: str) -> tuple[int, ...]:
    m = _VERSION.match(version)
    if not m:  # pragma: no cover - parse_cni rejects these first
        raise ValueError(f"bad CNI version {version!r}")
    return tuple(int(g) for g in m.groups() if g is not None)


def admin_tier_support(name: str, version: str | None = None) -> Support:
    """Does this CNI enforce AdminNetworkPolicy and BaselineAdminNetworkPolicy?

    A version too coarse to decide is ``unknown``, not enforced. The first version of this function truncated the
    TABLE's bound to the length of the INPUT, so ``calico:3`` compared (3,) against (3,) and answered "enforced" --
    an unknown read as a pass, on the one question this module exists to answer. ``3`` does not distinguish 3.31
    from 3.32, so it decides nothing, exactly like ``calico`` with no version at all.

    Past the removal the answer IS ``not-enforced`` however far past, including an undocumented major: Tigera's
    wording is "from 3.32 onward", so that is reading the source rather than extrapolating beyond it.
    """
    name = name.strip().lower()
    if name in _ENFORCING:
        return "enforced"
    if name in _VERSIONED:
        if version is None:
            return "unknown"  # the version is what decides, so without it there is no answer
        first, dropped = _VERSIONED[name]
        v = _tuple(version)
        if len(v) < len(dropped):
            return "unknown"  # too coarse to sit on either side of the bound
        v = v[: len(dropped)]
        return "not-enforced" if v >= dropped else ("enforced" if v >= first else "unknown")
    return "unknown"


#: Which CNIs enforce v1alpha2 ``ClusterNetworkPolicy``, by the same rule as the table above: answer only where
#: upstream does. Calico is the one version boundary that is documented -- Tigera's own upgrade note says "You
#: must migrate to ClusterNetworkPolicy before upgrading to v3.32", which states both halves: from 3.32 it
#: enforces the kind, and before 3.32 the CRD is not there to enforce. Every other CNI is ``unknown``, which
#: evaluates the tier and withholds it where it changes the answer, rather than guessing in either direction.
_CNP_VERSIONED: dict[str, tuple[int, ...]] = {"calico": (3, 32)}


def cnp_support(name: str, version: str | None = None) -> Support:
    """Does this CNI enforce ClusterNetworkPolicy v1alpha2?

    The mirror of :func:`admin_tier_support`, and deliberately not its inverse: "does not enforce ANP" is not
    the same claim as "enforces CNP", and a CNI that does neither would be read as doing the second.
    """
    name = name.strip().lower()
    if name not in _CNP_VERSIONED:
        return "unknown"
    if version is None:
        return "unknown"
    bound = _CNP_VERSIONED[name]
    v = _tuple(version)
    if len(v) < len(bound):
        return "unknown"  # too coarse to sit on either side of the bound
    return "enforced" if v[: len(bound)] >= bound else "not-enforced"


def cnp_reason(name: str, version: str | None, support: Support) -> str:
    """One sentence for the note or the finding, naming the version that decided it."""
    shown = f"{name} {version}" if version else name
    if support == "not-enforced":
        where = ".".join(str(p) for p in _CNP_VERSIONED[name])
        return (
            f"{shown} does not enforce it: {name} added ClusterNetworkPolicy in {where}, so on this version "
            "the CRD is not applied and this policy is in the cluster deciding nothing"
        )
    return (
        f"whether {shown} enforces ClusterNetworkPolicy is not something upstream states, so kube-noob does "
        "not assume it either way"
    )


def admin_tier_reason(name: str, version: str | None, support: Support) -> str:
    """One sentence for the finding or the note, naming the version that decided it."""
    shown = f"{name} {version}" if version else name
    if support == "not-enforced":
        dropped = _VERSIONED[name][1]
        where = ".".join(str(p) for p in dropped)
        return (
            f"{shown} does not enforce it: {name} removed AdminNetworkPolicy and BaselineAdminNetworkPolicy "
            f"support in {where} in favour of {REPLACEMENT}, and stops enforcing them without reporting an error, "
            "so this policy is in the cluster and decides nothing"
        )
    if name in _NO_STATED_SUPPORT:
        return (
            f"whether {shown} enforces it is unknown: the upstream network-policy-api implementations page lists "
            f"{name} with a tracking issue and no stated support, so neither evaluating nor ignoring the tier "
            "would be an answer this input supports"
        )
    if name in _VERSIONED and version and len(_tuple(version)) < len(_VERSIONED[name][1]):
        bound = ".".join(str(p) for p in _VERSIONED[name][1])
        return (
            f"whether {shown} enforces it cannot be decided from that version: {name} stopped enforcing it in "
            f"{bound}, and {version} does not say which side of that it is on"
        )
    return (
        f"whether {shown} enforces it is unknown: the upstream network-policy-api implementations page does not "
        f"list {'this version of ' if version else ''}{name} as implementing AdminNetworkPolicy"
    )
