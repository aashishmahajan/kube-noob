"""RPM version comparison, as ``rpm`` itself does it.

``rpmvercmp`` follows rpm's ``rpmio/rpmvercmp.cc`` (https://github.com/rpm-software-management/rpm, read at commit
4f7be32ef288a231893dd4c45d4ef36584e3d4b6): versions are split into numeric and alphabetic segments, separators are
skipped, ``~`` sorts before everything (pre-releases) and ``^`` after the base version (snapshots), numbers compare
by value, a numeric segment is newer than an alphabetic one, and the side with characters left over wins.
``compare_evr`` compares ``[epoch:]version[-release]`` as ``rpmverCmp`` in ``rpmio/rpmver.cc`` does: epoch (missing
is 0), then version, then release, where a present release sorts after a missing one. The tests run rpm's own
vectors (``tests/rpmvercmp.at``).
"""

from __future__ import annotations

import re

_EVR = re.compile(r"^(?:(\d{1,10}):)?([^:\s]+)$")
MAX_LEN = 256


def _alnum(c: str) -> bool:
    return ("0" <= c <= "9") or ("a" <= c <= "z") or ("A" <= c <= "Z")


def _digit(c: str) -> bool:
    return "0" <= c <= "9"


def _alpha(c: str) -> bool:
    return ("a" <= c <= "z") or ("A" <= c <= "Z")


def rpmvercmp(a: str, b: str) -> int:
    """1 when ``a`` is newer, 0 when the same version, -1 when ``b`` is newer."""
    if a == b:
        return 0
    i, j, n, m = 0, 0, len(a), len(b)
    while i < n or j < m:
        while i < n and not _alnum(a[i]) and a[i] not in "~^":
            i += 1
        while j < m and not _alnum(b[j]) and b[j] not in "~^":
            j += 1
        ca = a[i] if i < n else ""
        cb = b[j] if j < m else ""
        if ca == "~" or cb == "~":
            if ca != "~":
                return 1
            if cb != "~":
                return -1
            i, j = i + 1, j + 1
            continue
        if ca == "^" or cb == "^":
            if not ca:
                return -1
            if not cb:
                return 1
            if ca != "^":
                return 1
            if cb != "^":
                return -1
            i, j = i + 1, j + 1
            continue
        if not (ca and cb):
            break
        si, sj = i, j
        if _digit(ca):
            while i < n and _digit(a[i]):
                i += 1
            while j < m and _digit(b[j]):
                j += 1
            isnum = True
        else:
            while i < n and _alpha(a[i]):
                i += 1
            while j < m and _alpha(b[j]):
                j += 1
            isnum = False
        seg_a, seg_b = a[si:i], b[sj:j]
        if not seg_a:  # cannot happen: the first string has a segment here
            return -1
        if not seg_b:
            return 1 if isnum else -1
        if isnum:
            seg_a, seg_b = seg_a.lstrip("0"), seg_b.lstrip("0")
            if len(seg_a) != len(seg_b):
                return 1 if len(seg_a) > len(seg_b) else -1
        if seg_a != seg_b:
            return 1 if seg_a > seg_b else -1
    if i >= n and j >= m:
        return 0
    return -1 if i >= n else 1


def split_evr(evr: str) -> tuple[int, str, str]:
    """``[epoch:]version[-release]`` as (epoch, version, release); a missing epoch is 0."""
    text = evr.strip()
    if not text or len(text) > MAX_LEN:
        raise ValueError(f"not an RPM version: {evr[:60]!r}")
    m = _EVR.match(text)
    if not m:
        raise ValueError(f"not an RPM version: {evr[:60]!r}")
    epoch = int(m.group(1) or 0)
    rest = m.group(2)
    version, sep, release = rest.rpartition("-")
    if not sep:
        return epoch, rest, ""
    return epoch, version, release


def compare_evr(a: str, b: str) -> int:
    """Compare two ``[epoch:]version-release`` strings: 1 when ``a`` is newer, 0 equal, -1 older."""
    ea, va, ra = split_evr(a)
    eb, vb, rb = split_evr(b)
    if ea != eb:
        return 1 if ea > eb else -1
    rc = rpmvercmp(va, vb)
    if rc:
        return rc
    if ra and rb:
        return rpmvercmp(ra, rb)
    if ra or rb:  # rpmverCmp's compare_values: a present release sorts after a missing one
        return 1 if ra else -1
    return 0


def normalise(evr: str) -> str:
    """``0:1.2-3`` and ``1.2-3`` are the same package version: drop a zero epoch."""
    text = evr.strip()
    return text[2:] if text.startswith("0:") else text
