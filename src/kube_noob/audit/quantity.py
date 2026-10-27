"""Kubernetes resource.Quantity parsing (subset sufficient for requests/limits comparison)."""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation

_BINARY = {"Ki": 2**10, "Mi": 2**20, "Gi": 2**30, "Ti": 2**40, "Pi": 2**50, "Ei": 2**60}
_DECIMAL = {
    "n": Decimal("1e-9"),
    "u": Decimal("1e-6"),
    "m": Decimal("1e-3"),
    "": Decimal(1),
    "k": Decimal("1e3"),
    "M": Decimal("1e6"),
    "G": Decimal("1e9"),
    "T": Decimal("1e12"),
    "P": Decimal("1e15"),
    "E": Decimal("1e18"),
}
_RE = re.compile(r"^([+-]?(?:\d+\.?\d*|\.\d+))(?:[eE]([+-]?\d+))?(Ki|Mi|Gi|Ti|Pi|Ei|n|u|m|k|M|G|T|P|E)?$")


def parse_quantity(value: str | int | float) -> Decimal:
    """Return the quantity in base units (cores for CPU, bytes for memory). Raises ValueError."""
    if isinstance(value, bool):
        raise ValueError(f"Invalid quantity {value!r}")
    if isinstance(value, int | float):
        return Decimal(str(value))
    s = str(value).strip()
    m = _RE.match(s)
    if not m:
        raise ValueError(f"Invalid quantity {value!r}")
    number, exp, suffix = m.group(1), m.group(2), m.group(3) or ""
    try:
        base = Decimal(number)
    except InvalidOperation as exc:
        raise ValueError(f"Invalid quantity {value!r}") from exc
    if exp is not None:
        if suffix:
            raise ValueError(f"Invalid quantity {value!r}: exponent and suffix cannot be combined")
        return base * (Decimal(10) ** int(exp))
    if suffix in _BINARY:
        return base * _BINARY[suffix]
    return base * _DECIMAL[suffix]
