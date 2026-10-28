"""Signals: the canonical names an error carries (alert names, event and condition reasons, container reasons,
admission rules, components and normalised error templates). They are the join key between an error, a known issue
and a past fix; text search is the fallback. See ``extract``."""

from kube_noob.signals.core import KINDS, Signal, extract, normalise_error

__all__ = ["KINDS", "Signal", "extract", "normalise_error"]
