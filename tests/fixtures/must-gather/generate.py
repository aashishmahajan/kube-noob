"""The synthetic must-gather the tests use: ``kube_noob.mustgather.sample`` (shared with ``kube-noob demo
must-gather``). ``python tests/fixtures/must-gather/generate.py <dir>`` writes it under ``<dir>``."""

from __future__ import annotations

import sys
from pathlib import Path

from kube_noob.mustgather.sample import FILES, IMAGE, MARKER, NESTED, TOP, write

__all__ = ["FILES", "IMAGE", "MARKER", "NESTED", "TOP", "main"]


def main(out: Path) -> None:
    write(out)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
