# Contributing

```bash
uv venv && . .venv/bin/activate && uv pip install -e ".[dev]"
ruff check src tests scripts && ruff format --check src tests scripts && mypy && pytest
```

Ground rules:
- **Facts need sources.** Knowledge docs (`src/kube_noob/data/knowledge/*.md`) list their sources in front matter;
  catalog tables (`catalog.py`) cite the document they were verified against. No unverified version numbers.
- **Rule ids are a public contract** (graders, exercises and training rewards use them). Never renumber; add new ids.
- **Generator output must audit clean** (`tests/test_generate.py`). Exercises must have a passing reference solution.
- **No network at query time** unless guarded by `webEnabled`. Use `kube_noob.net.http_client` only.
- Respect licenses: new corpus sources need an SPDX license and a correct `redistributable` flag.
- Sign off commits (`git commit -s`) to certify the Developer Certificate of Origin.

Refresh vendored schemas: `python scripts/vendor_schemas.py --k8s v1.35.0` (updates `PROVENANCE.json`).
