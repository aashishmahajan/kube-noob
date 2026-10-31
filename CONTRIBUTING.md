# Contributing

```bash
uv venv && . .venv/bin/activate && uv pip install -e ".[dev]"
ruff check src tests scripts && ruff format --check src tests scripts && mypy && pytest
```

Ground rules:
- **Facts need sources.** Knowledge docs (`src/kube_noob/data/knowledge/*.md`) list their sources in front matter;
  catalog tables (`catalog.py`) cite the document they were verified against. No unverified version numbers.
  `platforms` decides where a doc answers (an OpenShift- or ROSA-only doc needs the question to say so when no
  platform is given); a doc whose words are broader than its subject declares `requires` (word groups, each needed),
  as `k8s-compose-migration.md` does. Rerun `scripts/eval_questions.py --grades` after changing knowledge.
- **Rule ids are a public contract** (graders, exercises and training rewards use them). Never renumber; add new ids.
- **Generator output must audit clean** (`tests/test_generate.py`). Exercises must have a passing reference solution.
- **No network at query time** unless guarded by `webEnabled`. Use `kube_noob.net.http_client` only.
- Respect licenses: new corpus sources need an SPDX license and a correct `redistributable` flag.
- Sign off commits (`git commit -s`) to certify the Developer Certificate of Origin.
- **Working through an AI agent?** [AGENTS.md](AGENTS.md) has what agents get wrong here: the one command that decides whether a change is done, the generated plugin copy that must never be edited, and the gates that exist specifically to catch generated code.

Refresh vendored schemas: `python scripts/vendor_schemas.py --k8s v1.35.0` (updates `PROVENANCE.json`).

Releases and the weekly risk review: [docs/operations.md](docs/operations.md). Bump versions only with
`python scripts/bump_version.py <version> "<reason>"` (it updates PyPI, MCP Registry, plugin, chart and image metadata
together; `tests/test_distribution.py` enforces it).
