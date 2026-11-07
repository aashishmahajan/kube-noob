# The krew plugin

`kubectl krew install noob` is not live yet: the plugin and its manifest are built and tested here, but adding it
to [krew-index](https://github.com/kubernetes-sigs/krew-index) is a pull request against someone else's
repository and the manifest has to name a published release asset. Both are owner actions, so nothing in the
README advertises the plugin until the index PR merges.

## What is in here

| File | What it is |
|---|---|
| `kubectl-noob.in` | The source of the entry-point script. `__VERSION__` is substituted at build time |
| `kubectl-noob` | Generated, committed, and the file that actually ships inside the archive |
| `noob.yaml` | Generated krew-index manifest. Its `sha256` is the digest of the archive built from the script |

Both generated files are written by `scripts/krew_manifest.py`, and `tests/test_krew.py` fails if either is stale,
if the manifest's digest is not the archive's digest, or if the script stops forwarding its arguments unchanged.

The script is a passthrough on purpose: every argument goes to the kube-noob CLI as given, so there is no verb
table to drift when a subcommand moves. What it adds is the fallback -- if `kube-noob` is not on `PATH` but `uv`
is, it runs the pinned release through `uvx`, so the plugin works on a machine with no Python environment set up.
The pin is the plugin's own version, so `kubectl noob --version` agrees with what krew installed.

## Why one platform entry and no architecture matrix

The plugin is a POSIX shell script, so there is nothing per-architecture to publish. The manifest selects
`os in (darwin, linux)` with a single archive. Windows is not claimed, because the script is not a Windows
executable.

## Why the archive is byte-reproducible

The manifest states a digest, so the digest has to be a property of the script rather than of the machine that
packed it. The archive fixes the member name, mode, mtime, uid, gid and user name, and gzips with no timestamp.
Without that, every release would produce a different hash for identical content and `--check` could never pass.

## Releasing it (owner)

The release workflow already checks the manifest and builds `dist/kubectl-noob-v<version>.tar.gz`, asserting that
its digest matches the manifest. After the release is published, verify the plugin against the real asset and then
submit it:

```bash
cd kube-noob && python scripts/krew_manifest.py --check && kubectl krew install --manifest=krew/noob.yaml && kubectl noob --version && kubectl krew uninstall noob && gh repo fork kubernetes-sigs/krew-index --clone --remote=false -- /tmp/krew-index && cd /tmp/krew-index && git checkout -b add-noob && mkdir -p plugins && cp ~/kube-noob/krew/noob.yaml plugins/noob.yaml && git add plugins/noob.yaml && git commit -s -m "Add noob plugin" && git push -u origin add-noob && gh pr create --repo kubernetes-sigs/krew-index --title "Add noob plugin" --body "kube-noob: offline Kubernetes/OpenShift manifest audit, policy reachability and must-gather reader. No AI inside. Apache-2.0. The plugin is a POSIX shell passthrough to the kube-noob CLI, with a uvx fallback so it works without a Python environment."
```

`kubectl krew install --manifest=` is the step that matters: it downloads the URI in the manifest and refuses the
install if the digest does not match, so it proves the published asset is the archive the manifest describes. Run
it before opening the PR, not after.

Both `noob` and `kube-noob` were unclaimed in krew-index when this was written (`plugins/noob.yaml` and
`plugins/kube-noob.yaml` both 404). `noob` is the name used here, because krew runs the plugin as
`kubectl <name>` and `kubectl noob audit` reads better than `kubectl kube-noob audit`.
