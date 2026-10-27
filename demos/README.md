# Demo recordings

Each tape records one `kube-noob demo` scenario with [VHS](https://github.com/charmbracelet/vhs). The release
workflow renders every tape from the released wheel and attaches the GIFs to the GitHub release, so recordings always
match the shipped version. The demos are offline and use a throwaway data directory.

```bash
vhs demos/diagnose.tape
```

## Videos

All three are rendered from real output (needs Node with Playwright and Chromium, and ffmpeg):

| Video | Command | Source |
|---|---|---|
| 2-minute walkthrough + YouTube thumbnail | `demos/video/render.sh <out-dir>` | `kube-noob demo` and `selftest` |
| kube-noob as tools for Claude (MCP), 70 s | `demos/video/render.sh <out-dir> mcp <session.jsonl>` | a `claude -p --plugin-dir plugin/kube-noob --output-format stream-json --verbose` session, with its prompt in `<session>.prompt.txt` |
| kube-noob as a sidecar on a cluster | `demos/video/render.sh <out-dir> sidecar <transcript.txt>` | the transcript `scripts/demo_sidecar_kind.sh` records in CI (job `e2e-kind`, OpenShift 4.22 leg) |

The voice-over, title options and chapters are in [youtube-walkthrough.md](youtube-walkthrough.md). Prompts for an
AI-generated teaser, sidecar and MCP explainer are in [ai-video-prompts.md](ai-video-prompts.md).
