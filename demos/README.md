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

### Animated videos, no video model

The same three scripts, rendered locally in the look of the Grok teaser (navy server room, glass terminal, rocket
mascot) with a Piper voice-over and generated music. Every terminal line in them is copied from a real run: the
0.2.1 CLI, the CI sidecar transcript and the recorded Claude session.

| Video | Length | Command |
|---|---|---|
| Teaser: no AI inside | 30 s | `demos/video/stage/build.sh <out-dir> teaser` |
| kube-noob as a sidecar | 56 s | `demos/video/stage/build.sh <out-dir> sidecar` |
| kube-noob as tools for Claude (MCP) | 57 s | `demos/video/stage/build.sh <out-dir> mcp` |

Needs python3 with `piper-tts` and `numpy`, Node with Playwright and Chromium, and ffmpeg. Scenes, captions and
voice-over lines are in [video/stage/videos.json](video/stage/videos.json); `--speaker N` picks another LibriTTS
voice (0 to 903). The voice is CC BY 4.0, credited on each end card.
