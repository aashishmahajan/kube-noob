# Prompts for a text-to-video model

Three short videos to generate with a text-to-video model (for example Sora or a similar tool). Paste each scene's
prompt as one generation, then cut the clips together and add the voice-over.

## Before you generate

- **Real terminal text comes from the real recordings.** Video models garble on-screen text, so every scene that
  shows commands asks for a blank, glowing terminal window. Overlay the matching segment of a real recording on it:
  `kube-noob-walkthrough.mp4`, `kube-noob-mcp.mp4` or `kube-noob-sidecar.mp4` (`demos/video/render.sh`).
- **No real logos or people.** Do not ask for the Kubernetes, OpenShift, Red Hat, AWS or Anthropic logos, or for a
  real person's likeness. The prompts use generic shapes instead (pods and clusters are "glowing cubes").
- **Brand look:** deep navy background (#0b1020), green for safe actions (#4ade80), red for destructive ones
  (#f87171), the rocket mascot from `docs/brand/kube-noob-icon.svg` (upload it as a reference image where the tool
  allows).
- **Format:** 16:9, 1920x1080, 24 or 30 fps; for LinkedIn and Shorts, also render 1:1 or 9:16 crops.

## Video 1: launch teaser (30 seconds)

| # | Length | Prompt | On-screen text | Voice-over |
|---|---|---|---|---|
| 1 | 5 s | A dark navy control room at night, one glowing terminal window floating in the center. A red command line appears and the whole room flickers red, like an alarm. Cinematic, shallow depth of field, no readable text. | Your AI ran `delete` first. | When a pod breaks at 2 a.m., the fastest command is delete. |
| 2 | 5 s | The red glow freezes and fades; small glowing cubes (pods) dissolve into dust, suggesting lost evidence. Slow motion, moody. | The evidence is gone. | It's also the one that destroys your evidence. |
| 3 | 7 s | A friendly cartoon rocket with a round window and a smile flies in from the lower left on a green-blue arc of light and stops beside the terminal. Clean 3D illustration style, soft rim light. | kube-noob | Meet kube-noob. There's no AI inside it. |
| 4 | 8 s | Split screen: on the left a chat bubble labelled only with a speech icon, on the right the rocket holding a clipboard with green check marks; a beam connects them. Flat, modern, navy and green palette. | No AI inside. Works with yours. | Your AI does the talking. kube-noob supplies the rules, the read-only steps and the citations. |
| 5 | 5 s | The terminal window turns calm green; three green lines type out (blank text to overlay later). The rocket gives a thumbs up. | pipx install kube-noob | Free and open source. Link below. |

## Video 2: kube-noob as a sidecar (60 seconds)

| # | Length | Prompt | On-screen text | Voice-over |
|---|---|---|---|---|
| 1 | 8 s | Isometric 3D illustration: a large translucent box (a pod) on a navy grid; inside it two smaller containers side by side, one labelled with a chat icon (the app), one with the rocket mascot. Soft studio lighting. | Your app + kube-noob, one pod | Run kube-noob next to your own app, in the same pod. |
| 2 | 10 s | A short glowing cable loops between the two containers inside the pod only. Outside the pod, other glowing cubes try to reach the rocket and bounce off a transparent shield. | 127.0.0.1 only | It listens on 127.0.0.1, so only containers in that pod can call it. |
| 3 | 10 s | The pod's outer wall shows a single small door marked with a padlock; arrows to the outside world fade out before reaching it. | No egress. No token to manage. | It needs no network access at all, and there's no Service, Route or token to manage. |
| 4 | 12 s | Blank glowing terminal window over the isometric scene (overlay the real `kube-noob-sidecar.mp4` segment: audit, rollout, MCP calls, closed port). | Pod Security restricted | We deploy it on a cluster that enforces Pod Security restricted. The app asks it to audit a Deployment and diagnose a crash, over loopback. |
| 5 | 8 s | A small gauge on the rocket's container settles at a low level, green. | 68 MiB peak · 256 MiB limit | In our test cluster it peaked at sixty-eight mebibytes, well under its limit. |
| 6 | 12 s | Pull back to show many pods on the grid, each with a tiny rocket beside its app. | deploy/sidecar/app-with-kube-noob-sidecar.yaml | One example manifest, audited for OpenShift 4.20 and later. Link below. |

## Video 3: kube-noob as tools for Claude (MCP, 60 seconds)

| # | Length | Prompt | On-screen text | Voice-over |
|---|---|---|---|---|
| 1 | 8 s | A laptop on a desk at night, a code editor glowing; a speech bubble rises from the screen. Warm desk lamp, navy room. | Ask in your own words | Paste a Deployment into Claude and ask what's wrong for OpenShift 4.22. |
| 2 | 12 s | From the laptop, a thin beam goes to the rocket mascot sitting on the desk next to the laptop (not in the cloud). The rocket flips through a thick rulebook. | Runs on your machine | The kube-noob plugin runs on your machine. Claude calls its tools: audit, fix, diagnose. |
| 3 | 15 s | Blank glowing terminal window (overlay the real `kube-noob-mcp.mp4` segment: tool calls and the score). | 37/100 · 3 high findings | kube-noob checks the YAML against sixty rules and returns findings with line numbers and fixes. Same answer every time. |
| 4 | 15 s | The speech bubble fills with neat green check marks while the rulebook closes. | Claude explains. kube-noob checks. | Claude explains the result in plain language and cites the rule ids. |
| 5 | 10 s | The laptop's network icon stays dim while the rocket works; a tiny label reads "local". | No AI inside kube-noob | There's no model inside kube-noob, and it makes no network calls of its own. |
