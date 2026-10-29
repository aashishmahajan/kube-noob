# kube-noob.com

The website, generated from this repository by `scripts/build_site.py` and deployed to GitHub Pages by
`.github/workflows/site.yml` on every push to `main`. Nothing on it is written by hand twice: docs, references,
numbers and demo output all come from the checkout, so the site cannot drift from the code.

| Page | Built from |
|---|---|
| Home, Journey | README, `docs/architecture.md` (the 7 steps), real `kube-noob demo` runs, CHANGELOG |
| Playground | kube-noob's real tools, running in the visitor's browser (Pyodide, offline lock on) |
| Ask | the visitor's own Anthropic key: Claude calls kube-noob's tools, which run in the browser |
| Docs | every Markdown doc in the repo, links rewritten to site pages |
| Reference | MCP tools and schemas (the server's ToolSpecs), CLI help, audit rules, playbooks, knowledge base, release-note issue index, Helm values |
| Insights | counts and the self-test, computed at build time; the roadmap status table |
| Videos | the three animated videos (`demos/video/stage/build.sh`) and the release's terminal recordings |

## Privacy and security of the site itself

- No server, no analytics, no cookies, no third-party requests: fonts, scripts, the Python runtime and videos are all
  served from the site. A Content-Security-Policy on every page allows scripts and connections only to the site, plus
  `api.anthropic.com` for the Ask page. Remote images in the docs (status badges) are replaced by their text.
- Playground: what visitors paste is processed in their tab and never sent anywhere.
- Ask: the visitor's key and messages go from their browser straight to `api.anthropic.com` with the official
  Anthropic SDK (`dangerouslyAllowBrowser`, which is the intended use here: the key belongs to the visitor). The key is
  kept in memory, or in `sessionStorage` only if the visitor ticks the box; never in `localStorage`. Requests ask for
  the server-side refusal fallback (`fallbacks: "default"`).

## Build and preview locally

```bash
pip install -e ".[dev]"
python -m build --wheel --outdir dist
curl -fsSLO https://github.com/pyodide/pyodide/releases/download/314.0.7/pyodide-314.0.7.tar.bz2   # 337 MB, once
(cd site && npm ci --ignore-scripts)
KN_SCALE=1 demos/video/stage/build.sh .cache/videos all          # optional: the videos (needs ffmpeg, kokoro-onnx)
python scripts/build_site.py --out _site --clean --pyodide pyodide-314.0.7.tar.bz2 --wheel dist/*.whl \
  --videos .cache/videos
node site/bundle.mjs _site
python -m http.server 8000 -d _site                              # open http://localhost:8000
node site/smoke.mjs http://localhost:8000                        # the checks CI runs before deploying
```

Without `--pyodide` and `--wheel` the site still builds; the Playground and Ask pages then say the runtime is missing.
`--strict` (used by CI) fails instead.

## Put it on kube-noob.com (domain registered elsewhere)

The domain can stay with any registrar; only its DNS records change. Steps, once:

1. **Publish from Actions.** Repository **Settings > Pages > Build and deployment > Source: GitHub Actions**.
2. **Merge to `main`.** The `site` workflow builds, smoke-tests and deploys; the first run renders the videos (about
   10 minutes), later runs reuse them from the cache.
3. **Verify the domain** (prevents anyone else from claiming it on GitHub Pages). Your account **Settings > Pages >
   Add a domain**: `kube-noob.com`. GitHub shows a TXT record named `_github-pages-challenge-aashishmahajan.kube-noob.com`
   with a value; add it at your DNS provider, wait, then click **Verify**.
4. **DNS records** at your registrar or DNS provider (delete any parking or forwarding records for `@` and `www`):

   | Type | Name | Value |
   |---|---|---|
   | A | `@` | `185.199.108.153` |
   | A | `@` | `185.199.109.153` |
   | A | `@` | `185.199.110.153` |
   | A | `@` | `185.199.111.153` |
   | AAAA | `@` | `2606:50c0:8000::153` |
   | AAAA | `@` | `2606:50c0:8001::153` |
   | AAAA | `@` | `2606:50c0:8002::153` |
   | AAAA | `@` | `2606:50c0:8003::153` |
   | CNAME | `www` | `aashishmahajan.github.io` |

   If the provider supports `ALIAS` or `ANAME` at the apex, `@ -> aashishmahajan.github.io` replaces the A and AAAA
   records.
5. **Custom domain.** Repository **Settings > Pages > Custom domain**: `kube-noob.com`, **Save**. After the DNS check
   passes (minutes to 24 hours), tick **Enforce HTTPS**. `www.kube-noob.com` then redirects to `kube-noob.com`.
6. **Check:** `dig kube-noob.com +short` lists the four addresses; `https://kube-noob.com` serves the site.
   Optionally set the repository's **About > Website** to `https://kube-noob.com`.

Records and steps verified against GitHub's documentation ("Managing a custom domain for your GitHub Pages site" and
"Verifying your custom domain for GitHub Pages", github/docs, 2026-10-29).
