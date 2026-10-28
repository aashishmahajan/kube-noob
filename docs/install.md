# Install kube-noob

kube-noob needs Python 3.11 or newer. macOS's built-in `python3` (from the Xcode Command Line Tools) is 3.9, so a
plain `pip install` there fails. Homebrew and uv bring their own Python (uv downloads one when yours is too old), and
pipx installed with Homebrew uses Homebrew's.

| Method | Commands | Upgrade |
|---|---|---|
| Homebrew (Apple silicon macOS, Linux) | `brew tap aashishmahajan/kube-noob https://github.com/aashishmahajan/kube-noob`, then `brew trust --formula aashishmahajan/kube-noob/kube-noob`, then `brew install kube-noob` | `brew update && brew upgrade kube-noob` |
| uv (downloads a Python if yours is too old) | `uv tool install kube-noob` | `uv tool upgrade kube-noob` |
| pipx | `pipx install kube-noob` | `pipx upgrade kube-noob` |
| pip, in a virtual environment | `python3.13 -m venv ~/.venvs/kube-noob`, then `~/.venvs/kube-noob/bin/pip install kube-noob` | `~/.venvs/kube-noob/bin/pip install -U kube-noob` |
| Container | `podman run --rm ghcr.io/aashishmahajan/kube-noob:0.5 --version` | pull the new tag |
| Claude Code plugin | `/plugin marketplace add aashishmahajan/kube-noob`, then `/plugin install kube-noob@kube-noob` | `/plugin marketplace update kube-noob` |

The tap is needed because kube-noob is not in Homebrew's main catalogue; after `brew tap`, `brew install kube-noob`
finds it. Homebrew 6 and later also refuse formulae from third-party taps until you trust them; `brew trust
--formula` trusts only this one formula ([Homebrew: Tap Trust](https://docs.brew.sh/Tap-Trust)). Get uv or pipx with `brew install uv` or `brew install pipx`.

Every method installs two commands: `kube-noob` and its short form `noob` (from 0.2.3). The PyPI package named
`noob` is an unrelated graph library that also installs a `noob` command; if you have it, use `kube-noob`.

Check what you are running:

```bash
kube-noob --version
which -a kube-noob
```

`which -a` lists every `kube-noob` on your `PATH`. If it prints more than one, an older install is shadowing the new
one: remove it with the tool that installed it (`pipx uninstall kube-noob`, `uv tool uninstall kube-noob` or
`brew uninstall kube-noob`).

## Errors and fixes

| You see | Why | Fix |
|---|---|---|
| `No available formula with the name "kube-noob"` | The tap is not added | `brew tap aashishmahajan/kube-noob https://github.com/aashishmahajan/kube-noob`, then `brew trust --formula aashishmahajan/kube-noob/kube-noob`, then `brew install kube-noob` |
| `Refusing to load formula aashishmahajan/kube-noob/kube-noob from untrusted tap` | Homebrew 6 requires trust for third-party taps | `brew trust --formula aashishmahajan/kube-noob/kube-noob`, then `brew install kube-noob` |
| `Requires-Python >=3.11.4` and `No matching distribution found for kube-noob` | Your `python3` is older than 3.11 | Use Homebrew, uv or pipx above, or a virtual environment made with Python 3.11+ |
| `error: externally-managed-environment` | Homebrew's or the system's Python refuses packages installed into it (PEP 668) | Use pipx, uv or a virtual environment; do not add `--break-system-packages` |
| `zsh: command not found: pip` | macOS has no `pip` command, only `pip3` | Use pipx or uv, or `python3 -m pip` inside a virtual environment |
| `command not found: kube-noob` after pipx or uv | Their bin folder is not on your `PATH` yet | `pipx ensurepath` or `uv tool update-shell`, then open a new terminal |
| An old version after upgrading | Another install comes first on `PATH` | `which -a kube-noob` and remove the older one |
