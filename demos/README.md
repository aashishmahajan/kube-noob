# Demo recordings

Each tape records one `kube-noob demo` scenario with [VHS](https://github.com/charmbracelet/vhs). The release
workflow renders every tape from the released wheel and attaches the GIFs to the GitHub release, so recordings always
match the shipped version. The demos are offline and use a throwaway data directory.

```bash
vhs demos/diagnose.tape
```
