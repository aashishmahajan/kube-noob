"""Code findings (requirements R4.5-R4.7): what static analysis tools already found, where it ships and who runs it.

kube-noob has no analysis engine of its own for any language. It reads the SARIF 2.1.0 that Semgrep, Bandit,
SpotBugs (with FindSecBugs), ESLint and CodeQL write (``sarif``), follows each finding's file through the
Containerfiles into the images that ship it (``ship``), places those images in the workloads that run them with the
attack-path model, and points language-package vulnerabilities from SBOM-based scanners at the dependency file that
declares them (``deps``). ``assess`` joins the three.
"""
