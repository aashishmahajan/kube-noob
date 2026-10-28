"""A four-service repository, what five static analysis tools and two image scanners report on it, and what the
assessment must say (requirements R4.5-R4.7). Each SARIF file is shaped as its tool writes it (see
``kube_noob.code.sarif`` for the source each shape was read from).

``python tests/fixtures/code/generate.py <dir>`` writes:

- ``repo/``: ``web`` (Python, Flask), ``ui`` (JavaScript built into nginx), ``api`` (Node.js), ``worker`` (Java) with
  their Containerfiles, ``.dockerignore``, dependency files and placeholder sources; ``tools/`` and ``web/tests/``,
  which no image ships;
- ``semgrep.sarif``, ``bandit.sarif``, ``spotbugs.sarif``, ``eslint.sarif``, ``codeql.sarif``;
- ``trivy-web.json`` (Trivy JSON of the web image: an installed Python package), ``grype-api.json`` (Grype JSON of
  the api image: an npm package seen in its lockfile and node_modules), ``cyclonedx-worker.json`` (Grype's CycloneDX
  of the worker image: a jar, syft location properties);
- ``expected.json``: the merged findings with their tools, what is shipped and how, the ranking order, the excluded
  results with their reasons, and the dependency file and line for each language-package vulnerability.

Scanners ran in ``/home/runner/work/shop/shop`` (the source root). CVE ids are in 2099.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = "/home/runner/work/shop/shop"
WEB, UI, API, WORKER = (f"quay.io/acme/shop-{n}" for n in ("web", "ui", "api", "worker"))

REPO: dict[str, str] = {
    "web/Containerfile": (
        "FROM registry.access.redhat.com/ubi9/python-311:9.6 AS build\n"
        "WORKDIR /opt/app-root/src\n"
        "COPY requirements.txt ./\n"
        "RUN pip install --no-cache-dir -r requirements.txt\n"
        "COPY app/ ./app/\n"
        "FROM registry.access.redhat.com/ubi9/python-311:9.6\n"
        "COPY --from=build /opt/app-root /opt/app-root\n"
        "USER 1001\n"
        'CMD ["python", "-m", "app"]\n'
    ),
    "web/.dockerignore": "tests/\n*.md\n",
    "web/requirements.txt": "flask==3.0.3\nrequests==2.25.0\n",
    "web/app/db.py": "# query helpers\n",
    "web/app/views.py": "# views\n",
    "web/app/config.py": "# settings\n",
    "web/tests/test_db.py": "# tests\n",
    "ui/Containerfile": (
        "FROM registry.access.redhat.com/ubi9/nodejs-20:9.6 AS build\n"
        "WORKDIR /opt/app-root/src\n"
        "COPY package.json package-lock.json ./\n"
        "RUN npm ci\n"
        "COPY src ./src\n"
        "RUN npm run build\n"
        "FROM registry.access.redhat.com/ubi9/nginx-124:9.6\n"
        "COPY --from=build /opt/app-root/src/dist /opt/app-root/src\n"
        'CMD ["nginx", "-g", "daemon off;"]\n'
    ),
    "ui/package.json": '{\n  "name": "shop-ui",\n  "devDependencies": {\n    "vite": "5.4.0"\n  }\n}\n',
    "ui/package-lock.json": '{\n  "name": "shop-ui",\n  "lockfileVersion": 3\n}\n',
    "ui/src/render.js": "// render\n",
    "ui/src/util.js": "// util\n",
    "ui/src/legacy.js": "// legacy\n",
    "api/Containerfile": (
        "FROM registry.access.redhat.com/ubi9/nodejs-20-minimal:9.6\n"
        "WORKDIR /opt/app-root/src\n"
        "COPY package.json package-lock.json ./\n"
        "RUN npm ci --omit=dev\n"
        "COPY server.js ./\n"
        "USER 1001\n"
        'CMD ["node", "server.js"]\n'
    ),
    "api/package.json": '{\n  "name": "shop-api",\n  "dependencies": {\n    "express": "4.19.2",\n'
    '    "lodash": "4.17.20"\n  }\n}\n',
    "api/package-lock.json": '{\n  "name": "shop-api",\n  "lockfileVersion": 3,\n  "packages": {\n'
    '    "node_modules/express": {\n      "version": "4.19.2"\n    },\n    "node_modules/lodash": {\n'
    '      "version": "4.17.20"\n    }\n  }\n}\n',
    "api/server.js": "// server\n",
    "worker/Containerfile": (
        "FROM registry.access.redhat.com/ubi9/openjdk-21:1.21 AS build\n"
        "WORKDIR /build\n"
        "COPY pom.xml ./\n"
        "COPY src ./src\n"
        "RUN mvn -q package\n"
        "FROM registry.access.redhat.com/ubi9/openjdk-21-runtime:1.21\n"
        "COPY --from=build /build/target/worker.jar /deployments/worker.jar\n"
    ),
    "worker/pom.xml": (
        "<project>\n  <dependencies>\n    <dependency>\n      <groupId>org.apache.logging.log4j</groupId>\n"
        "      <artifactId>log4j-core</artifactId>\n      <version>2.14.1</version>\n    </dependency>\n"
        "  </dependencies>\n</project>\n"
    ),
    "worker/src/main/java/com/acme/Report.java": "// report\n",
    "tools/seed.py": "# seed data\n",
}
BUILDS = [  # (containerfile, image, context)
    ("web/Containerfile", WEB, "web"),
    ("ui/Containerfile", UI, "ui"),
    ("api/Containerfile", API, "api"),
    ("worker/Containerfile", WORKER, "worker"),
]
SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"


def _log(run: dict) -> dict:  # type: ignore[type-arg]
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [run]}


def semgrep() -> dict:  # type: ignore[type-arg]
    rules = [
        {
            "id": "python.lang.security.audit.formatted-sql-query.formatted-sql-query",
            "name": "python.lang.security.audit.formatted-sql-query.formatted-sql-query",
            "shortDescription": {"text": "Semgrep Finding: python.lang.security.audit.formatted-sql-query"},
            "fullDescription": {"text": "Detected possible formatted SQL query. Use parameterized queries instead."},
            "defaultConfiguration": {"level": "warning"},
            "properties": {
                "precision": "very-high",
                "tags": [
                    "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                    "HIGH CONFIDENCE",
                    "OWASP-A03:2021 - Injection",
                    "security",
                ],
            },
        },
        {
            "id": "generic.secrets.security.detected-generic-secret",
            "name": "generic.secrets.security.detected-generic-secret",
            "shortDescription": {"text": "Semgrep Finding: generic.secrets.security.detected-generic-secret"},
            "fullDescription": {"text": "Generic Secret detected"},
            "defaultConfiguration": {"level": "error"},
            "properties": {
                "precision": "very-high",
                "tags": ["CWE-798: Use of Hard-coded Credentials", "LOW CONFIDENCE", "security"],
            },
        },
    ]

    def result(rule: str, path: str, line: int, msg: str, **extra: object) -> dict:  # type: ignore[type-arg]
        return {
            "ruleId": rule,
            "message": {"text": msg},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": path, "uriBaseId": "%SRCROOT%"},
                        "region": {
                            "startLine": line,
                            "startColumn": 5,
                            "endLine": line,
                            "endColumn": 60,
                            "snippet": {"text": "requires login"},
                        },
                    }
                }
            ],
            "fingerprints": {"matchBasedId/v1": f"semgrep-{path}-{line}"},
            "properties": {},
            **extra,
        }

    results = [
        result(rules[0]["id"], "web/app/db.py", 42, "Detected possible formatted SQL query."),
        result(rules[1]["id"], "tools/seed.py", 4, "Generic Secret detected"),
        result(rules[1]["id"], "web/app/config.py", 9, "Generic Secret detected", baselineState="absent"),
    ]
    return _log(
        {
            "tool": {"driver": {"name": "Semgrep OSS", "semanticVersion": "1.95.0", "rules": rules}},
            "results": results,
            "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": []}],
        }
    )


def bandit() -> dict:  # type: ignore[type-arg]
    tests = {
        "B608": ("hardcoded_sql_expressions", 89),
        "B602": ("subprocess_popen_with_shell_equals_true", 78),
        "B105": ("hardcoded_password_string", 259),
        "B101": ("assert_used", 703),
    }
    issues = [  # test id, path, line, severity, confidence, text
        (
            "B608",
            "web/app/db.py",
            42,
            "MEDIUM",
            "LOW",
            "Possible SQL injection vector through string-based query construction.",
        ),
        ("B602", "web/app/views.py", 17, "HIGH", "HIGH", "subprocess call with shell=True identified, security issue."),
        ("B105", "web/app/config.py", 5, "LOW", "MEDIUM", "Possible hardcoded password: 'changeme'"),
        ("B101", "web/tests/test_db.py", 10, "LOW", "HIGH", "Use of assert detected."),
    ]
    order: list[str] = []
    for tid, *_ in issues:
        if tid not in order:
            order.append(tid)
    rules = [
        {
            "id": tid,
            "name": tests[tid][0],
            "properties": {"tags": ["security", f"external/cwe/cwe-{tests[tid][1]}"], "precision": "high"},
            "helpUri": f"https://bandit.readthedocs.io/en/1.7.10/plugins/{tid.lower()}_{tests[tid][0]}.html",
        }
        for tid in order
    ]
    level = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
    results = [
        {
            "message": {"text": text},
            "level": level[sev],
            "locations": [
                {
                    "physicalLocation": {
                        "region": {
                            "snippet": {"text": "..."},
                            "endColumn": 40,
                            "endLine": line,
                            "startColumn": 9,
                            "startLine": line,
                        },
                        "artifactLocation": {"uri": path},
                        "contextRegion": {"snippet": {"text": "..."}, "endLine": line + 1, "startLine": line - 1},
                    }
                }
            ],
            "properties": {"issue_confidence": conf, "issue_severity": sev},
            "ruleId": tid,
            "ruleIndex": order.index(tid),
        }
        for tid, path, line, sev, conf, text in issues
    ]
    return _log(
        {
            "tool": {
                "driver": {
                    "name": "Bandit",
                    "organization": "PyCQA",
                    "rules": rules,
                    "version": "1.7.10",
                    "semanticVersion": "1.7.10",
                }
            },
            "invocations": [{"executionSuccessful": True, "endTimeUtc": "2026-10-28T10:00:00Z"}],
            "properties": {"metrics": {"_totals": {"loc": 120}}},
            "results": results,
        }
    )


def spotbugs() -> dict:  # type: ignore[type-arg]
    base = "11c4f2a9"  # SpotBugs names each source directory with a hash of it
    return _log(
        {
            "tool": {
                "driver": {
                    "name": "SpotBugs",
                    "version": "4.8.6",
                    "language": "en",
                    "informationUri": "https://spotbugs.github.io/",
                    "rules": [
                        {
                            "id": "SQL_INJECTION_JDBC",
                            "shortDescription": {"text": "Potential JDBC Injection"},
                            "fullDescription": {
                                "text": "The input values included in SQL queries need to be passed in safely."
                            },
                            "messageStrings": {
                                "default": {"text": "This use of {0} can be vulnerable to SQL injection"}
                            },
                            "helpUri": "https://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_JDBC",
                            "properties": {"tags": ["SECURITY"]},
                            "relationships": [
                                {
                                    "target": {"id": "89", "toolComponent": {"name": "CWE", "guid": "b8c54a32"}},
                                    "kinds": ["superset"],
                                }
                            ],
                        },
                        {
                            "id": "DM_DEFAULT_ENCODING",
                            "shortDescription": {"text": "Reliance on default encoding"},
                            "messageStrings": {"default": {"text": "Found reliance on default encoding in {0}"}},
                            "properties": {"tags": ["I18N"]},
                        },
                    ],
                    "supportedTaxonomies": [{"name": "CWE", "guid": "b8c54a32"}],
                },
                "extensions": [{"name": "com.h3xstream.findsecbugs", "version": "1.13.0"}],
            },
            "taxonomies": [{"name": "CWE", "guid": "b8c54a32", "version": "4.4", "taxa": [{"id": "89"}]}],
            "originalUriBaseIds": {base: {"uri": f"file://{ROOT}/worker/src/main/java/"}},
            "results": [
                {
                    "ruleId": "SQL_INJECTION_JDBC",
                    "ruleIndex": 0,
                    "message": {"id": "default", "arguments": ["java/sql/Statement.executeQuery(String)"]},
                    "level": "error",
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "com/acme/Report.java", "uriBaseId": base},
                                "region": {"startLine": 31},
                            },
                            "logicalLocations": [
                                {
                                    "name": "monthly",
                                    "kind": "function",
                                    "fullyQualifiedName": "com.acme.Report.monthly(String)",
                                }
                            ],
                        }
                    ],
                },
                {
                    "ruleId": "DM_DEFAULT_ENCODING",
                    "ruleIndex": 1,
                    "message": {"id": "default", "arguments": ["com.acme.Report.write()"]},
                    "level": "note",
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "com/acme/Report.java", "uriBaseId": base},
                                "region": {"startLine": 58},
                            }
                        }
                    ],
                },
            ],
        }
    )


def eslint() -> dict:  # type: ignore[type-arg]
    def file(rel: str) -> str:
        return f"file://{ROOT}/{rel}"

    rules = [
        {
            "id": "no-unsanitized/property",
            "helpUri": "https://github.com/mozilla/eslint-plugin-no-unsanitized",
            "properties": {"category": "Possible Errors"},
            "shortDescription": {"text": "ensure no unsanitized code is assigned to innerHTML"},
        },
        {
            "id": "no-unused-vars",
            "helpUri": "https://eslint.org/docs/latest/rules/no-unused-vars",
            "properties": {"category": "Variables"},
            "shortDescription": {"text": "Disallow unused variables"},
        },
        {
            "id": "security/detect-eval-with-expression",
            "helpUri": "https://github.com/eslint-community/eslint-plugin-security",
            "properties": {"category": "Possible Security Vulnerability"},
            "shortDescription": {"text": "Detects eval(variable)"},
        },
        {
            "id": "security/detect-child-process",
            "helpUri": "https://github.com/eslint-community/eslint-plugin-security",
            "properties": {"category": "Possible Security Vulnerability"},
            "shortDescription": {"text": "Detects instances of child_process and non-literal exec()"},
        },
    ]
    files = ["ui/src/render.js", "ui/src/util.js", "ui/src/legacy.js", "api/server.js"]

    def result(rule: int, rel: str, line: int, level: str, msg: str, suppressed: bool = False) -> dict:  # type: ignore[type-arg]
        return {
            "level": level,
            "message": {"text": msg},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file(rel), "index": files.index(rel)},
                        "region": {"startLine": line, "startColumn": 3, "endLine": line, "endColumn": 30},
                    }
                }
            ],
            "ruleId": rules[rule]["id"],
            "ruleIndex": rule,
            "suppressions": [{"kind": "inSource", "justification": "legacy widget, sandboxed"}] if suppressed else [],
        }

    return _log(
        {
            "tool": {
                "driver": {
                    "name": "ESLint",
                    "informationUri": "https://eslint.org",
                    "rules": rules,
                    "version": "9.12.0",
                }
            },
            "artifacts": [{"location": {"uri": file(f)}} for f in files],
            "results": [
                result(0, "ui/src/render.js", 12, "error", "Unsafe assignment to innerHTML"),
                result(1, "ui/src/util.js", 3, "warning", "'unused' is defined but never used."),
                result(2, "ui/src/legacy.js", 8, "error", "eval with argument of type Identifier", suppressed=True),
                result(3, "api/server.js", 20, "error", "Found child_process.exec() with non Literal first argument"),
            ],
            "columnKind": "utf16CodeUnits",
        }
    )


def codeql() -> dict:  # type: ignore[type-arg]
    def rule(rid: str, name: str, cwe: str, sev: str) -> dict:  # type: ignore[type-arg]
        return {
            "id": rid,
            "name": rid,
            "shortDescription": {"text": name},
            "fullDescription": {"text": name + "."},
            "defaultConfiguration": {"enabled": True, "level": "error"},
            "properties": {
                "tags": ["security", f"external/cwe/cwe-{cwe}"],
                "description": name,
                "id": rid,
                "kind": "path-problem",
                "name": name,
                "precision": "high",
                "problem.severity": "error",
                "security-severity": sev,
            },
        }

    py = [rule("py/sql-injection", "SQL query built from user-controlled sources", "089", "8.8")]
    java = [
        rule("java/xss", "Cross-site scripting", "079", "6.1"),
        rule("java/sql-injection", "Query built from user-controlled sources", "089", "8.8"),
    ]

    def result(rid: str, comp: int, idx: int, path: str, line: int, msg: str) -> dict:  # type: ignore[type-arg]
        return {
            "ruleId": rid,
            "rule": {"id": rid, "index": idx, "toolComponent": {"index": comp}},
            "message": {"text": msg},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": path, "uriBaseId": "%SRCROOT%", "index": 0},
                        "region": {"startLine": line, "startColumn": 18, "endColumn": 50},
                    }
                }
            ],
            "partialFingerprints": {
                "primaryLocationLineHash": hashlib.sha256(path.encode()).hexdigest()[:16] + ":1",
                "primaryLocationStartColumnFingerprint": "13",
            },
            "codeFlows": [],
            "relatedLocations": [],
        }

    return _log(
        {
            "tool": {
                "driver": {"name": "CodeQL", "organization": "GitHub", "semanticVersion": "2.19.1", "rules": []},
                "extensions": [
                    {"name": "codeql/python-queries", "semanticVersion": "1.3.0", "rules": py},
                    {"name": "codeql/java-queries", "semanticVersion": "1.1.9", "rules": java},
                ],
            },
            "artifacts": [{"location": {"uri": "web/app/db.py", "uriBaseId": "%SRCROOT%", "index": 0}}],
            "results": [
                result(
                    "py/sql-injection",
                    0,
                    0,
                    "web/app/db.py",
                    42,
                    "This SQL query depends on a [user-provided value](1).",
                ),
                result(
                    "java/sql-injection",
                    1,
                    1,
                    "worker/src/main/java/com/acme/Report.java",
                    31,
                    "This query depends on a [user-provided value](1).",
                ),
            ],
            "automationDetails": {"id": "/language:python/"},
            "properties": {"semmle.formatSpecifier": "sarifv2.1.0"},
        }
    )


def trivy_web() -> dict:  # type: ignore[type-arg]
    pkg_path = "opt/app-root/lib64/python3.11/site-packages/requests-2.25.0.dist-info/METADATA"
    return {
        "SchemaVersion": 2,
        "ArtifactName": f"{WEB}:1.4.2",
        "ArtifactType": "container_image",
        "Metadata": {"OS": {"Family": "redhat", "Name": "9.6"}, "RepoTags": [f"{WEB}:1.4.2"]},
        "Results": [
            {
                "Target": "Python",
                "Class": "lang-pkgs",
                "Type": "python-pkg",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2099-3001",
                        "PkgID": "requests@2.25.0",
                        "PkgName": "requests",
                        "PkgPath": pkg_path,
                        "PkgIdentifier": {"PURL": "pkg:pypi/requests@2.25.0"},
                        "InstalledVersion": "2.25.0",
                        "FixedVersion": "2.31.0",
                        "Status": "fixed",
                        "Severity": "MEDIUM",
                        "CVSS": {"ghsa": {"V3Score": 6.1}},
                    }
                ],
            }
        ],
    }


def grype_api() -> dict:  # type: ignore[type-arg]
    return {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2099-3002",
                    "severity": "High",
                    "fix": {"versions": ["4.17.21"], "state": "fixed"},
                    "cvss": [{"version": "3.1", "metrics": {"baseScore": 7.2}}],
                },
                "relatedVulnerabilities": [],
                "matchDetails": [],
                "artifact": {
                    "id": "a1",
                    "name": "lodash",
                    "version": "4.17.20",
                    "type": "npm",
                    "locations": [
                        {"path": "/opt/app-root/src/package-lock.json", "layerID": "sha256:" + "c3" * 32},
                        {
                            "path": "/opt/app-root/src/node_modules/lodash/package.json",
                            "layerID": "sha256:" + "c4" * 32,
                        },
                    ],
                    "language": "javascript",
                    "licenses": ["MIT"],
                    "cpes": [],
                    "purl": "pkg:npm/lodash@4.17.20",
                    "upstreams": [],
                },
            }
        ],
        "source": {"type": "image", "target": {"userInput": f"{API}:1.4.2", "tags": [f"{API}:1.4.2"]}},
        "distro": {"name": "rhel", "version": "9.6"},
        "descriptor": {"name": "grype", "version": "0.82.0"},
    }


def cyclonedx_worker() -> dict:  # type: ignore[type-arg]
    ref = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?package-id=w1"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"type": "container", "name": f"{WORKER}:1.4.2"}},
        "components": [
            {"type": "operating-system", "name": "rhel", "version": "9.6"},
            {
                "bom-ref": ref,
                "type": "library",
                "group": "org.apache.logging.log4j",
                "name": "log4j-core",
                "version": "2.14.1",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "properties": [
                    {"name": "syft:package:type", "value": "java-archive"},
                    {"name": "syft:location:0:layerID", "value": "sha256:" + "d5" * 32},
                    {"name": "syft:location:0:path", "value": "/deployments/worker.jar"},
                ],
            },
        ],
        "vulnerabilities": [
            {
                "bom-ref": "v1",
                "id": "CVE-2099-3003",
                "ratings": [{"score": 10.0, "severity": "critical", "method": "CVSSv31"}],
                "affects": [
                    {
                        "ref": ref,
                        "versions": [
                            {"version": "2.14.1", "status": "affected"},
                            {"range": "vers:maven/>=2.17.1", "status": "unaffected"},
                        ],
                    }
                ],
            }
        ],
    }


def expected() -> dict:  # type: ignore[type-arg]
    return {
        "findings": {  # id -> (tools, severity, shipped how per image)
            "web/app/db.py:42/CWE-89": {
                "tools": ["Bandit", "CodeQL", "Semgrep OSS"],
                "severity": "high",
                "shipped": [[WEB, "copied"]],
            },
            "web/app/views.py:17/CWE-78": {"tools": ["Bandit"], "severity": "high", "shipped": [[WEB, "copied"]]},
            "web/app/config.py:5/CWE-259": {"tools": ["Bandit"], "severity": "low", "shipped": [[WEB, "copied"]]},
            "ui/src/render.js:12/no-unsanitized/property": {
                "tools": ["ESLint"],
                "severity": "high",
                "shipped": [[UI, "built"]],
            },
            "api/server.js:20/security/detect-child-process": {
                "tools": ["ESLint"],
                "severity": "high",
                "shipped": [[API, "copied"]],
            },
            "worker/src/main/java/com/acme/Report.java:31/CWE-89": {
                "tools": ["CodeQL", "SpotBugs"],
                "severity": "high",
                "shipped": [[WORKER, "built"]],
            },
            "web/tests/test_db.py:10/CWE-703": {"tools": ["Bandit"], "severity": "low", "shipped": []},
            "tools/seed.py:4/CWE-798": {"tools": ["Semgrep OSS"], "severity": "high", "shipped": []},
        },
        "ranked": [
            "web/app/db.py:42/CWE-89",
            "ui/src/render.js:12/no-unsanitized/property",
            "web/app/views.py:17/CWE-78",
            "worker/src/main/java/com/acme/Report.java:31/CWE-89",
            "api/server.js:20/security/detect-child-process",
            "web/app/config.py:5/CWE-259",
        ],
        "excluded": {
            "web/app/config.py:9/CWE-798": "fixed",
            "ui/src/legacy.js:8/security/detect-eval-with-expression": (
                "suppressed (inSource): legacy widget, sandboxed"
            ),
        },
        "quality": 2,  # ESLint no-unused-vars, SpotBugs DM_DEFAULT_ENCODING
        "sca": {
            "CVE-2099-3001": {
                "declaredIn": [["web/requirements.txt", 2]],
                "copiedFrom": [],
                "action": "update requests from 2.25.0 to 2.31.0 in web/requirements.txt:2",
            },
            "CVE-2099-3002": {
                "declaredIn": [["api/package-lock.json", 8], ["api/package.json", 5]],
                "copiedFrom": [["api/package-lock.json", 3]],
                "action": "update lodash from 4.17.20 to 4.17.21 in api/package.json:5",
            },
            "CVE-2099-3003": {
                "declaredIn": [["worker/pom.xml", 5]],
                "copiedFrom": [],
                "action": "update log4j-core from 2.14.1 to 2.17.1 in worker/pom.xml:5",
            },
        },
    }


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for rel, text in REPO.items():
        p = out / "repo" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    for name, doc in (
        ("semgrep.sarif", semgrep()),
        ("bandit.sarif", bandit()),
        ("spotbugs.sarif", spotbugs()),
        ("eslint.sarif", eslint()),
        ("codeql.sarif", codeql()),
        ("trivy-web.json", trivy_web()),
        ("grype-api.json", grype_api()),
        ("cyclonedx-worker.json", cyclonedx_worker()),
        ("expected.json", expected()),
    ):
        (out / name).write_text(json.dumps(doc, indent=1) + "\n")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
