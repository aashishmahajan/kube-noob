"""Write the 60 labelled build logs for the R4.1 gate: ``python tests/fixtures/build_logs/generate.py``.

Each log is a complete job log in the shape its CI system writes (GitHub Actions with runner timestamps and
``##[group]Run`` steps, Jenkins Pipeline and freestyle consoles, ``tkn pipelinerun logs`` with ``[task : step]``
prefixes, ``oc logs build/<name>`` with buildah STEP lines), with successful steps before the failure, warnings and
retries that are not the cause, and the tool's own error lines in the failing step. ``labels.json`` holds the system,
the cause class and the failing step for each file. The output is deterministic: run it again and nothing changes.
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).parent
SHA = "5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"

# -- what failed: (command, tool output lines, exit code) per cause class ----------------------------------------
SNIPPETS: dict[str, list[tuple[str, list[str], int]]] = {
    "dependency-fetch": [
        (
            "npm ci",
            [
                "npm WARN deprecated inflight@1.0.6: This module is not supported, and leaks memory.",
                "npm ERR! code E404",
                "npm ERR! 404 Not Found - GET https://registry.npmjs.org/@acme%2fui-kit - Not found",
                "npm ERR! 404",
                "npm ERR! 404  '@acme/ui-kit@^2.3.0' is not in this registry.",
                "npm ERR! A complete log of this run can be found in: /home/runner/.npm/_logs/debug-0.log",
            ],
            1,
        ),
        (
            "pip install -r requirements.txt",
            [
                "Collecting flask==3.0.3",
                "  Downloading flask-3.0.3-py3-none-any.whl (101 kB)",
                "ERROR: Could not find a version that satisfies the requirement acme-internal==1.4.2 "
                "(from versions: none)",
                "ERROR: No matching distribution found for acme-internal==1.4.2",
            ],
            1,
        ),
        (
            "mvn -B -DskipTests package",
            [
                "[INFO] Scanning for projects...",
                "[INFO] ------------------------< com.acme:orders >-------------------------",
                "[INFO] BUILD FAILURE",
                "[ERROR] Failed to execute goal on project orders: Could not resolve dependencies for project "
                "com.acme:orders:jar:1.0.0: Could not find artifact com.acme:shared-lib:jar:2.1.0 in central "
                "(https://repo.maven.apache.org/maven2) -> [Help 1]",
            ],
            1,
        ),
        (
            "go mod download",
            [
                "go: downloading github.com/acme/kit v1.2.3",
                "go: github.com/acme/kit@v1.2.3: reading https://proxy.golang.org/github.com/acme/kit/@v/v1.2.3.mod: "
                "404 Not Found",
                "\tserver response: not found: github.com/acme/kit@v1.2.3: invalid version: unknown revision v1.2.3",
            ],
            1,
        ),
        (
            "dnf install -y nodejs",
            [
                "Updating Subscription Management repositories.",
                "Errors during downloading metadata for repository 'ubi-9-appstream-rpms':",
                "  - Curl error (6): Couldn't resolve host name for https://cdn-ubi.redhat.com/content/public/ubi/dist/"
                "ubi9/9/x86_64/appstream/os/repodata/repomd.xml [Could not resolve host: cdn-ubi.redhat.com]",
                "Error: Failed to download metadata for repo 'ubi-9-appstream-rpms': Cannot download repomd.xml: "
                "Cannot download repodata/repomd.xml: All mirrors were tried",
            ],
            1,
        ),
        (
            "./gradlew build",
            [
                "> Task :app:compileJava FAILED",
                "",
                "FAILURE: Build failed with an exception.",
                "",
                "* What went wrong:",
                "Execution failed for task ':app:compileJava'.",
                "> Could not resolve all files for configuration ':app:compileClasspath'.",
                "   > Could not find com.acme:shared:2.0.0.",
                "",
                "BUILD FAILED in 14s",
            ],
            1,
        ),
    ],
    "compile": [
        (
            "mvn -B -DskipTests package",
            [
                "[INFO] --- maven-compiler-plugin:3.13.0:compile (default-compile) @ orders ---",
                "[INFO] Compiling 42 source files with javac [debug target 17] to target/classes",
                "[ERROR] COMPILATION ERROR : ",
                "[ERROR] /workspace/source/src/main/java/com/acme/orders/OrderService.java:[57,23] cannot find symbol",
                "  symbol:   method findByCustomer(java.lang.String)",
                "  location: variable repository of type com.acme.orders.OrderRepository",
                "[INFO] 1 error",
                "[INFO] BUILD FAILURE",
                "[ERROR] Failed to execute goal org.apache.maven.plugins:maven-compiler-plugin:3.13.0:compile "
                "(default-compile) on project orders: Compilation failure",
            ],
            1,
        ),
        (
            "npm run build",
            [
                "> web@1.4.0 build",
                "> tsc -p tsconfig.json && vite build",
                "",
                "src/api/client.ts(41,7): error TS2322: Type 'string | undefined' is not assignable to type 'string'.",
            ],
            2,
        ),
        (
            "go build ./...",
            [
                "# github.com/acme/billing/internal/invoice",
                "internal/invoice/render.go:88:14: undefined: formatCurrency",
                "internal/invoice/render.go:91:2: cannot use total (variable of type float64) as int value in "
                "assignment",
            ],
            1,
        ),
        (
            "npm run build",
            [
                "> shop@0.9.0 build",
                "> react-scripts build",
                "",
                "Creating an optimized production build...",
                "Failed to compile.",
                "",
                "Module not found: Error: Can't resolve './components/Chart' in '/opt/app-root/src/src/pages'",
            ],
            1,
        ),
        (
            "make all",
            [
                "gcc -O2 -Wall -c src/lexer.c -o build/lexer.o",
                "src/lexer.c:40:9: warning: unused variable 'tmp' [-Wunused-variable]",
                "gcc -O2 -Wall -c src/parser.c -o build/parser.o",
                "src/parser.c:112:5: error: implicit declaration of function 'parse_token' "
                "[-Wimplicit-function-declaration]",
                "make: *** [Makefile:24: build/parser.o] Error 1",
            ],
            2,
        ),
        (
            "cargo build --release",
            [
                "   Compiling serde v1.0.210",
                "   Compiling acme-agent v0.3.1 (/workspace/source)",
                "error[E0425]: cannot find value `config_path` in this scope",
                "  --> src/main.rs:22:31",
                'error: could not compile `acme-agent` (bin "acme-agent") due to 1 previous error',
            ],
            101,
        ),
    ],
    "test": [
        (
            "pytest -q",
            [
                "============================= test session starts ==============================",
                "collected 214 items",
                "tests/test_api.py ....................F.....",
                "=================================== FAILURES ===================================",
                "___________________________ test_refund_rounding ___________________________",
                "E       AssertionError: assert Decimal('10.01') == Decimal('10.00')",
                "FAILED tests/test_api.py::test_refund_rounding - AssertionError: assert Decimal('10.01') == "
                "Decimal('10.00')",
                "========================= 1 failed, 213 passed in 41.27s =========================",
            ],
            1,
        ),
        (
            "mvn -B verify",
            [
                "[INFO] Running com.acme.orders.OrderServiceTest",
                "[ERROR] Tests run: 18, Failures: 1, Errors: 0, Skipped: 0, Time elapsed: 2.311 s <<< FAILURE! -- in "
                "com.acme.orders.OrderServiceTest",
                "[ERROR] com.acme.orders.OrderServiceTest.cancelsExpiredOrders -- Time elapsed: 0.042 s <<< FAILURE!",
                "org.opentest4j.AssertionFailedError: expected: <CANCELLED> but was: <OPEN>",
                "[ERROR] Tests run: 120, Failures: 1, Errors: 0, Skipped: 2",
                "[ERROR] There are test failures.",
            ],
            1,
        ),
        (
            "npm test -- --ci",
            [
                "FAIL src/cart/__tests__/totals.test.ts",
                "  ● totals › applies the discount once",
                "    expect(received).toBe(expected) // Object.is equality",
                "Test Suites: 1 failed, 23 passed, 24 total",
                "Tests:       1 failed, 187 passed, 188 total",
            ],
            1,
        ),
        (
            "go test ./...",
            [
                "ok  \tgithub.com/acme/billing/internal/invoice\t0.031s",
                "=== RUN   TestRetryBackoff",
                "    backoff_test.go:42: got 400ms, want 200ms",
                "--- FAIL: TestRetryBackoff (0.00s)",
                "FAIL",
                "FAIL\tgithub.com/acme/billing/internal/retry\t0.012s",
            ],
            1,
        ),
        (
            "./gradlew test",
            [
                "> Task :app:test FAILED",
                "",
                "OrderControllerTest > rejectsUnknownCustomer() FAILED",
                "    java.lang.AssertionError at OrderControllerTest.java:77",
                "",
                "There were failing tests. See the report at: file:///workspace/app/build/reports/tests/test/index.html",
            ],
            1,
        ),
    ],
    "image-push": [
        (
            "podman push quay.io/acme/api:1.8.0",
            [
                "Getting image source signatures",
                f"Copying blob sha256:{SHA}",
                "Error: writing blob: uploading layer chunked: received unexpected HTTP status: 503 Service "
                "Unavailable",
            ],
            125,
        ),
        (
            "docker push quay.io/acme/web-frontend:2.0.1",
            [
                "The push refers to repository [quay.io/acme/web-frontend]",
                "5f70bf18a086: Preparing",
                "name unknown: repository name not known to registry",
            ],
            1,
        ),
        (
            "buildah push registry.internal.acme.com/team/api:1.8.0",
            [
                "Getting image source signatures",
                'Error: pushing image "registry.internal.acme.com/team/api:1.8.0" to '
                '"docker://registry.internal.acme.com/team/api:1.8.0": trying to reuse blob sha256:'
                + SHA
                + " at destination: pinging container registry registry.internal.acme.com: Get "
                '"https://registry.internal.acme.com/v2/": tls: failed to verify certificate: x509: certificate signed '
                "by unknown authority",
            ],
            125,
        ),
    ],
    "registry-auth": [
        (
            "docker push docker.io/acme/api:1.8.0",
            [
                "The push refers to repository [docker.io/acme/api]",
                "5f70bf18a086: Preparing",
                "denied: requested access to the resource is denied",
            ],
            1,
        ),
        (
            "npm ci",
            [
                "npm ERR! code E401",
                "npm ERR! Unable to authenticate, your authentication token seems to be invalid.",
                "npm ERR! To correct this please try logging in again with:",
                "npm ERR!     npm login",
            ],
            1,
        ),
        (
            "mvn -B deploy",
            [
                "[INFO] Uploading to acme-releases: https://nexus.acme.com/repository/releases/com/acme/orders/1.0.0/"
                "orders-1.0.0.jar",
                "[ERROR] Failed to execute goal org.apache.maven.plugins:maven-deploy-plugin:3.1.2:deploy "
                "(default-deploy) on project orders: Failed to deploy artifacts: Could not transfer artifact "
                "com.acme:orders:jar:1.0.0 from/to acme-releases (https://nexus.acme.com/repository/releases/): status "
                "code: 401, reason phrase: Unauthorized (401) -> [Help 1]",
            ],
            1,
        ),
    ],
    "quota": [
        (
            "oc apply -f deploy/",
            [
                'Error from server (Forbidden): error when creating "deploy/api.yaml": pods "api-7f9c" is forbidden: '
                "exceeded quota: compute, requested: requests.cpu=2, used: requests.cpu=7, limited: requests.cpu=8",
            ],
            1,
        ),
        (
            "docker build -t acme/web .",
            [
                "#9 [build 5/7] RUN npm run build",
                "#9 ERROR: failed to copy files: copy file range failed: no space left on device",
                "ERROR: failed to solve: failed to copy files: copy file range failed: no space left on device",
            ],
            1,
        ),
        (
            "kubectl apply -f k8s/job.yaml",
            [
                'Error from server (Forbidden): error when creating "k8s/job.yaml": pods "migrate" is forbidden: '
                "maximum memory usage per Container is 2Gi, but limit is 4Gi",
            ],
            1,
        ),
    ],
    "timeout": [],  # system-specific: see the wrappers
    "out-of-memory": [
        (
            "npm run build",
            [
                "> web@1.4.0 build",
                "> vite build",
                "<--- Last few GCs --->",
                "[412:0x5f2c]    92310 ms: Mark-Compact 2046.2 (2081.1) -> 2045.9 (2082.3) MB",
                "FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory",
                " 1: 0xb7c3a0 node::Abort() [node]",
                "Aborted (core dumped)",
            ],
            134,
        ),
        (
            "mvn -B package",
            [
                "[INFO] --- maven-shade-plugin:3.6.0:shade (default) @ orders ---",
                'Exception in thread "main" java.lang.OutOfMemoryError: Java heap space',
            ],
            1,
        ),
        (
            "npm run build",
            [
                "> web@1.4.0 build",
                "> webpack --mode production",
                "/bin/sh: line 1:   412 Killed                  webpack --mode production",
            ],
            137,
        ),
        (
            "./gradlew assemble",
            [
                "> Task :app:compileKotlin",
                "Expiring Daemon because JVM heap space is exhausted",
                "Daemon will be stopped at the end of the build after running out of JVM memory",
            ],
            1,
        ),
    ],
    "permissions": [
        (
            "npm ci",
            [
                "npm ERR! code EACCES",
                "npm ERR! syscall mkdir",
                "npm ERR! path /.npm",
                "npm ERR! errno -13",
                "npm ERR! Error: EACCES: permission denied, mkdir '/.npm'",
            ],
            243,
        ),
        (
            "make install",
            [
                "install -d /app/logs",
                "mkdir: cannot create directory '/app/logs': Permission denied",
                "make: *** [Makefile:40: install] Error 1",
            ],
            2,
        ),
        (
            "oc apply -f debug-pod.yaml",
            [
                'Error from server (Forbidden): error when creating "debug-pod.yaml": pods "debug" is forbidden: '
                'unable to validate against any security context constraint: [provider "anyuid": Forbidden: not '
                "usable by user or serviceaccount, spec.containers[0].securityContext.privileged: Invalid value: true: "
                "Privileged "
                "containers are not allowed]",
            ],
            1,
        ),
        (
            "oc set image deployment/api api=quay.io/acme/api:1.8.0 -n prod",
            [
                'Error from server (Forbidden): deployments.apps "api" is forbidden: User '
                '"system:serviceaccount:ci:pipeline" cannot patch resource "deployments" in API group "apps" in the '
                'namespace "prod"',
            ],
            1,
        ),
    ],
}

GOOD_NOISE = [
    "npm WARN config production Use `--omit=dev` instead.",
    "Retrying (Retry(total=4, connect=None, read=None, redirect=None, status=None)) after connection broken by "
    "'ReadTimeoutError(\"HTTPSConnectionPool(host='pypi.org', port=443): Read timed out. (read timeout=15)\")'",
    "[INFO] Tests run: 120, Failures: 0, Errors: 0, Skipped: 2",
    "warning: unused import: `std::fmt`",
    "found 0 vulnerabilities",
]


# -- the CI systems -----------------------------------------------------------------------------------------------
def _ts(i: int) -> str:
    return f"2026-10-27T10:{11 + i // 60:02d}:{i % 60:02d}.{(i * 7919) % 10_000_000:07d}Z "


def github(cmd: str, body: list[str], code: int, cls: str, variant: int) -> tuple[list[str], str]:
    lines = [
        "Requested labels: ubuntu-24.04",
        "Job defined at: acme/app/.github/workflows/ci.yml@refs/heads/main",
        "Waiting for a runner to pick up this job...",
        "Job is about to start running on the hosted runner: GitHub Actions 7 (hosted)",
        "Current runner version: '2.329.0'",
        "##[group]Operating System",
        "Ubuntu",
        "24.04.3",
        "LTS",
        "##[endgroup]",
        "##[group]GITHUB_TOKEN Permissions",
        "Contents: read",
        "Metadata: read",
        "##[endgroup]",
        "Secret source: Actions",
        "Prepare workflow directory",
        "Prepare all required actions",
        "Getting action download info",
        "Download action repository 'actions/checkout@v4' (SHA:11bd71901bbe5b1630ceea73d27597364c9af683)",
        "Complete job name: build",
        "##[group]Run actions/checkout@v4",
        "with:",
        "  repository: acme/app",
        "  fetch-depth: 1",
        "##[endgroup]",
        "Syncing repository: acme/app",
        "##[group]Getting Git version info",
        "git version 2.51.0",
        "##[endgroup]",
        "[command]/usr/bin/git checkout --progress --force -B main refs/remotes/origin/main",
        "Switched to a new branch 'main'",
        "##[group]Run actions/setup-node@v4",
        "with:",
        "  node-version: 20",
        "##[endgroup]",
        "Found in cache @ /opt/hostedtoolcache/node/20.18.0/x64",
        GOOD_NOISE[variant % len(GOOD_NOISE)],
    ]
    step = cmd
    if cls == "timeout":
        step = "make integration-test"
        lines += [
            f"##[group]Run {step}",
            step,
            "shell: /usr/bin/bash -e {0}",
            "##[endgroup]",
            "go test -tags integration ./test/...",
            "=== RUN   TestCheckoutFlow",
        ]
        if variant % 2:
            lines += [
                "##[error]The job running on runner GitHub Actions 7 has exceeded the maximum execution time "
                "of 60 minutes.",
                "##[error]The operation was canceled.",
            ]
        else:
            lines += ["##[error]The action 'Integration tests' has timed out after 30 minutes."]
    else:
        lines += [
            f"##[group]Run {cmd}",
            cmd,
            "shell: /usr/bin/bash -e {0}",
            "##[endgroup]",
            *body,
            f"##[error]Process completed with exit code {code}.",
        ]
    lines += ["Post job cleanup.", "[command]/usr/bin/git version", "Cleaning up orphan processes"]
    return [_ts(i) + x for i, x in enumerate(lines)], step


def jenkins(cmd: str, body: list[str], code: int, cls: str, variant: int) -> tuple[list[str], str]:
    if variant % 4 == 3 and cls != "timeout":  # a freestyle job
        lines = [
            "Started by an SCM change",
            "Running as SYSTEM",
            "Building on the built-in node in workspace /var/lib/jenkins/workspace/billing-build",
            "The recommended git tool is: NONE",
            "No credentials specified",
            " > git rev-parse --resolve-git-dir /var/lib/jenkins/workspace/billing-build/.git # timeout=10",
            "Checking out Revision 1f2e3d4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e (refs/remotes/origin/main)",
            "[billing-build] $ /bin/sh -xe /tmp/jenkins8123456789.sh",
            f"+ {cmd}",
            *body,
            "Build step 'Execute shell' marked build as failure",
            "Finished: FAILURE",
        ]
        return lines, "Execute shell"
    stage = {
        "test": "Test",
        "image-push": "Publish",
        "registry-auth": "Publish",
        "quota": "Deploy",
        "permissions": "Deploy",
        "timeout": "Integration",
    }.get(cls, "Build")
    if cls == "registry-auth" and cmd.startswith("npm"):
        stage = "Build"
    lines = [
        "Started by user Dana",
        "Obtained Jenkinsfile from git https://github.com/acme/orders.git",
        "[Pipeline] Start of Pipeline",
        "[Pipeline] node",
        "Running on agent-linux-3 in /home/jenkins/agent/workspace/orders_main",
        "[Pipeline] {",
        "[Pipeline] stage",
        "[Pipeline] { (Declarative: Checkout SCM)",
        "[Pipeline] checkout",
        "The recommended git tool is: NONE",
        "using credential github-app",
        "Checking out Revision 1f2e3d4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e (main)",
        "[Pipeline] }",
        "[Pipeline] // stage",
        "[Pipeline] withEnv",
        "[Pipeline] {",
    ]
    if stage != "Build":
        lines += [
            "[Pipeline] stage",
            "[Pipeline] { (Build)",
            "[Pipeline] sh",
            "+ mvn -B -DskipTests package",
            "[INFO] BUILD SUCCESS",
            GOOD_NOISE[variant % len(GOOD_NOISE)],
            "[Pipeline] }",
            "[Pipeline] // stage",
        ]
    lines += ["[Pipeline] stage", f"[Pipeline] {{ ({stage})"]
    if cls == "timeout":
        lines += [
            "[Pipeline] timeout",
            "Timeout set to expire in 20 min",
            "[Pipeline] {",
            "[Pipeline] sh",
            "+ ./run-integration.sh",
            "Waiting for http://orders-test:8080/health ...",
            "Cancelling nested steps due to timeout",
            "Sending interrupt signal to process",
            "./run-integration.sh: line 12:  4122 Terminated              sleep 5",
            "script returned exit code 143",
            "[Pipeline] }",
            "[Pipeline] // timeout",
        ]
        end = ["Timeout has been exceeded", "Finished: ABORTED"]
    else:
        lines += ["[Pipeline] sh", f"+ {cmd}", *body]
        end = [f"ERROR: script returned exit code {code}", "Finished: FAILURE"]
    lines += ["[Pipeline] }", "[Pipeline] // stage"]
    order = ["Build", "Test", "Publish", "Deploy", "Integration"]
    for later in ("Test", "Publish", "Deploy"):
        if later != stage and order.index(later) > order.index(stage):
            lines += [
                "[Pipeline] stage",
                f"[Pipeline] {{ ({later})",
                f'Stage "{later}" skipped due to earlier failure(s)',
                "[Pipeline] }",
                "[Pipeline] // stage",
            ]
    lines += [
        "[Pipeline] stage",
        "[Pipeline] { (Declarative: Post Actions)",
        "[Pipeline] junit",
        "Recording test results",
        "[Pipeline] }",
        "[Pipeline] // stage",
        "[Pipeline] }",
        "[Pipeline] // withEnv",
        "[Pipeline] }",
        "[Pipeline] // node",
        "[Pipeline] End of Pipeline",
        *end,
    ]
    return lines, stage


def tekton(cmd: str, body: list[str], code: int, cls: str, variant: int) -> tuple[list[str], str]:
    run = f"app-ci-run-x7k2p-{variant:02d}"
    lines = [
        "[fetch-source : clone] + CHECKOUT_DIR=/workspace/output/",
        '[fetch-source : clone] {"level":"info","ts":1730023872.12,"caller":"git/git.go:176","msg":"Successfully '
        'cloned https://github.com/acme/web.git @ 1f2e3d4 (grafted, HEAD) in path /workspace/output/"}',
        f"[fetch-source : clone] {GOOD_NOISE[variant % len(GOOD_NOISE)]}",
    ]
    if cls == "timeout":
        lines += [
            "[e2e : run-tests] + npx playwright test",
            "[e2e : run-tests] Running 48 tests using 2 workers",
            "[e2e : run-tests]   ✓  checkout › pays with a saved card (3.1s)",
            f'task e2e failed: TaskRun "{run}-e2e" failed to finish within "15m0s". Run tkn tr desc '
            f"{run}-e2e for more details",
        ]
        return lines, "e2e : run-tests"
    if cls == "quota" and variant % 2 == 0:
        lines += [
            f'task build failed: TaskRun Pod exceeded available resources: pods "{run}-build-pod" is '
            "forbidden: exceeded quota: ci-quota, requested: limits.memory=4Gi, used: limits.memory=6Gi, "
            f"limited: limits.memory=8Gi. Run tkn tr desc {run}-build for more details"
        ]
        return lines, "build"
    task, step = ("build", "build") if cls not in {"test"} else ("unit-test", "run-tests")
    if cls in {"image-push", "registry-auth"} and "push" in cmd:
        step = "push"
        lines += [
            "[build : build] STEP 1/6: FROM registry.access.redhat.com/ubi9/nodejs-20:1-60",
            '[build : build] STEP 6/6: CMD ["npm", "start"]',
            "[build : build] COMMIT quay.io/acme/api:1.8.0",
            f"[build : build] --> {SHA[:12]}",
        ]
    lines += [f"[{task} : {step}] + {cmd}", *[f"[{task} : {step}] {x}" for x in body]]
    if cls == "out-of-memory" and variant % 2:
        tail = f'"step-{step}" exited with code 137: OOMKilled'
    else:
        tail = f'"step-{step}" exited with code {code}'
    lines += [f"task {task} failed: {tail}. Run tkn tr desc {run}-{task} for more details"]
    return lines, f"{task} : {step}"


def openshift(cmd: str, body: list[str], code: int, cls: str, variant: int) -> tuple[list[str], str]:
    head = [
        'Cloning "https://github.com/acme/web.git" ...',
        "\tCommit:\t1f2e3d4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e (Fix cart totals)",
        "\tAuthor:\tDana <dana@example.com>",
        "\tDate:\tMon Oct 26 10:11:12 2026 +0000",
        'time="2026-10-27T10:11:15Z" level=info msg="Not using native diff for overlay, this may cause degraded '
        'performance for building images: kernel has CONFIG_OVERLAY_FS_REDIRECT_DIR enabled"',
        'I1027 10:11:15.123456       1 defaults.go:112] Defaulting to storage driver "overlay" with options '
        "[mountopt=metacopy=on].",
        'Caching blobs under "/var/cache/blobs".',
    ]
    if cls == "registry-auth" and variant % 3 == 0:  # a private Git source without credentials
        return [
            head[0],
            'error: failed to fetch requested repository "https://github.com/acme/web.git" with provided credentials',
        ], "fetch source"
    base = "registry.access.redhat.com/ubi9/nodejs-20:1-60"
    if cls == "quota":
        base = "docker.io/library/node:20-alpine"
        return [
            *head,
            f"Trying to pull {base}...",
            f"STEP 1/7: FROM {base}",
            "error: build error: creating build container: initializing source docker://node:20-alpine: reading "
            "manifest 20-alpine in docker.io/library/node: toomanyrequests: You have reached your pull rate "
            "limit. You may increase the limit by authenticating and upgrading: "
            "https://www.docker.com/increase-rate-limit",
        ], f"FROM {base}"
    if cls == "registry-auth" and variant % 3 == 1:
        base = "registry.redhat.io/ubi9/nodejs-20:latest"
        return [
            *head,
            f"Trying to pull {base}...",
            f"STEP 1/7: FROM {base}",
            f"error: build error: creating build container: initializing source docker://{base}: unable to "
            "retrieve auth token: invalid username/password: unauthorized: Please login to the Red Hat Registry "
            "using your Customer Portal credentials.",
        ], f"FROM {base}"
    lines = [
        *head,
        f"Trying to pull {base}...",
        "Getting image source signatures",
        f"Copying blob sha256:{SHA}",
        "Writing manifest to image destination",
        f"STEP 1/7: FROM {base}",
        "STEP 2/7: WORKDIR /opt/app-root/src",
        f"--> {SHA[:12]}",
        "STEP 3/7: COPY package*.json ./",
        f"--> {SHA[1:13]}",
    ]
    if cls in {"image-push", "registry-auth"}:
        lines += [
            "STEP 4/7: RUN npm ci",
            "added 812 packages in 21s",
            f"--> {SHA[2:14]}",
            "STEP 5/7: COPY . .",
            "STEP 6/7: RUN npm run build",
            "built in 9.81s",
            'STEP 7/7: CMD ["npm", "start"]',
            "COMMIT temp.builder.openshift.io/shop/web-3:3b2a1c0d",
            f"--> {SHA[3:15]}",
            "Successfully tagged temp.builder.openshift.io/shop/web-3:3b2a1c0d",
            "Pushing image image-registry.openshift-image-registry.svc:5000/shop/web:latest ...",
            "Getting image source signatures",
            f"Copying blob sha256:{SHA}",
        ]
        if cls == "image-push":
            lines += [
                "error: build error: Failed to push image: writing blob: uploading layer to "
                "https://image-registry.openshift-image-registry.svc:5000/v2/shop/web/blobs/uploads/0b3f: blob "
                "upload unknown"
            ]
        else:
            lines += [
                "error: build error: Failed to push image: trying to reuse blob sha256:" + SHA + " at "
                "destination: checking whether a blob sha256:" + SHA + " exists in quay.io/acme/web: "
                "unauthorized: access to the requested resource is not authorized"
            ]
        return lines, "push image"
    step = f"RUN {cmd}"
    lines += [f"STEP 4/7: {step}", *body]
    status = 137 if cls == "out-of-memory" else code
    lines += [f'error: build error: building at STEP "{step}": while running runtime: exit status {status}']
    return lines, step


WRAPPERS = {"github-actions": github, "jenkins": jenkins, "tekton": tekton, "openshift-build": openshift}
PLAN: list[tuple[str, str]] = [
    *[
        ("github-actions", c)
        for c in (
            "dependency-fetch",
            "dependency-fetch",
            "compile",
            "compile",
            "test",
            "test",
            "image-push",
            "registry-auth",
            "quota",
            "timeout",
            "timeout",
            "out-of-memory",
            "out-of-memory",
            "permissions",
            "registry-auth",
            "test",
        )
    ],
    *[
        ("jenkins", c)
        for c in (
            "dependency-fetch",
            "compile",
            "compile",
            "test",
            "test",
            "image-push",
            "registry-auth",
            "quota",
            "quota",
            "timeout",
            "out-of-memory",
            "permissions",
            "permissions",
            "dependency-fetch",
            "compile",
        )
    ],
    *[
        ("tekton", c)
        for c in (
            "dependency-fetch",
            "compile",
            "test",
            "test",
            "image-push",
            "registry-auth",
            "quota",
            "quota",
            "timeout",
            "out-of-memory",
            "out-of-memory",
            "permissions",
            "dependency-fetch",
            "compile",
            "permissions",
        )
    ],
    *[
        ("openshift-build", c)
        for c in (
            "dependency-fetch",
            "dependency-fetch",
            "compile",
            "compile",
            "test",
            "image-push",
            "registry-auth",
            "registry-auth",
            "registry-auth",
            "quota",
            "out-of-memory",
            "out-of-memory",
            "permissions",
            "dependency-fetch",
        )
    ],
]


def main() -> None:
    assert len(PLAN) == 60
    labels = []
    seen: dict[str, int] = {}
    for n, (system, cls) in enumerate(PLAN, 1):
        variant = seen.get(cls, 0)
        seen[cls] = variant + 1
        options = SNIPPETS[cls] or [("", [], 1)]
        if system == "openshift-build" and cls == "permissions":
            options = [x for x in options if not x[0].startswith("oc ")]
        if system == "openshift-build" and cls == "dependency-fetch":
            options = [x for x in options if x[0].split()[0] in {"npm", "pip", "dnf", "go"}]
        cmd, body, code = options[variant % len(options)]
        lines, step = WRAPPERS[system](cmd, body, code, cls, variant)
        name = f"{n:02d}-{system}-{cls}.log"
        (HERE / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
        labels.append({"file": name, "system": system, "class": cls, "step": step})
    (HERE / "labels.json").write_text(json.dumps(labels, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
