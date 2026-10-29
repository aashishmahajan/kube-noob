# CEPH1: Ceph health-code catalogue for Rook-Ceph and OpenShift Data Foundation

Notes for the lead, who integrates CHANGELOG.md, README.md, docs/guidance.md, docs/use-cases.md and the loop state.

## What was built

- **Catalogue** `src/kube_noob/data/ceph_health.yaml` (90 KB) with its loader and Pydantic models (`extra="forbid"`)
  in `src/kube_noob/signals/ceph.py`. Each code has a one-sentence meaning, likely causes, a fix in words (never a
  command), read-only steps, the codes that usually cause it (`after`), search terms, and the Ceph doc section and
  source lines it was checked against at a pinned commit. Descriptions are kube-noob's own words; the Ceph docs
  (CC BY-SA 3.0) are cited, not copied.
- **New signal kind** `ceph_health` in the existing signals catalogue (`signals/catalogue.py`, `signals/core.py`):
  every code is a `ceph_health:<CODE>` entry with its citations, and each Rook or ODF alert is an `alert:<Name>`
  entry whose new `health_codes` field names the codes it watches. `for_text` turns a watched alert into the codes it
  implies (`CephOSDDiskNotResponding` implies `OSD_DOWN`), the same way phrases imply alerts.
- **Recognition** (`signals/ceph.py`, wired into `extract`): `ceph health detail` text (`[WRN] CODE: summary`, muted
  lines, the older layout without brackets), `ceph status` and `ceph health` summaries (mapped through the wording
  Ceph's source composes, only inside a health report), `ceph health detail -f json`, `ceph status -f json`, a Rook
  CephCluster (`status.ceph.details`, YAML or JSON, single or in a List) and that details map alone, as the first
  read-only step (`oc get cephcluster -o jsonpath='{.status.ceph.details}'`) prints it, so its output pastes back. Codes the docs or alert rules spell
  differently map to the emitted code (`MDS_HEALTH_READ_ONLY` to `MDS_READ_ONLY`). A catalogued code written in prose
  counts when the text is about Ceph or the code's own name says so (OSD, PG, MON, MDS...). `[WRN]` lines with
  uncatalogued codes are named (`notCatalogued`), never guessed.
- **Answers**: `diagnose` (CLI, `kubenoob_diagnose`, REST) returns `cephHealth`: platform and namespace, common read
  steps (CephCluster status, StorageCluster on ODF) and the toolbox `ceph health detail`, one entry per code (cause
  first, then errors before warnings), alerts that name no single code (`CephClusterWarningState`...), and `stop` when
  any entry escalates. `insight` names the new `ceph-health` input kind and shows one finding per code (meaning,
  cause, fix, `escalate`, toolbox commands marked as needing approval); its read-only steps start with the CephCluster
  status. The live debug bundle renders a Ceph section. Tool input descriptions mention Ceph output
  (`docs/api/openapi.json` regenerated).
- **Read-only by construction**: a step is either an `oc` read (`classify_step` says read, no Secret, no shell
  syntax) or a Ceph command matching `READ_ONLY_TOOLBOX`, checked when the catalogue loads. Commands that can lose
  data (OSDs or objects declared lost, OSD purge/destroy/out, forcing recovery or PG creation, monitor removal and
  monmap surgery, object store and CephFS recovery tools, pool deletion, PG repair, raising full ratios, auth
  removal) are refused anywhere in the catalogue's text. 14 codes carry `escalate`; their answer starts with "Stop and
  involve storage support (Red Hat support for OpenShift Data Foundation, your Ceph experts for Rook) before changing
  anything." and gives the reason.
- **Platforms** through `_for_platform`: ODF or OpenShift text (or an ODF-only alert) gets `oc` and
  `openshift-storage`; plain Kubernetes gets `kubectl` and `rook-ceph`; Rook on OpenShift keeps `rook-ceph` when the
  text names it. Toolbox commands are `oc exec -n <ns> deploy/rook-ceph-tools -- ceph ...` (kubectl the same), so
  flags such as `-f json` are never taken by `oc rsh`. The note says the ODF toolbox exists only when the
  StorageCluster sets `enableCephTools` (off by default). Commands carry the OSD, PG and monitor the input names, each
  through a `\Z` validator.
- **Re-verification script** `scripts/verify_ceph_catalogue.py --ceph DIR --rook DIR --odf DIR`: re-reads every
  citation (doc heading, source line, summary wording, alert rule line, the codes a rule's expression reads, ODF
  runbook links) at the pinned commits and lists the alerts left out. Run on 2026-10-29: 121 codes and 69 alerts,
  0 mismatches.

## Counts

- **121 entries covering 135 emitted codes** (the 11 `OSD_<crush type>_DOWN` names and 4 `_MANY` variants share an
  entry), plus 5 documented or alert-rule aliases. 114 are cited to the two Ceph docs; 7 are raised by the source
  but not in those pages, and are cited to source only (`POOL_NEARFULL`, `POOL_BACKFILLFULL`, `POOL_NO_REDUNDANCY`,
  `OSD_SLOW_PING_TIME_BACK`, `OSD_SLOW_PING_TIME_FRONT`, `DEGRADED_STRETCH_MODE`, `RECOVERING_STRETCH_MODE`). 104 have
  `ceph status` summary wording.
- **69 alerts**: 47 Rook (ceph-mixin based) and 27 ODF, 5 shipped by both under one name. 39 read the health code
  itself, 25 read another metric showing the same condition, 5 are overall-state alerts with their own steps.
- **Escalate (14)**: MON_DOWN, AUTH_INSECURE_KEYS_ALLOWED, OSD_FULL, BLUESTORE_DISK_SIZE_MISMATCH,
  DEVICE_HEALTH_TOOMANY, PG_AVAILABILITY, PG_RECOVERY_FULL, PG_DAMAGED, OSD_SCRUB_ERRORS, OBJECT_UNFOUND,
  DEGRADED_STRETCH_MODE, BLAUM_ROTH_W_IS_NOT_PRIME, MDS_DAMAGE, MDS_ALL_DOWN.
- **49 read-only steps**: 16 `oc` reads and 33 toolbox Ceph reads.

## Verification sources (all checked 2026-10-29)

| Source | URL | Commit |
|---|---|---|
| Ceph health checks doc | https://github.com/ceph/ceph/blob/eb3b634bccd18715735a74cf55808e98c5dbd04b/doc/rados/operations/health-checks.rst | eb3b634bccd18715735a74cf55808e98c5dbd04b |
| CephFS health messages doc | https://github.com/ceph/ceph/blob/eb3b634bccd18715735a74cf55808e98c5dbd04b/doc/cephfs/health-messages.rst | same |
| Ceph source (code names, summary wording, text and JSON formats) | `src/mon/HealthMonitor.cc`, `src/mon/Monitor.cc`, `src/mon/health_check.h`, `src/include/health.h`, `src/osd/OSDMap.cc`, `src/mon/PGMap.cc`, `src/mon/AuthMonitor.cc`, `src/mon/MgrMonitor.cc`, `src/mgr/PyModuleRegistry.cc`, `src/mgr/DaemonHealthMetricCollector.cc`, `src/messages/MMDSBeacon.h`, `src/mon/MDSMonitor.cc`, `src/mds/MDSMap.cc`, `src/mds/FSMap.cc`, `src/mon/NVMeofGwMap.cc`, `src/pybind/mgr/{crash,devicehealth,pg_autoscaler,telemetry,prometheus}/module.py` | same |
| Ceph CLI commands used in steps | `doc/man/8/ceph.rst`, `doc/rados/troubleshooting/troubleshooting-pg.rst`, `doc/cephfs/damaged-rank.rst`, `doc/mgr/crash.rst`, `doc/rados/operations/devices.rst` | same |
| Ceph licence (docs CC-BY-SA-3.0, code LGPL-2.1 or LGPL-3) | https://github.com/ceph/ceph/blob/eb3b634bccd18715735a74cf55808e98c5dbd04b/COPYING | same |
| Rook alert rules | https://github.com/rook/rook/blob/61a8fea150f63616ab48853b0dafb1f32933331c/deploy/charts/rook-ceph-cluster/prometheus/localrules.yaml (same alert names as `deploy/examples/monitoring/localrules.yaml`) | 61a8fea150f63616ab48853b0dafb1f32933331c |
| Rook toolbox, labels, CephCluster status | `deploy/examples/toolbox.yaml` (deploy/rook-ceph-tools in rook-ceph), `Documentation/Troubleshooting/ceph-toolbox.md` (`kubectl -n rook-ceph exec -it deploy/rook-ceph-tools -- bash`), `pkg/operator/k8sutil/pod.go` (label key `app`), `pkg/operator/ceph/cluster/{osd/osd.go,mon/mon.go,mgr/mgr.go}`, `pkg/operator/ceph/file/mds/mds.go` (`rook-ceph-osd`, `-mon`, `-mgr`, `-mds`; `rook-ceph-osd-%d`; `ceph-osd-id`), `pkg/apis/ceph.rook.io/v1/types.go` (CephStatus `health`, `details`; MonSpec `allowMultiplePerNode`), `deploy/examples/operator.yaml` (`rook-ceph-operator`), LICENSE (Apache-2.0) | same |
| ODF Ceph alert rules | https://github.com/red-hat-storage/ocs-operator/blob/731e93be48c7b5a2cbe1ee8db2b9974049c45f0b/internal/controller/storagecluster/prometheus/localcephrules.yaml | 731e93be48c7b5a2cbe1ee8db2b9974049c45f0b |
| ODF toolbox switch | `api/v1/storagecluster_types.go` (`EnableCephTools`, "Defaults to false"), `internal/controller/storagecluster/cephtoolbox.go` (deployment `rook-ceph-tools`), LICENSE (Apache-2.0) | same |
| kubectl/oc jsonpath prints a map as JSON (why the CephCluster details map pastes back) | https://github.com/kubernetes/client-go/blob/79dc79d833507b4f0d23a9eb5a77780f8450b340/util/jsonpath/jsonpath.go#L159-L178 (`PrintResults`) | 79dc79d833507b4f0d23a9eb5a77780f8450b340 |

## Findings worth passing on

- **Docs and source disagree on names.** `doc/cephfs/health-messages.rst` heads three sections with the MDS enum
  names (`MDS_HEALTH_CLIENT_LATE_RELEASE`, `MDS_HEALTH_CLIENT_RECALL_MANY`, `MDS_HEALTH_READ_ONLY`), but the MDS
  emits `mds_metric_name()` (`src/messages/MMDSBeacon.h` lines 62-77): `MDS_CLIENT_LATE_RELEASE`,
  `MDS_CLIENT_RECALL_MANY`, `MDS_READ_ONLY`. The rados page's `BLUESTORE_FRAGMENTATION` is emitted as
  `BLUESTORE_FREE_FRAGMENTATION` (`src/mon/PGMap.cc` 3350). The catalogue uses the emitted names and reads the doc
  names as aliases.
- **A Rook alert that may never fire.** Rook's `CephFilesystemReadOnly` (from ceph-mixin) reads
  `ceph_health_detail{name="MDS_HEALTH_READ_ONLY"}` (`localrules.yaml` line 333); the MDS reports that condition as
  `MDS_READ_ONLY`, and the prometheus module labels `ceph_health_detail` with the check name. The catalogue entry says
  so and tells the user to check the codes directly. Worth an upstream issue (ceph-mixin and Rook).
- **Not a bug, checked:** ODF's `CephPoolNearFull` reads `POOL_NEARFULL` while Rook's reads `POOL_NEAR_FULL`; both are
  real (OSDMap.cc 8302 for OSD fullness, PGMap.cc 3144 for quotas). The merged alert entry watches both.
- **Documented but not raised at this commit:** `OSD_FILESTORE` (kept, cited to the doc, for older clusters);
  `BLUEFS_AVAILABLE_SPACE` and `BLUEFS_LOW_SPACE` are doc subsections, not health checks (left out).
- **Left out on purpose:** 42 Rook alerts that watch no Ceph health code (node, network, hardware, NVMe-oF, RBD
  mirroring, certificates, Prometheus job, PG imbalance, pool growth), and ODF's non-Ceph-cluster alerts in
  `metrics/deploy/prometheus-ocs-rules.yaml` (mirroring, OBC quotas, KMS, storage clients, auto-scaling, node
  latency). The verify script lists the Rook and ODF Ceph rule-file alerts left out.
- **A precision fix found on the way:** Ceph's wording "1 MDSs report slow requests" made the existing phrase alias
  "slow requests" imply `etcdGRPCRequestsSlow` and rank DBG-ETCD. Inside Ceph health output, phrase inference is now
  skipped (the codes read it); elsewhere the phrase still implies the etcd alert (regression test included).

## Gate

- `scripts/check.sh` with the worktree venv first on PATH (uv picked Python 3.14.6): **exit status 1**. Plugin copy,
  ruff, format and mypy pass; pytest has 1519 passed, 1 skipped and 1 failed, the pre-existing Python 3.14 failure
  described under Tests, so `set -e` stops before the self-test. Run on its own, `python -m kube_noob selftest`
  passes 63/63.
- The same `scripts/check.sh` with a Python 3.13.17 venv at `.venv` (CI's matrix is 3.11 to 3.13): **exit status
  0**: plugin copy in sync, ruff and format clean, mypy clean (134 files), 1520 passed and 1 skipped, self-test 63/63.
  The worktree's `.venv` was put back to the original 3.14 one afterwards.

## Measurement

- `python scripts/eval_golden.py`: output identical to the baseline taken before the change; `regressed 0` in every
  domain (helm 16/16, kubernetes 15/16, openshift 13/16, policy 14/16, rhacs 15/16, rosa-hcp 16/16).
- `python scripts/eval_triage.py`: identical; all cause right 80/114, playbook found 94, first 85.
- `python scripts/eval_triage.py --dir tests/fixtures/triage-train`: identical; all cause right 136/171, found 145,
  first 130.
- The owner's ODF/Rook community rows were not available here; the blinded measurement is the lead's.

## Tests

`tests/test_ceph_health.py` (30 tests from 25 functions, one parametrised over 6 inputs): detail text with severities
and muted lines; the older layout and codes in prose; `ceph status` and `ceph health` summaries including the
CRUSH-type family; the JSON shapes (health detail, status, the CephCluster details map that the first read-only step
prints) and a CephCluster in YAML and in a List; doc and alert-rule names mapped to emitted codes; uncatalogued codes named; an ODF
alert in prose and in an Alertmanager payload (the "contact support" one) with escalation; state alerts; cause before
symptom; escalation text and no destructive step; no destructive command anywhere in the catalogue and planted ones
refused; every step read-only and keyless; the platform split (ODF text, plain Kubernetes, forced kubernetes, given
openshift, ROSA, Rook on OpenShift); names from the input and hostile values kept out of commands; a mixed paste in
`insight`; every Ceph shape recognised; CLI insight and signals; the debug bundle; the MCP signals tool's citations;
hostile and oversized input bounded and fast; determinism under shuffled lines; Ceph wording not read as an etcd
phrase; prose about Ceph without a code gets no Ceph advice; the catalogue's shape and citations.
`tests/fixtures/insight/cases.py` gains 22 `ceph-health` cases (appended after the existing 360, which are unchanged;
`tests/test_insight.py` now expects 382), and the recogniser gate passes on both seeds.

Pre-existing, not from this change (both reproduce on an untouched export of the base commit with the same venv):
`tests/test_red_team_rt1.py::test_deeply_nested_jsonl_cases_are_refused_cleanly` fails on Python 3.14.6, whose json
module parses 20,000-deep nesting without a RecursionError; `tests/test_policy.py::test_explain_stays_fast_on_hostile_input[text1]`
takes 2.3 to 3.5 s in `policy._kyverno_entries` against a 3.0 s limit on this machine and fails now and then.

## Suggested CHANGELOG bullets (## Unreleased)

- Ceph health codes on Rook-Ceph and OpenShift Data Foundation: `diagnose`, `insight` and `kube-noob signals` read
  `ceph health detail`, `ceph status` and `ceph health` (text or JSON) and a CephCluster's status, and explain each of
  135 codes (121 entries) with its meaning, likely causes, the fix in words and read-only steps: `oc` and
  `openshift-storage` on ODF, `kubectl` and `rook-ceph` on Rook, Ceph commands in the Rook toolbox marked as needing
  approval. Codes whose usual fix can lose data (unfound objects, inconsistent or incomplete placement groups, lost
  monitor quorum, full OSDs, damaged CephFS metadata...) say to stop and involve storage support, and no catalogue
  step, fix or note names a command that can lose data.
- 69 Rook and ODF Prometheus alerts map to the codes they watch, including ODF alerts whose text only says to contact
  support (CephMonQuorumAtRisk, CephMonQuorumLost, CephDataRecoveryTakingTooLong, CephPGRepairTakingTooLong): each
  now comes with the evidence to collect first. Every code and alert cites the Ceph doc section, source lines and
  rule line it was checked against (ceph/ceph eb3b634b, rook/rook 61a8fea1, ocs-operator 731e93be);
  `scripts/verify_ceph_catalogue.py` re-checks them.

## Suggested docs/guidance.md row

| G105 | Ceph health codes and the Rook and ODF alerts that watch them are explained read-only: every code and alert cites the Ceph doc section, source lines and alert rule it was checked against; steps are `oc` reads or allow-listed Ceph reads in the toolbox (needing approval), oc and openshift-storage on ODF, kubectl and rook-ceph on Rook; no catalogue text names a command that can lose data, and a code whose usual fix can lose data says to stop and involve storage support; parsing is bounded and deterministic, and Ceph's wording is never read as another product's phrase | `tests/test_ceph_health.py::test_no_catalogue_text_contains_a_destructive_command`, `tests/test_ceph_health.py::test_every_step_only_reads_and_never_prints_a_key`, `tests/test_ceph_health.py::test_escalation_says_stop_and_never_shows_a_destructive_step`, `tests/test_ceph_health.py::test_alert_that_says_contact_support_gets_evidence_and_an_explicit_escalation`, `tests/test_ceph_health.py::test_platform_split`, `tests/test_ceph_health.py::test_commands_carry_names_from_the_input_and_never_hostile_ones`, `tests/test_ceph_health.py::test_hostile_and_oversized_input_is_bounded_and_fast`, `tests/test_ceph_health.py::test_output_is_deterministic`, `tests/test_ceph_health.py::test_catalogue_is_well_formed_and_cited`, `tests/test_ceph_health.py::test_ceph_wording_is_not_read_as_an_etcd_phrase` |

## Suggested docs/use-cases.md paragraph (SRE or on-call)

### What does this Ceph health code mean? Rook-Ceph and OpenShift Data Foundation

Paste `ceph health detail`, `ceph status` (text or `-f json`), a CephCluster's status or a firing Rook or ODF alert
into `kube-noob insight`. Each health code gets what it means, the likely causes, the fix in words and the read-only
steps that confirm it: the CephCluster status first (no shell needed), then the Ceph commands to run in the Rook
toolbox, which need approval because they execute in a container. On ODF the steps use `oc` and `openshift-storage`;
on Rook they use `kubectl` and `rook-ceph`. When the usual fix can lose data (unfound objects, inconsistent placement
groups, lost monitor quorum, full OSDs), the answer says to stop and involve storage support, and kube-noob never
offers the destructive command. ODF alerts that only say "contact support" come with the evidence to collect first.

```bash
oc get cephcluster -n openshift-storage -o jsonpath='{.status.ceph.details}' | kube-noob insight -f -
kube-noob insight -f ceph-health-detail.txt --platform openshift
```
