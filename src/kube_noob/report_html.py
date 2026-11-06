"""One self-contained HTML page for a gate report, a posture report or the KSI crosswalk (U1).

The audience is a compliance reviewer, and what a reviewer gets from the terminal is text they cannot forward and
JSON they will not read. So: one file, inline styling, no script, no stylesheet, no font, no image, nothing the
browser has to fetch -- openable from an email attachment on a laptop with no network, which is the situation
this tool is used in.

Two rules hold the whole module up.

**Every caveat the text view carries survives into the page, above the findings.** `assumptions`,
`notCheckedBeyond`, an unreadable file, a withheld control standing, `audited: false` -- each one changes what a
count means, and a reader who meets an empty findings table first has already drawn their conclusion. An HTML
report that drops them would be G221 in a third format.

**A chart shows only what a table on the same page shows** (U3). Every chart in :mod:`kube_noob.charts` is a
second reading of counts the reader can check row by row underneath it, and a count that was withheld is not
drawn at all -- an empty bar and a zero-length bar are the same picture, which is G221 again in ink.

**Nothing from a manifest is ever markup.** Resource names, messages, paths and reasons come from someone else's
cluster, and this is the one place in the product where that text becomes a document another person opens. Every
value goes through :func:`_esc`; there is no template interpolation anywhere that does not.
"""

from __future__ import annotations

import datetime as dt
import html
from typing import Any

from kube_noob import charts

#: Rows past this are summarised rather than listed: a 4,000-row table is not a report anybody reads, and the
#: count says how many are missing rather than letting the table end silently.
MAX_ROWS = 300

_CSS = """
:root { color-scheme: light dark; --fg: #16181d; --bg: #fff; --dim: #5b6070; --line: #d9dce3;
        --warn-bg: #fff6e5; --warn-line: #e0a63a; --bad: #a4262c; --ok: #1a7f4b; }
@media (prefers-color-scheme: dark) {
  :root { --fg: #e7e9ee; --bg: #15171c; --dim: #a2a8b8; --line: #343845;
          --warn-bg: #2d2516; --warn-line: #b78a2e; --bad: #f2898f; --ok: #6fd79b; }
}
* { box-sizing: border-box; }
body { margin: 0; padding: 2rem 1rem 4rem; color: var(--fg); background: var(--bg);
       font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
main { max-width: 68rem; margin: 0 auto; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; letter-spacing: -.01em; }
h2 { font-size: 1.1rem; margin: 2.2rem 0 .6rem; padding-bottom: .3rem; border-bottom: 1px solid var(--line); }
h3 { font-size: .95rem; margin: 1.4rem 0 .3rem; }
p, li { margin: .4rem 0; }
.sub { color: var(--dim); margin: 0 0 1.2rem; font-size: .9rem; }
.caveat { background: var(--warn-bg); border: 1px solid var(--warn-line); border-left-width: 4px;
          border-radius: 3px; padding: .7rem .9rem; margin: .6rem 0; }
.caveat b { display: block; margin-bottom: .2rem; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; font-size: .88rem; }
th, td { text-align: left; padding: .35rem .5rem; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--dim); font-weight: 600; white-space: nowrap; }
td.n, th.n { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .85em; }
.sev { font-weight: 600; white-space: nowrap; }
.sev-critical, .sev-high { color: var(--bad); }
.fails { color: var(--bad); font-weight: 600; }
.pass { color: var(--ok); font-weight: 600; }
.note { color: var(--dim); font-size: .85rem; }
.ev { margin: .2rem 0 .8rem; padding-left: .8rem; border-left: 2px solid var(--line); }
.ev dt { color: var(--dim); font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; margin-top: .4rem; }
.ev dd { margin: .1rem 0 0; }
@media print { body { padding: 0; } .caveat { border-left-width: 3px; } }
"""


def _esc(value: Any) -> str:
    """The only way text enters the page. ``quote=True`` so a value is safe in an attribute as well."""
    return html.escape("" if value is None else str(value), quote=True)


def _rich(value: Any) -> str:
    """Escaped text, then the `backticks` the prose is written with turned into code spans.

    Order matters and is the whole safety argument: the value is escaped FIRST, so the only markup that can
    exist by the time this looks for backticks is markup this function wrote. A hostile name containing
    backticks becomes a code span holding escaped text, which is harmless.
    """
    out = _esc(value)
    parts = out.split("`")
    if len(parts) < 3:
        return out
    rebuilt = [parts[0]]
    for i, part in enumerate(parts[1:], start=1):
        rebuilt.append(f"<code>{part}</code>" if i % 2 else part)
    # An unpaired trailing backtick leaves the last fragment unwrapped; splitting on an odd count would have
    # opened a tag with nothing to close it.
    if len(parts) % 2 == 0:
        rebuilt[-1] = parts[-1]
    return "".join(rebuilt)


def _row(cells: list[str], *, numeric: set[int] | None = None, head: bool = False, width: int = 0) -> str:
    """A row. A short row's last cell spans the rest, so a note does not sit under a numeric heading."""
    tag = "th" if head else "td"
    num = numeric or set()
    out = []
    for i, cell in enumerate(cells):
        cls = ' class="n"' if i in num else ""
        span = ""
        if width and i == len(cells) - 1 and len(cells) < width:
            span = f' colspan="{width - len(cells) + 1}"'
            cls = ""
        out.append(f"<{tag}{cls}{span}>{cell}</{tag}>")
    return "<tr>" + "".join(out) + "</tr>"


def _table(headers: list[str], rows: list[list[str]], numeric: set[int] | None = None) -> list[str]:
    if not rows:
        return []
    shown, hidden = rows[:MAX_ROWS], max(0, len(rows) - MAX_ROWS)
    out = ["<table>", "<thead>", _row([_esc(h) for h in headers], numeric=numeric, head=True), "</thead>", "<tbody>"]
    out += [_row(r, numeric=numeric, width=len(headers)) for r in shown]
    out += ["</tbody>", "</table>"]
    if hidden:
        out.append(f'<p class="note">{hidden} more row(s) not listed here; the JSON output carries all of them.</p>')
    return out


#: Worst first, which is the order the findings table is already sorted in. A severity this does not name is
#: listed after these, alphabetically, rather than guessed at a position.
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

#: Written where a value is missing, so an empty cell is never read as a zero.
_EM_DASH = "\u2014"


def _severity_sections(report: dict[str, Any]) -> list[str]:
    """The gate's own `counts`, as a table and a bar per severity. Nothing when every count is zero: a row of
    empty bars says less than the sentence about there being no finding."""
    counts = report.get("counts")
    if not isinstance(counts, dict):
        return []
    rows: list[tuple[str, int]] = []
    for name in _SEVERITY_ORDER:
        if isinstance(counts.get(name), int):
            rows.append((name, int(counts[name])))
    rows += sorted((str(k), int(v)) for k, v in counts.items() if isinstance(v, int) and k not in _SEVERITY_ORDER)
    if not any(c for _, c in rows):
        return []
    drawn = charts.bars(rows, caption="Findings by severity", classes=charts.SEVERITY_CLASS)
    table = _table(["Severity", "Findings"], [[_esc(n), _esc(c)] for n, c in rows], numeric={1})
    return drawn + table


def _trend_sections(report: dict[str, Any]) -> list[str]:
    """Open and excepted findings across the snapshots still kept (U3).

    The table is always rendered; the line only when every point is a complete measurement of the same
    population. Each reason it is withheld is one of the ways a number can be absent rather than zero -- a
    snapshot that was refused a resource reports a floor, a report written before kube-noob recorded
    completeness cannot say, a report that does not say when it was taken cannot be placed, a file that could
    not be read is a point missing from the middle, and two sources in one folder are two populations. Joining
    any of them to its neighbours would publish a change in findings that may only be a change in what
    kube-noob was allowed to see.
    """
    hist = report.get("history")
    if not isinstance(hist, dict):
        return []
    points = [p for p in hist.get("points") or [] if isinstance(p, dict)]
    unplaced = [str(x) for x in hist.get("unplaced") or []]
    if len(points) < 2 and not unplaced:
        return []
    out = ["<h2>Open findings over time</h2>"]
    kept = len(points) + len(unplaced)
    counted = [p for p in points if isinstance(p.get("open"), int) and isinstance(p.get("excepted"), int)]
    partial = [p for p in points if p.get("complete") is False]
    unknown = [p for p in points if p.get("complete") is None]
    undated = [p for p in points if not p.get("at")]
    sources = sorted({str(p["source"]) for p in points if p.get("source")})
    why: list[str] = []
    if partial:
        why.append(
            f"{len(partial)} of the {kept} kept came from a snapshot that could not read every resource, so "
            "their open-finding counts are a floor rather than a measurement"
        )
    if unknown:
        why.append(
            f"{len(unknown)} were written before kube-noob recorded whether a snapshot had read everything, "
            "so whether their counts are complete is not known"
        )
    if undated:
        why.append(f"{len(undated)} do not say when they were taken")
    if len(counted) != len(points):
        why.append(f"{len(points) - len(counted)} do not carry both counts")
    if unplaced:
        why.append(f"{len(unplaced)} could not be read back or were not read ({', '.join(unplaced)})")
    if len(sources) > 1:
        why.append(
            "the series mixes snapshots of different things (" + ", ".join(sources) + "), which are different "
            "populations rather than one population over time"
        )
    if why or len(points) < 2:
        out.append(
            '<div class="caveat"><b>No trend is drawn.</b>'
            + _esc("; ".join(why) or "there is one point, which is not a trend")
            + ". A line through those points would publish a change in findings that may only be a change in "
            "what kube-noob was allowed to see. The counts themselves are below, each marked with whether its "
            "snapshot read every resource.</div>"
        )
    else:
        shown = points[-charts.MAX_POINTS :]
        out += charts.lines(
            [str(p["at"])[:10] for p in shown],
            [
                ("Open", [int(p["open"]) for p in shown]),
                ("Excepted", [int(p["excepted"]) for p in shown]),
            ],
            caption="Open and excepted findings per snapshot",
        )
        out.append(
            '<p class="note">The points are evenly spaced by snapshot, not by date: the dates say which '
            "snapshot each point is, and a gap between two runs is not drawn as a gap.</p>"
        )
        if len(points) > len(shown):
            out.append(
                f'<p class="note">{len(points) - len(shown)} older point(s) are in the table below, not in '
                "the chart.</p>"
            )
    out += _table(
        ["Taken", "Open", "Excepted", "Source", "Read everything"],
        [
            [
                f'<span class="mono">{_esc(p.get("at") or _EM_DASH)}</span>',
                _esc(p["open"]) if isinstance(p.get("open"), int) else _EM_DASH,
                _esc(p["excepted"]) if isinstance(p.get("excepted"), int) else _EM_DASH,
                _esc(p.get("source") or _EM_DASH),
                "yes"
                if p.get("complete") is True
                else f'<span class="fails">{"no" if p.get("complete") is False else "not recorded"}</span>',
            ]
            for p in points
        ],
        numeric={1, 2},
    )
    out.append(
        '<p class="note">"Read everything" is whether the snapshot was refused a resource it asked the cluster '
        "for. It does not cover a kind kube-noob has no reader for: the audit records that as an assumption on "
        "the run itself.</p>"
    )
    if unplaced:
        out.append(
            '<p class="note">Kept files behind a point that could not be made: '
            f'<span class="mono">{_esc(", ".join(unplaced))}</span>.</p>'
        )
    return out


def _caveats(report: dict[str, Any]) -> list[str]:
    """Everything that changes what a count below means. Rendered first, always."""
    out: list[str] = []
    if report.get("audited") is False:
        out.append(
            '<div class="caveat"><b>Nothing was audited.</b>This is the crosswalk itself, not a result: no '
            "manifests were read, so no row below carries a finding count. A zero would read as a pass.</div>"
        )
    for note in report.get("assumptions") or []:
        out.append(f'<div class="caveat"><b>Assumed</b>{_rich(note)}</div>')
    limit = report.get("notCheckedBeyond")
    if limit:
        out.append(f'<div class="caveat"><b>Not checked that far</b>{_rich(limit.get("why"))}</div>')
    unreadable = report.get("unreadable") or []
    if unreadable:
        items = "".join(
            f'<li><span class="mono">{_esc(u.get("path"))}</span>: {_esc(u.get("why"))}</li>' for u in unreadable
        )
        out.append(
            '<div class="caveat"><b>Files that could not be read</b>'
            f"<ul>{items}</ul>This is not a complete audit, so nothing below is a clean result.</div>"
        )
    not_read = report.get("notRead") or []
    if not_read:
        items = "".join(f"<li>{_esc(n)}</li>" for n in not_read)
        out.append(
            '<div class="caveat"><b>Resources that could not be read</b>'
            f"<ul>{items}</ul>This is not a complete read of the cluster, so nothing below is a clean result.</div>"
        )
    for note in report.get("notes") or []:
        out.append(f'<div class="caveat"><b>Note</b>{_rich(note)}</div>')
    return out


def _gate_sections(report: dict[str, Any]) -> list[str]:
    out: list[str] = []
    if "passed" in report:
        verdict = '<span class="pass">passed</span>' if report["passed"] else '<span class="fails">failed</span>'
        out.append(
            f"<p>The gate <b>{verdict}</b> at <code>--fail-on {_esc(report.get('failOn'))}</code> "
            f"for platform <code>{_esc(report.get('platform'))}</code>.</p>"
        )
    if report.get("failures"):
        out.append("<h2>Why the gate failed</h2>")
        out.append("<ul>" + "".join(f"<li>{_esc(f)}</li>" for f in report["failures"]) + "</ul>")
    findings = report.get("findings")
    if isinstance(findings, list):
        out.append(f"<h2>Findings ({len(findings)})</h2>")
        if not findings:
            out.append(
                '<p class="note">No finding at or above the configured severity. Read the caveats above before '
                "reading that as a clean result.</p>"
            )
        out += _severity_sections(report)
        out += _table(
            ["Rule", "Severity", "Fails gate", "Resource", "Where", "What"],
            [
                [
                    f'<span class="mono">{_esc(f.get("ruleId"))}</span>',
                    f'<span class="sev sev-{_esc(str(f.get("severity", "")).lower())}">'
                    f"{_esc(f.get('severity'))}</span>",
                    '<span class="fails">yes</span>' if f.get("failsGate") else "no",
                    _esc(f.get("resource")),
                    f'<span class="mono">{_esc(f.get("uri"))}{":" + str(f["line"]) if f.get("line") else ""}</span>',
                    _esc(f.get("message")),
                ]
                for f in findings
            ],
        )
    if report.get("excepted"):
        out.append(f"<h2>Excepted ({len(report['excepted'])})</h2>")
        out += _table(
            ["Rule", "Resource", "Exception", "Owner", "Expires"],
            [
                [
                    f'<span class="mono">{_esc(f.get("ruleId"))}</span>',
                    _esc(f.get("resource")),
                    _esc((f.get("exception") or {}).get("id")),
                    _esc((f.get("exception") or {}).get("owner")),
                    _esc((f.get("exception") or {}).get("expires")),
                ]
                for f in report["excepted"]
            ],
        )
    return out


def _posture_findings(report: dict[str, Any]) -> list[str]:
    """A posture report's `findings` is a dict of buckets (new, fixed, still open), not a list."""
    buckets = report.get("findings")
    if not isinstance(buckets, dict):
        return []
    out = ["<h2>What changed</h2>"]
    out += _table(
        ["Bucket", "Findings"],
        [[_esc(name), _esc(len(rows) if isinstance(rows, list) else rows)] for name, rows in buckets.items()],
        numeric={1},
    )
    for name, rows in buckets.items():
        if not isinstance(rows, list) or not rows:
            continue
        out.append(f"<h3>{_esc(name)} ({len(rows)})</h3>")
        out += _table(
            ["Rule", "Severity", "Resource", "Namespace", "Owner"],
            [
                [
                    f'<span class="mono">{_esc(f.get("ruleId"))}</span>',
                    _esc(f.get("severity")),
                    _esc(f.get("resource")),
                    _esc(f.get("namespace")),
                    _esc(f.get("owner")),
                ]
                for f in rows
                if isinstance(f, dict)
            ],
        )
    return out


def _standing_sections(report: dict[str, Any]) -> list[str]:
    out: list[str] = []
    by_control = (report.get("violations") or {}).get("byControl")
    if by_control:
        out.append("<h2>Open findings by control</h2>")
        out += charts.bars(
            [(str(c.get("control")), int(c.get("findings") or 0)) for c in by_control if isinstance(c, dict)],
            caption="Most open findings first",
        )
        out += _table(
            ["Control", "Title", "Findings", "Namespaces"],
            [
                [
                    f'<span class="mono">{_esc(c.get("control"))}</span>',
                    _esc(c.get("title")),
                    _esc(c.get("findings")),
                    _esc(", ".join(c.get("namespaces") or []))
                    + (f' <span class="note">+{c["moreNamespaces"]} more</span>' if c.get("moreNamespaces") else ""),
                ]
                for c in by_control
            ],
            numeric={2},
        )
    standing = report.get("controlStanding")
    out.append("<h2>Control standing</h2>")
    if standing is None:
        out.append(
            '<div class="caveat"><b>No standing is reported.</b>Some resources could not be read, and a rule '
            "that never ran cannot be counted clean, so standing is withheld entirely rather than published "
            "with a bucket that cannot be trusted.</div>"
        )
        return out
    controls = standing.get("controls") or []
    buckets = ("findings", "excepted", "withheld", "clean", "notEvaluated")
    out += charts.stacked(
        [(str(c.get("id")), [int(c.get(b) or 0) for b in buckets]) for c in controls if isinstance(c, dict)],
        series=["Findings", "Excepted", "Withheld", "Clean", "Not evaluated"],
        caption="Per-control standing, rules counted",
    )
    out += _table(
        ["Control", "Title", "Findings", "Excepted", "Withheld", "Clean", "Not evaluated"],
        [
            [
                f'<span class="mono">{_esc(c.get("id"))}</span>',
                _esc(c.get("title")),
                _esc(c.get("findings", 0)),
                _esc(c.get("excepted", 0)),
                _esc(c.get("withheld", 0)),
                _esc(c.get("clean", 0)),
                _esc(c.get("notEvaluated", 0)),
            ]
            for c in controls
        ],
        numeric={2, 3, 4, 5, 6},
    )
    return out


def _ksi_sections(report: dict[str, Any]) -> list[str]:
    indicators = report.get("indicators")
    if indicators is None:
        return []
    out: list[str] = []
    data = report.get("dataset") or {}
    if data:
        out.append(
            f'<p class="note">{_esc(data.get("name"))} version <code>{_esc(data.get("version"))}</code> '
            f"(updated {_esc(data.get('lastUpdated'))}), retrieved {_esc(data.get('retrieved'))}, sha256 "
            f'<span class="mono">{_esc(data.get("sha256"))}</span>.</p>'
        )
    for key in ("note", "applicability", "sharedControlCaveat"):
        if report.get(key):
            out.append(f'<div class="caveat"><b>Read this first</b>{_rich(report[key])}</div>')
    if report.get("unmappedControls"):
        out.append(
            '<p class="note">Controls kube-noob maps that no indicator cites, so no finding reaches an indicator '
            f"through them: {_esc(', '.join(report['unmappedControls']))}.</p>"
        )
    for miss in report.get("findingsNotMapped") or []:
        out.append(
            f'<div class="caveat"><b>Findings that reach no indicator</b>{_esc(miss.get("findings"))} from '
            f'<span class="mono">{_esc(miss.get("ruleId"))}</span>: {_rich(miss.get("why"))}</div>'
        )
    audited = report.get("audited")
    out.append(f"<h2>Indicators ({len(indicators)})</h2>")
    headers = ["Indicator", "Family", "Name", "kube-noob controls"]
    numeric: set[int] = set()
    if audited:
        headers += ["Findings", "Clean", "Not evaluated", "Withheld"]
        numeric = {4, 5, 6, 7}
    else:
        headers += ["Rules behind it"]
        numeric = {4}
    rows: list[list[str]] = []
    for r in indicators:
        base = [
            f'<span class="mono">{_esc(r.get("id"))}</span>',
            _esc(r.get("family")),
            _esc(r.get("name")),
            _esc(", ".join(r.get("controls") or [])) or "—",
        ]
        if not r.get("evidenced"):
            # One cell spanning the count columns: the note used to sit under the "Findings" heading, which is
            # the one place on this page a reader must not misread.
            base.append(f'<span class="note">{_esc(r.get("why"))}</span>')
        elif audited:
            base += [
                _esc(r.get("findings", 0)),
                _esc(r.get("clean", 0)),
                _esc(r.get("notEvaluated", 0)),
                _esc(r.get("withheld", 0)),
            ]
        else:
            base.append(_esc(r.get("rulesBehind", 0)))
        rows.append(base)
    out += _table(headers, rows, numeric=numeric)
    curated = [r for r in indicators if r.get("evidence")]
    if curated:
        out.append("<h2>What the evidence shows, and what it does not</h2>")
        for r in curated:
            out.append(f'<h3><span class="mono">{_esc(r["id"])}</span> — {_esc(r.get("name"))}</h3>')
            if r.get("warning"):
                out.append(f'<div class="caveat"><b>Warning</b>{_rich(r["warning"])}</div>')
            ev = r["evidence"]
            out.append(
                '<dl class="ev">'
                f"<dt>Shows</dt><dd>{_rich(ev.get('shows'))}</dd>"
                f"<dt>Does not show</dt><dd>{_rich(ev.get('doesNotShow'))}</dd>"
                f'<dt>Rules named</dt><dd><span class="mono">{_esc(", ".join(ev.get("rulesNamed") or []))}</span></dd>'
                "</dl>"
            )
            if r.get("notEvaluatedRules"):
                more = f" and {r['moreNotEvaluated']} more" if r.get("moreNotEvaluated") else ""
                out.append(
                    f'<p class="note">Declined to decide: <span class="mono">'
                    f"{_esc(', '.join(r['notEvaluatedRules']))}</span>{_esc(more)}.</p>"
                )
    return out


def _title(report: dict[str, Any]) -> str:
    if "indicators" in report:
        return "FedRAMP 20x Key Security Indicators"
    if "passed" in report or "failures" in report:
        return "kube-noob gate"
    if "controlStanding" in report or "violations" in report:
        return "kube-noob posture"
    return "kube-noob report"


def render(report: dict[str, Any], *, generated_at: dt.datetime | None = None) -> str:
    """One page for whichever report this is. Unknown shapes still produce a valid page rather than an error."""
    when = (generated_at or dt.datetime.now(dt.UTC)).strftime("%Y-%m-%d %H:%M UTC")
    title = _title(report)
    # kube-noob's version only. The KSI report carries dataset.version (2026.11.02.01), and borrowing it for
    # the byline printed "by kube-noob 2026.11.02.01" -- a false claim about the tool, in the first line of a
    # document written for someone checking claims.
    version = str(report.get("version") or "")
    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{_esc(title)}</title>",
        f"<style>{_CSS}{charts.CSS}</style>",
        "</head><body><main>",
        f"<h1>{_esc(title)}</h1>",
        f'<p class="sub">Generated {_esc(when)} by kube-noob'
        + (f" {_esc(version)}" if version else "")
        + ". No network was used to produce this page, and the page itself loads nothing.</p>",
    ]
    # Explicit dispatch, because the three reports share key NAMES with different shapes: a gate report's
    # `findings` is a list of findings and a posture report's is a dict of buckets, and rendering one as the
    # other produced a page built from dictionary keys.
    is_gate = "passed" in report or "failOn" in report
    is_posture = "controlStanding" in report or "violations" in report
    parts += _caveats(report)
    if is_gate:
        parts += _gate_sections(report)
    if is_posture:
        parts += _posture_findings(report)
        parts += _standing_sections(report)
        parts += _trend_sections(report)
    parts += _ksi_sections(report)
    parts += ["</main></body></html>", ""]
    return "\n".join(parts)
