"""The inline SVG charts in the HTML report (U3).

A chart is the one part of a report nobody checks arithmetic on, which is exactly why these tests check it: the
geometry is integers computed from the counts, so "twice the findings is twice the bar" is an assertion rather
than an impression. The rest hold the three rules the module is built on -- a chart says only what a table on
the same page says, colour is never the only carrier, and an absence is never drawn as a zero.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

import pytest

from kube_noob import charts

PLOT = charts.W - 170 - 48 - 8  # the label column, the room kept for the value, and the margin


def _widths(markup: str) -> list[int]:
    return [int(w) for w in re.findall(r'<rect[^>]*\swidth="(\d+)"', markup)]


def _texts(markup: str) -> list[str]:
    return re.findall(r">([^<>]+)</text>", markup)


class _Sinks(HTMLParser):
    """Anything that would make the browser fetch or run something."""

    def __init__(self) -> None:
        super().__init__()
        self.bad: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "iframe", "object", "embed", "image", "foreignobject", "use"}:
            self.bad.append(tag)
        for name, value in attrs:
            if name.startswith("on") or (name in {"src", "href", "xlink:href", "data"} and value):
                self.bad.append(f"{tag}@{name}")


def test_a_bar_is_as_long_as_its_count() -> None:
    page = "".join(charts.bars([("a", 2), ("b", 4), ("c", 0)], caption="counts"))
    widths = _widths(page)
    assert widths == [PLOT // 2, PLOT, 0], widths
    assert widths[1] == 2 * widths[0], "twice the count has to be twice the bar"


def test_a_count_above_zero_is_never_drawn_as_nothing_and_the_number_says_the_rest() -> None:
    """The one place proportionality stops. A 1 beside a 10 000 is one pixel, and so is a 20 -- drawing them
    as zero would make a finding look like none, which is the worse error of the two. The number beside each
    bar is what separates them, which is why colour and length are never the only carriers."""
    page = "".join(charts.bars([("a", 10_000), ("b", 1), ("c", 20)], caption="counts"))
    assert _widths(page) == [PLOT, 1, 1]
    assert _texts(page)[-1] == "20", "the count that the bar cannot show is written out"


def test_every_bar_says_its_name_and_its_count() -> None:
    """Colour is never the only carrier: the page is read in print, in forced colours and by someone with no
    colour vision at all, and none of them loses a number."""
    page = "".join(charts.bars([("critical", 3), ("low", 11)], caption="by severity"))
    text = _texts(page)
    assert "critical" in text and "3" in text
    assert "low" in text and "11" in text


def test_a_chart_fetches_nothing_and_runs_nothing() -> None:
    drawn = "".join(
        charts.bars([("a", 1)], caption="c")
        + charts.stacked([("x", [1, 2])], series=["One", "Two"], caption="c")
        + charts.lines(["a", "b"], [("One", [1, 2])], caption="c")
    )
    sink = _Sinks()
    sink.feed(drawn)
    assert sink.bad == [], sink.bad


def test_a_hostile_label_is_text_and_not_markup() -> None:
    """The names come from someone else's cluster, and an SVG is as good a place to run a script as an HTML
    body is. The escaping rule is the page's rule, applied one layer down."""
    evil = "<script>alert(1)</script>"
    for drawn in (
        "".join(charts.bars([(evil, 2)], caption=evil)),
        "".join(charts.stacked([(evil, [1, 1])], series=[evil, "b"], caption=evil)),
        "".join(charts.lines([evil, "b"], [(evil, [1, 2])], caption=evil)),
    ):
        assert "<script>" not in drawn
        assert "&lt;script&gt;" in drawn


def test_an_all_zero_chart_is_not_drawn() -> None:
    """A row of empty bars and a row of missing bars are the same picture. The caller writes the sentence."""
    assert charts.bars([("a", 0), ("b", 0)], caption="c") == []
    assert charts.stacked([("a", [0, 0])], series=["x", "y"], caption="c") == []
    assert charts.bars([], caption="c") == []


def test_a_stacked_row_keeps_the_series_order_and_names_its_total() -> None:
    drawn = "".join(charts.stacked([("AC-6", [3, 0, 0, 15, 0])], series=list("abcde"), caption="standing"))
    assert re.findall(r'class="(kn-q\d)"', drawn) == ["kn-q0", "kn-q3"], "the empty buckets draw nothing"
    assert "18" in _texts(drawn), "the row total is written beside the bar"
    assert "AC-6 — a: 3" in drawn, "every segment carries its own hover title"


@pytest.mark.parametrize(
    "rows",
    [
        [("a", [7, 3, 5, 11, 2]), ("b", [1, 1, 1, 1, 1])],
        # The case that used to overrun: four segments at the one-pixel floor, each rounded up, pushed the bar
        # four pixels past the plot it is scaled against.
        [("a", [996, 1, 1, 1, 1])],
        [("a", [1, 1, 1, 1, 1]), ("b", [0, 0, 0, 0, 500])],
    ],
)
def test_a_stacked_bar_never_outruns_its_plot(rows: list[tuple[str, list[int]]]) -> None:
    drawn = "".join(charts.stacked(rows, series=list("vwxyz"), caption="c"))
    ends = [int(x) + int(w) for x, w in re.findall(r'<rect[^>]*\sx="(\d+)"[^>]*\swidth="(\d+)"', drawn)]
    assert max(ends) <= 170 + PLOT, max(ends)


def test_rows_past_the_cap_are_counted_rather_than_dropped_silently() -> None:
    rows = [(f"r{i}", i + 1) for i in range(charts.MAX_BARS + 5)]
    drawn = "".join(charts.bars(rows, caption="c"))
    assert len(_widths(drawn)) == charts.MAX_BARS
    assert "5 more row(s) are in the table below" in drawn


def test_the_y_axis_starts_at_zero_and_is_labelled_at_the_top() -> None:
    """A trend drawn from a floor other than zero exaggerates the change, which on a page about findings is the
    one thing a chart must not do."""
    drawn = "".join(charts.lines(["a", "b", "c"], [("Open", [40, 44, 41])], caption="c"))
    text = _texts(drawn)
    assert "0" in text and "44" in text
    ys = [int(y) for y in re.findall(r'cy="(\d+)"', drawn)]
    assert ys[1] < ys[2] < ys[0], "44 is drawn highest and 40 lowest (y grows downwards)"


def test_one_point_is_a_dot_and_not_a_line() -> None:
    drawn = "".join(charts.lines(["a"], [("Open", [3])], caption="c"))
    assert "<polyline" not in drawn
    assert drawn.count("<circle") == 1


def test_only_the_newest_points_are_kept() -> None:
    n = charts.MAX_POINTS + 10
    drawn = "".join(charts.lines([f"d{i}" for i in range(n)], [("Open", list(range(n)))], caption="c"))
    assert drawn.count("<circle") == charts.MAX_POINTS
    assert f"d{n - 1}" in drawn and "d0</text>" not in drawn


def test_a_series_longer_than_its_ticks_draws_nothing() -> None:
    """Rather than drawing the pair it can line up: a chart that silently plots four of five points is a
    wrong chart, and a missing one sends the reader to the table."""
    assert charts.lines(["a", "b"], [("Open", [1, 2, 3])], caption="c") == []
    assert charts.lines([], [("Open", [])], caption="c") == []


def test_a_trend_longer_than_the_chart_says_how_many_points_it_left_out() -> None:
    n = charts.MAX_POINTS + 4
    drawn = "".join(charts.lines([f"d{i}" for i in range(n)], [("Open", list(range(n)))], caption="c"))
    assert drawn.count("<circle") == charts.MAX_POINTS
    assert "4 more point(s) are in the table below, not in the chart" in drawn


def test_an_all_zero_series_labels_the_axis_with_nothing_it_did_not_measure() -> None:
    """`max(1, top)` keeps the arithmetic safe and must not reach the label: an axis topped with 1 over a
    series that never left zero puts a number on the page that nothing measured."""
    drawn = "".join(charts.lines(["a", "b"], [("Open", [0, 0])], caption="c"))
    assert _texts(drawn) == ["0", "a", "b"], _texts(drawn)
    assert drawn.count("<circle") == 2, "the points are still drawn, flat on the baseline"
