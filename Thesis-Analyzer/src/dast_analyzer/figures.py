"""The load-bearing thesis figures (matplotlib, pgf-friendly, thesis fonts).

Each function builds one figure from the analyzer tables and returns a matplotlib
``Figure``; ``render_all`` writes the standard set. Figures are emitted as ``.pgf``
(the thesis \\input{}s these, so the fonts and sizes match the body) plus ``.pdf``
/ ``.png`` for preview. The order follows the README's priority order.

Design: the validated colour-blind-safe categorical palette (fixed hue order, not
cycled), reserved status colours for the detected / missed / flickering semantics,
direct value labels instead of dense legends, and recessive axes (no top/right
spine, light horizontal grid, ink-coloured text that never carries series
identity). The figures read as one system and survive a monochrome print.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # headless; .pgf is written by the pgf canvas on save
import matplotlib.pyplot as plt  # noqa: E402

from . import cuts, g9, markers, metrics, spread  # noqa: E402
from .findings import two_arm_matrix  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

# Validated categorical palette (dataviz skill, fixed order — never cycled).
CAT = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
BLUE, ORANGE, AQUA, YELLOW, MAGENTA, GREEN, VIOLET, RED = CAT
# Reserved status colours (state, never reused as a series): a confirmed catch is
# good (green), a flickering one is a warning (orange), a miss is neutral grey.
GOOD, WARN, MISS, SERIOUS = "#1baf7a", "#eb6834", "#c9c8c0", "#e34948"
# Ink + surface tokens: text and structure, never identity.
INK, INK2, GRID, SURFACE = "#1a1a19", "#52514e", "#e6e5e0", "#ffffff"
DEFAULT_FORMATS = ("pgf", "pdf", "png")


def thesis_rc() -> dict:
    """rcParams that make the saved ``.pgf`` match a serif LaTeX thesis body.

    ``pgf.rcfonts=False`` hands font selection to the document's own preamble; we
    do not force ``text.usetex`` (brittle/slow and unnecessary to emit valid pgf).
    """
    return {
        "font.family": "serif",
        "font.size": 9.5,
        "axes.titlesize": 11,
        "axes.titleweight": "bold",
        "axes.labelsize": 9.5,
        "axes.labelcolor": INK2,
        "axes.edgecolor": INK2,
        "axes.linewidth": 0.8,
        "legend.fontsize": 8.5,
        "xtick.labelsize": 8.5,
        "ytick.labelsize": 8.5,
        "xtick.color": INK2,
        "ytick.color": INK2,
        "text.color": INK,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "figure.autolayout": True,
        "figure.facecolor": SURFACE,
        "axes.facecolor": SURFACE,
        "pgf.texsystem": "pdflatex",
        "pgf.rcfonts": False,
    }


def configure() -> None:
    plt.rcParams.update(thesis_rc())


def _recede(ax, grid_axis: str | None = "x") -> None:
    """A light, recessive frame: no top/right spine, one faint grid axis, ink text."""
    if grid_axis:
        ax.grid(axis=grid_axis, color=GRID, linewidth=0.8, zorder=0)
        ax.set_axisbelow(True)
    ax.tick_params(length=0)
    ax.title.set_color(INK)


def _hlabels(ax, ys, vals, fmt="{:.0f}", dx=0, color=INK2, size=8):
    """Direct value labels at the end of horizontal bars."""
    for y, v in zip(ys, vals):
        ax.text(v + dx, y, fmt.format(v), va="center", ha="left", color=color, fontsize=size)


def _cell(t, a):
    return f"{t[:4]}-{a[0]}"


# --------------------------------------------------------------------------- #
# 1. Two-arm agreement — the central claim: the model arm rescues nothing new
# --------------------------------------------------------------------------- #
def fig_two_arm_matrix(index):
    m = two_arm_matrix(index).copy()
    m["cell"] = [_cell(t, a) for t, a in zip(m.target, m.auth)]
    m = m.sort_values(["deterministic-only"], ascending=True)
    fig, ax = plt.subplots(figsize=(6.0, 3.6))
    y = range(len(m))
    h = 0.38
    det = m["deterministic-only"].to_numpy()
    llm = m["llm-only"].to_numpy()
    ax.barh([yi + h / 2 for yi in y], det, h, color=BLUE, label="table-only rescues", zorder=3)
    ax.barh([yi - h / 2 for yi in y], llm, h, color=RED, label="model-only rescues", zorder=3)
    _hlabels(ax, [yi + h / 2 for yi in y], det, dx=0.3)
    for yi in y:  # model-only is 0 everywhere — say so explicitly at the baseline
        ax.text(0.3, yi - h / 2, "0", va="center", ha="left", color=RED, fontsize=8)
    ax.set_yticks(list(y))
    ax.set_yticklabels(m["cell"])
    ax.set_xlabel("findings uniquely rescued by one arm")
    ax.set_title("The model arm rescues nothing the table missed")
    ax.margins(x=0.12)
    ax.legend(loc="lower right", frameon=False)
    _recede(ax, "x")
    return fig


# --------------------------------------------------------------------------- #
# 2. Detection ladder — blind vs ceiling, per layer
# --------------------------------------------------------------------------- #
def fig_detection_ladder(index):
    bvc = markers.blind_vs_ceiling(index)
    allrows = bvc[bvc.target == "ALL"]
    layers = list(markers.LAYERS)
    names = ["scanner", "det. table", "llm arm", "verify"]
    fig, ax = plt.subplots(figsize=(5.6, 3.2))
    x = range(len(layers))
    w = 0.38
    vmax = 0
    for i, (role, color) in enumerate((("blind", MISS), ("ceiling", GOOD))):
        row = allrows[allrows.role == role].iloc[0]
        vals = [int(row[l]) for l in layers]
        vmax = max(vmax, *vals)
        xs = [xi + (i - 0.5) * w for xi in x]
        ax.bar(xs, vals, w, color=color, label=role, zorder=3)
        for xi, v in zip(xs, vals):
            ax.text(xi, v + 0.03, str(v), ha="center", va="bottom", color=INK2, fontsize=8)
    ax.set_xticks(list(x))
    ax.set_xticklabels(names)
    ax.set_ylabel("markers caught (of 22)")
    # Headroom for the value labels; derived from the data so a new catch never
    # clips a bar (this read "ceiling tops out at 1" with a hardcoded 1.5 limit
    # until cacti's RCE became a second ceiling detection).
    ax.set_ylim(0, vmax + 0.4)
    ceiling = allrows[allrows.role == "ceiling"].iloc[0]
    ax.set_title(f"Detection per layer: blind is 0, "
                 f"ceiling detects {int(ceiling['detected'])}, "
                 f"confirms {int(ceiling['verify'])} in-pipeline")
    ax.legend(frameon=False, loc="upper right")
    _recede(ax, "y")
    return fig


# --------------------------------------------------------------------------- #
# 3. Alert volume as a range, detection as a point
# --------------------------------------------------------------------------- #
def fig_alert_volume_vs_detection(index):
    av = metrics.alert_volume_vs_detection(index).sort_values("results.alerts.mean")
    fig, ax = plt.subplots(figsize=(6.0, 3.0))
    y = list(range(len(av)))
    mean = av["results.alerts.mean"].to_numpy()
    lo = mean - av["results.alerts.min"].to_numpy()
    hi = av["results.alerts.max"].to_numpy() - mean
    ax.errorbar(mean, y, xerr=[lo, hi], fmt="o", color=BLUE, ecolor=BLUE,
                elinewidth=5, capsize=5, markersize=7, alpha=0.95, zorder=3,
                label="alert volume (mean, min-max)")
    ax.plot([0] * len(av), y, "D", color=SERIOUS, markersize=8, zorder=4, label="markers detected (blind)")
    ratio = (av["results.alerts.max"] / av["results.alerts.min"]).to_numpy()
    for yi, (m, rr) in enumerate(zip(mean, ratio)):
        ax.annotate(f"{rr:.2f}x", (m, yi), textcoords="offset points", xytext=(0, 9), ha="center",
                    color=INK2, fontsize=7.5)
    ax.set_yticks(y)
    ax.set_yticklabels(av["target"])
    ax.set_xlabel("count (symlog)")
    ax.set_xscale("symlog")
    ax.set_xlim(left=-2)
    ax.set_title("Alert volume is a range; detection is a point (0)")
    ax.legend(frameon=False, loc="lower right")
    ax.margins(y=0.22)
    _recede(ax, "x")
    return fig


# --------------------------------------------------------------------------- #
# 4. Synthesis recurrence vs post-verification disposition
# --------------------------------------------------------------------------- #
def fig_synthesis_recurrence(index):
    ct = cuts.recurrence_disposition_crosstab(index).set_index("recurrence")
    order = [c for c in ("not-attempted", "refuted", "inconclusive", "confirmed") if c in ct.columns]
    disp_color = {"refuted": AQUA, "inconclusive": WARN, "not-attempted": MISS, "confirmed": BLUE}
    fig, ax = plt.subplots(figsize=(5.8, 3.0))
    left = [0.0] * len(ct)
    ys = list(range(len(ct)))
    for col in order:
        ax.barh(ys, ct[col], left=left, color=disp_color[col], label=col,
                edgecolor=SURFACE, linewidth=0.6, zorder=3)
        left = [b + v for b, v in zip(left, ct[col])]
    ax.set_yticks(ys)
    ax.set_yticklabels(ct.index.astype(str))
    ax.set_xlabel("synthesis claims")
    ax.set_ylabel("recurrence (seen_in / of)")
    ax.set_title("Recurrence buys a synthesis claim no verdict")
    ax.legend(frameon=False, ncol=4, loc="upper center", bbox_to_anchor=(0.5, -0.22), fontsize=7.5)
    _recede(ax, "x")
    return fig


# --------------------------------------------------------------------------- #
# 5. G4 Noir seeding delta (crawl vs seeded), per target — log scale
# --------------------------------------------------------------------------- #
def fig_noir_seeding(index):
    nd = cuts.noir_seeding_delta(index)
    targets = sorted(nd.target.unique())
    fig, ax = plt.subplots(figsize=(6.0, 3.2))
    x = range(len(targets))
    w = 0.38
    for i, (arm, color) in enumerate((("crawl", ORANGE), ("seeded", BLUE))):
        means, errs = [], [[], []]
        for t in targets:
            sub = nd[(nd.target == t) & (nd.arm == arm)]
            r = sub.iloc[0]
            means.append(r.alerts_mean)
            errs[0].append(max(r.alerts_mean - r.alerts_min, 0))
            errs[1].append(max(r.alerts_max - r.alerts_mean, 0))
        xs = [xi + (i - 0.5) * w for xi in x]
        ax.bar(xs, means, w, yerr=errs, capsize=3, color=color, label=arm, zorder=3,
               error_kw=dict(ecolor=INK2, elinewidth=0.9))
    ax.set_yscale("log")
    ax.set_xticks(list(x))
    ax.set_xticklabels(targets)
    ax.set_ylabel("alerts (mean, min-max; log)")
    ax.set_title("Noir seeding is direction-reversing (crawl vs seeded)")
    ax.legend(frameon=False, loc="upper left")
    _recede(ax, "y")
    return fig


# --------------------------------------------------------------------------- #
# 6. Frontier (G8): no added value at Nx cost — log scale
# --------------------------------------------------------------------------- #
def fig_frontier(index):
    fm = cuts.frontier_measured(index)
    fig, ax = plt.subplots(figsize=(5.6, 3.2))
    x = range(len(fm))
    w = 0.38
    ax.bar([xi - w / 2 for xi in x], fm.default_usd, w, color=AQUA, label="default", zorder=3)
    ax.bar([xi + w / 2 for xi in x], fm.opus_usd, w, color=RED, label="Opus 5.5", zorder=3)
    for xi, (d, o, mlt) in enumerate(zip(fm.default_usd, fm.opus_usd, fm.multiple)):
        ax.text(xi + w / 2, o * 1.08, f"{mlt:.0f}x", ha="center", va="bottom", color=INK2, fontsize=8)
    ax.set_yscale("log")
    ax.set_xticks(list(x))
    ax.set_xticklabels(fm.stage)
    ax.set_ylabel("cost per stage, gitea (USD; log)")
    ax.set_title("Frontier model: no added value at 16-37x the cost")
    ax.legend(frameon=False, loc="upper left")
    _recede(ax, "y")
    return fig


# --------------------------------------------------------------------------- #
# 7. SAST↔DAST cross-section: CWE-79 source hundreds, DAST-confirmed 0
# --------------------------------------------------------------------------- #
def fig_sast_dast(index):
    cross = g9.sast_dast_cross(index)
    c79 = cross[cross.cwe == "CWE-79"].sort_values("sast_security")
    fig, ax = plt.subplots(figsize=(5.8, 2.9))
    y = list(range(len(c79)))
    ax.barh(y, c79.sast_security, 0.6, color=BLUE, zorder=3, label="SAST flags (CWE-79, in source)")
    _hlabels(ax, y, c79.sast_security.to_numpy(), dx=3)
    # DAST confirmed is 0 for every target — mark the baseline explicitly.
    ax.plot([0] * len(c79), y, "D", color=SERIOUS, markersize=7, zorder=4, label="DAST confirmed")
    ax.set_yticks(y)
    ax.set_yticklabels(c79.target)
    ax.set_xlabel("findings")
    ax.margins(x=0.14)
    ax.set_title("CWE-79: SAST flags hundreds, DAST confirms 0")
    ax.legend(frameon=False, loc="lower right")
    _recede(ax, "x")
    return fig


# --------------------------------------------------------------------------- #
# 8. Ceiling catch likelihood per marker (pilot + campaign oracle samples)
# --------------------------------------------------------------------------- #
def fig_ceiling_variance(index):
    cv = markers.ceiling_variance(index)
    cv = cv[cv.reached_samples > 0].sort_values("catch_rate")
    labels = [r.marker_id for r in cv.itertuples()]  # name by marker slug, not CVE (9/22 have none; markers.tex)
    colors = [GOOD if r.catch_rate >= 0.99 else WARN if r.catch_rate > 0 else MISS for r in cv.itertuples()]
    fig, ax = plt.subplots(figsize=(6.2, 4.4))
    y = list(range(len(cv)))
    ax.barh(y, cv.catch_rate, 0.68, color=colors, zorder=3)
    for yi, r in zip(y, cv.itertuples()):
        ax.text(max(r.catch_rate, 0) + 0.015, yi, f"{int(r.detected)}/{int(r.reached_samples)}",
                va="center", ha="left", color=INK2, fontsize=7.5)
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=6.5)
    ax.set_xlim(0, 1.18)
    ax.set_xlabel("catch rate  (confirmed / oracle samples the sink was reached)")
    ax.set_title("Ceiling catch likelihood: one reproducible, one flickering")
    # a small legend keyed to the status colours
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color=GOOD, label="reproducible"), Patch(color=WARN, label="flickering"),
                       Patch(color=MISS, label="never confirmed")], frameon=False, loc="lower right", fontsize=7.5)
    _recede(ax, "x")
    return fig


# --------------------------------------------------------------------------- #
# Block-6 (§10): spread, timing and catch over the post-corpus repeats.
# Each reads the §10 repeats via spread.* (corpus="post"); rows read
# "target (blind)" / "target (ceiling)".
# --------------------------------------------------------------------------- #
_C6_COL = {"blind": BLUE, "ceiling": ORANGE}


def fig_campaign6_accumulation(index):
    acc = spread.accumulation(index)
    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    # gitea's two modes are the highlight; the other targets are flat references.
    style = {
        ("gitea", "persistent"): dict(color=SERIOUS, ls="--", marker="o", label="gitea (persistent)"),
        ("gitea", "reset"): dict(color=BLUE, ls="-", marker="o", label="gitea (--reset-target)"),
        ("wordpress", "persistent"): dict(color=GREEN, ls="-", marker="s", alpha=0.65, label="wordpress"),
        ("grafana", "persistent"): dict(color=VIOLET, ls="-", marker="^", alpha=0.65, label="grafana"),
        ("cacti", "persistent"): dict(color=AQUA, ls="-", marker="D", alpha=0.65, label="cacti"),
    }
    for (target, mode), g in acc.groupby(["target", "mode"]):
        st = style.get((target, mode))
        if st is None:
            continue
        ax.plot(g.seq, g.tree, lw=1.8, markersize=5, markeredgecolor=SURFACE,
                markeredgewidth=0.8, zorder=3, **st)
    ax.set_yscale("log")
    ax.set_xlabel("scan repeat (chronological)")
    ax.set_ylabel("spider tree size (URLs, log)")
    ax.set_title("Scan-surface accumulation across repeats: only gitea swells under persistence")
    ax.legend(frameon=False, fontsize=7.5, loc="center right", ncol=1)
    _recede(ax, "y")
    return fig


def fig_campaign6_alert_spread(index):
    av = spread.scan_alert_spread(index)
    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    ys, labels = [], []
    for i, r in av.iterrows():
        y = len(av) - 1 - i
        ys.append(y)
        labels.append(f"{r.target} ({r.pol})")
        c = _C6_COL[r.pol]
        ax.plot([r.lo, r.hi], [y, y], color=c, lw=6, solid_capstyle="round", alpha=0.85, zorder=3)
        ax.plot([r["mean"]], [y], "o", color=c, markersize=7, markeredgecolor=SURFACE, markeredgewidth=1.2, zorder=4)
        fold = r.hi / r.lo if r.lo else 1.0
        lab = f"{r.lo:.0f}-{r.hi:.0f}" if r.lo != r.hi else f"{r.lo:.0f}"
        ax.text(r.hi * 1.12, y, f"{lab}  (n={int(r.n)}, {fold:.1f}x)", va="center", ha="left", color=INK2, fontsize=7.3)
    ax.set_yticks(ys)
    ax.set_yticklabels(labels, fontsize=8)
    ax.set_xscale("log")
    ax.set_xlim(70, 70000)
    ax.set_xlabel("ZAP alerts per run (log)")
    ax.set_title("Scan reproducibility across repeats: alert volume per target")
    ax.legend(handles=[Patch(color=BLUE, label="blind"), Patch(color=ORANGE, label="ceiling")],
              frameon=False, loc="upper right", fontsize=8)
    _recede(ax, "x")
    return fig


def fig_campaign6_ceiling_catch(index):
    cat = spread.ceiling_catch(index)
    fig, ax = plt.subplots(figsize=(6.0, 2.9))
    def status(x):
        return GOOD if x >= 0.99 else WARN if x > 0 else MISS
    y = list(range(len(cat)))
    ax.barh(y, cat.rate, 0.6, color=[status(x) for x in cat.rate], zorder=3)
    for yi, r in zip(y, cat.itertuples()):
        ax.text(max(r.rate, 0) + 0.02, yi, f"{int(r.hits)}/{int(r.n)}", va="center", ha="left", color=INK2, fontsize=8)
    ax.set_yticks(y)
    ax.set_yticklabels(cat.target)
    ax.set_xlim(0, 1.18)
    ax.set_xlabel("fraction of ceiling repeats that confirmed a CVE")
    ax.set_title("Ceiling catch (verify-level): grafana every run, wordpress 1-in-6")
    ax.legend(handles=[Patch(color=GOOD, label="reproducible"), Patch(color=WARN, label="flickering"),
                       Patch(color=MISS, label="never / n=1")], frameon=False, loc="lower right", fontsize=7.5)
    _recede(ax, "x")
    return fig


def fig_campaign6_marker_catch(index):
    mc = spread.marker_catch(index)
    mc = mc[mc.reached_samples > 0] if not mc.empty else mc
    if mc.empty:
        raise ValueError("no post-corpus cve-detection.json (run `dast cve` over the §10 runs)")
    mc = mc.sort_values(["catch_rate", "reached_samples"]).reset_index(drop=True)
    labels = [r.marker_id for r in mc.itertuples()]  # name by marker slug, not CVE (9/22 have none; markers.tex)
    colors = [GOOD if r.catch_rate >= 0.99 else WARN if r.catch_rate > 0 else MISS for r in mc.itertuples()]
    fig, ax = plt.subplots(figsize=(6.2, 4.6))
    y = list(range(len(mc)))
    ax.barh(y, mc.catch_rate, 0.68, color=colors, zorder=3)
    for yi, r in zip(y, mc.itertuples()):
        ax.text(max(r.catch_rate, 0) + 0.015, yi, f"{int(r.detected)}/{int(r.reached_samples)}",
                va="center", ha="left", color=INK2, fontsize=7.3)
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=6.3)
    ax.set_xlim(0, 1.18)
    ax.set_xlabel("ground-truth catch rate  (detected / oracle reached, n=6 repeats)")
    ax.set_title("Per-marker ceiling catch: only grafana's traversal confirms, 6/6")
    ax.legend(handles=[Patch(color=GOOD, label="reproducible"), Patch(color=MISS, label="reached, never confirmed")],
              frameon=False, loc="lower right", fontsize=7.5)
    _recede(ax, "x")
    return fig


def fig_campaign6_stage_spread(index):
    sc = spread.stage_count_spread(index)
    rowkeys = [(t, p) for t in spread.TARGET_ORDER for p in ("blind", "ceiling")]
    ylabels = [f"{t} ({p})" for (t, p) in rowkeys]
    panels = [("claims", "triage claims"), ("refuted", "verify refuted"), ("confirmed", "verify confirmed")]
    fig, axes = plt.subplots(1, 3, figsize=(8.2, 3.7), sharey=True)
    for ax, (metric, title) in zip(axes, panels):
        g = sc[sc.metric == metric].set_index(["target", "pol"])
        for i, (t, p) in enumerate(rowkeys):
            y = len(rowkeys) - 1 - i
            if (t, p) not in g.index:
                continue
            r = g.loc[(t, p)]
            c = _C6_COL[p]
            ax.plot([r.lo, r.hi], [y, y], color=c, lw=5.5, solid_capstyle="round", alpha=0.85, zorder=3)
            ax.plot([r["mean"]], [y], "o", color=c, markersize=6, markeredgecolor=SURFACE, markeredgewidth=1.1, zorder=4)
        ax.set_title(title, fontsize=10)
        ax.set_xlim(left=-0.5)
        _recede(ax, "x")
        ax.margins(y=0.08)
    axes[0].set_yticks(range(len(rowkeys)))
    axes[0].set_yticklabels(ylabels[::-1], fontsize=8)
    axes[2].set_xlim(-0.2, 2.6)
    fig.suptitle("Model-stage spread across repeats (min-max, mean dot)", fontsize=11, fontweight="bold", color=INK)
    axes[2].legend(handles=[Patch(color=BLUE, label="blind"), Patch(color=ORANGE, label="ceiling")],
                   frameon=False, loc="lower right", fontsize=8)
    fig.supxlabel("findings per run", fontsize=9.5, color=INK2)
    return fig


def fig_campaign6_stage_time(index):
    st = spread.stage_time(index)
    dpiv = st.pivot_table(index=["target", "pol"], columns="stage", values="minutes", fill_value=0)
    rowkeys = [(t, p) for t in spread.TARGET_ORDER for p in ("blind", "ceiling")]
    ylabels = [f"{t} ({p})" for (t, p) in rowkeys]
    stages = [("scan", BLUE), ("triage", ORANGE), ("verify", AQUA), ("report", YELLOW)]
    fig, ax = plt.subplots(figsize=(6.6, 3.9))
    for i, key in enumerate(rowkeys):
        yi = len(rowkeys) - 1 - i
        if key not in dpiv.index:
            continue
        row = dpiv.loc[key]
        left = 0.0
        for stage, color in stages:
            v = float(row.get(stage, 0.0))
            if v <= 0.02:
                continue
            ax.barh(yi, v, left=left, height=0.62, color=color, edgecolor=SURFACE, linewidth=0.7, zorder=3)
            left += v
        ax.text(left + 0.6, yi, f"{left:.0f} min", va="center", ha="left", color=INK2, fontsize=7.6)
    ax.set_yticks(range(len(rowkeys)))
    ax.set_yticklabels(ylabels[::-1], fontsize=8)
    ax.set_xlabel("mean minutes per run")
    ax.set_xlim(0, 78)
    ax.set_title("Where the wall-clock goes: scan dominates every target")
    ax.legend(handles=[Patch(color=c, label=s) for s, c in stages], frameon=False, loc="upper right", ncol=2, fontsize=7.8)
    _recede(ax, "x")
    return fig


def fig_campaign6_total_time(index):
    agg = spread.total_time_spread(index)
    fig, ax = plt.subplots(figsize=(6.2, 3.6))
    ys, labels = [], []
    for i, r in agg.iterrows():
        y = len(agg) - 1 - i
        ys.append(y)
        labels.append(f"{r.target} ({r.pol})")
        c = _C6_COL[r.pol]
        ax.plot([r.lo, r.hi], [y, y], color=c, lw=6, solid_capstyle="round", alpha=0.85, zorder=3)
        ax.plot([r["mean"]], [y], "o", color=c, markersize=7, markeredgecolor=SURFACE, markeredgewidth=1.2, zorder=4)
        lab = f"{r.lo:.0f}-{r.hi:.0f}" if round(r.lo) != round(r.hi) else f"{r.lo:.0f}"
        ax.text(r.hi + 1.2, y, f"{lab} min (n={int(r.n)})", va="center", ha="left", color=INK2, fontsize=7.4)
    ax.set_yticks(ys)
    ax.set_yticklabels(labels, fontsize=8)
    ax.set_xlabel("total wall-clock minutes per run")
    ax.set_xlim(0, 88)
    ax.set_title("Per-run wall-clock: tight within a cell, ~3.5x across targets")
    ax.legend(handles=[Patch(color=BLUE, label="blind"), Patch(color=ORANGE, label="ceiling")],
              frameon=False, loc="upper right", fontsize=8)
    _recede(ax, "x")
    return fig


def fig_campaign6_marker_lifecycle(index):
    lc = spread.marker_lifecycle(index)
    if lc.empty:
        raise ValueError("no post-corpus cve-detection.json (run `dast cve` over the §10 runs)")
    from matplotlib.patches import Rectangle

    cols = [s for s, _ in spread.LIFECYCLE_STAGES]
    collabels = ["reached", "ZAP\nalert", "triage\nflag", "LLM\nflag",
                 "verify\ndispatch", "verify\nconfirm", "detected\n(strict)"]
    rowlabels = [r.marker_id for r in lc.itertuples()]  # name by marker slug, not CVE (9/22 have none; markers.tex)
    # Three discrete levels in the house palette (no colourbar): none / some
    # repeats (WARN, the flickering collisions) / all repeats (BLUE). Drawn as
    # vector rects (not imshow) so the .pgf stays vector like the other figures.
    level_color = {0: GRID, 1: WARN, 2: BLUE}
    nrow, ncol = len(lc), len(cols)
    fig, ax = plt.subplots(figsize=(6.8, 6.2))
    for i in range(nrow):
        for j, col in enumerate(cols):
            v = float(lc[col].iloc[i])
            lv = 2 if v >= 0.999 else 1 if v > 0 else 0
            ax.add_patch(Rectangle((j - 0.5, i - 0.5), 1, 1, facecolor=level_color[lv],
                                   edgecolor=SURFACE, linewidth=2, zorder=2))
            if 0 < v < 0.999:  # label only the flickering collisions
                ax.text(j, i, f".{int(round(v * 100)):02d}", ha="center", va="center",
                        color=INK, fontsize=6, zorder=4)
    ax.set_xlim(-0.5, ncol - 0.5)
    ax.set_ylim(nrow - 0.5, -0.5)  # row 0 at the top
    ax.set_xticks(range(ncol))
    ax.set_xticklabels(collabels, fontsize=7.5)
    ax.set_yticks(range(nrow))
    ax.set_yticklabels(rowlabels, fontsize=6.3)
    # darker separators between target groups
    for i in range(1, nrow):
        if lc.target.iloc[i] != lc.target.iloc[i - 1]:
            ax.axhline(i - 0.5, color=INK2, linewidth=1.6, zorder=5)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title("Marker lifecycle: every marker reached, only one confirmed strictly")
    ax.legend(handles=[Patch(color=BLUE, label="all 6 repeats"),
                       Patch(color=WARN, label="some repeats"),
                       Patch(color=GRID, label="none")],
              frameon=False, loc="upper left", bbox_to_anchor=(1.01, 1.0), fontsize=7.5)
    return fig


def fig_declutter_funnel(index):
    f = spread.declutter_funnel(index)
    if f.empty:
        raise ValueError("no blind report.md found (needs the full chain's reports)")
    from matplotlib.lines import Line2D

    stages = [s for s, _ in spread.FUNNEL_STAGES]
    stage_labels = ["raw ZAP\nalerts", "findings\n(dedup)", "need\na person", "tool-settled\n(conf + ref)"]
    tcolor = {"grafana": BLUE, "wordpress": ORANGE, "cacti": AQUA, "gitea": VIOLET}
    fig, ax = plt.subplots(figsize=(6.6, 4.0))
    x = list(range(len(stages)))
    handles = []
    for r in f.itertuples():
        ys = [max(float(getattr(r, s)), 0.7) for s in stages]  # floor 0 for log
        c = tcolor.get(r.target, INK2)
        ax.plot(x, ys, "-o", color=c, markersize=6, lw=1.8,
                markeredgecolor=SURFACE, markeredgewidth=1.0, zorder=3)
        ax.text(-0.06, ys[0], f"{int(r.raw_alerts):,}", ha="right", va="center", color=c, fontsize=7.3)
        lab = f"{int(r.settled)}" + (f" +{int(r.confirmed)} conf" if r.confirmed >= 0.5 else "")
        ax.text(3.06, ys[-1], lab, ha="left", va="center", color=c, fontsize=7.3)
        handles.append(Line2D([0], [0], color=c, lw=2.4, marker="o", label=r.target))
    ax.set_yscale("log")
    ax.set_xticks(x)
    ax.set_xticklabels(stage_labels, fontsize=8)
    ax.set_xlim(-0.95, 3.8)
    ax.set_ylim(0.5, 9000)
    ax.set_ylabel("count per blind run (log)")
    ax.set_title("Noise control: a raw alert dump to an evidenced, triageable report")
    ax.legend(handles=handles, frameon=False, loc="upper right", fontsize=8)
    _recede(ax, "y")
    return fig


def fig_report_ordering(index=None):
    """Static decision-flow of the report's sort keys (from report.py). Needs no
    run data, so it renders on any checkout."""
    from matplotlib.patches import FancyBboxPatch

    BLUE2 = "#6aa0e0"  # a lighter BLUE for the secondary (tiebreak) sort key
    fig, ax = plt.subplots(figsize=(7.4, 4.6))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 10)
    ax.axis("off")

    def box(x, y, w, h, text, fc=BLUE, tc=SURFACE, fs=8):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.1",
                                    facecolor=fc, edgecolor="none", zorder=3))
        ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", color=tc,
                fontsize=fs, zorder=4, linespacing=1.3)

    def arrow(x0, x1, y):
        ax.annotate("", xy=(x1, y), xytext=(x0, y),
                    arrowprops=dict(arrowstyle="-|>", color=INK2, lw=1.6), zorder=2)
        ax.text((x0 + x1) / 2, y + 0.3, "then", ha="center", va="bottom", color=INK2,
                fontsize=7, style="italic")

    # Track 1 — the sections, top to bottom of the report
    ax.text(0.3, 9.5, "Sections, in the order a reader works through them", ha="left",
            fontsize=9, color=INK, fontweight="bold")
    sections = ["reproduced\nby a tool", "open", "claims", "evident", "refuted", "informational"]
    for i, name in enumerate(sections):
        box(0.3 + i * 1.58, 7.9, 1.4, 1.1, name, fc=AQUA, tc=INK, fs=6.6)

    # Track 2 — within a section, one line per ZAP rule
    ax.text(0.3, 7.2, "Within a section: one line per ZAP rule, led by its worst member", ha="left",
            fontsize=9, color=INK, fontweight="bold")
    keys = ["1. ZAP risk", "2. a scanner\nattacked for it", "3. both arms\nflagged it",
            "4. ZAP\nconfidence", "5. rule id\n(stable tiebreak)"]
    for i, name in enumerate(keys):
        box(0.3 + i * 1.9, 5.4, 1.6, 1.2, name, fc=BLUE if i == 0 else BLUE2, fs=7)

    # Track 3 — cross-endpoint synthesis claims
    ax.text(0.3, 4.7, "Open claims: one line per claim", ha="left",
            fontsize=9, color=INK, fontweight="bold")
    box(0.3, 3.0, 3.0, 1.2, "1. models agreeing\n(most first)", fc=BLUE, fs=8)
    arrow(3.4, 4.5, 3.6)
    box(4.6, 3.0, 3.0, 1.2, "2. reproducibility\n(seen_in samples)", fc=BLUE2, fs=8)
    ax.text(7.9, 3.6, 'a 1-sample claim is\nflagged "lead, not a result"',
            ha="left", va="center", color=WARN, fontsize=6.8, linespacing=1.3)

    # severity note (orthogonal axis)
    box(0.3, 0.8, 9.0, 1.5,
        "Severity (SARIF level) = ZAP risk, set by the scanner  (High=error, Medium=warning, Low=note).\n"
        "The order is ordinal: it sorts evidence, sets a SARIF rank, never the level, and is not a ranking by true risk.",
        fc=GRID, tc=INK, fs=7.2)
    ax.set_title("How the report orders findings: sections, then sort keys")
    return fig


FIGURES = {
    "two-arm-matrix": fig_two_arm_matrix,
    "detection-ladder": fig_detection_ladder,
    "alert-volume": fig_alert_volume_vs_detection,
    "synthesis-recurrence": fig_synthesis_recurrence,
    "noir-seeding": fig_noir_seeding,
    "frontier": fig_frontier,
    "sast-dast": fig_sast_dast,
    "declutter-funnel": fig_declutter_funnel,
    "report-ordering": fig_report_ordering,
    "ceiling-variance": fig_ceiling_variance,
    "campaign6-accumulation": fig_campaign6_accumulation,
    "campaign6-alert-spread": fig_campaign6_alert_spread,
    "campaign6-stage-spread": fig_campaign6_stage_spread,
    "campaign6-stage-time": fig_campaign6_stage_time,
    "campaign6-total-time": fig_campaign6_total_time,
    "campaign6-ceiling-catch": fig_campaign6_ceiling_catch,
    "campaign6-marker-catch": fig_campaign6_marker_catch,
    "campaign6-marker-lifecycle": fig_campaign6_marker_lifecycle,
}


def save_figure(fig, out_dir: str | Path, name: str, formats=DEFAULT_FORMATS) -> list[Path]:
    """Save one figure in each format; a format needing an absent TeX is skipped."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for ext in formats:
        path = out_dir / f"{name}.{ext}"
        try:
            fig.savefig(path, bbox_inches="tight")
            written.append(path)
        except Exception:  # pragma: no cover - only when a TeX engine is missing
            continue
    plt.close(fig)
    return written


def render_all(index, out_dir: str | Path, formats=DEFAULT_FORMATS, only: list[str] | None = None) -> list[Path]:
    """Build and save the standard figure set; returns the files written."""
    configure()
    written: list[Path] = []
    for name, builder in FIGURES.items():
        if only and name not in only:
            continue
        try:
            fig = builder(index)
        except Exception as exc:  # a cut with no data in a narrow selection
            print(f"  (skipped figure {name}: {type(exc).__name__}: {exc})")
            continue
        written.extend(save_figure(fig, out_dir, name, formats))
    return written
