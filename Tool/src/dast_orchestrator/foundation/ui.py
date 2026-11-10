"""Consistent console output: one shape for every phase of every command, because a run's
log is read far more often than any artifact.

Four rule characters in descending density (``#`` session, ``=`` run/row, ``+`` stage,
``-`` phase) so the hierarchy reads before the words. :func:`phase` opens and
:func:`done` closes (the only place a duration prints, always last); files sit
second-to-last; ``warn``/``fail``/``error`` go to stderr; every line is one write so a
background sampler cannot interleave.
"""

from __future__ import annotations

import os
import sys
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

#: Total width of a banner. Wide enough that a centred title has visible rule on
#: both sides, still inside a standard 100-column terminal.
WIDTH = 78

#: Column at which a key/value line's value starts. Two columns read as a table
#: — the eye finds a setting by scanning the left edge instead of parsing prose.
LABEL_WIDTH = 26


def _write(line: str, stream: Any = None) -> None:
    """One line, one write — see the module docstring."""
    stream = stream or sys.stdout
    stream.write(line + "\n")
    stream.flush()


#: Repo root, for rendering paths the way a reader would type them.
_REPO_ROOT = Path(__file__).resolve().parents[3]


def short_path(value: Any) -> str:
    """A path relative to the repo root when it is inside it, else unchanged.

    Log output is read next to the commands that produced it, and
    ``/Users/<name>/…/Prototype/config/scanner/.env`` says the same thing as
    ``config/scanner/.env`` while burying it — three of them on one line and the
    line stops being readable. It is also what a reader would *type*. The same
    reasoning the artifacts already follow: a path quoted in the writeup should
    not carry the author's home directory.
    """
    # Unresolved first, then resolved. `.venv/bin/python3` is a symlink out of
    # the tree, so resolving it lands in /opt/homebrew and the shortening is lost
    # on the one token that appears in every spawned command.
    for candidate in (Path(value), Path(value).resolve()):
        try:
            return str(candidate.relative_to(_REPO_ROOT))
        except (ValueError, TypeError, OSError):
            continue
    return str(value)


def short_command(argv: "list[str]") -> str:
    """A spawned command with every in-repo path shortened, for the log."""
    return " ".join(short_path(token) if "/" in str(token) else str(token)
                    for token in argv)


def session(title: str, subtitle: str = "", facts: "dict[str, Any] | None" = None,
            note: str = "") -> None:
    """Open something that *contains* commands — a harness sheet, not a stage.

    **The rule character is the hierarchy**, four distinct glyphs in descending
    density so a reader tells the level by shape, not line-weight:

    * ``#`` a session: many runs, one sheet (this).
    * ``=`` one run or sheet row (:func:`section`, :func:`session_divider`).
    * ``+`` a stage of the pipeline (:func:`headline`).
    * ``-`` a phase or section inside one (:func:`phase`).

    A sheet spawns a stage per row, and every stage prints its own ``+`` banner.
    Without a heavier rule above them the log is a wall of identical headers with
    no way to see where the *sheet* began — and a night's log is exactly the one
    read long after the fact, by someone scrolling for a boundary.
    """
    _write("\n" + "#" * WIDTH)
    _write(f"  {title.upper()}")
    if subtitle:
        _write(f"  {subtitle}")
    for label, value in (facts or {}).items():
        _write(f"  {str(label) + ':':<{LABEL_WIDTH}}{value}")
    _write(f"  {'started:':<{LABEL_WIDTH}}{_now()}")
    if note:
        _write("")
        _write(f"  {note}")
    _write("#" * WIDTH)


def session_divider(label: str) -> None:
    """Separate one member of a session from the next.

    Carries its own position (``3/12``) because the reason to scroll a night's
    log is almost always "where did execution N start" — and a divider that says
    only *what* ran leaves the reader counting.
    """
    body = f"  {label}  "
    side = 6
    line = "=" * side + body + "=" * max(3, WIDTH - side - len(body))
    _write("\n" + line)


def session_end(title: str, facts: "dict[str, Any] | None" = None) -> None:
    """Close a session with the same rule it opened with."""
    _write("\n" + "#" * WIDTH)
    _write(f"  {title.upper()}")
    for label, value in (facts or {}).items():
        _write(f"  {str(label) + ':':<{LABEL_WIDTH}}{value}")
    _write(f"  {'finished:':<{LABEL_WIDTH}}{_now()}")
    _write("#" * WIDTH)


#: The ``[n/N]`` a stage carries while it runs as part of a sequence, set by the
#: orchestrator (:func:`dast_orchestrator.cli.run`) around each stage's ``main``
#: and read by :func:`headline` and :func:`finished`. Empty for a stage run on
#: its own (a harness subprocess, a bare ``python -m``), which then prints no
#: position — there is no sequence to place it in.
_stage_label = ""


def set_stage(label: str) -> None:
    """Set (or clear, with ``""``) the ``n/N`` a stage's banners carry."""
    global _stage_label
    _stage_label = label


def _stage_prefix() -> str:
    return f"[{_stage_label}] " if _stage_label else ""


def section(title: str, subtitle: str = "") -> None:
    """A run-level banner ruled with ``=``, framing one run: the ``dast —`` wrapper
    around its stages and the closing run summary.

    Ruled differently from a stage :func:`headline` (``+``) on purpose: a reader
    scrolling a long log can tell "this is the run frame" from "a stage started"
    at a glance, rather than reading every banner's text to place it.
    """
    _write("\n" + "=" * WIDTH)
    _write(f"  {title}")
    if subtitle:
        _write(f"  {subtitle}")
    _write("=" * WIDTH)


def headline(title: str, subtitle: str = "") -> None:
    """Open a whole command: what ran, which run it belongs to, and when.

    A run's log is read long after the run, often next to another run's log, and
    the two things needed to tell them apart — the run id, which is also the
    directory every artifact landed in, and the wall-clock time — were nowhere in
    the output. Both are here now, and :func:`finished` closes with the end time,
    so a log pasted into a notebook carries its own span. In a sequence the stage
    carries its ``[n/N]`` position (:func:`set_stage`) at the head of the title.
    """
    _write("\n" + "+" * WIDTH)
    _write(f"  {_stage_prefix()}{title}")
    if subtitle:
        _write(f"  {subtitle}")
    _write(f"  started {_now()}")
    _write("+" * WIDTH)


def finished(what: str = "") -> None:
    """Close a command with the wall-clock time it ended, carrying the stage's
    ``[n/N]`` position when it has one (:func:`set_stage`)."""
    _write(f"\n  {_stage_prefix()}finished {_now()}{f'  — {what}' if what else ''}")


def now() -> str:
    """The local wall-clock time, for a caller that wants to stamp its own line."""
    return _now()


def _now() -> str:
    """Local wall-clock time, seconds resolution, with the offset.

    Local rather than UTC on purpose: this line exists so a human can line the
    log up against when they started something, and the run id already carries
    the UTC instant for machines.
    """
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def phase(title: str) -> None:
    """Open a phase with a centred banner. Pairs with :func:`done`."""
    body = f" {title} "
    side = max(3, (WIDTH - len(body)) // 2)
    line = "-" * side + body + "-" * max(3, WIDTH - side - len(body))
    _write("\n" + line)


def step(message: str) -> None:
    """Progress while a phase runs, e.g. a poll or a per-item counter."""
    _write(f"  {message}")


def blank() -> None:
    """One empty line, to separate a block from what follows it."""
    _write("")


def found(message: str) -> None:
    """What the phase produced: counts, outcomes, findings."""
    _write(f"  {message}")


def item(label: str, value: Any) -> None:
    """One ``label:   value`` line, for configuration and settings.

    Settings are a table, not a narrative: ``connecting to http://…`` and
    ``ZAP 2.17.0 ready, target http://…`` say the same things as ``address:``
    and ``version:`` while making the reader parse a sentence to find either.
    """
    _write(f"  {str(label) + ':':<{LABEL_WIDTH}}{value}")


def wrote(path: Any, label: str = "") -> None:
    """A file this phase wrote. Always after :func:`found`, before :func:`done`."""
    _write(f"  → {path}{f'  ({label})' if label else ''}")


def two_columns(left_header: str, right_header: str,
                left: "list[str]", right: "list[str]", gap: int = 3) -> None:
    """Two aligned columns — an in→out summary read down each side.

    The whole point is the delta at a glance: what a stage was *given* on the
    left, what it *produced* on the right, one row per fact. Rows are zipped, a
    missing cell is blank, and the left column is sized to its widest entry (with
    room kept for the right).
    """
    from itertools import zip_longest

    col = min(max([len(left_header), *(len(s) for s in left)]), WIDTH // 2)

    def row(a: str, b: str) -> str:
        return f"  {a:<{col}}{' ' * gap}{b}".rstrip()

    _write(row(left_header, right_header))
    for a, b in zip_longest(left, right, fillvalue=""):
        _write(row(a, b))


#: How many warnings this process has emitted. A caller can snapshot it around a
#: block to ask "did anything warn?" — the harness uses it to decide whether a
#: dry-run's scratch was clean enough to remove.
_warnings = 0


def warning_count() -> int:
    return _warnings


def warn(message: str) -> None:
    global _warnings
    _warnings += 1
    _write(_wrap(message, "  [Warning] ", " " * len("  [Warning] ")), sys.stderr)


def error(message: str) -> None:
    """A refusal the run stops on, in the ``[Warning]`` house style.

    Distinct from :func:`fail` (the ``✗`` end-of-run marker): ``[Error]`` is the
    up-front "this cannot run as asked" line — a missing required secret, an
    unusable configuration — so it reads as the sibling of :func:`warn`.
    """
    _write(_wrap(message, "  [Error] ", " " * len("  [Error] ")), sys.stderr)


def fail(message: str) -> None:
    _write(_wrap(message, "  ✗ ", "    "), sys.stderr)


def _wrap(message: str, prefix: str, indent: str) -> str:
    """Wrap to :data:`WIDTH` with a hanging indent.

    A warning is the one line a reader must not skim past, and an unbroken
    200-character line wrapped by the terminal is exactly what gets skimmed.
    """
    import textwrap

    lines = textwrap.wrap(" ".join(str(message).split()),
                          width=WIDTH - len(indent)) or [""]
    return "\n".join([prefix + lines[0]] + [indent + line for line in lines[1:]])


def done(seconds: float, note: str = "") -> None:
    """Close a phase with its duration — the last line, every time.

    Durations are rendered in the unit a reader can act on: seconds below two
    minutes, minutes above. "1643.2s" and "27.4 min" carry the same information
    and only one of them is read correctly at a glance.
    """
    duration = f"{seconds:.1f}s" if seconds < 120 else f"{seconds / 60:.1f} min"
    _write(f"  ✓ {duration}{f'  {note}' if note else ''}")


class Progress:
    """A progress indicator for a stage whose percentage is actually known.

    **Two renderings, chosen by whether stdout is a terminal**, because the same
    output has two very different readers:

    * **At a terminal** — one line, redrawn in place with a bar, the percentage,
      elapsed time and an ETA extrapolated from the rate so far. A 45-minute
      active scan should say how much of it is left.
    * **Redirected** — exactly the stepped lines this project already emitted:
      one line per ``step`` percent plus a ``heartbeat``. A CI log is read after
      the fact and by a machine, and carriage returns turn it into one unreadable
      line. That constraint is also why this is ~100 lines of stdlib rather than
      a progress-bar library: none of them treat the redirected case as the one
      that matters.

    The ETA is deliberately plain arithmetic on the rate so far, and it is
    labelled ``~``: ZAP's active scanner does not advance linearly, so a
    confident-looking estimate would be a lie. It is there to distinguish "ten
    more minutes" from "this is not going to finish", which is the decision a
    watcher actually makes.
    """

    #: Width of the drawn bar, leaving room for the label, percent and times.
    BAR_WIDTH = 24

    def __init__(self, label: str, step: int = 5, heartbeat: float = 300.0,
                 stream: Any = None) -> None:
        """
        :param step: percent between lines when redirected; ``0`` means report
            on the heartbeat only.
        :param heartbeat: seconds after which an unchanged percentage is
            reprinted, so a long plateau still shows the run is alive.
        """
        self.label = label
        self.step = step
        self.heartbeat = heartbeat
        self.stream = stream or sys.stdout
        # Redirected output gets the stepped lines, and so does anything running
        # under CI even if that CI allocated a pty. `CI` is set by GitHub
        # Actions, GitLab CI, CircleCI, Travis and Jenkins alike; honouring it
        # costs one condition and removes the whole class of "the log is one
        # unreadable line of carriage returns" failure.
        self.tty = (
            bool(getattr(self.stream, "isatty", lambda: False)())
            and not os.getenv("CI")
        )
        self._last_shown: int | None = None
        self._last_report = -heartbeat
        self._drawn = False
        # Last reported position, so a durable log line printed *through* the bar
        # (:meth:`line`) can repaint it without the caller passing the numbers
        # again.
        self._pct = 0
        self._elapsed = 0.0

    def update(self, percent: int, elapsed: float) -> None:
        """Report progress. Safe to call on every poll; it decides what to emit."""
        if self.tty:
            self._draw(percent, elapsed)
            return

        stepped = self.step > 0 and (
            self._last_shown is None
            or percent >= self._last_shown + self.step
            or percent >= 100
        )
        if self.step <= 0 and percent >= 100:
            stepped = True
        if stepped or (elapsed - self._last_report) >= self.heartbeat:
            # "unchanged" only means something when the cadence is *change*. On
            # a clock-only stage every line is a heartbeat, so the note would be
            # on every line and inform nobody.
            suffix = "" if stepped or self.step <= 0 else (
                f"  (unchanged for {self.heartbeat / 60:.0f}m)"
            )
            _write(f"  [{self.label}] {percent:3d}%{suffix}", self.stream)
            self._last_report = elapsed
            if stepped:
                self._last_shown = percent

    #: Lines the bar sits above. The bar is a **fixed header**: it is painted
    #: once and stays put while rows stream in below it, and each repaint reaches
    #: back up to it by this count. Every line that appears below the bar must go
    #: through :meth:`line` so the count stays exact — a stray write desyncs it.
    _below = 0

    def _bar_text(self, percent: int, elapsed: float) -> str:
        """The bar line: ``\\r`` to the start, the bar, ``\\033[K`` to clear any
        tail from a longer previous paint. No newline."""
        percent = max(0, min(100, int(percent)))
        filled = round(self.BAR_WIDTH * percent / 100)
        bar = "█" * filled + "░" * (self.BAR_WIDTH - filled)
        eta = ""
        if 0 < percent < 100 and elapsed > 0:
            remaining = elapsed * (100 - percent) / percent
            eta = f"  ~{_duration(remaining)} left"
        return (f"\r  [{self.label}] {bar} {percent:3d}%  "
                f"{_duration(elapsed)}{eta}\033[K")

    def _repaint(self) -> None:
        """Redraw the fixed bar in place, wherever the cursor is now.

        The cursor always rests at the start of a blank line below every row, so
        the bar is ``_below + 1`` lines above it: step up, rewrite, step back
        down. ``\\033[0A`` would move one line (ANSI treats 0 as 1), hence the
        offset is never zero.
        """
        up = self._below + 1
        self.stream.write(f"\033[{up}A{self._bar_text(self._pct, self._elapsed)}"
                          f"\033[{up}B\r")
        self.stream.flush()

    def _draw(self, percent: int, elapsed: float) -> None:
        self._pct, self._elapsed = max(0, min(100, int(percent))), elapsed
        if not self._drawn:
            # First paint: the bar takes a line and the cursor drops to the blank
            # line below it, where the first row (or nothing, for a bar-only
            # stage) will go.
            self.stream.write(self._bar_text(percent, elapsed) + "\n")
            self._drawn = True
            self.stream.flush()
            return
        self._repaint()

    def line(self, text: str, percent: "int | None" = None,
             elapsed: "float | None" = None) -> None:
        """Append a row **below** the fixed bar, then repaint the bar in place.

        This is what lets a stage keep its per-item roll-call *and* show one bar:
        the bar stays on top as a header, the rows stream beneath it. Redirected,
        it is just the row (the bar's stepped ``%`` comes from :meth:`update`).
        ``percent``/``elapsed`` advance the bar in the same call, so a caller does
        not also call :meth:`update`. Every line below the bar must come through
        here, or the header's line count drifts.
        """
        if percent is not None:
            self._pct = max(0, min(100, int(percent)))
        if elapsed is not None:
            self._elapsed = elapsed
        if not self.tty:
            _write(f"  {text}", self.stream)
            return
        if not self._drawn:
            self.stream.write(self._bar_text(self._pct, self._elapsed) + "\n")
            self._drawn = True
        # Kept to one visual line so the header's `_below` count matches reality:
        # a wrapped row would occupy two rows and throw the cursor arithmetic off.
        width = _terminal_width(self.stream)
        row = text if len(text) <= width - 2 else text[:width - 3] + "…"
        self.stream.write(f"  {row}\033[K\n")
        self._below += 1
        self._repaint()

    def close(self, note: str = "") -> None:
        """Finish the indicator. The fixed bar and every row are already durable;
        a closing note (how a bar-only stage ended) prints below them."""
        if note:
            _write(f"  [{self.label}] {note}", self.stream)


def _terminal_width(stream: Any) -> int:
    """The stream's column count, or :data:`WIDTH` when it cannot be read.

    Used only to keep a progress row on one visual line — a wrapped row would
    make the fixed bar's line count wrong.
    """
    try:
        return os.get_terminal_size(stream.fileno()).columns
    except (OSError, ValueError, AttributeError):
        return WIDTH


def _duration(seconds: float) -> str:
    """``94.2s`` / ``12.3m`` / ``1.4h`` — one unit, always."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    return f"{seconds / 3600:.1f}h"


class OpenPhase:
    """A phase whose body is not a single block, closed with :meth:`close`.

    Most phases are a ``with`` block. Setup is not: it interleaves configuration
    calls with the checks that report them, and wrapping it would mean either
    hiding those lines or nesting the whole scan inside it. It still has to end
    the same way every other phase does — files, then time — so it gets an
    object that remembers when it started.
    """

    def __init__(self, title: str) -> None:
        phase(title)
        self._started = time.monotonic()

    def close(self, note: str = "", files: "list[Any] | None" = None,
              timed: bool = True) -> float:
        """Emit this phase's files and, unless ``timed`` is false, its duration.

        :param timed: a phase that only *echoes* what it is about to do — a plan,
            a list of inputs — did no work worth a stopwatch, and a ``✓ 0.0s``
            on it is noise that reads as a measurement. Those close ``timed=False``:
            files still print, the duration does not.
        """
        for item in files or []:
            wrote(item)
        seconds = time.monotonic() - self._started
        if timed:
            done(seconds, note)
        elif note:
            _write(f"  {note}")
        return seconds


def open_phase(title: str) -> OpenPhase:
    return OpenPhase(title)


@contextmanager
def timed_phase(title: str, note: str = "") -> Iterator[dict[str, Any]]:
    """Open a phase, time it, and close it even if the body raises.

    A phase that fails still reports how long it burned before failing — the
    duration of a failed stage is exactly the number missing when a run has to be
    re-planned.
    """
    phase(title)
    started = time.monotonic()
    state: dict[str, Any] = {"note": note, "files": []}
    try:
        yield state
    finally:
        # Files second to last, time last — always, so the two things a reader
        # looks for are in a fixed place regardless of what the phase did.
        for item in state.get("files") or []:
            wrote(item)
        done(time.monotonic() - started, str(state.get("note") or ""))
