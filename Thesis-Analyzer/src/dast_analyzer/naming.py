"""Parse a campaign row name into its axes.

The row-name grammar is RUN-PLAN §4; the minting-vs-suffixed distinction and the
`frver2`/`frver3` operational re-runs are the two edge cases the parser must get
right, so the logic is driven by the record's own metadata (``label`` against
``harness_row``), never by guessing which trailing digits are a repeat.

  - Base / minting rows (G1-G4): ``label`` is empty, ``harness_row`` is the full
    ``<target>-<auth>-<role>``. A G3 scan repeat is a *distinct run* with the same
    name, so its repeat ordinal is assigned run-wise by the index, not parsed here
    (``repeat`` stays None).
  - Suffixed / non-minting rows (G5-G8): ``harness_row`` is
    ``<target>-<auth>-<role>-<variant>`` and ``label`` extends it by ``-<repeat>``.
  - ``frver2`` / ``frver3``: ``label == harness_row`` (no ``-<repeat>`` tail), so
    the digit belongs to the variant, which stays ``frver2`` / ``frver3``. The
    ``variant_family`` collapses the trailing digits so a ``frontier-verification``
    selection catches all of ``frver`` / ``frver2`` / ``frver3``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

TARGETS = ("gitea", "wordpress", "grafana", "cacti")
AUTHS = ("none", "user", "admin")
ROLES = ("blind", "ceiling", "crawl")
# Pilot rows use role token "baseline"; kept here so the parser recognises rather
# than rejects them (they are marked campaign=pilot and excluded by default).
PILOT_ROLES = ("baseline",)

_TRAILING_DIGITS = re.compile(r"\d+$")


@dataclass(frozen=True)
class RowName:
    """The parsed axes of one configuration.

    ``raw`` is the string parsed (label when present, else harness_row).
    ``repeat`` is the suffix repeat ordinal when the name carries one (``rep-2``),
    else None — minting repeats are numbered run-wise by the index.
    ``parsed`` is False when the tokens do not fit the matrix grammar (pilot rows,
    malformed names); the row is kept but its axes are best-effort.
    """

    target: str | None
    auth: str | None
    role: str | None
    variant: str
    variant_family: str
    repeat: int | None
    raw: str
    parsed: bool


def _split_repeat(label: str, harness_row: str) -> tuple[str, int | None]:
    """Return (name_without_repeat, repeat).

    A repeat is the harness's trailing ``-<N>`` suffix: a *hyphen-delimited,
    all-digit* final token. That peels ``…-rep-1`` -> (``…-rep``, 1) identically
    whether the record stored ``harness_row`` with the number (the verify reps) or
    without it (the triage reps), so one logical repeat is numbered one way. It
    deliberately does **not** touch ``frver2``: its digit is glued to the word, so
    the final token is ``frver2`` (not all-digit) and stays part of the variant.
    Minting G3 repeats carry no such suffix, so ``repeat`` stays None and the index
    numbers them run-wise.
    """
    name = (label or harness_row or "").strip()
    tokens = name.split("-")
    if len(tokens) > 1 and tokens[-1].isdigit():
        return "-".join(tokens[:-1]), int(tokens[-1])
    return name, None


def _variant_family(variant: str) -> str:
    """Collapse a trailing operational-rerun digit (frver2 -> frver, rep-1 -> rep)."""
    if not variant:
        return ""
    head = variant.split("-")[0]
    return _TRAILING_DIGITS.sub("", head)


def parse_row_name(label: str, harness_row: str) -> RowName:
    """Parse ``<target>-<auth>-<role>[-<variant>]`` from the record's metadata."""
    name, repeat = _split_repeat(label, harness_row)
    tokens = name.split("-") if name else []

    target = tokens[0] if tokens and tokens[0] in TARGETS else None
    auth = tokens[1] if len(tokens) > 1 and tokens[1] in AUTHS else None
    role = (
        tokens[2]
        if len(tokens) > 2 and tokens[2] in (ROLES + PILOT_ROLES)
        else None
    )
    # Variant is whatever follows a well-formed target-auth-role triple.
    variant = ""
    if target and auth and role:
        variant = "-".join(tokens[3:])
    parsed = bool(target and auth and role in ROLES)

    return RowName(
        target=target,
        auth=auth,
        role=role,
        variant=variant,
        variant_family=_variant_family(variant),
        repeat=repeat,
        raw=name,
        parsed=parsed,
    )
