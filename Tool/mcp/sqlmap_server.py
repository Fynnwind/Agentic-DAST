"""stdio MCP wrapper around sqlmap: confirm ZAP's SQL-injection findings, one parameter
per run, mapping sqlmap's own verdict onto the four-state vocabulary.

Injectable → CONFIRMED; ran-and-not-injectable → REFUTED; timeout/error or a
self-reported degraded page comparison → INCONCLUSIVE (a refutation resting on an
unreliable comparison is a claim about the run, not the target). The verdict is read from
stdout (sqlmap exits 0), and a form-protected POST it holds no session/CSRF for may be
REFUTED for reasons unrelated to SQLi.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _dispatch_common import (  # noqa: E402
    CONFIRMED,
    INCONCLUSIVE,
    REFUTED,
    outcome,
    run_container,
    warning_lines,
)
from mcp.server import MCPServer  # noqa: E402

#: Pinned, arm64-native. Never ``:latest`` — a verification verdict has to be
#: reproducible against the exact tool that produced it.
SQLMAP_IMAGE = "secsi/sqlmap:1.10@sha256:dcc989c4f1c87d31f680494dde502b000906bbd5187c61dca135b35c98963fcf"

#: sqlmap's custom injection point. Kept in step with
#: :data:`dast_orchestrator.stages.verify.SQLMAP_INJECTION_MARKER`, which puts it there.
SQLMAP_INJECTION_MARKER = "*"

#: The value a body's added CSRF field starts with; sqlmap swaps in the fetched
#: token before every request, and skips the target if it finds none.
CSRF_PLACEHOLDER = "x"

#: Phrases sqlmap prints when it *has* found an injection point.
_VULN_MARKERS = (
    "is vulnerable",
    "sqlmap identified the following injection point",
    "the back-end dbms is",
)
#: Phrases sqlmap prints when it has tested and found nothing.
_CLEAN_MARKERS = (
    "all tested parameters do not appear to be injectable",
    "does not seem to be injectable",
    "might not be injectable",
)

#: Warnings in which sqlmap says its own page comparison is degraded. Both are
#: about the *basis* of the refutation rather than about the target:
#:
#: * *content is not stable* — two identical requests returned different bodies,
#:   so sqlmap falls back to a fuzzy sequence matcher and says so;
#: * *reflective values found and filtering out* — the payload is echoed back,
#:   so sqlmap strips it from the comparison, removing exactly the content a
#:   boolean-based test would read.
#:
#: A tool that has just qualified its own comparison has not *refuted* anything,
#: and the four-state vocabulary exists for precisely this: the honest answer is
#: :data:`INCONCLUSIVE`, not a false-positive verdict the writeup would count.
#: Measured on the recorded runs, this moves 6 of 22 refutations in the
#: ``20260825T135646Z`` run — a sixth of the false-positive claim.
#:
#: Deliberately narrow. sqlmap's WAF probe line ("checking if the target is
#: protected by some kind of WAF/IPS") mentions the same subject on *every* run
#: and is an INFO line, not a warning; treating it as one would downgrade every
#: verdict the wrapper has ever produced. See
#: :func:`_dispatch_common.warning_lines` for the marker requirement that keeps
#: the two apart.
SHAKY_COMPARISON = (
    "content is not stable",
    "reflective value",
)

srv = MCPServer("sqlmap-verify", version="0.1.0")


@srv.tool(
    description=(
        "Run sqlmap against one parameter of a URL to confirm or refute a "
        "suspected SQL injection. Returns a four-state outcome "
        "(confirmed/refuted/inconclusive) with the sqlmap evidence line."
    )
)
def verify_sqlmap(
    target: str,
    param: str,
    method: str = "GET",
    data: str = "",
    timeout: int = 120,
    level: int = 1,
    risk: int = 1,
    cookie: str = "",
    csrf_field: str = "",
    csrf_url: str = "",
) -> dict:
    """Verify one SQLi finding.

    :param target: the URL to probe, payload-stripped by the driver. A ``*`` in
        it marks a custom injection point — how a *path* parameter is reached,
        since a URL segment has no name for ``-p`` to address.
    :param param: the parameter to test, ``-p`` in sqlmap terms. Empty when the
        URL carries a ``*`` marker instead.
    :param method: HTTP method; ``data`` is required for anything but GET.
    :param data: form body for POST/PUT, ``a=1&b=2`` style. The flagged param
        should appear here for a POST finding.
    :param timeout: per-invocation ceiling; a kill maps to inconclusive.
    :param level, risk: sqlmap's own breadth knobs, kept low so an unattended
        CI probe stays bounded.
    :param cookie: an authenticated session cookie (``name=value``) so guarded
        routes are reachable.
    :param csrf_field, csrf_url: when set, sqlmap fetches a fresh anti-CSRF
        token by GET from ``csrf_url`` for each request and submits it as
        ``csrf_field`` — its native handling of the CSRF wall that otherwise
        refutes a POST probe for the wrong reason. sqlmap only refreshes a field
        the body already carries, so a POST ``data`` without it gets it added.
    """
    if not param and SQLMAP_INJECTION_MARKER not in target:
        return outcome(
            INCONCLUSIVE, "sqlmap", None,
            "no parameter to test — SQLi verification needs a named parameter or "
            f"a {SQLMAP_INJECTION_MARKER!r} injection point in the URL",
            # Nothing was dispatched, so nothing was tested. `outcome()` defaults
            # `tested` to true for every state but not-attempted, which is right
            # for a tool that ran and wrong for a refusal that precedes one.
            tested=False,
        )

    args = [
        "-u", target,
        "--batch",
        "--disable-coloring",
        f"--level={level}",
        f"--risk={risk}",
        # Bound each individual HTTP request so a slow route cannot blow the
        # per-invocation budget one request at a time.
        "--timeout=10",
        "--retries=1",
        # A fresh session each run: a cached previous verdict would make the
        # result non-reproducible and could confirm on stale state.
        "--flush-session",
    ]
    # `-p` names a parameter; a `*` in the URL *is* the parameter (a path
    # segment has no name). Passing both makes sqlmap ignore the marker.
    if param and SQLMAP_INJECTION_MARKER not in target:
        args += ["-p", param]
    if method.upper() != "GET":
        args += ["--method", method.upper()]
        if csrf_field and csrf_url:
            data = _with_field(data, csrf_field)
    if data:
        args += ["--data", data]
    if cookie:
        args += ["--cookie", cookie]
    if csrf_field and csrf_url:
        args += [f"--csrf-token={csrf_field}", f"--csrf-url={csrf_url}",
                 "--csrf-method=GET"]

    result = run_container(SQLMAP_IMAGE, args, timeout=timeout)
    if result.timed_out:
        return outcome(
            INCONCLUSIVE, "sqlmap", result,
            f"sqlmap killed at the {timeout}s timeout before deciding — unknown, "
            "not refuted",
            tested=False,
        )
    low = result.stdout.lower()
    shaky = warning_lines(result.stdout, SHAKY_COMPARISON)
    for marker in _VULN_MARKERS:
        if marker in low:
            evidence = _first_line_containing(result.stdout, marker)
            # A confirmation is positive evidence — sqlmap found an injection
            # point *despite* a noisy page — so a degraded comparison does not
            # weaken it. The warnings ride along so the reader can judge.
            return outcome(
                CONFIRMED, "sqlmap", result,
                "sqlmap reports the parameter is injectable", evidence=evidence,
                warnings=shaky,
            )
    if any(marker in low for marker in _CLEAN_MARKERS):
        if shaky:
            return outcome(
                INCONCLUSIVE, "sqlmap", result,
                "sqlmap found no injection, but had already qualified its own "
                f"page comparison ({shaky[0]}) — not a refutation",
                warnings=shaky, tested=False,
            )
        return outcome(
            REFUTED, "sqlmap", result,
            "sqlmap tested the parameter and found no injection",
            warnings=shaky,
        )
    # sqlmap states why it stopped on a [CRITICAL] line ("page not found (404)",
    # "unable to connect to the target URL", ...). Quoting it turns an
    # inconclusive from "something went wrong" into a diagnosis — the 404 that
    # showed a misplaced injection marker was found exactly this way.
    critical = _first_line_containing(result.stdout, "[critical]")
    return outcome(
        INCONCLUSIVE, "sqlmap", result,
        f"sqlmap stopped before deciding: {critical}" if critical else
        "sqlmap neither confirmed nor cleanly refuted (target may have rejected "
        "the probe, e.g. missing CSRF/session)",
        # Both branches mean the same thing: sqlmap stopped before it had tested
        # anything. The 404 that exposed a misplaced injection marker arrived
        # exactly here, and reading it as work done would have made it a refutation.
        tested=False,
    )


def _with_field(data: str, field: str) -> str:
    """``data`` carrying ``field``, added with :data:`CSRF_PLACEHOLDER` when absent."""
    if field in {pair.split("=", 1)[0] for pair in data.split("&") if pair}:
        return data
    return f"{data}&{field}={CSRF_PLACEHOLDER}" if data else f"{field}={CSRF_PLACEHOLDER}"


def _first_line_containing(text: str, marker: str) -> str | None:
    for line in text.splitlines():
        if marker in line.lower():
            return line.strip()[:300]
    return None


if __name__ == "__main__":
    srv.run("stdio")
