"""stdio MCP wrapper around nuclei: probe ZAP's injection-class findings with its DAST
(fuzzing) templates, mapped onto the four-state outcome vocabulary.

Templates are pinned via a mounted cache volume and the run is offline; an empty volume
is recorded INCONCLUSIVE, never allowed to reach the network. OOB templates are armed
against the self-hosted interactsh sink (never oast.pro) only after a reachability
preflight, and this deployment's OOB is HTTP-only, so "no interaction" reads as *not
proven*, never *disproven*. → DECISIONS.md.
"""

from __future__ import annotations

import json
import os
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

#: Pinned, arm64-native. Never ``:latest``.
NUCLEI_IMAGE = "projectdiscovery/nuclei:v3.4.10@sha256:aeb5ea2db32a252b8135707d2ad0e89b90e19a18ea7816d38759bc51efb46b97"

#: Named Docker volume holding the pinned nuclei-templates checkout, mounted at
#: the container's ``$HOME`` so both templates and config persist offline.
TEMPLATES_VOLUME = os.getenv("VERIFY_NUCLEI_TEMPLATES_VOLUME", "nuclei-home")

#: The **self-hosted** interactsh sink in the OOB stack (docker/oob.yml), reached by
#: container name on ``dast-net``. Never oast.pro: a public pool would send this
#: target's out-of-band interactions to someone else's server.
INTERACTSH_SERVER = os.getenv("VERIFY_INTERACTSH_SERVER", "http://target-interactsh:8080")

#: Split-horizon resolver for out-of-band confirmation, as ``docker run --dns``
#: values on nuclei's (and the preflight's) container. Empty by default, so a
#: run keeps Docker's embedded DNS unless a target that needs OOB sets it.
#:
#: The interactsh correlation domain nuclei generates callbacks under comes from
#: the HOST of :data:`INTERACTSH_SERVER`. For a callback to land, BOTH nuclei's
#: container (to register and poll) AND the scanned target (to resolve the
#: callback host) must resolve that domain. With ``INTERACTSH_SERVER=
#: http://interactsh.local:8080`` and ``INTERACTSH_DNS=172.19.0.252`` (the
#: resolver in docker/oob.yml), nuclei resolves ``interactsh.local`` and
#: the target — whose own ``dns:`` points at the same resolver — resolves the
#: ``<id>.interactsh.local`` callback. Leaving the default
#: ``target-interactsh`` host would generate ``<id>.target-interactsh``
#: callbacks, which the target cannot resolve (Docker's embedded DNS has no
#: wildcard for a container name) — the gap the resolver closes. See
#: NEXT_SESSION §G2 and Targets/dns/Corefile.
INTERACTSH_DNS = tuple(
    d for d in os.getenv("VERIFY_INTERACTSH_DNS", "").split(",") if d.strip()
)

#: Seconds nuclei keeps polling the sink after the scan itself is done. An
#: out-of-band interaction is asynchronous by definition — the point of OAST is
#: that the callback arrives on the *target's* schedule — so a run that stops
#: polling the moment it finishes sending requests would miss exactly the
#: interactions it exists to catch.
INTERACTSH_COOLDOWN_SECONDS = int(os.getenv("VERIFY_INTERACTSH_COOLDOWN_SECONDS", "10"))

#: Phrases nuclei prints when it ran *nothing*. The templates ship in a cache
#: volume rather than in the image, so an unpopulated or wrongly-mounted volume
#: is a live failure mode — and with ``-silent`` its symptom is an empty stdout,
#: which is indistinguishable from "ran everything and matched nothing". That is
#: the worst shape a bug can take here: it would refute every finding it was
#: given, silently, and the run would look like a clean sweep of false
#: positives. Checked on stderr as well as stdout, since nuclei's diagnostics go
#: there.
NO_TEMPLATES = (
    "no templates provided",
    "could not find any templates",
    "no valid templates",
    "templates directory does not exist",
)

#: How long a preflight of the sink may take. Short: it is a health check on a
#: container one network hop away, and the dispatch budget pays for it.
INTERACTSH_PREFLIGHT_SECONDS = 5

def interactsh_reachable(server: str = INTERACTSH_SERVER,
                         timeout: int = INTERACTSH_PREFLIGHT_SECONDS) -> bool:
    """Whether the self-hosted sink answers, checked from *inside* ``dast-net``.

    The check runs in the same pinned curl container the login flow uses, on the
    same network as the scan, because that is the only vantage point whose answer
    means anything: the sink being reachable from the host says nothing about
    whether nuclei's container can reach it.

    ``/metrics`` is used as the liveness endpoint — it needs no registration and
    no token, so a positive answer means the server is up without creating a
    session that would then have to be cleaned up.
    """
    result = run_container(
        CURL_IMAGE,
        ["-s", "-o", "/dev/null", "-m", str(timeout), "-w", "%{http_code}",
         f"{server.rstrip('/')}/metrics"],
        timeout=timeout + 5,
        # Resolve the sink through the split-horizon resolver when set, so the
        # preflight and nuclei agree on how interactsh.local resolves.
        dns=list(INTERACTSH_DNS),
    )
    return result.stdout.strip() == "200"


#: Pinned, arm64-native; the same image the seeded-session login uses.
CURL_IMAGE = "curlimages/curl:8.10.1"

srv = MCPServer("nuclei-verify", version="0.1.0")


@srv.tool(
    description=(
        "Run nuclei DAST (fuzzing) templates against a URL to confirm or refute "
        "an injection-class finding. Returns a four-state outcome with the "
        "matched template id as evidence when confirmed."
    )
)
def verify_nuclei(
    target: str,
    param: str = "",
    method: str = "GET",
    timeout: int = 150,
    tags: str = "",
    cookie: str = "",
    oob: bool = False,
    headers: str = "",
) -> dict:
    """Verify one injection-class finding with nuclei's fuzzing templates.

    :param target: the full URL ZAP flagged; DAST templates fuzz the parameters
        already present on it.
    :param param: recorded for provenance; nuclei fuzzes every parameter, so it
        is not passed through as a filter.
    :param method: recorded for provenance.
    :param timeout: per-invocation ceiling; a kill maps to inconclusive.
    :param tags: optional comma-separated template tags to narrow the run
        (e.g. ``xss``). Empty means the full DAST set.
    :param cookie: an authenticated session cookie to send (``name=value``),
        so the probe reaches routes behind login. Empty for an anonymous probe.
    :param headers: fixed request headers to add, one ``Name: value`` per line —
        the target's ``scan_headers``, so nuclei reaches a header-gated sink the
        scan reached the same way (Cacti's ``X-Forwarded-For`` bypass). Empty
        when the target gates nothing.
    :param oob: arm out-of-band (OAST) templates against the self-hosted
        interactsh sink. Silently downgraded to off when the sink does not
        answer — with the reason recorded, never as an unexplained timeout.
    """
    args = [
        "-target", target,
        "-dast",
        # Fuzz ONE parameter per request, keeping the others at their original
        # values. nuclei's default fuzzes every parameter at once, which for an
        # endpoint that validates its OTHER parameters server-side corrupts them
        # and makes the handler bail before the injected parameter is ever used —
        # measured on Cacti's remote_agent.php (CVE-2022-46169), whose host_id
        # and local_data_ids are validated as numbers: multi-param fuzzing found
        # nothing, single-param confirmed the command injection out of band. The
        # correct mode for confirming ONE finding's parameter anyway.
        "-fuzzing-mode", "single",
        "-jsonl",
        "-silent",
        "-no-color",
        "-disable-update-check",
        "-timeout", "10",
        # Ask nuclei to report what it actually did. Without this a run that
        # matched nothing produces an EMPTY stdout, so the loop's model is handed
        # `stdout_excerpt: ""` and has nothing but this wrapper's own verdict to
        # reason from — measured 2026-09-04 on the rule-40026 false refutation.
        # `-stats` writes one JSON object per interval to *stderr* carrying
        # `templates`, `requests` and `matched`, which turns "the tool said
        # nothing" into "195 templates sent 387 requests and matched none".
        "-stats",
    ]
    oob_state = "disabled"
    if oob:
        if interactsh_reachable():
            oob_state = "armed"
            args += [
                "-iserver", INTERACTSH_SERVER,
                # Keep polling after the scan: the callback is the target's to
                # make, on its own schedule.
                "-interactions-cooldown-period", str(INTERACTSH_COOLDOWN_SECONDS),
            ]
        else:
            # Say it rather than let every OAST template hang on a dead sink and
            # come back as an unexplained inconclusive.
            oob_state = "sink-unreachable"
            args += ["-no-interactsh"]
    else:
        args += ["-no-interactsh"]
    if tags:
        args += ["-tags", tags]
    if cookie:
        args += ["-H", f"Cookie: {cookie}"]
    for line in headers.splitlines():
        if line.strip():
            args += ["-H", line.strip()]

    result = run_container(
        NUCLEI_IMAGE, args, timeout=timeout,
        volumes=[f"{TEMPLATES_VOLUME}:/root"],
        # Only when OOB is armed does nuclei need to resolve the interactsh
        # correlation domain; an in-band run keeps Docker's default DNS.
        dns=list(INTERACTSH_DNS) if oob_state == "armed" else None,
    )
    if result.timed_out:
        return outcome(
            INCONCLUSIVE, "nuclei", result,
            f"nuclei killed at the {timeout}s timeout before finishing — unknown, "
            "not refuted",
        )
    # nuclei -silent prints one JSONL object per match to stdout and nothing
    # else, so any non-blank stdout line is a finding.
    # "Did the tool run at all" is asked BEFORE "did it match", and the order is
    # load-bearing. nuclei writes `[WRN] No DAST templates found` to *stdout*,
    # so with the guard second a run that tested nothing short-circuited it and
    # was reported CONFIRMED, evidence `?`. Observed 2026-09-03 on a baseline
    # run: nuclei said "no templates provided for scan", exited 1, and this
    # wrapper turned that sentence into the corpus's only confirmed finding.
    empty = warning_lines(f"{result.stdout}\n{result.stderr}", NO_TEMPLATES, marker="")
    if empty:
        return outcome(
            INCONCLUSIVE, "nuclei", result,
            f"nuclei ran no templates ({empty[0]}) — nothing was tested, so this "
            "is unknown, not a refutation. The pinned templates volume is "
            "probably empty; see the module docstring for how to populate it.",
            warnings=empty, tested=False,
        )

    stats = scan_stats(result.stderr)
    # A hard "did it test anything", from nuclei's own counter rather than from
    # whether it happened to print a warning. The NO_TEMPLATES guard above needs
    # nuclei to say so in words; this needs it to have done nothing.
    if stats is not None and not stats.get("templates"):
        return outcome(
            INCONCLUSIVE, "nuclei", result,
            "nuclei loaded 0 templates for this target, so nothing was tested — "
            "unknown, not a refutation",
            tested=False, scan_stats=stats,
        )

    matches = _match_lines(result.stdout)
    if matches:
        matched = _matched_templates(matches)
        return outcome(
            CONFIRMED, "nuclei", result,
            f"nuclei matched {len(matches)} DAST template(s) (OAST {oob_state})",
            evidence=", ".join(m["template_id"] for m in matched),
            scan_stats=stats,
            # The classification travels with the verdict so the driver can ask
            # whether the template that matched belongs to the same family as
            # the ZAP rule it is meant to be confirming. The wrapper reports what
            # nuclei said; deciding what that means about the flagged rule needs
            # the rule, which only the driver has.
            matched_templates=matched,
        )
    if result.exit_code == 0:
        # Say what "matched nothing" was made of. A refutation carrying
        # "195 template(s), 387 request(s)" is a different piece of evidence from
        # the same word with an empty stdout behind it, and the loop's model gets
        # only what is written here.
        ran = (f" — {stats['templates']} template(s) sent "
               f"{stats.get('requests', '?')} request(s), 0 matched"
               if stats else "")
        return outcome(
            REFUTED, "nuclei", result,
            f"nuclei ran the DAST templates and matched nothing "
            f"(OAST {oob_state}){ran}. This says the templates that ran did not "
            "reproduce the finding; it is not evidence that no template class "
            "could.",
            scan_stats=stats,
        )
    return outcome(
        INCONCLUSIVE, "nuclei", result,
        f"nuclei exited {result.exit_code} without matching or cleanly finishing "
        "— treated as unknown, not refuted (a nonzero exit can come from a "
        "template-level error or a disrupted Docker daemon, not the scan itself)",
        # The exit code is exactly what makes it impossible to say whether the
        # templates ran, so the honest answer to "did it test anything" is no.
        tested=False, scan_stats=stats,
    )


def scan_stats(stderr: str) -> "dict[str, int] | None":
    """nuclei's own tally of the run, from the last ``-stats`` line on stderr.

    Every interval prints a fresh object, so the last complete one is the final
    state. Returns ``None`` when nothing parseable is there — an older nuclei, a
    run killed before the first tick — because a missing measurement and a
    measured zero must not look alike.
    """
    latest: "dict[str, int] | None" = None
    for line in (stderr or "").splitlines():
        line = line.strip()
        if not (line.startswith("{") and '"templates"' in line):
            continue
        try:
            raw = json.loads(line)
        except ValueError:
            continue
        parsed: dict[str, int] = {}
        for key in ("templates", "requests", "matched", "errors"):
            try:
                parsed[key] = int(raw[key])
            except (KeyError, TypeError, ValueError):
                continue
        if "templates" in parsed:
            latest = parsed
    return latest


#: A `-jsonl` match is a JSON object, one per line. Anything else on stdout is
#: nuclei talking — warnings, banners, progress — and must not be counted.
def _match_lines(stdout: str) -> list[str]:
    """The stdout lines that are actually match records.

    Treating *any* non-blank line as a match was the whole bug: under
    ``-jsonl -silent`` the assumption was that stdout carries nothing else, and
    nuclei's own `[WRN] No DAST templates found` disproved it by becoming a
    confirmed finding. A match has to look like what ``-jsonl`` emits — a JSON
    object — before anything downstream is entitled to call it one.

    Deliberately shape-based rather than a full parse: a match whose JSON is
    malformed is still a match nobody can classify (see
    :func:`_matched_templates`), and losing it would be the opposite error.
    """
    lines = []
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            lines.append(line)
    return lines


def _matched_templates(jsonl_lines: list[str]) -> list[dict]:
    """What nuclei matched: template id, its CWEs and its tags, best-effort.

    The CWEs are the load-bearing part. The project's one confirmed finding is a
    nuclei ``cookie-injection`` match standing against a ZAP *XSS* rule: both
    tools agree the parameter is injectable and disagree about the class, and
    nothing noticed. Reporting the classification is what lets the driver notice
    (:func:`dast_orchestrator.domain.verification.classification_match`).

    A match whose JSON does not parse still yields an entry, with unknown id and
    no classification — a match nobody can classify must not silently become no
    match at all.
    """
    import json

    out: list[dict] = []
    for line in jsonl_lines[:10]:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            out.append({"template_id": "?", "cwe": [], "tags": []})
            continue
        info = record.get("info") or {}
        classification = info.get("classification") or {}
        out.append({
            "template_id": str(record.get("template-id") or "?"),
            "cwe": [str(c) for c in (classification.get("cwe-id") or [])],
            "tags": [str(t) for t in (info.get("tags") or [])],
        })
    return out


if __name__ == "__main__":
    srv.run("stdio")
