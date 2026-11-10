"""Shared plumbing for the three stdio verification-tool wrappers (nuclei/sqlmap/ffuf).

Each wrapper is a one-tool MCP **stdio** server, not HTTP: the dispatcher spawns it as a
subprocess for the length of one call, so there is no port to bind or daemon to keep
alive. This module holds ``run_container`` (the one-shot pinned-image ``docker run`` on
``dast-net``), the four-state outcome vocabulary, and ``outcome`` (the single return
shape), so wrapper and dispatcher never drift.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

# The wrappers are standalone scripts outside the installed package, so make the
# package importable when run directly. This shim is sanctioned only in `mcp/`
# (here, and once more in `context_server.py`, which shares no code with the
# dispatch wrappers); it exists so a server is both hand-runnable and able to
# share the pipeline's own vocabulary and primitives rather than redefining them.
_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from dast_orchestrator.domain.verification import (  # noqa: E402
    CONFIRMED,
    INCONCLUSIVE,
    NOT_ATTEMPTED,
    REFUTED,
)

__all__ = [
    "CONFIRMED",
    "REFUTED",
    "INCONCLUSIVE",
    "NOT_ATTEMPTED",
    "DAST_NET",
    "ContainerResult",
    "run_container",
    "outcome",
    "warning_lines",
    "EXCERPT_CHARS",
    "AUDITABLE_EXCERPT_CHARS",
]

#: The shared external network both compose stacks attach to. The tool
#: container joins it so ``target-gitea`` resolves, mirroring how ZAP reaches
#: the target from inside its own container.
DAST_NET = "dast-net"

#: How long, on top of the caller's timeout, to wait for ``docker run`` before
#: giving up on it. ``subprocess.run(timeout=)`` kills the ``docker run`` *client*,
#: which does NOT stop the container — it runs under dockerd, so ``--rm`` never
#: fires and the tool keeps hitting the target. On expiry the container is instead
#: force-removed by its ``--name`` (:func:`_force_remove`); this only bounds how
#: long we wait before doing so.
_DOCKER_REAP_GRACE = 5

#: Every one-shot tool container is launched under an explicit ``--name`` with
#: this prefix, so one orphaned by a killed client can be force-removed by name
#: and a target reset can sweep any straggler by filtering on it.
CONTAINER_NAME_PREFIX = "dast-verify"


class ContainerResult:
    """The raw result of one ``docker run``, before tool-specific interpretation.

    :param argv: the exact command executed, kept so the artifact can quote a
        reproducible invocation.
    :param exit_code: the container's exit status, or ``None`` if it was killed
        by the timeout (the signal that the answer is :data:`INCONCLUSIVE`).
    :param timed_out: whether the per-invocation timeout fired.
    """

    def __init__(
        self,
        argv: list[str],
        exit_code: int | None,
        stdout: str,
        stderr: str,
        seconds: float,
        timed_out: bool,
    ) -> None:
        self.argv = argv
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.seconds = seconds
        self.timed_out = timed_out


def _force_remove(name: str) -> None:
    """``docker rm -f`` a container by name, best-effort.

    Reaps a container whose ``docker run`` client was killed at the timeout: the
    container outlives the client, so ``--rm`` never removed it. A container that
    already auto-removed makes this a harmless no-op.
    """
    try:
        subprocess.run(
            ["docker", "rm", "-f", name],
            capture_output=True,
            timeout=_DOCKER_REAP_GRACE,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def run_container(
    image: str,
    tool_args: list[str],
    timeout: int,
    network: str = DAST_NET,
    volumes: list[str] | None = None,
    stdin: bytes | None = None,
    entrypoint: str | None = None,
    dns: list[str] | None = None,
) -> ContainerResult:
    """Run one pinned tool image once and capture its output.

    :param image: pinned, arm64-native tool image (never ``:latest``).
    :param tool_args: the tool's own argv, appended after the image name.
    :param timeout: per-invocation ceiling in seconds. On expiry the container
        is killed and :attr:`ContainerResult.timed_out` is set — the caller
        maps that to :data:`INCONCLUSIVE`.
    :param network: Docker network to join; the target is reached by container
        name on it.
    :param volumes: ``docker run -v`` specs, e.g. a named templates cache. Kept
        explicit rather than hidden so the invocation the artifact quotes is the
        one that ran.
    :param stdin: bytes to feed the container's stdin (ffuf reads its wordlist
        from ``-w -`` this way, avoiding a mounted wordlist file).
    :param entrypoint: override the image's own entrypoint. Needed by the
        browser wrapper, which drives the Chromium *inside* the nuclei image
        rather than nuclei itself — reusing a pinned image that already carries
        an arm64 browser, instead of adding one to the stack.
    :param dns: ``docker run --dns`` resolvers for this container. Used for
        out-of-band confirmation: nuclei's container must resolve the interactsh
        correlation domain (``interactsh.local``) through the split-horizon
        resolver, which Docker's default embedded DNS does not answer.
    """
    if not shutil.which("docker"):
        return ContainerResult(
            ["docker"], None, "", "docker not on PATH", 0.0, timed_out=False
        )
    name = f"{CONTAINER_NAME_PREFIX}-{uuid.uuid4().hex[:12]}"
    argv = ["docker", "run", "--rm", "--name", name]
    if stdin is not None:
        argv.append("-i")
    argv += ["--network", network]
    for resolver in dns or []:
        argv += ["--dns", resolver]
    for vol in volumes or []:
        argv += ["-v", vol]
    if entrypoint:
        argv += ["--entrypoint", entrypoint]
    argv += [image, *tool_args]
    started = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            input=stdin,
            capture_output=True,
            timeout=timeout + _DOCKER_REAP_GRACE,
        )
    except subprocess.TimeoutExpired as exc:
        # The timeout killed the ``docker run`` client, not the container it
        # launched — dockerd still runs it and ``--rm`` never fires, so the tool
        # keeps hitting the target. Force-remove it by name; without this a
        # timed-out fuzzer survives into the next run and re-saturates the target.
        _force_remove(name)
        return ContainerResult(
            argv,
            None,
            (exc.stdout or b"").decode(errors="replace"),
            (exc.stderr or b"").decode(errors="replace"),
            round(time.monotonic() - started, 3),
            timed_out=True,
        )
    return ContainerResult(
        argv,
        proc.returncode,
        proc.stdout.decode(errors="replace"),
        proc.stderr.decode(errors="replace"),
        round(time.monotonic() - started, 3),
        timed_out=False,
    )


#: Stdout kept for a verdict that settles a finding either way. Bounded because
#: scanner output can be megabytes and the verdict already distils it.
EXCERPT_CHARS = 1500

#: Stdout kept for a verdict that a reader will want to check. Measured need:
#: 1500 characters truncate sqlmap before its own verdict lines, so the artifact
#: could not be audited without re-running the tool — which for an
#: :data:`INCONCLUSIVE` is precisely the state where re-running is least likely
#: to reproduce what happened. Applied to :data:`CONFIRMED` and
#: :data:`INCONCLUSIVE`; a refutation is the cheap, repeatable case and keeps the
#: smaller excerpt.
AUDITABLE_EXCERPT_CHARS = 12000

#: Which outcomes get the larger excerpt.
_AUDITABLE = frozenset({CONFIRMED, INCONCLUSIVE})


def warning_lines(text: str, patterns: "tuple[str, ...]",
                  marker: str = "[warning]") -> list[str]:
    """Lines of tool output carrying ``marker`` and one of ``patterns``.

    Used by the wrappers to notice a tool saying its own result is shaky. The
    ``marker`` requirement is what keeps this from matching the *routine* lines
    that mention the same words — sqlmap announces "checking if the target is
    protected by some kind of WAF/IPS" on every run, and reading that as a
    warning would downgrade every verdict it ever produced.

    Matching is case-insensitive; the lines are returned as printed, trimmed, so
    a verdict can quote the tool verbatim instead of paraphrasing it.
    """
    found: list[str] = []
    for line in text.splitlines():
        low = line.lower()
        if marker in low and any(p in low for p in patterns):
            found.append(line.strip()[:300])
    return found


def outcome(
    state: str,
    tool: str,
    result: ContainerResult | None,
    detail: str,
    *,
    evidence: str | None = None,
    stdout_excerpt_chars: int | None = None,
    warnings: "list[str] | None" = None,
    tested: "bool | None" = None,
    **extra: Any,
) -> dict[str, Any]:
    """The one structure every wrapper returns, so the dispatcher parses one shape.

    :param state: one of the four outcome constants.
    :param tool: the tool that produced it (``nuclei`` / ``sqlmap`` / ``ffuf``).
    :param result: the container run this verdict rests on, or ``None`` if the
        wrapper decided before running anything (e.g. missing input).
    :param detail: a one-line human reason for the verdict.
    :param evidence: the concrete proof, when there is one (matched marker,
        sqlmap's vulnerability line). Left ``None`` rather than empty so a
        confirmed-with-no-evidence bug is visible.
    :param stdout_excerpt_chars: override the excerpt size. Defaults to
        :data:`AUDITABLE_EXCERPT_CHARS` for a confirmed or inconclusive verdict
        and :data:`EXCERPT_CHARS` otherwise — the outcome decides, so no wrapper
        has to remember to ask for a readable excerpt on the verdicts that need
        one.
    :param warnings: lines in which the tool qualified its own result, recorded
        whether or not they changed the verdict. A refutation that stands
        *despite* such a line and one that was never in doubt must not look
        alike in the artifact.
    :param tested: whether this invocation actually put the question to the
        target. Defaults to true for every state but :data:`NOT_ATTEMPTED`, and
        is passed ``False`` at each site where the tool answered ``inconclusive``
        because it never tested anything — no templates, requests that never
        landed, a page comparison the tool had already disowned, a kill at the
        timeout. **Stated here rather than inferred downstream**: the driver's
        resolution rule turns on "did the tool do work", and a rule that has to
        guess that from the wrapper's prose is one wording change away from
        promoting a non-run to a refutation.
    :param extra: further tool-specific facts to record (nuclei's matched
        template classification, say), kept out of ``detail`` so the driver can
        act on them rather than parse prose.
    """
    payload: dict[str, Any] = {
        "tool": tool,
        "outcome": state,
        "detail": detail,
        "evidence": evidence,
        "tested": (state != NOT_ATTEMPTED) if tested is None else bool(tested),
        **extra,
    }
    if warnings:
        payload["tool_warnings"] = warnings
    if stdout_excerpt_chars is None:
        stdout_excerpt_chars = (
            AUDITABLE_EXCERPT_CHARS if state in _AUDITABLE else EXCERPT_CHARS
        )
    if result is not None:
        # Shell-quote each argv token rather than space-join them: a header like
        # ``-H Cookie: a=b`` is two tokens with an internal space, so a bare join
        # is neither copy-pasteable NOR safely redactable — NFR-06's header-value
        # scrub runs to the first quote/newline, so on an unquoted join it ate the
        # cookie value *and* every token after it (the ``-H X-Forwarded-For`` the
        # cacti sink needs). Quoting bounds the value inside its own argument.
        payload["command"] = shlex.join(result.argv)
        payload["exit_code"] = result.exit_code
        payload["seconds"] = result.seconds
        payload["timed_out"] = result.timed_out
        # A bounded excerpt only: full scanner output can be megabytes and the
        # verdict already distils it. Enough to audit the call, not to replay it.
        payload["stdout_excerpt"] = result.stdout[:stdout_excerpt_chars]
        if result.stderr.strip():
            payload["stderr_excerpt"] = result.stderr[:stdout_excerpt_chars]
    return payload
