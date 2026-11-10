"""Shared constants and the wrapper command for the verify stage.

The bottom of the ``verify`` package: the refusal-code vocabulary (why a probe
could not be built), the pinned tool images recorded as run provenance, and the
per-tool stdio command. Pure data and leaf helpers the rest of the package
imports; depends on nothing else in the package.
"""
from __future__ import annotations
import os
import sys
from pathlib import Path
from typing import Any
from mcp import StdioServerParameters
from mcp.client.stdio import get_default_environment
from dast_orchestrator.foundation import run_paths

REPO_ROOT = Path(__file__).resolve().parents[4]
#: Runs a person started. A sheet points its stages elsewhere; see
#: :mod:`dast_orchestrator.foundation.run_paths`.
DATA_DIR = run_paths.default_runs_dir()
WRAPPER_DIR = REPO_ROOT / "mcp"

VERIFICATION_SCHEMA_VERSION = 2

#: Pinned images each wrapper drives, recorded as run provenance. Kept in step
#: with the constants in the wrapper modules; duplicated here only so the driver
#: can report provenance without importing three standalone scripts.
TOOL_IMAGES = {
    "nuclei": "projectdiscovery/nuclei:v3.4.10@sha256:aeb5ea2db32a252b8135707d2ad0e89b90e19a18ea7816d38759bc51efb46b97",
    "sqlmap": "secsi/sqlmap:1.10@sha256:dcc989c4f1c87d31f680494dde502b000906bbd5187c61dca135b35c98963fcf",
    "ffuf": "secsi/ffuf:2.2.1@sha256:eb69340b78ad7d5cab51cc1f46c673fb9cb94eea87ee43eb933ef308b8bc2fce",
    # The browser probe drives the Chromium inside the nuclei image rather than
    # nuclei itself, so the pin is shared deliberately — no image was added to
    # the stack for it.
    "browser": "projectdiscovery/nuclei:v3.4.10@sha256:aeb5ea2db32a252b8135707d2ad0e89b90e19a18ea7816d38759bc51efb46b97",
}

#: Run config the verify wrappers read from their OWN environment — nuclei's
#: interactsh/OOB settings and templates volume. The MCP SDK spawns a wrapper
#: with :func:`get_default_environment`'s safe subset, which drops these, so a
#: run's ``VERIFY_INTERACTSH_*`` overrides never reached the wrapper and nuclei
#: fell back to the container-name interactsh default — whose ``<id>.target-
#: interactsh`` callback the target cannot resolve, making every in-pipeline OOB
#: confirmation silently time out. Forwarded explicitly; never ``os.environ``
#: wholesale, so the API key cannot reach a tool subprocess.
_WRAPPER_ENV_PASSTHROUGH = (
    "VERIFY_INTERACTSH_SERVER",
    "VERIFY_INTERACTSH_DNS",
    "VERIFY_INTERACTSH_COOLDOWN_SECONDS",
    "VERIFY_NUCLEI_TEMPLATES_VOLUME",
)


def _wrapper_command(tool: str) -> StdioServerParameters:
    env = get_default_environment()
    for var in _WRAPPER_ENV_PASSTHROUGH:
        value = os.getenv(var)
        if value is not None:
            env[var] = value
    return StdioServerParameters(
        command=sys.executable,
        args=[str(WRAPPER_DIR / f"{tool}_server.py")],
        env=env,
    )


# -- building one dispatch from a finding ----------------------------------


#: How a probe's URL was derived from the alert, recorded per dispatch so the
#: artifact says what was actually aimed at rather than leaving it to be
#: inferred from the command line.
URL_AS_RECORDED = "as-recorded"
URL_QUERY_RESET = "query-value-reset"
URL_PATH_STRIPPED = "path-payload-stripped"
#: The alert records no URL at all, so there is nothing to aim at.
URL_NONE_RECORDED = "no-example-url"
#: A dispatch this layer SYNTHESISED from a ground-truth marker's documented
#: sink, with no ZAP alert behind it — the oracle-seeded verify dispatch
#: (``VERIFY_ORACLE_SEED_DISPATCH``, oracle mode only). Recorded as the probe's
#: ``url_source`` and paired with :data:`ORIGIN_ORACLE_SEED`, so such a record is
#: never read as a finding-derived probe.
URL_ORACLE_SEEDED = "oracle-seeded-marker"
#: ``origin`` on an oracle-seeded verification record: the probe was aimed at a
#: marker's own documented sink, not at a ZAP finding. Its own field (not a
#: ``url_source`` reused on the flagged population) so the record is identifiable
#: as a ceiling reading and never counted with the blind detections.
ORIGIN_ORACLE_SEED = "oracle-seeded"
#: A payload sits in a path segment and the alert does not say what the segment
#: held before it. Refused rather than probed: see :class:`ProbeTarget`.
URL_PAYLOAD_UNRECOVERABLE = "path-payload-unrecoverable"

#: The two ``url_source`` values that mean *no probe was derivable*. A dispatch
#: is refused on either, and recorded ``not-attempted`` with the reason, rather
#: than sent at a URL that would answer a different question.
URL_REFUSALS = (URL_NONE_RECORDED, URL_PAYLOAD_UNRECOVERABLE)

#: sqlmap was told to test a parameter that is in neither the URL nor the body it
#: carries. sqlmap cannot address a parameter it cannot find, so it returns "the
#: target may have rejected the probe" — an honest inconclusive that costs a
#: dispatch (and can hold a rule's whole per-rule cap) while settling nothing.
PARAM_NOT_IN_REQUEST = "param-absent-from-request"

#: The flagged parameter is a form-body field and the tool carries no body.
#:
#: **sqlmap is the only wrapper that sends one** (``data``); nuclei, ffuf and the
#: browser oracle are handed a URL and nothing else, so a parameter that lives in
#: the request body is not in the request they send. What comes back is a verdict
#: about the query string they *did* fuzz, filed against the body field ZAP
#: flagged.
#:
#: Every such probe reads in the artifact as "the tool ran to completion and could
#: not reproduce it" — a refutation the probe did not actually establish, which is
#: exactly what this layer's central claim rests on.
PARAM_NOT_IN_TOOLS_REQUEST = "param-absent-from-tools-request"

#: The wrappers that can carry a request body, and so can be asked about a
#: parameter that lives in one. sqlmap has ``--data``; the browser oracle has a
#: self-submitting bootstrap form, which is what lets rule ``10031`` (whose flagged
#: parameters are often form fields) route to an execution oracle. nuclei and ffuf
#: are handed a URL and nothing else.
BODY_CAPABLE_TOOLS = frozenset({"sqlmap", "browser"})

#: The two refusals that mean *the tool cannot reach the flagged parameter*, as
#: opposed to *no URL could be derived*. Kept as a set so the reason code is
#: chosen from the cause rather than from a chain of ``or``s that a third such
#: refusal would silently fall off the end of.
PARAM_REACH_REFUSALS = frozenset({PARAM_NOT_IN_REQUEST,
                                  PARAM_NOT_IN_TOOLS_REQUEST})

#: sqlmap's injection point is a path segment and none could be marked safely.
#: A tool WAS named, so this is a probe refusal and not a routing gap — the
#: branch used to return a bare ``None``, which
#: :func:`~dast_orchestrator.stages.verify.run_loop` could not tell apart from "no arm
#: named a tool" and duly counted as one.
PATH_NOT_MARKABLE = "path-injection-point-unmarkable"

#: Where the flagged parameter lives, which is what decides how a tool can reach
#: it at all: a query parameter has a name to pass to ``-p``, a *path* parameter
#: has none — it is a URL segment, and sqlmap needs an injection marker instead.
INJECT_QUERY = "query"
INJECT_PATH = "path"
INJECT_BODY = "body"

#: sqlmap's custom injection point. It is **appended to the value**, not
#: substituted for it: sqlmap replaces the marker with each payload, so marking
#: ``/commit/*`` strips the commit id and every request 404s before a single
#: test runs (observed exactly that way). ``/commit/<sha>*`` keeps the URL valid,
#: which is what gives the probe a real baseline response to compare against.
SQLMAP_INJECTION_MARKER = "*"

#: Shortest ``attack`` string that may be matched against a URL path. ZAP
#: records an attack for alerts that injected nothing, and matching one or two
#: characters against a path would rewrite ordinary URLs on a coincidence.
MIN_PAYLOAD_MATCH_CHARS = 4

#: Characters that mark an ``attack`` string as an actual payload rather than an
#: ordinary value. The distinction is load-bearing and was found by test: ZAP's
#: traversal alert on ``/avatar/{hash}`` records ``param="user"`` and
#: ``attack="avatar"`` — a plain word that *is* a path segment of the recorded
#: URL. Rewriting on the strength of "the attack string appears in the path"
#: turned ``/avatar/avatar`` into ``/user/avatar``, a URL the target does not
#: serve, which is the same class of mistake as probing the payload-laden URL:
#: a verdict about something other than the endpoint.
#:
#: So a path occurrence counts as a payload only when the attack string could
#: not be an ordinary path value. Erring towards *not* recognising one is the
#: safe direction — the URL is then left as recorded, exactly as before.
_PAYLOAD_SIGNALS = frozenset(" %<>\"'`;|&$()[]{}\\\n\t*")

#: Neutral value for a query parameter whose recorded value is a payload. Any
#: value works — sqlmap replaces it — but it must not itself be broken syntax,
#: which is the whole failure being fixed here.
BENIGN_PARAM_VALUE = "1"

#: What a form field gets when the target declares no filler for it. Named
#: rather than inline because it is a *synthetic* value and the artifact should
#: be able to say which fields carry one — see :func:`placeholder_fields`.
FORM_PLACEHOLDER = "ZAP"




__all__ = [
    'REPO_ROOT',
    'DATA_DIR',
    'WRAPPER_DIR',
    'VERIFICATION_SCHEMA_VERSION',
    'TOOL_IMAGES',
    '_wrapper_command',
    'URL_AS_RECORDED',
    'URL_QUERY_RESET',
    'URL_PATH_STRIPPED',
    'URL_NONE_RECORDED',
    'URL_ORACLE_SEEDED',
    'ORIGIN_ORACLE_SEED',
    'URL_PAYLOAD_UNRECOVERABLE',
    'URL_REFUSALS',
    'PARAM_NOT_IN_REQUEST',
    'PARAM_NOT_IN_TOOLS_REQUEST',
    'BODY_CAPABLE_TOOLS',
    'PARAM_REACH_REFUSALS',
    'PATH_NOT_MARKABLE',
    'INJECT_QUERY',
    'INJECT_PATH',
    'INJECT_BODY',
    'SQLMAP_INJECTION_MARKER',
    'MIN_PAYLOAD_MATCH_CHARS',
    '_PAYLOAD_SIGNALS',
    'BENIGN_PARAM_VALUE',
    'FORM_PLACEHOLDER',
]
