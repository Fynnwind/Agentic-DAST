"""Structural parameters: make ``?action=<name>`` part of a URL's identity.

ZAP builds its site tree from paths, so WordPress's ``admin-ajax.php?action=…`` endpoints
collapse to one node; declaring ``action`` structural (``target.yml``
``zap_context.structural_parameters``) splits it into one scan target per value. ZAP 2.17's
REST API cannot set this (upstream #2141), so the only route is export → rewrite the
context's ``struct`` JSON → import; it changes what a scan contains, so it is in the run-id
digest and invalidates that target's earlier baseline. → DECISIONS.md.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

from dast_orchestrator.foundation import run_paths
from dast_orchestrator.foundation import ui
from dast_orchestrator.adapters.zap_client import ZapClient

#: Where the context XML is written inside the daemon. Same idiom and the same
#: reason as :data:`dast_orchestrator.adapters.zap_plan.CONTAINER_PLAN_PATH`: the API
#: reads the file itself, from its own filesystem, and the daemon has no bind
#: mount.
#:
#: **Per run, and that is not tidiness.** ``docker cp`` writes the file as the
#: *host* user, so the copied-in file is owned by a uid the daemon does not run
#: as — and the next run's ``exportContext`` then fails with a bare HTTP 500
#: ``internal_error`` because ZAP cannot overwrite it. A fresh name per run
#: sidesteps the ownership entirely and leaves each run's exact loaded context
#: inspectable in the container.
CONTAINER_CONTEXT_DIR = "/home/zap"


def container_path(run_id: str) -> str:
    return f"{CONTAINER_CONTEXT_DIR}/dast-context-{run_id}.xml"


#: Name of the context this pipeline manages. One per run, created after the
#: session reset (which clears contexts) and never reused across runs.
CONTEXT_NAME = "dast"

#: The XML element holding the URL parameter parser's JSON configuration. The
#: POST parser has an identical block, deliberately left alone: a structural
#: parameter is about URL identity, and making a body field structural would
#: split the tree on values the application does not route by.
_URLPARSER_CONFIG_RE = re.compile(
    r"(<urlparser>.*?<config>)(.*?)(</config>.*?</urlparser>)", re.S)


class ContextError(RuntimeError):
    """Raised when the context could not be created, edited or loaded."""


def structural_config(existing: str, parameters: list[str]) -> str:
    """The parser config with ``parameters`` as its ``struct`` list.

    Everything else in the config — the separators ``kvps`` and ``kvs`` — is
    carried through from what the daemon exported rather than restated, so a ZAP
    release that changes a default does not silently get overridden here.

    The XML holds the JSON *entity-escaped* (``&amp;`` for the ``&`` separator),
    so it is unescaped before parsing and re-escaped after.
    """
    decoded = existing.replace("&amp;", "&")
    try:
        config = json.loads(decoded)
    except json.JSONDecodeError as exc:
        raise ContextError(
            f"ZAP's exported parameter-parser config is not JSON: {decoded[:120]!r}"
        ) from exc
    config["struct"] = list(parameters)
    return json.dumps(config, separators=(",", ":")).replace("&", "&amp;")


def rewrite(xml: str, parameters: list[str]) -> str:
    """An exported context XML with its URL parser's ``struct`` list replaced."""
    match = _URLPARSER_CONFIG_RE.search(xml)
    if match is None:
        raise ContextError(
            "the exported context has no <urlparser><config> block; ZAP's "
            "context format has changed and the structural-parameter recipe "
            "needs re-deriving against the daemon"
        )
    head, config, tail = match.groups()
    return xml[:match.start()] + head + structural_config(config, parameters) \
        + tail + xml[match.end():]


def _docker(*argv: str, what: str) -> None:
    try:
        result = subprocess.run(["docker", *argv], capture_output=True,
                                text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ContextError(f"could not {what}: {exc}") from exc
    if result.returncode != 0:
        raise ContextError(
            f"could not {what}: {result.stderr.strip() or result.stdout.strip()}")


def apply(zap: ZapClient, target_url: str, parameters: list[str],
          container: str, work_dir: Path,
          name: str = CONTEXT_NAME) -> dict[str, Any]:
    """Create the run's context and make ``parameters`` structural in it.

    Call **after** the session reset (which clears every context) and **before**
    seeding, so the first request already lands in a tree that splits on these
    parameters.

    :param work_dir: where the context XML is staged on the host. The run's own
        directory, so the exact XML that was loaded is on disk beside the
        artifacts it shaped.
    :returns: what was done, for the run's metrics: the context name, the
        parameters, and the config ZAP reported *after* the import — read back
        rather than assumed, because a silently-ignored import would otherwise
        look identical to a successful one.
    """
    if not parameters:
        return {}
    work_dir = Path(work_dir)
    host_path = work_dir / run_paths.ZAP_CONTEXT
    # The run directory's own name is the run id — the file inside the container
    # is named after it so two runs never contend for one path.
    inside = container_path(work_dir.name)

    zap.new_context(name)
    # Anchored on the target's own origin: the context decides which URLs get
    # this parser, and a looser regex would apply the target's routing quirks to
    # anything else that happened into the tree.
    zap.include_in_context(name, re.escape(target_url.rstrip("/")) + ".*")
    zap.export_context(name, inside)
    _docker("cp", f"{container}:{inside}", str(host_path),
            what=f"copy the exported context out of {container}")

    host_path.write_text(rewrite(host_path.read_text(), parameters))

    _docker("cp", str(host_path), f"{container}:{inside}",
            what=f"copy the edited context into {container}")
    # Import refuses a name that already exists, so the freshly-created one goes
    # first. Nothing is lost: it holds only what was just written into the file.
    zap.remove_context(name)
    zap.import_context(inside)

    applied = zap.context(name).get("urlParameterParserConfig", "")
    active = json.loads(applied or "{}").get("struct", [])
    if sorted(active) != sorted(parameters):
        raise ContextError(
            f"ZAP accepted the context but reports structural parameters "
            f"{active!r}, not {parameters!r} — the scan would have run with a "
            "site tree that does not match its recorded configuration"
        )
    ui.item("structural parameters", ", ".join(parameters))
    return {"context": name, "structural_parameters": list(parameters),
            "url_parameter_parser": applied, "context_file": host_path.name}
