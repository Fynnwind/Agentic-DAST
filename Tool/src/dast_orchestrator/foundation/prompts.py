"""Versioned prompt files: ``prompts/<group>/<pass>.v<N>.md``, loaded recursively (the
filename is the identity, not the location).

The filename's ``vN`` is the version, so a prompt cannot drift from its content: to
change one you add ``v<N+1>`` and leave the old, and a run records which it used — never
edit in place. Three passes (``screening``, ``synthesis``, ``verify``); selecting a
version is ordinary config (``TRIAGE_PROMPT_VERSION`` etc.) so a sheet can A/B two
wordings over one scan. → DECISIONS.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]

#: One directory, at the repo root, holding every prompt the pipeline sends.
PROMPTS_DIR = REPO_ROOT / "prompts"

#: ``triage.v3.md`` -> name ``triage``, version ``3``. Lowercase and hyphenated
#: so a name is safe as a filename, an env value and a metrics key alike.
FILENAME_RE = re.compile(r"^(?P<name>[a-z0-9][a-z0-9-]*)\.v(?P<version>\d+)\.md$")

#: The passes that have a prompt, and what each is for. Named here so an unknown
#: name fails with the list rather than with a missing-file error.
PASSES = {
    "screening": "the triage stage's pass 1 — per-endpoint rescan verdicts",
    "synthesis": "the triage stage's pass 2 — cross-endpoint findings only",
    "verify": "the verification loop — propose an invocation and a signal, "
              "read the tool's output, refine or conclude",
}

#: The oracle-guided (`--oracle`/ceiling) blocks, one per stage, in
#: ``prompts/oracle/``. They are prompts by every property that matters — sent
#: verbatim to a model and quoted in the artifact — but they are **not versioned**:
#: unlike the pass prompts, they are generic scaffolding, not an A/B axis, so a
#: change to one is a plain edit (still recorded verbatim). They live here rather
#: than as string constants in :mod:`dast_orchestrator.analysis.oracle` so an edit
#: is never a silent code change. Loaded with :func:`load_oracle`, not :func:`load`.
ORACLE_BLOCKS = {
    "oracle-screening": "oracle-guided pass 1 — is a ZAP alert here the alert a "
                        "documented weakness would raise?",
    "oracle-synthesis": "oracle-guided pass 2 — the signs of a documented "
                        "weakness across the whole scan",
    "oracle-verify": "oracle-guided verification — probe the described "
                     "mechanism, acting on what triage flagged",
}


class PromptError(RuntimeError):
    """An unknown pass, or a version that is not on disk."""


@dataclass(frozen=True)
class Prompt:
    """One prompt file: what it is, which version, and its verbatim text."""

    name: str
    version: int
    text: str
    path: Path

    def as_metadata(self) -> dict[str, object]:
        """What an artifact records about the prompt that produced it.

        The text is included, not just the reference: a run has to stay readable
        after the file is edited, moved or deleted, and "prompt v3" means nothing
        to a reader who does not have this checkout.
        """
        return {
            "prompt_name": self.name,
            "prompt_version": self.version,
            "prompt_file": self.path.name,
            "system_prompt": self.text,
        }


def available(name: str, prompts_dir: "Path | None" = None) -> list[int]:
    """Every version of one pass present on disk, ascending.

    Searched **recursively**, so the files may be grouped into subdirectories
    (``prompts/triage/``, ``prompts/oracle/``, …) for readability — the filename,
    not the location, is the identity (:data:`FILENAME_RE`).
    """
    directory = Path(prompts_dir or PROMPTS_DIR)
    if not directory.is_dir():
        return []
    found = []
    for path in directory.rglob(f"{name}.v*.md"):
        match = FILENAME_RE.match(path.name)
        if match and match.group("name") == name:
            found.append(int(match.group("version")))
    return sorted(found)


def load(name: str, version: "int | str | None" = None,
         prompts_dir: "Path | None" = None) -> Prompt:
    """The prompt for one pass, at ``version`` or the newest on disk.

    :param version: an explicit version to pin, or ``None``/``""`` for the
        highest available. Defaulting to the newest is what keeps a plain run
        current, while a harness row that pins one keeps its comparison valid
        when a newer prompt lands.
    :raises PromptError: on an unknown pass name, or a version that is not
        there — naming what *is* there, since the usual cause is a typo or a
        prompt that was renamed rather than added.
    """
    if name not in PASSES:
        raise PromptError(
            f"unknown prompt {name!r}; known: "
            + ", ".join(f"{k} ({v})" for k, v in PASSES.items())
        )
    directory = Path(prompts_dir or PROMPTS_DIR)
    versions = available(name, directory)
    if not versions:
        raise PromptError(f"no {name}.v*.md in {directory}")

    if version in (None, ""):
        chosen = versions[-1]
    else:
        try:
            chosen = int(str(version).lstrip("vV"))
        except ValueError as exc:
            raise PromptError(
                f"{name} prompt version {version!r} is not a number"
            ) from exc
        if chosen not in versions:
            raise PromptError(
                f"no {name} prompt v{chosen} in {directory}; available: "
                + ", ".join(f"v{v}" for v in versions)
            )
    # Recursive, matching `available` — the file may sit in a subdirectory
    # (`prompts/triage/…`); its filename is its identity, not its location.
    path = next(p for p in directory.rglob(f"{name}.v{chosen}.md")
                if FILENAME_RE.match(p.name))
    return Prompt(name=name, version=chosen, text=path.read_text(), path=path)


def load_oracle(name: str, prompts_dir: "Path | None" = None) -> Prompt:
    """One **unversioned** oracle block (``prompts/oracle/<name>.md``).

    The oracle blocks carry no ``vN`` — see :data:`ORACLE_BLOCKS` — so they load
    by bare filename rather than by version. The returned :class:`Prompt` has
    ``version`` 0, the sentinel for "unversioned"; its verbatim text still reaches
    the artifact like any other prompt.
    """
    if name not in ORACLE_BLOCKS:
        raise PromptError(
            f"unknown oracle block {name!r}; known: " + ", ".join(ORACLE_BLOCKS)
        )
    directory = Path(prompts_dir or PROMPTS_DIR)
    path = next((p for p in directory.rglob(f"{name}.md")), None)
    if path is None:
        raise PromptError(f"no {name}.md in {directory}")
    return Prompt(name=name, version=0, text=path.read_text(), path=path)
