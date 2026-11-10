"""``dast docs``: generate the Markdown API reference under ``docs/api/`` from the
package's own docstrings.

One Markdown file per layer (foundation/domain/…), plus an index, so the API reads
on GitHub the way :mod:`dast_orchestrator.cli.command_docs` makes the flags read.
The docstrings are the source of truth; this only introspects them, converting the
reST inline markup (``:func:`` roles, ``\\`\\`literal\\`\\``) to Markdown. Do not edit
the output by hand — edit the docstrings and regenerate.
"""
from __future__ import annotations

import argparse
import importlib
import inspect
import pkgutil
import re
from pathlib import Path

from dast_orchestrator.adapters import targets
from dast_orchestrator.foundation import config

PACKAGE = "dast_orchestrator"

#: The layers, in dependency order, each with a one-line blurb for its page.
LAYERS = {
    "foundation": "Infrastructure with no domain knowledge.",
    "domain": "Pure data and vocabulary, no I/O.",
    "context": "Assemble the evidence a prompt reasons from.",
    "adapters": "Isolate every external tool behind one place.",
    "analysis": "The judgement logic — the triage arms and the verify loop.",
    "stages": "The stage drivers: argparse plus orchestration.",
    "cli": "The front end that routes to stages.",
}

_ROLE = re.compile(r":[a-z]+:`([^`]+)`")


def rst_to_md(text: "str | None") -> str:
    """Convert the reST inline markup used in docstrings to Markdown.

    ``:func:`~a.b.c``` → ``c`` in a code span (the ``~`` means "last component
    only", as in Sphinx); ``:data:`X``` → ``X``; a reST double-backtick literal →
    a single-backtick Markdown code span. Block structure (paragraphs, ``*``
    lists) is already valid Markdown.
    """
    if not text:
        return ""

    def role(m: "re.Match[str]") -> str:
        target = m.group(1)
        if target.startswith("~"):
            target = target[1:].rsplit(".", 1)[-1]
        return f"`{target}`"

    text = _ROLE.sub(role, text)
    text = re.sub(r"``([^`]+)``", r"`\1`", text)
    return inspect.cleandoc(text)


def _summary(doc: "str | None") -> str:
    """The first line of a member's docstring, for the one-line API list."""
    first = (doc or "").strip().split("\n", 1)[0].strip()
    return rst_to_md(first)


def _modules(layer: str) -> "list[str]":
    """Every module (and sub-package) name under one layer, sorted."""
    pkg = importlib.import_module(f"{PACKAGE}.{layer}")
    names = []
    for info in pkgutil.iter_modules(pkg.__path__):
        if not info.name.startswith("_"):
            names.append(info.name)
    # a layer that is itself a package (cli) documents its own __init__ too
    return sorted(names)


def _public_members(module) -> list:
    """Classes and functions *defined in* this module (not imported), public.

    A stage split into a package (``verify``/``triage``/``scan``) exposes its
    surface through the package ``__init__``, so for a package a member
    re-exported from one of its own submodules counts as defined here.
    """
    prefix = module.__name__ + "."
    is_pkg = hasattr(module, "__path__")
    out = []
    for name, obj in vars(module).items():
        if name.startswith("_"):
            continue
        mod = getattr(obj, "__module__", None)
        if mod != module.__name__ and not (is_pkg and mod and mod.startswith(prefix)):
            continue
        if inspect.isclass(obj) or inspect.isfunction(obj):
            out.append((name, obj))
    return out


def _signature(obj) -> str:
    try:
        sig = f"{obj.__name__}{inspect.signature(obj)}"
    except (ValueError, TypeError):
        return obj.__name__
    # A default that is a function/object reprs with a volatile memory address
    # (``<function httpx_fetch at 0x10...>``); drop it so the output is stable.
    sig = re.sub(r" at 0x[0-9a-fA-F]+", "", sig)
    # A path default embeds the checkout's absolute location; name its root instead.
    for root, name in ((targets.TARGETS_DIR, "<targets>"), (config.REPO_ROOT, "<repo>")):
        sig = sig.replace(str(root), name)
    return sig


def render_module(dotted: str) -> str:
    module = importlib.import_module(dotted)
    lines = [f"### `{dotted}`", ""]
    doc = rst_to_md(module.__doc__)
    if doc:
        lines += [doc, ""]
    members = _public_members(module)
    if members:
        lines.append("| member | summary |")
        lines.append("|---|---|")
        for name, obj in members:
            kind = "class" if inspect.isclass(obj) else "def"
            sig = _signature(obj).replace("|", "\\|")
            lines.append(f"| `{kind} {sig}` | {_summary(obj.__doc__)} |")
        lines.append("")
    return "\n".join(lines)


def render_layer(layer: str) -> str:
    lines = [f"# {layer}", "", LAYERS[layer], ""]
    if layer == "cli":  # the package __init__ is the front end itself
        lines += [render_module(f"{PACKAGE}.cli"), ""]
    for name in _modules(layer):
        lines += [render_module(f"{PACKAGE}.{layer}.{name}"), ""]
    return "\n".join(lines).rstrip() + "\n"


def render_index() -> str:
    lines = [
        "# API reference",
        "",
        "Generated by `dast docs` from the package docstrings — do not edit by "
        "hand. The conceptual overview is in [ARCHITECTURE.md](../ARCHITECTURE.md); "
        "the flag reference is [COMMANDS.md](../COMMANDS.md).",
        "",
        "| layer | what it is |",
        "|---|---|",
    ]
    for layer, blurb in LAYERS.items():
        lines.append(f"| [{layer}]({layer}.md) | {blurb} |")
    lines.append("")
    return "\n".join(lines)


def write(out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = [out_dir / "README.md"]
    (out_dir / "README.md").write_text(render_index())
    for layer in LAYERS:
        path = out_dir / f"{layer}.md"
        path.write_text(render_layer(layer))
        written.append(path)
    return written


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dast docs",
        description="Generate the Markdown API reference (docs/api/) from the "
                    "package docstrings.",
    )
    parser.add_argument(
        "--out-dir", type=Path, default=config.REPO_ROOT / "docs" / "api",
        help="Directory to write the per-layer Markdown into "
             "(default: docs/api).",
    )
    return parser


def main(argv: "list[str] | None" = None) -> int:
    args = build_parser().parse_args(argv)
    for path in write(args.out_dir):
        print(path.relative_to(config.REPO_ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
