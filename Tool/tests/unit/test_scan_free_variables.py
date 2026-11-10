"""Guard the scan package against the "extracted a helper but dropped a free
variable" bug class (e.g. ``target_url``), which the mocked suite cannot see
because the offending code runs only against a live ZAP daemon.
→ DECISIONS.md (the 2ea8835 run_scan decomposition)."""

from __future__ import annotations

import ast
import builtins
import importlib
import inspect
import pkgutil

import pytest

import dast_orchestrator.stages.scan as scan_pkg

#: Every module under the scan package; a new scan submodule is covered the day
#: it is added, without editing this test.
SCAN_MODULES = sorted(
    m.name for m in pkgutil.walk_packages(scan_pkg.__path__, scan_pkg.__name__ + ".")
)


def _strip_annotations(fn: ast.AST) -> None:
    """Drop annotation subtrees in place, so a name that appears ONLY in a type
    hint (possibly a ``TYPE_CHECKING``-only or stringised import) is never
    mistaken for a runtime free variable."""
    for node in ast.walk(fn):
        if isinstance(node, (ast.arg, ast.AnnAssign)):
            node.annotation = None
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            node.returns = None


def _bound_names(fn: ast.AST) -> set[str]:
    out: set[str] = set()
    args = fn.args
    for a in args.posonlyargs + args.args + args.kwonlyargs:
        out.add(a.arg)
    if args.vararg:
        out.add(args.vararg.arg)
    if args.kwarg:
        out.add(args.kwarg.arg)
    for node in ast.walk(fn):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            out.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node is not fn:
                out.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                out.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ExceptHandler) and node.name:
            out.add(node.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            out.update(node.names)
        elif isinstance(node, ast.arg):
            out.add(node.arg)
    return out


def _loaded_names(fn: ast.AST) -> set[str]:
    return {
        node.id
        for node in ast.walk(fn)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    }


@pytest.mark.parametrize("modname", SCAN_MODULES)
def test_no_undefined_free_names_in_scan_module(modname: str) -> None:
    """Every name a top-level function LOADS is either bound somewhere in that
    function's own scope or in the module's resolved globals (``dir(module)``
    already reflects a ``from .common import *``). A name that is neither is a
    ``NameError`` waiting for the first live run — the class of bug that stopped
    the whole blind matrix at ZAP setup."""
    module = importlib.import_module(modname)
    resolved_globals = set(dir(module)) | set(dir(builtins)) | {"__class__"}
    tree = ast.parse(inspect.getsource(module))

    escapes: list[str] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _strip_annotations(node)
            undefined = _loaded_names(node) - _bound_names(node) - resolved_globals
            escapes += [f"{node.name}() -> {name!r}" for name in sorted(undefined)]

    assert not escapes, (
        f"{modname}: name(s) loaded but never bound (a NameError on the first "
        f"live run): " + ", ".join(escapes)
    )
