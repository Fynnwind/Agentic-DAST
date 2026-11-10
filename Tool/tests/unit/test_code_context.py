"""The scoped code extractor: ctags parsing, resolution, the bounded walk.

Uses a small in-memory index rather than a live ctags run, so the unit tier
stays hermetic; an e2e test covers the real image against the Gitea tree.
"""

from __future__ import annotations

import pathlib

import pytest

from dast_orchestrator.context import code_context as cc


def _sym(name, package, path, start, end):
    return cc.Symbol(name=name, package=package, path=path, start=start, end=end,
                     kind="func")


def _index():
    return cc.SymbolIndex([
        _sym("Issues", "repo", "repo/issue.go", 375, 413),
        _sym("issues", "repo", "repo/issue.go", 117, 372),
        _sym("Action", "repo", "repo/repo.go", 279, 311),
        _sym("Action", "user", "user/profile.go", 359, 379),
        _sym("AvatarPost", "setting", "user/setting/avatar.go", 20, 40),
    ])


# -- ctags output parsing --------------------------------------------------

def test_parse_tags_reads_end_and_package():
    line = ("Issues\trouters/web/repo/issue.go\t/^func Issues() {$/;\"\t"
            "func\tline:375\tpackage:repo\tend:413")
    [sym] = cc.parse_tags(line)
    assert sym.name == "Issues" and sym.package == "repo"
    assert sym.start == 375 and sym.end == 413 and sym.lines == 39


def test_parse_tags_keeps_a_line_without_end_for_backfill():
    # ctags parsers that locate a start but no scope end (PHP) must not lose the
    # symbol; it is kept with end == UNKNOWN_END for backfill_extents to fill in.
    line = "Foo\ta.php\t/^function Foo() {$/;\"\tfunction\tline:1"
    [sym] = cc.parse_tags(line)
    assert sym.name == "Foo" and sym.start == 1 and sym.end == cc.UNKNOWN_END


def test_parse_tags_skips_a_line_without_a_start():
    line = "Foo\ta.go\t/^func Foo() {$/;\"\tfunc"
    assert cc.parse_tags(line) == []


# -- extent backfill (ctags emits no scope end, e.g. PHP) ------------------

def test_backfill_bounds_a_symbol_by_the_next_and_trims_blanks(tmp_path):
    (tmp_path / "a.php").write_text(
        "<?php\n"                       # 1
        "function first() {\n"          # 2
        "    return 1;\n"               # 3
        "}\n"                           # 4
        "\n"                            # 5  blank between defs -> trimmed off first
        "\n"                            # 6
        "function second() {\n"         # 7
        "    return 2;\n"               # 8
        "}\n"                           # 9
    )
    raw = [
        cc.Symbol("first", "", "a.php", 2, cc.UNKNOWN_END, "function", ""),
        cc.Symbol("second", "", "a.php", 7, cc.UNKNOWN_END, "function", ""),
    ]
    first, second = sorted(cc.backfill_extents(raw, tmp_path), key=lambda s: s.start)
    assert (first.start, first.end) == (2, 4)   # bounded at 6->trimmed to 4
    assert (second.start, second.end) == (7, 9)  # last in file runs to EOF


def test_backfill_leaves_a_known_extent_untouched(tmp_path):
    # A symbol ctags already gave an end for (Go) must not be recomputed.
    (tmp_path / "a.go").write_text("package x\nfunc F() {\n}\nfunc G() {\n}\n")
    known = cc.Symbol("F", "x", "a.go", 2, 3, "func", "")
    [out] = cc.backfill_extents([known], tmp_path)
    assert out.end == 3


# -- resolution ------------------------------------------------------------

def test_resolve_prefers_the_named_package():
    idx = _index()
    assert idx.resolve("repo.Action").package == "repo"
    assert idx.resolve("user.Action").package == "user"


def test_resolve_bare_name_uses_prefer_package():
    idx = _index()
    assert idx.resolve("Action", prefer_package="user").package == "user"


def test_import_alias_resolves_only_when_unique():
    idx = _index()
    # `setting` is not a package name the qualifier `user_setting` matches, but
    # AvatarPost is unique, so the alias is admitted.
    sym = cc.resolve_reference(idx, "user_setting.AvatarPost")
    assert sym is not None and sym.name == "AvatarPost"
    # A qualified call into stdlib whose bare name is NOT unique is refused.
    sym = cc.resolve_reference(idx, "http.Action")
    assert sym is None  # Action is ambiguous, so no alias guess


# -- the walk --------------------------------------------------------------

def test_extract_reports_unresolved_roots():
    idx = _index()
    blocks, unresolved = cc.extract(idx, pathlib.Path("/nonexistent"),
                                    ["repo.DoesNotExist"], max_hops=1)
    assert blocks == []
    assert "repo.DoesNotExist" in unresolved


def test_walk_is_breadth_first_and_bounded(tmp_path):
    # A tiny source tree so read_block returns real text.
    src = tmp_path
    (src / "repo").mkdir()
    handler = "\n".join(
        [f"func Issues() {{"] + ["  issues()"] + [f"  x{i}" for i in range(36)] + ["}"]
    )
    inner = "\n".join([f"func issues() {{"] + [f"  y{i}" for i in range(254)] + ["}"])
    (src / "repo" / "issue.go").write_text(handler + "\n" + inner)
    idx = cc.SymbolIndex([
        _sym("Issues", "repo", "repo/issue.go", 1, 39),
        _sym("issues", "repo", "repo/issue.go", 40, 295),
    ])
    blocks, _ = cc.extract(idx, src, ["repo.Issues"], max_hops=1, max_lines=5000)
    assert [b.symbol.name for b in blocks] == ["Issues", "issues"]
    assert blocks[1].reached_from == "repo.Issues"
    # A tight budget keeps the handler and drops the hop, never the reverse.
    blocks, unresolved = cc.extract(idx, src, ["repo.Issues"], max_hops=1, max_lines=50)
    assert [b.symbol.name for b in blocks] == ["Issues"]
    assert any("budget" in u for u in unresolved)


def test_parameter_sites_are_a_string_search(tmp_path):
    src = tmp_path
    (src / "repo").mkdir()
    (src / "repo" / "issue.go").write_text(
        'func issues() {\n  selectLabels := ctx.FormString("labels")\n  _ = x\n}'
    )
    idx = cc.SymbolIndex([_sym("issues", "repo", "repo/issue.go", 1, 4)])
    blocks, _ = cc.extract(idx, src, ["repo.issues"], max_hops=0)
    sites = cc.parameter_sites(blocks, "labels")
    assert sites and sites[0]["location"].endswith(":2")


# -- code_paths fallback (callee-absent resolution) ------------------------

def test_index_relative_path_strips_the_mount_prefix():
    # Noir mounts the tree at /src; a nested plugin src/ survives the strip.
    assert cc._index_relative_path("/src/routers/web/web.go") == "routers/web/web.go"
    assert cc._index_relative_path("/src/src/Admin/X.php") == "src/Admin/X.php"


def test_extract_from_paths_resolves_by_file_when_no_callees(tmp_path):
    """Noir named no callees but located the handler file, so source resolves
    by file — the WordPress case."""
    src = tmp_path
    (src / "Admin").mkdir()
    body = "\n".join(["function handle() {"] + ["  work()"]
                     + [f"  z{i}" for i in range(5)] + ["}"])
    (src / "Admin" / "AdminController.php").write_text(body)
    idx = cc.SymbolIndex([_sym("handle", "", "Admin/AdminController.php", 1, 8)])
    # Noir reports the mounted /src/ path and line 0 (file known, line not).
    blocks, unresolved = cc.extract_from_paths(
        idx, src, [("/src/Admin/AdminController.php", 0)], max_hops=1, max_lines=5000)
    assert [b.symbol.name for b in blocks] == ["handle"]
    assert not unresolved


def test_extract_from_paths_picks_the_enclosing_symbol_by_line(tmp_path):
    src = tmp_path
    (src / "a.php").write_text("\n".join(f"line{i}" for i in range(1, 21)))
    idx = cc.SymbolIndex([
        _sym("first", "", "a.php", 1, 5),
        _sym("second", "", "a.php", 6, 20),
    ])
    blocks, _ = cc.extract_from_paths(
        idx, src, [("/src/a.php", 8)], max_hops=0, max_lines=5000)
    assert [b.symbol.name for b in blocks] == ["second"]


def test_extract_from_paths_reports_a_file_outside_the_scope(tmp_path):
    idx = cc.SymbolIndex([_sym("f", "", "in/scope.go", 1, 3)])
    blocks, unresolved = cc.extract_from_paths(
        idx, tmp_path, [("/src/pkg/api/other.go", 0)], max_hops=0)
    assert not blocks
    assert any("no symbol in the indexed scope" in u for u in unresolved)


# -- PHP hops -------------------------------------------------------------------


def _php(name, path, start, end, scope=""):
    return cc.Symbol(name=name, package="", path=path, start=start, end=end,
                     kind="function", scope=scope)


def test_php_hops_follow_php_receivers_and_never_choose(tmp_path):
    """`$this->`/`self::` stay in the class, `X::` follows the imports, a call
    on an arbitrary object or an ambiguous name resolves to nothing."""
    (tmp_path / "A.php").write_text(
        "<?php\nnamespace N;\nuse M\\Util;\nclass A {\n"
        "function handle() {\n"
        "  $this->own();\n  self::own2();\n  Util::help();\n"
        "  $obj->get();\n  shared();\n  unique_fn();\n"
        "  // $this->commented();\n"
        "}\n"
        "function own() {}\nfunction own2() {}\nfunction commented() {}\n}\n")
    index = cc.SymbolIndex([
        _php("handle", "A.php", 5, 13, "N\\A"),
        _php("own", "A.php", 14, 14, "N\\A"),
        _php("own", "B.php", 1, 1, "N\\B"),          # same name, other class
        _php("own2", "A.php", 15, 15, "N\\A"),
        _php("commented", "A.php", 16, 16, "N\\A"),
        _php("help", "U.php", 1, 1, "M\\Util"),
        _php("get", "X.php", 1, 1, "N\\X"),
        _php("get", "Y.php", 1, 1, "N\\Y"),          # ambiguous by name
        _php("shared", "f1.php", 1, 1),
        _php("shared", "f2.php", 1, 1),              # ambiguous free function
        _php("unique_fn", "f3.php", 1, 1),
    ])
    handle = index.named("handle")[0]
    text = cc.read_block(tmp_path, handle)
    names = [s.qualified for s in cc.php_callees(text, index, handle, tmp_path)]
    assert names == ["N\\A::own", "N\\A::own2", "M\\Util::help", "unique_fn"]


def test_a_php_method_is_qualified_by_its_class():
    assert _php("own", "A.php", 1, 1, "N\\A").qualified == "N\\A::own"
    assert _php("fn", "f.php", 1, 1).qualified == "fn"
    assert _sym("Issues", "repo", "repo/issue.go", 1, 2).qualified == "repo.Issues"
