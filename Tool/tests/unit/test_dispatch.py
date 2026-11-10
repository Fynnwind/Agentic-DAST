"""Locating a handler from the call that registers it (WordPress), and its PHP parsing.

Hermetic: small PHP files in a temp tree and an in-memory index. The real plugin
tree is checked against a hand-written answer key in the e2e tier.
"""

from __future__ import annotations

import pytest

from dast_orchestrator.context import code_context as cc
from dast_orchestrator.context import dispatch


def _sym(name, path, start, end, scope=""):
    return cc.Symbol(name=name, package="", path=path, start=start, end=end,
                     kind="function", scope=scope)


HOOKS = """<?php
namespace P\\Admin;

use P\\Locks\\Gate as Lock;

class Hooks {
    function __construct() {
        add_action('wp_ajax_mine', [$this, 'mine']);
        add_action( "wp_ajax_nopriv_open" , array( $this , "open" ) );
        add_action('wp_ajax_other', [new Lock(), 'check']);
        add_action('wp_ajax_static', 'P\\Locks\\Gate::check');
        add_action('wp_ajax_fn', 'free_handler');
        add_action('wp_ajax_closure', function () { echo 1; });
        add_action('wp_ajax_dyn', $callback);
        add_action('wp_ajax_missing', [$this, 'nothing']);
        // add_action('wp_ajax_gone', [$this, 'mine']);
        /* add_action('wp_ajax_gone2', [$this, 'mine']); */
        register_rest_route('ns/v1', '/item/(?P<id>\\d+)', array(
            'methods' => 'GET',
            'callback' => [$this, 'item'],
            'permission_callback' => function () { return true; },
        ));
        register_rest_route('ns', '/multi', array(
            array('methods' => 'GET', 'callback' => [$this, 'read']),
            array('methods' => WP_REST_Server::CREATABLE, 'callback' => [$this, 'write']),
        ));
    }
    function mine() {}
    function open() {}
}
"""

GATE = """<?php
namespace P\\Locks;
class Gate {
    function check() {}
}
"""


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Hooks.php").write_text(HOOKS)
    (tmp_path / "src" / "Gate.php").write_text(GATE)
    hooks_end = HOOKS.count("\n")
    index = cc.SymbolIndex([
        _sym("__construct", "src/Hooks.php", 7, 30, "P\\Admin\\Hooks"),
        _sym("mine", "src/Hooks.php", 31, 31, "P\\Admin\\Hooks"),
        _sym("open", "src/Hooks.php", 32, 32, "P\\Admin\\Hooks"),
        _sym("item", "src/Hooks.php", 33, hooks_end, "P\\Admin\\Hooks"),
        _sym("read", "src/Hooks.php", 33, hooks_end, "P\\Admin\\Hooks"),
        _sym("check", "src/Gate.php", 4, 4, "P\\Locks\\Gate"),
        _sym("check", "src/Other.php", 1, 2, "Q\\Gate"),
        _sym("free_handler", "src/fn.php", 1, 3),
    ])
    return index, tmp_path


def _endpoint(path, method="GET", file="/src/src/Hooks.php"):
    return {"method": method, "path": path, "technology": "php_wordpress",
            "code_paths": [{"path": file, "line": 0}]}


@pytest.mark.parametrize("action, expected", [
    ("mine", "P\\Admin\\Hooks::mine"),
    ("open", "P\\Admin\\Hooks::open"),           # nopriv hook, array() form
    ("other", "P\\Locks\\Gate::check"),          # `new Lock()` through a `use … as`
    ("static", "P\\Locks\\Gate::check"),         # 'Class::method' string
    ("fn", "free_handler"),
])
def test_an_ajax_hook_resolves_to_the_callable_it_registers(tree, action, expected):
    index, src = tree
    found = dispatch.locate_handler(
        _endpoint(f"/wp-admin/admin-ajax.php?action={action}"), index, src)
    assert found.symbol is not None and found.symbol.qualified == expected
    assert found.site.startswith("src/Hooks.php:")


def test_a_closure_attaches_the_definition_it_is_written_in(tree):
    index, src = tree
    found = dispatch.locate_handler(
        _endpoint("/wp-admin/admin-ajax.php?action=closure"), index, src)
    assert found.closure and found.symbol.qualified == "P\\Admin\\Hooks::__construct"


@pytest.mark.parametrize("action, reason", [
    ("dyn", "is dynamic"),
    ("missing", "P\\Admin\\Hooks::nothing is not defined"),
    ("gone", "no live registration"),            # commented out with //
    ("gone2", "no live registration"),           # commented out with /* */
    ("never", "no live registration"),
])
def test_an_unresolvable_hook_says_why(tree, action, reason):
    index, src = tree
    found = dispatch.locate_handler(
        _endpoint(f"/wp-admin/admin-ajax.php?action={action}"), index, src)
    assert found.symbol is None and reason in found.reason


def test_a_rest_route_matches_its_normalised_template(tree):
    index, src = tree
    found = dispatch.locate_handler(_endpoint("/wp-json/ns/v1/item/{id}"), index, src)
    assert found.symbol.qualified == "P\\Admin\\Hooks::item"


def test_a_rest_route_with_one_callback_per_verb_picks_the_verbs(tree):
    index, src = tree
    read = dispatch.locate_handler(_endpoint("/wp-json/ns/multi"), index, src)
    assert read.symbol.qualified == "P\\Admin\\Hooks::read"
    write = dispatch.locate_handler(_endpoint("/wp-json/ns/multi", "POST"), index, src)
    # `write` is not indexed, so it is named and not found — never `read` instead.
    assert write.symbol is None and "Hooks::write" in write.reason


def test_a_technology_without_a_resolver_is_not_asked(tree):
    index, src = tree
    endpoint = dict(_endpoint("/x"), technology="go_chi")
    assert dispatch.locate_handler(endpoint, index, src) is None


def test_file_dispatch_is_only_the_framework_less_script():
    assert dispatch.FILE_DISPATCH == frozenset({"php_pure"})


# -- PHP source helpers -------------------------------------------------------


def test_comment_stripping_keeps_offsets_strings_and_lines():
    src = ("<?php\n$a = 'it''s // not';\n// gone()\n# gone()\n/* gone()\n */\n"
           "?>\n<p>don't()</p>\n<?php live();\n")
    out = cc.strip_php_comments(src)
    assert len(out) == len(src) and out.count("\n") == src.count("\n")
    assert "gone" not in out and "don't" not in out
    assert "live();" in out and "'it''s // not'" in out


def test_comment_stripping_a_body_starts_inside_php():
    assert "call()" in cc.strip_php_comments("call(); // x", start_in_php=True)
    assert "call()" not in cc.strip_php_comments("call(); // x")


def test_class_names_resolve_through_namespace_and_imports():
    namespace, uses = cc.php_names(HOOKS)
    assert namespace == "P\\Admin" and uses == {"Lock": "P\\Locks\\Gate"}
    assert cc.class_candidates("Lock", namespace, uses)[0] == "P\\Locks\\Gate"
    assert cc.class_candidates("\\Abs\\X", namespace, uses) == ["Abs\\X"]
    assert cc.class_candidates("Near", namespace, uses)[0] == "P\\Admin\\Near"
