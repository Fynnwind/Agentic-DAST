"""How a framework dispatches a request to its handler, and locating that handler statically.

Keyed on Noir's per-endpoint ``technology``, never on a target name: a registration
resolver reads the call that registers an endpoint (WordPress's ``add_action`` /
``register_rest_route``) and names the callable it hands over, which ctags then
locates. It emits WHERE the handler is — the symbol and the registration site —
never what it does. → DECISIONS.md §"WordPress code context was never grounded".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, urlsplit

from dast_orchestrator.context import code_context as cc

#: Technologies whose endpoint IS its source file (a framework-less PHP script),
#: so the definitions in the file Noir located are that endpoint's code. Every
#: other technology registers a handler somewhere, and its file is only where the
#: registration sits — never source to attach as the handler.
FILE_DISPATCH = frozenset({"php_pure"})

#: Characters of the registration call kept as the ``call`` excerpt.
MAX_CALL_EXCERPT = 200


@dataclass(frozen=True)
class Registration:
    """What a registration resolver found for one endpoint.

    ``symbol`` is the handler when located; otherwise ``reason`` says why not.
    ``site`` and ``call`` locate the registration itself whenever it was found,
    located handler or not.
    """

    symbol: cc.Symbol | None
    reason: str = ""
    site: str = ""
    call: str = ""
    closure: bool = False


# -- PHP call parsing --------------------------------------------------------


def split_args(text: str, open_index: int) -> tuple[list[str], int] | None:
    """The top-level arguments of the call whose ``(`` is at ``open_index``.

    :returns: ``(arguments, index of the closing paren)``, or ``None`` when the
        parentheses do not balance. Commas inside ``()``, ``[]``, ``{}`` and
        string literals do not split.
    """
    depth = 0
    quote = ""
    args: list[str] = []
    start = open_index + 1
    i = open_index
    while i < len(text):
        char = text[i]
        if quote:
            if char == "\\":
                i += 2
                continue
            if char == quote:
                quote = ""
        elif char in ("'", '"'):
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth == 0:
                args.append(text[start:i])
                return [a.strip() for a in args], i
        elif char == "," and depth == 1:
            args.append(text[start:i])
            start = i + 1
        i += 1
    return None


def _array_items(expr: str) -> list[str] | None:
    """The top-level items of a PHP array literal (``[...]`` or ``array(...)``)."""
    expr = expr.strip()
    match = re.match(r"array\s*\(", expr, re.I)
    if match:
        parsed = split_args(expr, match.end() - 1)
    elif expr.startswith("[") and expr.endswith("]"):
        parsed = split_args("(" + expr[1:], 0)
    else:
        return None
    if parsed is None:
        return None
    items, _close = parsed
    return [item for item in items if item]


def _string_literal(expr: str) -> str | None:
    match = re.fullmatch(r"""\s*(['"])(.*)\1\s*""", expr, re.S)
    return match.group(2) if match else None


# -- callables ----------------------------------------------------------------

#: What a PHP callable expression names: ``(kind, class, member)`` with kind
#: ``this`` (the registering class), ``class`` (a named class), ``function`` or
#: ``closure``.
_THIS_RECEIVERS = {"$this", "__class__", "self::class", "static::class"}


def parse_callable(expr: str) -> tuple[str, str, str] | None:
    """Read a PHP callable expression. ``None`` when it is dynamic (a variable)."""
    expr = expr.strip()
    if re.match(r"(?:static\s+)?(?:function\b|fn\s*\()", expr, re.I):
        return ("closure", "", "")
    literal = _string_literal(expr)
    if literal is not None:
        cls, sep, member = literal.partition("::")
        if sep:
            return ("class", cls, member)
        return ("function", "", literal.lstrip("\\"))
    items = _array_items(expr)
    if items is None or len(items) != 2:
        return None
    receiver, member = items[0].strip(), _string_literal(items[1])
    if member is None:
        return None
    if receiver.lower() in _THIS_RECEIVERS:
        return ("this", "", member)
    new = re.fullmatch(r"new\s+(\\?[\w\\]+)\s*(?:\(.*\))?", receiver, re.S | re.I)
    if new:
        return ("class", new.group(1), member)
    named = _string_literal(receiver)
    if named is not None:
        return ("class", named, member)
    constant = re.fullmatch(r"(\\?[\w\\]+)::class", receiver)
    if constant:
        return ("class", constant.group(1), member)
    return None


def _enclosing(index: cc.SymbolIndex, rel_path: str, line: int) -> cc.Symbol | None:
    found = cc.symbols_in_file(index, rel_path, line)
    if len(found) == 1 and found[0].start <= line <= (found[0].end or found[0].start):
        return found[0]
    return None


def resolve_callable(index: cc.SymbolIndex, rel_path: str, line: int, text: str,
                     expr: str) -> tuple[cc.Symbol | None, str, bool]:
    """The symbol a callable registered at ``rel_path:line`` names.

    :returns: ``(symbol, reason, closure)``; ``reason`` is set when ``symbol``
        is ``None``.
    """
    parsed = parse_callable(expr)
    if parsed is None:
        return None, f"callback {_excerpt(expr)!r} is dynamic", False
    kind, cls, member = parsed
    enclosing = _enclosing(index, rel_path, line)
    if kind == "closure":
        if enclosing is None:
            return None, "closure callback outside any indexed definition", True
        return enclosing, "", True
    if kind == "function":
        symbol = cc.find_function(index, member)
        return (symbol, "" if symbol else
                f"callback function {member!r} is not a unique indexed definition",
                False)
    if kind == "this":
        if enclosing is None or not enclosing.scope:
            return None, "callback on $this outside any indexed class", False
        classes = [enclosing.scope]
    else:
        namespace, uses = cc.php_names(text)
        classes = cc.class_candidates(cls, namespace, uses)
    symbol = cc.find_method(index, member, classes)
    if symbol is None:
        return None, (f"callback {classes[0]}::{member} is not defined in the "
                      "indexed source"), False
    return symbol, "", False


def _excerpt(text: str) -> str:
    one_line = " ".join(text.split())
    return one_line[:MAX_CALL_EXCERPT]


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


# -- WordPress -----------------------------------------------------------------

_HOOK_ENDPOINTS = {
    "/wp-admin/admin-ajax.php": ("wp_ajax_", "wp_ajax_nopriv_"),
    "/wp-admin/admin-post.php": ("admin_post_", "admin_post_nopriv_"),
}
_REST_PREFIX = "/wp-json/"
_REST_METHOD_CONSTANTS = {
    "READABLE": {"GET"}, "CREATABLE": {"POST"}, "EDITABLE": {"POST", "PUT", "PATCH"},
    "DELETABLE": {"DELETE"},
    "ALLMETHODS": {"GET", "POST", "PUT", "PATCH", "DELETE"},
}


def _rest_path(namespace: str, route: str) -> str:
    """``/wp-json/<ns>/<route>`` in Noir's normalised template form."""
    path = f"{_REST_PREFIX}{namespace.strip().strip('/')}/{route.strip()}"
    path = re.sub(r"/+", "/", path)
    path = re.sub(r"\(\?P?<(\w+)>[^()]*(?:\([^()]*\)[^()]*)*\)", r"{\1}", path)
    path = path.replace("(?:", "")
    path = re.sub(r"[()^$?]", "", path)
    path = re.sub(r"/+", "/", path)
    return path.rstrip("/") or "/"


def _rest_methods(args: str) -> set[str]:
    methods = {verb for constant, verbs in _REST_METHOD_CONSTANTS.items()
               if f"WP_REST_Server::{constant}" in args for verb in verbs}
    for match in re.finditer(r"""['"]methods['"]\s*=>\s*['"]([^'"]+)['"]""", args, re.I):
        methods |= {v.strip().upper() for v in match.group(1).split(",")}
    for match in re.finditer(r"""['"]methods['"]\s*=>\s*(?:array\s*\(|\[)([^\)\]]*)""",
                             args, re.I):
        methods |= {v.upper() for v in re.findall(r"""['"]([A-Za-z]+)['"]""", match.group(1))}
    return methods


def _rest_callback(args_expr: str, method: str) -> tuple[str | None, str]:
    """The ``'callback' =>`` expression of a ``register_rest_route`` args array."""
    items = _array_items(args_expr)
    if items is None:
        return None, "route arguments are not a literal array"
    entries = [items]
    if items and all(_array_items(item) is not None for item in items):
        entries = [_array_items(item) or [] for item in items]   # one array per verb
    found: list[tuple[set[str], str]] = []
    for entry in entries:
        for item in entry:
            key, sep, value = item.partition("=>")
            if sep and _string_literal(key) == "callback":
                found.append((_rest_methods(",".join(entry)), value.strip()))
    if not found:
        return None, "route registers no 'callback'"
    matching = [cb for verbs, cb in found if not verbs or method in verbs]
    if len({cb for cb in matching}) == 1:
        return matching[0], ""
    if len({cb for _v, cb in found}) == 1:
        return found[0][1], ""
    return None, f"route registers {len(found)} callbacks and none is only for {method}"


def _wordpress_calls(text: str, path: str, method: str
                     ) -> tuple[list[tuple[int, str, str]], str]:
    """Registration calls in ``text`` that register this endpoint.

    :returns: ``([(offset, call excerpt, callable expression)], what was sought)``.
    """
    split = urlsplit(path)
    hooks = _HOOK_ENDPOINTS.get(split.path)
    calls: list[tuple[int, str, str]] = []
    if hooks:
        action = dict(parse_qsl(split.query)).get("action", "")
        wanted = {prefix + action for prefix in hooks}
        sought = " / ".join(sorted(wanted))
        for match in re.finditer(r"\badd_action\s*\(", text, re.I):
            parsed = split_args(text, match.end() - 1)
            if parsed is None:
                continue
            args, close = parsed
            if len(args) >= 2 and _string_literal(args[0]) in wanted:
                calls.append((match.start(), text[match.start():close + 1], args[1]))
        return calls, sought
    if split.path.startswith(_REST_PREFIX):
        sought = f"register_rest_route for {split.path}"
        for match in re.finditer(r"\bregister_rest_route\s*\(", text, re.I):
            parsed = split_args(text, match.end() - 1)
            if parsed is None:
                continue
            args, close = parsed
            if len(args) < 3:
                continue
            namespace, route = _string_literal(args[0]), _string_literal(args[1])
            if namespace is None or route is None:
                continue
            if _rest_path(namespace, route) != split.path:
                continue
            callback, why = _rest_callback(args[2], method)
            calls.append((match.start(), text[match.start():close + 1],
                          callback if callback is not None else f"<{why}>"))
        return calls, sought
    return [], f"no WordPress dispatch for {split.path}"


def wordpress_handler(endpoint: dict[str, Any], index: cc.SymbolIndex,
                      source_dir: Path) -> Registration:
    """Locate a WordPress admin-ajax / admin-post / REST endpoint's handler.

    Reads the registration in the file(s) Noir located, comments stripped, so a
    commented-out registration (which Noir 1.2.1 still emits as an endpoint)
    resolves to nothing rather than to whatever sits beside it.
    """
    method = str(endpoint.get("method") or "GET").upper()
    path = str(endpoint.get("path") or "")
    sought = ""
    for entry in endpoint.get("code_paths") or []:
        rel = cc.index_relative_path(str(entry.get("path") or ""))
        try:
            raw = (source_dir / rel).read_text(errors="replace")
        except OSError:
            continue
        text = cc.strip_php_comments(raw)
        calls, sought = _wordpress_calls(text, path, method)
        for offset, call, expr in calls:
            line = _line_of(text, offset)
            site = f"{rel}:{line}"
            if expr.startswith("<"):
                return Registration(None, expr.strip("<>"), site, _excerpt(call))
            symbol, reason, closure = resolve_callable(index, rel, line, text, expr)
            return Registration(symbol, reason, site, _excerpt(call), closure)
    return Registration(
        None,
        f"no live registration ({sought or 'nothing to seek'}) in the located "
        "file — commented out, or built dynamically",
    )


#: Registration resolvers by Noir technology.
RESOLVERS: dict[str, Callable[[dict[str, Any], cc.SymbolIndex, Path], Registration]] = {
    "php_wordpress": wordpress_handler,
}


def locate_handler(endpoint: dict[str, Any], index: cc.SymbolIndex,
                   source_dir: Path) -> Registration | None:
    """The handler the endpoint's registration names, or ``None`` when its
    technology has no registration resolver."""
    resolver = RESOLVERS.get(str(endpoint.get("technology") or ""))
    if resolver is None:
        return None
    return resolver(endpoint, index, source_dir)
