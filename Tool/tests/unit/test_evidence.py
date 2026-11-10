"""The evidence assembler: rule classification, the sidecar, excerpting, packs.

Every test here exists because the failure it guards against was measured, not
imagined: a body dropped for a class that needed it, an excerpt taken from the
top of a page while the payload sat at offset 9000, an observation read from one
fixed field while the plugin filled another, a "missing" body indistinguishable
from an empty one.
"""

from __future__ import annotations

import pathlib

import pytest

from dast_orchestrator.context import evidence


# -- rule classification ---------------------------------------------------

def test_explicit_rule_beats_cwe_and_name():
    # 90035 is SSTI by explicit row even though its CWE-1336 would also map.
    assert evidence.rule_class({"pluginId": "90035"}) == evidence.CLASS_SSTI


def test_unknown_rule_falls_back_to_cwe_then_name():
    assert evidence.rule_class({"pluginId": "99999", "cweid": "89"}) == evidence.CLASS_SQLI
    assert evidence.rule_class(
        {"pluginId": "x", "cweid": "", "name": "Foo Open Redirect"}
    ) == evidence.CLASS_REDIRECT


def test_body_is_kept_when_any_citing_class_needs_it():
    # A message cited by a header rule AND an XSS rule keeps its body.
    assert evidence.retain_body([evidence.CLASS_HEADER, evidence.CLASS_XSS])
    # A message cited only by header/cookie/identification rules does not.
    assert not evidence.retain_body([evidence.CLASS_HEADER, evidence.CLASS_COOKIE])


def test_informational_reflection_rule_keeps_its_body():
    # 10031 is Informational but its proof is the reflected attribute in the
    # body, so it must not be treated like a header rule.
    assert evidence.rule_class({"pluginId": "10031"}) == evidence.CLASS_XSS
    assert evidence.retain_body([evidence.CLASS_XSS])


# -- the message sidecar ---------------------------------------------------

def _alert(mid, plugin, cwe="", src=None):
    a = {"messageId": str(mid), "pluginId": plugin, "cweid": cwe}
    if src:
        a["sourceMessageId"] = str(src)
    return a


def _msg(mid, body="<html>body</html>"):
    return {
        "id": str(mid),
        "requestHeader": f"GET http://t/{mid} HTTP/1.1\r\nHost: t\r\n",
        "responseHeader": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n",
        "responseBody": body,
        "rtt": "3",
    }


def test_sidecar_drops_bodies_only_for_bodyless_classes():
    alerts = [_alert(1, "10038"), _alert(2, "40018")]  # header, sqli
    messages = {"1": _msg(1), "2": _msg(2)}
    side = evidence.build_message_sidecar(alerts, messages)
    assert side["counts"]["bodies_stored"] == 1
    assert side["counts"]["bodies_omitted"] == 1
    assert "response_body" not in side["messages"]["1"]
    assert side["messages"]["1"]["response_body_omitted"]
    assert side["messages"]["2"]["response_body"]


def test_sidecar_truncates_a_pathological_body():
    alerts = [_alert(1, "40018")]
    messages = {"1": _msg(1, "x" * (evidence.MAX_STORED_BODY_CHARS + 10))}
    side = evidence.build_message_sidecar(alerts, messages)
    assert side["messages"]["1"]["response_body_truncated"]
    assert len(side["messages"]["1"]["response_body"]) == evidence.MAX_STORED_BODY_CHARS


def test_message_ids_collects_both_source_and_message():
    ids = evidence.message_ids([_alert(5, "6", src=3)])
    assert ids == ["5", "3"]


# -- exchange parsing and reachability -------------------------------------

def _sidecar_entry(mid, plugin="40018", response_header=None, body="<html>b</html>"):
    """One entry in the sidecar's own snake_case shape, which parse_exchange reads."""
    msg = _msg(mid, body)
    if response_header:
        msg["responseHeader"] = response_header
    side = evidence.build_message_sidecar([_alert(mid, plugin)], {str(mid): msg})
    return side["messages"][str(mid)]


def test_parse_exchange_reads_request_and_status():
    ex = evidence.parse_exchange(_sidecar_entry(7))
    assert ex.method == "GET" and ex.status == 200


def test_reachability_anonymous_200_is_proof():
    ex = evidence.parse_exchange(_sidecar_entry(1))
    block = evidence.reachability("none", ex)
    assert "reachable" in block["conclusion"].lower()


def test_reachability_login_redirect_means_handler_not_reached():
    entry = _sidecar_entry(
        1, response_header="HTTP/1.1 302 Found\r\nLocation: /user/login\r\n")
    ex = evidence.parse_exchange(entry)
    block = evidence.reachability("none", ex)
    assert block["observed_status"] == 302
    assert "never reached" in block["conclusion"]


# -- observation normalisation ---------------------------------------------

def test_observation_reads_whichever_field_the_plugin_filled():
    # The 90035 shape: evidence empty, proof in `other`.
    found = evidence.normalise_observation({"evidence": "", "other": "Proof found"})
    assert found == {"other": "Proof found"}


# -- excerpting ------------------------------------------------------------

def test_around_match_centres_on_a_deep_payload():
    body = "A" * 9000 + "PAYLOAD" + "B" * 2000
    rule = evidence.ExcerptRule(body="around-match", body_chars=200)
    out = evidence.excerpt_body(body, rule, needles=["PAYLOAD"])
    assert "PAYLOAD" in out["shown"]
    assert out["offset"] > 0 and out["truncated"]


def test_head_mode_misses_a_deep_payload_by_design():
    body = "A" * 9000 + "PAYLOAD"
    rule = evidence.ExcerptRule(body="head", body_chars=200)
    out = evidence.excerpt_body(body, rule, needles=["PAYLOAD"])
    assert "PAYLOAD" not in out["shown"]  # which is why xss uses around-match


def test_error_region_falls_back_when_no_marker():
    body = "no markers here at all, just text"
    rule = evidence.ExcerptRule(body="error-region", body_chars=100)
    out = evidence.excerpt_body(body, rule, needles=[])
    assert out["mode"] == "head"


# -- policies --------------------------------------------------------------

def test_shipped_policies_load_and_validate():
    for name in evidence.available_policies():
        policy = evidence.load_policy(name)
        assert policy.name
        assert policy.source_text  # travels verbatim into the artifact


def test_none_policy_attaches_no_pack():
    policy = evidence.load_policy("none")
    assert not policy.attach
    asm = evidence.Assembler(policy=policy)
    assert asm.pack("f-1", object()) is None


def test_unknown_policy_is_a_clear_error():
    with pytest.raises(evidence.EvidenceError):
        evidence.load_policy("does-not-exist")


# -- what ZAP context reaches the model (the 2026-09-01 audit) --------------

class _Group:
    """The duck-typed AlertGroup shape `build_pack` reads."""

    def __init__(self, **fields):
        defaults = dict(
            plugin_id="10031", cweid="79", name="Reflected XSS", evidence="",
            other="", attack="", description="A rule.", solution="Fix it.",
            param="q", tags={}, input_vector="", message_ids=["1"],
            source_message_ids=[],
        )
        for key, value in {**defaults, **fields}.items():
            setattr(self, key, value)


def _store(body="<p>hello</p>", omitted=False):
    message = {
        "id": "1",
        "request_header": "GET http://t/x?q=1 HTTP/1.1\r\nhost: t\r\n",
        "request_body": "",
        "response_header": "HTTP/1.1 200 OK\r\n",
    }
    if omitted:
        message["response_body_omitted"] = "settled by headers"
    else:
        message["response_body"] = body
    return evidence.MessageStore({"1": message})


def _pack(group=None, mode=evidence.PUSH, store=None):
    return evidence.build_pack(
        # `store is not None`, not `store or …`: an empty MessageStore is falsy
        # (it defines __len__), which is exactly the case one test needs.
        "f-1", group or _Group(),
        store if store is not None else _store(),
        evidence.load_policy("balanced"),
        retrieval_mode=mode,
    )


def test_rule_tags_reach_the_prompt_as_names_not_links():
    """Found by the audit: `tags` on 1243 of 2036 alerts, never sent."""
    pack = _pack(_Group(tags={"OWASP_2021_A03": "https://owasp.org/…",
                              "CWE-79": "https://cwe.mitre.org/…"}))
    assert pack["zap_rule_tags"] == ["CWE-79", "OWASP_2021_A03"]


def test_an_alert_without_tags_carries_no_empty_key():
    assert "zap_rule_tags" not in _pack()


def test_the_injection_point_reaches_the_prompt_when_zap_recorded_one():
    """Rare (11 of 2036) and decisive exactly where it appears."""
    pack = _pack(_Group(input_vector="url_query_string"))
    assert pack["zap_injection_point"] == "url_query_string"
    assert "zap_injection_point" not in _pack()


# -- the pull pack ---------------------------------------------------------

def test_pull_replaces_the_excerpt_with_a_manifest():
    pack = _pack(mode=evidence.PULL)
    assert "http_exchange" not in pack
    manifest = pack["retrievable_exchange"]
    assert manifest["message_id"] == "1"
    assert manifest["status"] == 200
    assert manifest["response_body_chars"] == len("<p>hello</p>")
    assert "get_response_body" in manifest["retrieve_with"]


def test_pull_keeps_everything_small_and_decisive():
    """The cheap parts stay pushed: a round trip for them would cost more."""
    pack = _pack(_Group(other="Proof found"), mode=evidence.PULL)
    assert pack["rule_description"]
    assert pack["what_zap_observed"] == {"other": "Proof found"}
    assert pack["zap_suggested_remediation"]
    assert pack["reachability"]


def test_pull_keeps_not_stored_distinct_from_empty():
    """Collapsing the two would invent evidence in the cheaper mode."""
    omitted = _pack(mode=evidence.PULL, store=_store(omitted=True))
    assert "NOT STORED" in omitted["retrievable_exchange"]["response_body"]
    assert "response_body_chars" not in omitted["retrievable_exchange"]

    empty = _pack(mode=evidence.PULL, store=_store(body=""))
    assert empty["retrievable_exchange"]["response_body_chars"] == 0


def test_a_run_with_no_exchange_says_so_in_both_modes():
    for mode in (evidence.PUSH, evidence.PULL):
        pack = _pack(store=evidence.MessageStore(), mode=mode)
        assert "missing" in pack["http_exchange"]
        assert "retrievable_exchange" not in pack


def test_push_is_unchanged_by_the_mode_switch_existing():
    """The A/B baseline: push must be what it was, byte for byte."""
    pack = _pack(mode=evidence.PUSH)
    assert pack["http_exchange"]["response_body"]["shown"] == "<p>hello</p>"
    assert "retrievable_exchange" not in pack


def test_the_assembler_names_the_endpoint_block_by_mode():
    """A manifest under the name of the source itself would read as the source."""
    assert evidence.Assembler().endpoint_context_key == "handler_source"
    assert evidence.Assembler(
        retrieval_mode=evidence.PULL
    ).endpoint_context_key == "retrievable_source"


def test_the_assembler_records_the_mode_as_provenance():
    assert evidence.Assembler().as_dict()["retrieval_mode"] == evidence.PUSH
    assert evidence.Assembler(
        retrieval_mode=evidence.PULL
    ).as_dict()["retrieval_mode"] == evidence.PULL


def test_as_dict_reports_code_source_resolution_counts(tmp_path):
    """The run metric behind the asked level: how many candidate endpoints ctags
    resolved to handler source vs not. A measured zero (a scope/path miss, as
    seen on grafana and wordpress) must be visible, never indistinguishable from
    code context being off."""
    class _Index:
        provenance = {"version": "6.1.0", "scope": ["routers/web"]}

        def __len__(self):
            return 7

    # Code context OFF: the counts are absent, so a reader (and the triage
    # metric's `.get`) sees None, never a fabricated zero.
    off = evidence.Assembler().as_dict()
    assert "endpoints_with_source" not in off
    assert "endpoints_without_source" not in off

    # Code context ON: both counts are reported over the resolved context.
    asm = evidence.Assembler(
        code_level="handler+trace", index=_Index(), source_dir=tmp_path,
    )
    asm._context = {
        "ep-a": {"blocks": [object()]},   # resolved to handler source
        "ep-b": {"blocks": []},           # asked, nothing in scope resolved
        "ep-c": {"resolved": []},         # no 'blocks' key -> unresolved
    }
    d = asm.as_dict()
    assert d["endpoints_with_source"] == 1
    assert d["endpoints_without_source"] == 2


def test_pull_ships_no_parameter_sites():
    """A string search is `search_source`; pushing its answer is a half-pull."""
    asm = evidence.Assembler(retrieval_mode=evidence.PULL, code_level="handler+trace")
    assert asm._navigation(object(), _Group()) is None


# -- per-endpoint resolution record ------------------------------------------


class _Bundle:
    def __init__(self, identifier, callees=(), code_paths=(), technology=""):
        self.identifier = identifier
        method, _, path = identifier.partition(" ")
        self.static_context = {
            "method": method, "path": path, "technology": technology,
            "ai_context": {"callees": [{"name": n} for n in callees]},
            "code_paths": [{"path": p, "line": line} for p, line in code_paths],
        }


def _code_assembler(tmp_path, mode=evidence.PUSH):
    from dast_orchestrator.context import code_context as cc

    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / "issue.go").write_text(
        "func Issues() {\n  x := 1\n}\n")
    (tmp_path / "Admin").mkdir()
    (tmp_path / "Admin" / "X.php").write_text(
        "function register() {\n  add_action('wp_ajax_a', 'h');\n}\n")
    (tmp_path / "Admin" / "Hooks.php").write_text(
        "<?php\nnamespace P;\nclass Hooks {\n"
        "  function __construct() {\n"
        "    add_action('wp_ajax_go', [$this, 'go']);\n"
        "  }\n"
        "  function go() {\n    echo 1;\n  }\n}\n")
    index = cc.SymbolIndex([
        cc.Symbol("Issues", "repo", "repo/issue.go", 1, 3, kind="func"),
        cc.Symbol("register", "", "Admin/X.php", 1, 3, kind="function"),
        cc.Symbol("__construct", "", "Admin/Hooks.php", 4, 6, kind="function",
                  scope="P\\Hooks"),
        cc.Symbol("go", "", "Admin/Hooks.php", 7, 9, kind="function",
                  scope="P\\Hooks"),
    ])
    return evidence.Assembler(code_level="handler+trace", index=index,
                              source_dir=tmp_path, retrieval_mode=mode)


def _three_bundles():
    return [
        _Bundle("GET /issues", callees=["repo.Issues"]),
        _Bundle("GET /x.php", code_paths=[("/src/Admin/X.php", 0)],
                technology="php_pure"),
        _Bundle("GET /nowhere", callees=["http.Error"]),
    ]


WP_HOOK = _Bundle("GET /wp-admin/admin-ajax.php?action=go",
                  code_paths=[("/src/Admin/Hooks.php", 0)], technology="php_wordpress")
WP_PHANTOM = _Bundle("GET /wp-admin/admin-ajax.php?action=gone",
                     code_paths=[("/src/Admin/Hooks.php", 0)],
                     technology="php_wordpress")


def test_has_source_follows_what_the_endpoint_was_given(tmp_path):
    issues, php, nowhere = _three_bundles()
    asm = _code_assembler(tmp_path)
    asm.prepare([issues, nowhere])
    assert asm.has_source(issues) is True
    assert asm.has_source(nowhere) is False
    assert asm.has_source(php) is False, "never prepared, so never given"
    assert evidence.Assembler().has_source(issues) is False, "code context off"


def test_has_source_counts_what_a_pull_run_could_retrieve(tmp_path):
    issues, _, nowhere = _three_bundles()
    asm = _code_assembler(tmp_path, mode=evidence.PULL)
    asm.prepare([issues, nowhere])
    assert asm.has_source(issues) is True
    assert asm.has_source(nowhere) is False


def test_resolution_record_names_the_tier_and_whether_the_handler_is_located(tmp_path):
    """A Noir-named callee locates the endpoint's own handler; source reached
    through `code_paths` is file context — counted as source, never as a
    located handler."""
    asm = _code_assembler(tmp_path)
    asm.prepare(_three_bundles())
    assert asm.grounding() == {
        "endpoints": 3,
        "handler_located": 1,
        "by_resolution": {"callees": 1, "registration": 0, "code_paths": 1, "none": 1},
    }
    d = asm.as_dict()
    assert d["endpoints_with_source"] == 2
    assert d["endpoints_handler_located"] == 1
    assert d["endpoints_by_resolution"] == {
        "callees": 1, "registration": 0, "code_paths": 1, "none": 1}
    by_endpoint = {r["endpoint"]: r for r in d["endpoint_resolution"]}
    assert [r["endpoint"] for r in d["endpoint_resolution"]] == sorted(by_endpoint)
    assert by_endpoint["GET /issues"]["handler_located"] is True
    assert by_endpoint["GET /issues"]["symbols"] == ["repo.Issues"]
    assert by_endpoint["GET /x.php"]["resolved_by"] == "code_paths"
    assert by_endpoint["GET /x.php"]["handler_located"] is False
    assert by_endpoint["GET /nowhere"] == {
        "endpoint": "GET /nowhere", "resolved_by": "none",
        "handler_located": False, "symbols": [], "lines_included": 0,
    }


def test_resolution_record_stays_out_of_the_prompt_block(tmp_path):
    """The record is provenance about the pack, so the pack the model reads is
    byte-for-byte what it was before the record existed."""
    asm = _code_assembler(tmp_path)
    bundles = _three_bundles()
    asm.prepare(bundles)
    for bundle in bundles:
        block = asm.endpoint_context(bundle)
        assert "handler_located" not in block
        assert "endpoint" not in block


def test_grounding_counts_only_the_bundles_asked_about(tmp_path):
    asm = _code_assembler(tmp_path)
    bundles = _three_bundles()
    asm.prepare(bundles)
    assert asm.grounding(bundles[1:]) == {
        "endpoints": 2,
        "handler_located": 0,
        "by_resolution": {"callees": 0, "registration": 0, "code_paths": 1, "none": 1},
    }
    # An endpoint that was never prepared is not silently counted as anything.
    assert asm.grounding([_Bundle("GET /unprepared")])["endpoints"] == 0


def test_pull_mode_records_resolution_from_the_manifest(tmp_path):
    asm = _code_assembler(tmp_path, mode=evidence.PULL)
    asm.prepare(_three_bundles())
    grounding = asm.grounding()
    # Pull resolves Noir's callees only — it has no file fallback to count.
    assert grounding["handler_located"] == 1
    assert grounding["by_resolution"] == {
        "callees": 1, "registration": 0, "code_paths": 0, "none": 2}


def test_resolution_counts_are_absent_when_code_context_is_off():
    off = evidence.Assembler().as_dict()
    for key in ("endpoints_handler_located", "endpoints_by_resolution",
                "endpoint_resolution"):
        assert key not in off


def test_a_registration_locates_the_handler_the_hook_names(tmp_path):
    """WordPress: Noir names no callee, so the hook's callable is the handler —
    attached by itself, with the registration site beside it."""
    asm = _code_assembler(tmp_path)
    asm.prepare([WP_HOOK])
    block = asm.endpoint_context(WP_HOOK)
    assert block["resolved_by"] == "registration"
    assert [b["symbol"] for b in block["blocks"]] == ["P\\Hooks::go"]
    assert block["registered_at"]["site"] == "Admin/Hooks.php:5"
    assert asm.grounding()["handler_located"] == 1


def test_an_unregistered_endpoint_gets_no_file_dump(tmp_path):
    """A registration that resolves nothing leaves the endpoint ungrounded and
    says why — never the registering file's definitions in its place."""
    asm = _code_assembler(tmp_path)
    asm.prepare([WP_PHANTOM])
    block = asm.endpoint_context(WP_PHANTOM)
    assert block["blocks"] == []
    assert any("no live registration" in r for r in block["not_resolved"])
    assert "registration call did not lead" in block["note"]
    assert asm.grounding()["by_resolution"]["none"] == 1


def test_pull_mode_offers_the_registered_handler(tmp_path):
    asm = _code_assembler(tmp_path, mode=evidence.PULL)
    asm.prepare([WP_HOOK])
    manifest = asm.endpoint_context(WP_HOOK)
    assert [s["symbol"] for s in manifest["retrievable_symbols"]] == ["P\\Hooks::go"]
    assert asm.grounding()["by_resolution"]["registration"] == 1
