"""Structural parameters: the export/edit/import recipe, and why it is one.

ZAP 2.17's REST `context` component has **no action** that sets a structural
parameter. That was established against the running daemon on 2026-09-05, not
read out of documentation: `newContext`, `includeInContext` and their kin answer
`missing_parameter` (they exist), while `setContextStructuralParameters`,
`setContextStructure`, `setUrlParameterParser` and every other plausible
spelling answer `bad_action` (they do not). The setting is reachable only
through the context's serialised form, which is what
:mod:`dast_orchestrator.adapters.zap_context` edits.

Measured on the live daemon, three requests differing only in `action`:
without a structural parameter ZAP records **one** site-tree node carrying
whichever value arrived last; with one it records **three** leaf nodes. That is
the whole reason this module exists — 91 seeded WordPress requests collapse into
15 URLs, and the active scanner then attacks one endpoint where the application
has ninety.
"""

from __future__ import annotations

import pytest

from dast_orchestrator.adapters import zap_context

#: Trimmed from a real `exportContext` response (ZAP 2.17.0), including the
#: entity-escaped `&` separator and the POST parser block that must be left
#: alone — a structural parameter is about URL identity, and splitting the tree
#: on a body field would split it on values the application does not route by.
EXPORTED = """<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <context>
        <name>dast</name>
        <urlparser>
            <class>org.zaproxy.zap.model.StandardParameterParser</class>
            <config>{"kvps":"&amp;","kvs":"=","struct":[]}</config>
        </urlparser>
        <postparser>
            <class>org.zaproxy.zap.model.StandardParameterParser</class>
            <config>{"kvps":"&amp;","kvs":"=","struct":[]}</config>
        </postparser>
    </context>
</configuration>
"""


def test_only_the_url_parser_is_rewritten():
    out = zap_context.rewrite(EXPORTED, ["action"])
    url_block = out.split("<postparser>")[0]
    post_block = out.split("<postparser>")[1]
    assert '"struct":["action"]' in url_block
    assert '"struct":[]' in post_block, (
        "the POST parser must be left alone: a structural body field splits the "
        "tree on values the application does not route by"
    )


def test_the_separators_are_carried_through_not_restated():
    """A ZAP release that changes a default must not be silently overridden."""
    out = zap_context.rewrite(
        EXPORTED.replace('"kvps":"&amp;"', '"kvps":";"'), ["action"])
    assert '"kvps":";"' in out
    # …and the `&` separator survives its XML escaping in the untouched case.
    assert '"kvps":"&amp;"' in zap_context.rewrite(EXPORTED, ["action"])


def test_a_context_format_change_fails_loudly():
    """Silently scanning with the wrong tree shape is the outcome to avoid.

    If ZAP moves this setting, the run must stop — not proceed with a site tree
    that does not match its own recorded configuration.
    """
    with pytest.raises(zap_context.ContextError, match="no <urlparser>"):
        zap_context.rewrite("<configuration><context/></configuration>", ["action"])


def test_structural_config_round_trips_several_parameters():
    assert zap_context.structural_config(
        '{"kvps":"&amp;","kvs":"=","struct":[]}', ["action", "page"]
    ) == '{"kvps":"&amp;","kvs":"=","struct":["action","page"]}'


def test_the_target_that_needs_it_declares_it_and_the_other_does_not():
    """A property of how the application routes, so it lives with the target."""
    from dast_orchestrator.adapters import targets

    targets.load_all()
    assert targets.get("wordpress").structural_parameters == ("action",)
    # Gitea routes by path and declares none; a structural parameter it does not
    # need would split its tree for nothing.
    assert targets.get("gitea").structural_parameters == ()


def test_a_structural_parameter_is_part_of_the_run_id():
    """It changes what the scan CONTAINS, so it cannot share a name.

    91 seeded requests are 15 site-tree nodes without `action` and ~90 with it.
    Two runs differing only here are different experiments and their directories
    must differ.
    """
    from dast_orchestrator.foundation import run_paths
    from dast_orchestrator.stages import scan

    base = dict(target_url="http://t", auth_mode="none", use_noir=True)
    without = run_paths.config_digest(scan.scan_config(**base,
                                                       structural_parameters=""))
    with_it = run_paths.config_digest(scan.scan_config(**base,
                                                       structural_parameters="action"))
    assert without != with_it
