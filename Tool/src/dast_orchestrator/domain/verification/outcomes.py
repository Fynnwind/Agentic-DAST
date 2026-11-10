"""The verification vocabulary: the four outcomes, the tool/CWE/class tables, and the
predicates over them (:func:`tool_capabilities`, :func:`cwe_family`,
:func:`classification_match`) — the shared base the other verification submodules read.

The four outcomes never collapse into "not confirmed": CONFIRMED (a tool reproduced it),
REFUTED (ran to completion and could not — the false-positive result), INCONCLUSIVE
(timed out / errored / rejected — not a refutation), and NOT_ATTEMPTED (never dispatched,
a budget spent). A confirmation is also checked against the rule it confirms: a class
mismatch downgrades it to INCONCLUSIVE (the tool's own reading is kept in
``wrapper_verdict``), and otherwise the tool's category stands.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

#: Bumped when the outcome/disposition vocabulary changes shape, so a stored
#: verification artifact records which vocabulary produced it.
VERIFICATION_VOCAB_VERSION = 1


# -- outcome vocabulary ----------------------------------------------------

#: An independent tool reproduced the vulnerability ZAP reported.
CONFIRMED = "confirmed"
#: The tool ran to completion and could not reproduce it — the false-positive
#: verdict this layer exists to produce, and *not* the same as inconclusive.
REFUTED = "refuted"
#: The tool answered neither way: timeout, error, or the target refused the
#: probe. Never read as a clean bill of health.
INCONCLUSIVE = "inconclusive"
#: Selected for verification but never dispatched — a budget ran out first.
NOT_ATTEMPTED = "not-attempted"

OUTCOMES = (CONFIRMED, REFUTED, INCONCLUSIVE, NOT_ATTEMPTED)

#: Tools the dispatcher knows how to route to. Each has a thin stdio MCP wrapper
#: under ``mcp/``. ``none`` is what the LLM arm suggests for a finding
#: it judges needs no external tool; such findings are never dispatched.
DISPATCHABLE_TOOLS = frozenset({"nuclei", "sqlmap", "ffuf", "browser"})

#: What each wrapper can and cannot do, in the words the model is given (both LLM
#: stages are asked tool questions and must be told what the tools are). Orientation,
#: not documentation, and repeated in every call, so it is kept short; it describes the
#: fixed wrapper, and nuclei's ``tags`` are read from the pinned template set (a tag
#: outside it matches nothing and wastes the run). Each entry states limits as plainly
#: as abilities. → DECISIONS.md.
TOOL_CAPABILITIES: dict[str, dict[str, str]] = {
    "nuclei": {
        "tests": "Sends one HTTP probe per template from a pinned template set "
                 "and matches the response: reflected XSS, template injection, "
                 "open redirect, CRLF/header injection, known-CVE fingerprints, "
                 "and out-of-band interactions when OAST is armed.",
        "needs": "A URL. A query parameter to fuzz, if the finding is about "
                 "one. Nothing else — it carries its own payloads.",
        "ignores": "`param` and `method` are recorded but do nothing here: the "
                   "DAST templates decide which parameters and verbs to fuzz "
                   "from the template, not from you. Do not spend a round "
                   "setting them expecting the probe to change.",
        "tags": "OPTIONAL, and only these exist in the pinned DAST set: xss, "
                "ssti, sqli, rce, cmdi, lfi, xxe, ssrf, redirect, injection, "
                "csp-bypass, oast, oob, cve, vuln, dast. A tag outside this "
                "list matches NOTHING — nuclei then loads no templates, tests "
                "nothing, and the run is wasted. Leave tags empty to run the "
                "whole DAST set, which is usually right.",
        "cannot": "Cannot log in, cannot solve a CSRF form, and cannot reason "
                  "about application state. It decides by pattern, so an "
                  "application that answers 200 with an error page inside it "
                  "will not be distinguished from one that answers correctly.",
    },
    "sqlmap": {
        "tests": "Attempts real SQL injection against one named injection "
                 "point: boolean, error, time-based and UNION techniques, with "
                 "its own baseline comparison of the responses.",
        "needs": "A URL **and** an injection point it can address — a query or "
                 "form parameter by name, or a marked path segment. It fetches "
                 "a fresh CSRF token and replays the session cookie when the "
                 "target declares one.",
        "cannot": "Cannot test a parameter it cannot name. It qualifies its own "
                  "comparison when a page is unstable or reflective, and when "
                  "it does so its answer is INCONCLUSIVE, never a refutation.",
    },
    "ffuf": {
        "tests": "Replays one request many times over a wordlist and reports "
                 "which responses differ: path traversal, hidden files, "
                 "parameter and directory enumeration.",
        "needs": "A URL with a position to substitute into, and a wordlist the "
                 "wrapper supplies for traversal.",
        "ignores": "`method` is recorded but does nothing: this probe is GET-"
                   "only. Setting it will not change the request.",
        "cannot": "Cannot judge a response's meaning, only that it differs. It "
                  "will not find an injection that produces an identical-length "
                  "page, and it has no concept of a session.",
    },
    "browser": {
        "tests": "Whether a cross-site-scripting finding actually EXECUTES. It "
                 "injects breakout payloads that set a unique per-call marker "
                 "from JavaScript, loads the page in a real headless Chromium, "
                 "and confirms only if the rendered document's title equals "
                 "that marker — so a confirmation means script ran, not that a "
                 "payload was echoed back.",
        "needs": "A URL and the flagged parameter's name, which must be in the "
                 "query string. It replays a session cookie when one is given.",
        "cannot": "Cannot test a parameter that is not in the query string, and "
                  "cannot see an injection whose context none of its payloads "
                  "break out of. It says nothing about stored or DOM-only XSS "
                  "reached by a later interaction, because it loads one URL and "
                  "does not click.",
        "when": "PREFER THIS over nuclei for any XSS finding, and reach for it "
                "in particular when a string-matching probe reported nothing: "
                "output escaping can defeat a matcher without preventing "
                "execution, which is exactly how this pipeline once refuted a "
                "live XSS.",
    },
    "none": {
        "tests": "Nothing. Say `none` when no independent tool could settle "
                 "the finding — because the proof is already in the response "
                 "ZAP captured (a missing header), or because the question is "
                 "semantic (is this disclosed value sensitive?).",
        "needs": "-",
        "cannot": "-",
    },
}


def tool_capabilities(tools: "Iterable[str] | None" = None) -> dict[str, Any]:
    """The capability block a prompt carries, optionally narrowed to some tools."""
    names = list(tools) if tools else list(TOOL_CAPABILITIES)
    return {
        "note": "These are the ONLY tools this pipeline can dispatch, and this "
                "is what their wrappers actually do. Do not propose a tool or a "
                "capability that is not listed.",
        "how_you_invoke_them": {
            "you_set": PROBE_ARG_CONTRACT,
            "the_executor_sets": "everything else — the binary, the target URL "
                "(derived from the finding so a probe cannot be aimed elsewhere), "
                "authentication, the CSRF handshake, and the timeout. You direct "
                "HOW to look; you never choose WHERE.",
            "note": "Any other field you put in `arguments` is dropped before "
                "dispatch and recorded as rejected. These seven are the whole "
                "surface — a probe is these values, not a command line.",
        },
        "tools": {
            name: TOOL_CAPABILITIES[name]
            for name in names if name in TOOL_CAPABILITIES
        },
    }


# -- does the confirmation confirm the finding? ----------------------------

#: CWE ids grouped into the families a *tool* can distinguish. Deliberately
#: coarse: CWE is far more granular than any scanner's own classification, so
#: comparing raw ids would report a mismatch between two tools that plainly
#: agree (CWE-79 and CWE-80 are both reflected XSS). The families are the
#: resolution at which "did the confirming template belong to the flagged rule's
#: class?" is a meaningful question.
CWE_FAMILIES: dict[str, frozenset[int]] = {
    "xss": frozenset({79, 80, 83, 87, 116}),
    "sqli": frozenset({89, 564, 943}),
    "traversal": frozenset({22, 23, 35, 36, 98}),
    "redirect": frozenset({601}),
    "command-injection": frozenset({77, 78, 88, 917}),
    "injection": frozenset({74, 90, 91, 94, 95}),
    "crlf": frozenset({93, 113}),
    "ssrf": frozenset({918}),
    "format-string": frozenset({134}),
    "xxe": frozenset({611, 776}),
    "deserialization": frozenset({502}),
    "info-disclosure": frozenset({200, 209, 497, 532, 550, 598, 1295}),
    "headers": frozenset({693, 1021}),
    "cookies": frozenset({565, 614, 1004, 1275}),
}

#: ZAP rules whose class **only an execution oracle can settle**, listed by
#: plugin id because the question is about the rule, not about the CWE it
#: carries — ZAP attaches the catch-all CWE-20 to ``10031``, so
#: :func:`cwe_family` places it in no family at all.
#:
#: The 40026 result generalises to every one of them: a reflected payload can be
#: inert (an escaped context) and an altered payload can still execute
#: (WordPress slash-adds quotes, which broke nuclei's verbatim matcher on a bug
#: that is exploitable today). Reflection and execution are different questions,
#: and only ``browser`` asks the second one.
#:
#: Used by the *propagation* dispatch, which is free to override the tool a
#: synthesis claim asks for: the synthesis schema's ``suggested_tool`` enum has
#: no ``browser`` in it, so a model reasoning about a reflected-XSS claim can
#: only name a string matcher. ``rescan_table`` still owns the routing of
#: flagged findings, and ``10031`` is deliberately the one entry here that it
#: routes elsewhere — see the open question in ``DECISIONS.md``.
#: ``tests/unit/test_rescan_table.py`` pins the set against the table's own rule
#: names, so a new XSS rule cannot be added there and forgotten here.
XSS_RULES = frozenset({"10031", "40012", "40014", "40016", "40017", "40026"})

#: nuclei tags mapped onto the same families, used when a matched template
#: carries no CWE of its own — which many DAST fuzzing templates do not.
TAG_FAMILIES: dict[str, str] = {
    "xss": "xss", "rxss": "xss",
    "sqli": "sqli", "sql": "sqli", "error-sqli": "sqli", "blind-sqli": "sqli",
    "lfi": "traversal", "traversal": "traversal", "path-traversal": "traversal",
    "redirect": "redirect", "open-redirect": "redirect",
    "rce": "command-injection", "cmdi": "command-injection",
    "ssrf": "ssrf",
    "crlf": "crlf", "crlf-injection": "crlf",
    "xxe": "xxe",
    "ssti": "injection", "injection": "injection",
    "deserialization": "deserialization",
    # A cookie-injection template is about cookie handling, not generic
    # injection: map it to the `cookies` family so it AGREES with a cookie rule
    # (10029 / CWE-565) and is correctly a MISMATCH against an XSS rule (10031).
    # Without this it maps to `injection` only — mislabelling the true cookie
    # confirmation a mismatch while the false XSS one reads as unspecific.
    "cookie": "cookies", "cookie-injection": "cookies",
}

#: CWE ids too generic to place a finding in any family. CWE-20 (Improper Input
#: Validation) is the parent of most of the table above, and it is what ZAP
#: attaches to rule ``10031`` — so a confirmation of a ``10031`` finding can
#: neither agree nor disagree with it on class, and saying "mismatch" would be
#: as wrong as saying nothing.
UNSPECIFIC_CWES = frozenset({-1, 0, 16, 20, 693, 1173})

#: Both tools found something, in the same class.
CLASS_MATCH = "match"
#: Both found something, in *different* classes — the finding is not confirmed
#: as what it was reported to be, even though the parameter is evidently
#: reachable. A confirmation of this shape is downgraded to INCONCLUSIVE by the
#: verify records (the parameter is reachable; the reported class is not shown).
CLASS_MISMATCH = "mismatch"
#: The flagged rule's own CWE is a catch-all, so there is no class to agree on.
CLASS_UNSPECIFIC = "unspecific"
#: The confirming tool reported no classification at all.
CLASS_UNKNOWN = "unknown"

#: Single-class verification tools: the tool's own identity IS the class it can
#: confirm, so a match from one needs no per-template classification. nuclei is
#: absent on purpose — it runs a whole catalogue, so the class of ITS match must
#: be read from the template that matched, not assumed from the tool.
TOOL_CLASSES: dict[str, str] = {
    "sqlmap": "sqli",
    "ffuf": "traversal",
    "browser": "xss",
}

#: :mod:`dast_orchestrator.domain.evidence_class` rule classes mapped onto the
#: CWE-family vocabulary used here, so the authoritative per-rule class map can
#: name an alert's family when the alert's own CWE is a catch-all (CWE-20 on
#: ``10031``, say). ``other`` / ``identification`` have no injection family and
#: stay unplaceable (``None``).
_EVIDENCE_CLASS_FAMILY: dict[str, str] = {
    "xss": "xss",
    "sqli": "sqli",
    "traversal": "traversal",
    "redirect": "redirect",
    "cookie": "cookies",
    "header": "headers",
    "disclosure": "info-disclosure",
    "ssti": "injection",
    "injection": "injection",
}


def _rule_family(rule_id: str, alert_cwe: "int | str | None") -> str | None:
    """An alert's family from the authoritative per-rule class map, used only
    when the alert's own CWE could not place it. ``None`` for a rule the map
    leaves in ``other``/``identification``."""
    from dast_orchestrator.domain import evidence_class
    klass = evidence_class.rule_class(
        {"plugin_id": str(rule_id or ""), "cweid": alert_cwe})
    return _EVIDENCE_CLASS_FAMILY.get(klass)


#: Families that must agree when they meet. Command injection is a subtype of
#: injection, but the per-rule class map has one coarse ``injection`` class where
#: the CWE families split ``command-injection`` out — so a cmdi template
#: confirming an injection-classed rule (and the reverse) is a MATCH, not a
#: mismatch. Only injection is grouped; xss/sqli/traversal/etc. stay distinct.
_FAMILY_EQUIV: tuple[frozenset[str], ...] = (
    frozenset({"injection", "command-injection"}),
)


def _families_agree(alert_family: str, tool_families: "list[str]") -> bool:
    """Whether the alert's family is reproduced by any of the tool's, allowing
    the :data:`_FAMILY_EQUIV` groups to stand in for an exact string match."""
    if alert_family in tool_families:
        return True
    for group in _FAMILY_EQUIV:
        if alert_family in group and any(t in group for t in tool_families):
            return True
    return False


def cwe_family(cwe: "int | str | None") -> str | None:
    """The family a CWE id belongs to, or ``None`` if it is unspecific/unknown."""
    try:
        number = int(str(cwe).lower().removeprefix("cwe-"))
    except (TypeError, ValueError):
        return None
    if number in UNSPECIFIC_CWES:
        return None
    for family, members in CWE_FAMILIES.items():
        if number in members:
            return family
    return None


def classification_match(alert_cwe: "int | str | None",
                         matched_templates: "list[dict[str, Any]] | None",
                         rule_id: str = "",
                         tool: "str | None" = None,
                         ) -> dict[str, Any]:
    """Whether a confirming tool's match belongs to the flagged rule's class.

    A confirmation says *a tool reproduced something here*. It does not, on its
    own, say the tool reproduced **the reported vulnerability** — and the two
    were being conflated. The case that named the defect is a nuclei
    ``cookie-injection`` match standing against ZAP rule ``10031``, *potential
    XSS*: both tools agree the parameter is attacker-controlled and they disagree
    about what that lets an attacker do, and nothing noticed.

    The result is **acted on** (rebuilt 2026-10-26): a ``mismatch`` downgrades
    the confirmation to :data:`INCONCLUSIVE` — the parameter is reachable, but
    the *reported* class was not reproduced, so a ``confirmed`` overstates what
    the tool showed. Downgrading rather than refuting keeps the four-state
    vocabulary and the real signal (the parameter is injectable), and the tool's
    own reading is kept beside it in ``wrapper_verdict``. The downgrade lives in
    the caller (:func:`...stages.verify.records._class_check`); this function
    only classifies.

    :param alert_cwe: the ZAP rule's CWE id, as recorded on the alert.
    :param matched_templates: what the tool reported matching, each with its
        ``cwe`` list and ``tags`` (see the nuclei wrapper).
    :param rule_id: the ZAP plugin id, when known. A rule in :data:`XSS_RULES`
        is XSS by class even though ZAP attaches the catch-all CWE-20 to it
        (notably ``10031``), which :func:`cwe_family` cannot place — so for those
        the rule id, not the CWE, decides the alert's class. For any other rule
        whose CWE is a catch-all, the authoritative per-rule class map
        (:func:`_rule_family`) is consulted before giving up as ``unspecific``.
    :param tool: the tool that reported the match. A single-class tool
        (:data:`TOOL_CLASSES` — sqlmap/ffuf/browser) supplies its own class, since
        it carries no per-match template; ``None`` or ``nuclei`` reads the class
        off ``matched_templates``.
    :returns: ``{"class": <one of the CLASS_* values>, "detail": str,
        "alert_family": str|None, "tool_families": [str]}``
    """
    alert_family = cwe_family(alert_cwe)
    # ZAP attaches the catch-all CWE-20 to some XSS rules (notably 10031), so
    # cwe_family cannot place them — but the rule id can: an XSS rule's class is
    # xss regardless of the CWE recorded on the alert.
    if rule_id and str(rule_id) in XSS_RULES:
        alert_family = "xss"
    if alert_family is None and rule_id:
        # The rule's own CWE still could not place it; the authoritative per-rule
        # class map can for any rule the project has classified, which is what
        # closes the "unspecific" hole rather than leaving it a silent pass.
        alert_family = _rule_family(rule_id, alert_cwe)
    if tool in TOOL_CLASSES:
        # A single-class tool IS its class: it carries no per-match template, so
        # reading its class off `matched_templates` would make it "unknown" and
        # sink every sqlmap/ffuf/browser confirmation under the gate below.
        tool_families: list[str] = [TOOL_CLASSES[tool]]
    else:
        tool_families = []
        for template in matched_templates or []:
            for cwe in template.get("cwe") or []:
                family = cwe_family(cwe)
                if family and family not in tool_families:
                    tool_families.append(family)
            for tag in template.get("tags") or []:
                family = TAG_FAMILIES.get(str(tag).lower())
                if family and family not in tool_families:
                    tool_families.append(family)

    if alert_family is None:
        state, detail = CLASS_UNSPECIFIC, (
            f"the flagged rule's CWE ({alert_cwe}) is a catch-all, so the "
            "confirming template cannot be said to agree or disagree with it on "
            "class"
            + (f"; the tool matched {', '.join(tool_families)}"
               if tool_families else "")
        )
    elif not tool_families:
        state, detail = CLASS_UNKNOWN, (
            "the confirming template carries no CWE or recognised tag, so its "
            f"class could not be compared with the rule's ({alert_family})"
        )
    elif _families_agree(alert_family, tool_families):
        state, detail = CLASS_MATCH, (
            f"the confirming template is in the flagged rule's class ({alert_family})"
        )
    else:
        state, detail = CLASS_MISMATCH, (
            f"the flagged rule is {alert_family} but the confirming template is "
            f"{', '.join(tool_families)} — the parameter is reachable, but this "
            "is not a confirmation of the reported vulnerability class"
        )
    return {"class": state, "detail": detail, "alert_family": alert_family,
            "tool_families": tool_families}


def class_gate(reported: str, alert_cwe: "int | str | None",
               matched_templates: "list[dict[str, Any]] | None",
               rule_id: str = "", tool: "str | None" = None
               ) -> "tuple[str, dict[str, Any]]":
    """Gate a ``confirmed`` on class agreement — the precondition, not an afterthought.

    A tool match confirms *this finding* only when the match is in the flagged
    rule's class. Every other state is **not** a confirmation of the reported
    vulnerability and is downgraded to :data:`INCONCLUSIVE`: a different class
    (:data:`CLASS_MISMATCH`), a match too unclassifiable to compare
    (:data:`CLASS_UNKNOWN`), or a rule whose own class cannot be named
    (:data:`CLASS_UNSPECIFIC`). This inverts the old revoke-only-on-nameable-
    mismatch logic — confirmation now REQUIRES a positive in-class match, which
    is what closes the unknown/unspecific holes — while the tool's own reading
    is kept by the caller in ``wrapper_verdict``, so the move is a countable gate
    rather than a lost signal. A non-``confirmed`` verdict passes through
    untouched: there is nothing to cross-check about a refutation.

    :returns: ``(reported, extra)`` — the gated outcome and the fields to record:
        always ``classification`` on a confirmation, plus
        ``outcome_downgraded_from`` when the gate moved it.
    """
    if reported != CONFIRMED:
        return reported, {}
    check = classification_match(alert_cwe, matched_templates,
                                 rule_id=rule_id, tool=tool)
    extra: dict[str, Any] = {"classification": check}
    if check["class"] != CLASS_MATCH:
        extra["outcome_downgraded_from"] = CONFIRMED
        return INCONCLUSIVE, extra
    return CONFIRMED, extra


#: The same seven, described for the model — the prompt half of
#: :data:`ALLOWED_PROBE_ARGS`. A test asserts the two enumerate the same keys,
#: so a new lever cannot be added to one without describing it in the other. The
#: model said, in its own notes, "I need to include the full original POST body
#: so sqlmap can locate and test" — it has `data` for exactly that and was never
#: told the field was its to set.
PROBE_ARG_CONTRACT = {
    "param": "the parameter to attack; omit to keep the one ZAP flagged",
    "method": "the HTTP method; omit to keep the exchange's own",
    "data": "the request body, as `a=1&b=2`. Set this to give sqlmap the form "
            "fields it must post — the exchange above shows the body ZAP sent",
    "tags": "nuclei only: template tags to narrow the run; see that tool's "
            "`tags` list — a tag outside it matches nothing",
    "level": "sqlmap only: breadth 1-5",
    "risk": "sqlmap only: risk 1-3",
    "path_injection": "true when the injectable position is a URL path segment "
                      "rather than a named parameter; the executor marks the "
                      "segment for sqlmap and you leave `param` empty",
}
