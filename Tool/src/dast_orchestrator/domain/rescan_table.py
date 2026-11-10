"""The control arm: pure data plus a pure function, no model — the LLM triage pass must
beat this baseline, so it stays simple enough to state as one table.

It answers not "is this a true positive?" but *would an independent tool change what we
know?*, splitting ZAP's rules three ways: self-evident passive (ZAP holds the proof) →
NEVER, heuristic passive (a job for the LLM arm) → NEVER with the reason recorded, and
active-injection → ALWAYS or ``WHEN_UNCERTAIN``. Confidence is the second key: a rule at
High may carry a proof, at Medium be the false positive this layer settles.
→ DECISIONS.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

RESCAN_TABLE_VERSION = 3

#: The ZAP confidences an independent tool can still move. ``False Positive`` and
#: ``Confirmed`` are only ever set by a human in the desktop UI, and ``High`` is
#: already ZAP's strongest automated claim — so only ``Low``/``Medium`` are worth
#: a rescan.
UNCERTAIN_CONFIDENCES = frozenset({"Low", "Medium"})


class RescanPolicy(str, Enum):
    """What the table says about a rule, independent of a single alert."""

    ALWAYS = "always"
    """An independent tool can settle it and ZAP's own confidence is not enough."""

    WHEN_UNCERTAIN = "when_uncertain"
    """Verifiable, but skip it when ZAP already reports High/Confirmed."""

    NEVER = "never"
    """Either self-evident from the response, or not decidable by any scanner."""


@dataclass(frozen=True)
class RuleEntry:
    """One row of the table. `rationale` is quoted directly in the writeup."""

    plugin_id: str
    name: str
    policy: RescanPolicy
    rationale: str
    #: Verification tool Phase 4 would dispatch. Recorded now so the control arm
    #: already produces the routing decision, even though nothing dispatches yet.
    tool: str | None = None


@dataclass(frozen=True)
class RescanDecision:
    """The per-alert outcome, carried into the correlation artifact."""

    needs_rescan: bool
    reason: str
    policy: RescanPolicy
    plugin_id: str
    confidence: str
    tool: str | None = None
    in_table: bool = True


# -- the table -------------------------------------------------------------

#: Seeded from the rules that actually fired against Gitea 1.16.0, plus the
#: rules the documented CVE cluster says *should* fire once the active scanner
#: reaches the right routes. The latter say "not yet observed" in their
#: rationale: they are predictions from ground truth, not observations, and the
#: writeup must not blur the two.
RULES: dict[str, RuleEntry] = {
    # --- observed in the Phase 2 runs -------------------------------------
    "40018": RuleEntry(
        "40018", "SQL Injection", RescanPolicy.ALWAYS,
        "Inferred from response differences, which is exactly the inference an "
        "independent exploit attempt can confirm or refute. Both Phase 2 hits "
        "landed on /user/login at Medium confidence — the canonical case this "
        "verification layer exists to settle.",
        tool="sqlmap",
    ),
    "10031": RuleEntry(
        "10031", "User Controllable HTML Element Attribute (Potential XSS)",
        RescanPolicy.ALWAYS,
        "Explicitly a *potential* finding: ZAP reports that input reaches an "
        "attribute, not that it breaks out of one. 348 hits in the Phase 2 run "
        "make it the single largest triage burden, and an XSS payload probe "
        "answers it directly. Kept on nuclei rather than moved to the `browser` "
        "execution oracle with the other XSS rules — measured 2026-09-08, see "
        "DECISIONS.md \u00a7\"\u00a7N3\".",
        tool="nuclei",
    ),
    "90022": RuleEntry(
        "90022", "Application Error Disclosure", RescanPolicy.NEVER,
        "Pattern match over the response body. The stack trace is either in the "
        "response ZAP already captured or it is not; a second tool re-reads the "
        "same bytes.",
    ),
    "10023": RuleEntry(
        "10023", "Information Disclosure - Debug Error Messages",
        RescanPolicy.NEVER,
        "Same evidence class as 90022: the proof is the captured response.",
    ),
    "10096": RuleEntry(
        "10096", "Timestamp Disclosure - Unix", RescanPolicy.NEVER,
        "Notoriously noisy — any 10-digit number matches, and Gitea's pages are "
        "full of commit metadata. Noisy is not the same as verifiable: no "
        "scanner can decide whether a number is a timestamp that matters. This "
        "is left to the LLM arm on purpose, and the gap is a result, not a bug.",
    ),
    "10038": RuleEntry(
        "10038", "Content Security Policy (CSP) Header Not Set",
        RescanPolicy.NEVER,
        "Header presence check; deterministic and already proven by the "
        "response.",
    ),
    "10021": RuleEntry(
        "10021", "X-Content-Type-Options Header Missing", RescanPolicy.NEVER,
        "Header presence check, already proven by the captured response. 114 "
        "hits in the Phase 2 run, none of which any tool could usefully "
        "re-examine.",
    ),
    "10010": RuleEntry(
        "10010", "Cookie No HttpOnly Flag", RescanPolicy.NEVER,
        "Attribute check over a Set-Cookie header ZAP already holds; the "
        "flag is either there or it is not, so verification adds nothing.",
    ),
    "10054": RuleEntry(
        "10054", "Cookie without SameSite Attribute", RescanPolicy.NEVER,
        "Same evidence class as 10010: a Set-Cookie attribute check answered "
        "by the response already captured.",
    ),
    "10029": RuleEntry(
        "10029", "Cookie Poisoning", RescanPolicy.NEVER,
        "Informational: reports that a parameter name collides with a cookie "
        "name. Nothing to exploit and nothing for a tool to confirm.",
    ),
    "10024": RuleEntry(
        "10024", "Information Disclosure - Sensitive Information in URL",
        RescanPolicy.NEVER,
        "Whether a URL parameter is sensitive is a semantic judgement about the "
        "application, not an observation a scanner can repeat.",
    ),
    "10109": RuleEntry(
        "10109", "Modern Web Application", RescanPolicy.NEVER,
        "Purely descriptive: tells the operator the site uses JavaScript "
        "navigation. Not a vulnerability.",
    ),
    "10111": RuleEntry(
        "10111", "Authentication Request Identified", RescanPolicy.NEVER,
        "Identification aid for ZAP's own auth handling, not a finding.",
    ),
    "10112": RuleEntry(
        "10112", "Session Management Response Identified", RescanPolicy.NEVER,
        "Identification aid, not a finding. 783 hits in the Phase 2 run — the "
        "bulk of the alert count, and none of it is triage work.",
    ),

    "10104": RuleEntry(
        "10104", "User Agent Fuzzer", RescanPolicy.NEVER,
        "Replays each request under a set of User-Agent strings and reports any "
        "response difference. Not a vulnerability rule at all, and it dominates "
        "an active scan by volume: 4931 of the 4939 active-scanner alerts in "
        "the 60-minute run, across 366 URLs. Quote the active/passive split "
        "only alongside this number, or the scan looks far more productive "
        "than it was.",
    ),
    "10058": RuleEntry(
        "10058", "GET for POST", RescanPolicy.NEVER,
        "Reports that an endpoint served a GET where the application declared "
        "POST. Deterministic from the response pair ZAP already holds; whether "
        "it matters is a semantic question about the handler, which is the LLM "
        "arm's job.",
    ),
    "30002": RuleEntry(
        "30002", "Format String Error", RescanPolicy.WHEN_UNCERTAIN,
        "Active-scanner finding inferred from how the application responded to "
        "format specifiers, so an independent probe can retest it. Fired once "
        "in the 60-minute run, on an /api/ route Noir cannot see — the "
        "verification layer is the only thing that could settle it.",
        tool="nuclei",
    ),

    "90035": RuleEntry(
        "90035", "Server Side Template Injection", RescanPolicy.ALWAYS,
        "Fired High risk / High confidence on the `labels` query parameter, and "
        "the table had NO ROW FOR IT until 2026-08-28 — so the highest-severity "
        "finding in the corpus was silently unflagged and dispatched to nothing. "
        "It was found because the LLM arm flagged it in all six runs of sheet 5: "
        "the entire `llm-only` column, across every run this project has "
        "recorded, is essentially this rule. That is what an `llm-only` count of "
        "1-3 was actually made of — not noise, and not per-finding judgement "
        "either, but coverage of a rule nobody had enumerated. "
        "Always escalate: the payload `{{print \"a\" \"b\"}}` is Go "
        "text/template syntax against a Go application, so it is the right "
        "language for this target rather than a scanner firing a Jinja2 payload "
        "at something that could never evaluate it, and template injection is "
        "code execution if it evaluates.",
        tool="nuclei",
    ),

    # --- predicted by the Gitea 1.16.0 CVE cluster, not yet observed -------
    "20019": RuleEntry(
        "20019", "External Redirect", RescanPolicy.ALWAYS,
        "Not yet observed. Maps onto the CVE-2022-1058 open-redirect family "
        "fixed in Gitea 1.16.5; a redirect either lands off-host or it does "
        "not, so an independent request settles it.",
        tool="nuclei",
    ),
    "6": RuleEntry(
        "6", "Path Traversal", RescanPolicy.ALWAYS,
        "Not yet observed. Maps onto the Storage path-cleaning fix in 1.16.5; "
        "an independent fetch of a traversed path is decisive.",
        tool="ffuf",
    ),
    "40012": RuleEntry(
        "40012", "Cross Site Scripting (Reflected)", RescanPolicy.ALWAYS,
        "The rule this project's central verification result is about, so its "
        "row changed with that result on 2026-09-04. It was WHEN_UNCERTAIN with "
        "nuclei, reasoning that at High confidence ZAP has already echoed its "
        "own payload back out of context and a rescan adds nothing. Both halves "
        "of that are now wrong. "
        "\n\n"
        "Echoing a payload back is a REFLECTION oracle, and the whole lesson of "
        "the 40026 case is that reflection and execution are different "
        "questions: a payload can be reflected and inert (an escaped context), "
        "or altered in transit and still execute (WordPress slash-adds quotes, "
        "which broke nuclei's verbatim matcher on a bug that is exploitable "
        "today). So High confidence from a reflection-based rule is exactly "
        "when an execution oracle earns its page load, not when it stops being "
        "needed. ALWAYS, and `browser`.",
        tool="browser",
    ),
    "40026": RuleEntry(
        "40026", "Cross Site Scripting (DOM Based)", RescanPolicy.ALWAYS,
        "Fired High risk / High confidence from the ACTIVE scanner on `frameid` "
        "at the exact sink of the `wpdm-frameid-reflected-xss` marker on the "
        "2026-09-04 WordPress baseline, and the table had no row for it — so "
        "the one ground-truth-confirmed detection this project has produced was "
        "escalated on risk alone and dispatched to nothing. "
        "\n\n"
        "This row has been written three times in one day and the history is "
        "the point. ALWAYS/nuclei first, on the argument that independent "
        "corroboration is this stage's value; that dispatch REFUTED a "
        "vulnerability that is live, because nuclei's matcher wants its payload "
        "back verbatim and WordPress's slash-adding alters it. Then NEVER, on "
        "the reasoning that no tool here could settle the class. Then this: the "
        "premise of NEVER was wrong, because a tool that CAN settle it now "
        "exists. `browser` injects breakout payloads that set a unique marker "
        "from JavaScript and confirms only when the rendered title equals it — "
        "an EXECUTION oracle, the same class ZAP used to find this. It confirms "
        "the marker on the first payload and refutes both controls. "
        "\n\n"
        "ALWAYS because the probe is decisive either way and costs one page "
        "load: script either runs or it does not.",
        tool="browser",
    ),
    "40003": RuleEntry(
        "40003", "CRLF Injection", RescanPolicy.ALWAYS,
        "Header-splitting evidence is unambiguous at High confidence, which is "
        "why this was WHEN_UNCERTAIN until 2026-09-04. It is now ALWAYS for a "
        "reason that has nothing to do with the rule's evidence: it is named by "
        "Gitea's `csrf-token-validation` marker, and `ground_truth` reads the "
        "`+deterministic triage` layer off `needs_rescan`. A WHEN_UNCERTAIN "
        "marker rule meeting a High-confidence alert therefore reports the "
        "marker as UNDETECTED at that layer — the scan found it and the table "
        "declined to look, which reads like a triage failure. A marker rule "
        "must not skip; one probe is the cheaper mistake.",
        tool="nuclei",
    ),
    # --- ground-truth marker rules ------------------------------------------
    #
    # Every rule named in a target's `cve-markers.yml` MUST live here and MUST
    # route to a tool. The reason is a silent interaction rather than a dispatch
    # one: `ground_truth.assess_marker` reads the
    # `+deterministic triage` layer off `deterministic.needs_rescan`, so a
    # marker rule the table declines — by NEVER, or by WHEN_UNCERTAIN meeting a
    # High-confidence alert — makes that layer report the marker as UNDETECTED.
    # The scan found it, the table shrugged, and the detection table reads like
    # a triage failure. `tests/unit/test_rescan_table.py` pins this.

    "10028": RuleEntry(
        "10028", "Open Redirect", RescanPolicy.ALWAYS,
        "The second rule on Gitea's `open-redirect-login` marker, beside 20019, "
        "and unenumerated until 2026-09-04. Same class and same probe as 20019: "
        "a redirect either lands off-host or it does not, so one independent "
        "request settles it.",
        tool="nuclei",
    ),
    "40014": RuleEntry(
        "40014", "Cross Site Scripting (Persistent)", RescanPolicy.ALWAYS,
        "Named by five WordPress markers and one Gitea marker, and unenumerated "
        "until 2026-09-04. "
        "\n\n"
        "Routed to `browser` with a caveat that must travel with every verdict "
        "it produces: that probe injects at a query parameter and loads one "
        "URL, so it cannot perform the store-then-view flow persistent XSS "
        "actually needs. A refutation here therefore means less than a "
        "refutation on 40012. It is routed anyway rather than left NEVER "
        "because NEVER would drop these markers out of the deterministic "
        "detection layer silently, and a weak verdict that says so beats an "
        "invisible one. The honest fix is a probe mode that loads the flagged "
        "URL unmodified and asks whether the STORED payload executes.",
        tool="browser",
    ),
    "40016": RuleEntry(
        "40016", "Cross Site Scripting (Persistent) - Prime", RescanPolicy.ALWAYS,
        "The injection half of ZAP's persistent-XSS pair: this is where the "
        "payload is stored, 40017 is where it comes back. Same routing and the "
        "same caveat as 40014.",
        tool="browser",
    ),
    "40017": RuleEntry(
        "40017", "Cross Site Scripting (Persistent) - Spider", RescanPolicy.ALWAYS,
        "The retrieval half of the persistent-XSS pair, and named by four "
        "WordPress markers. Same routing and the same caveat as 40014.",
        tool="browser",
    ),
    "40019": RuleEntry(
        "40019", "SQL Injection - MySQL", RescanPolicy.ALWAYS,
        "One of the four engine-specific SQL-injection rules named by the "
        "WordPress SQLi markers beside the generic 40018, and unenumerated "
        "until 2026-09-04. MySQL is what this target actually runs, so this is "
        "the rule most likely to fire on the `package_ids` marker. sqlmap, for "
        "the same reason 40018 goes there: it attempts the injection for real.",
        tool="sqlmap",
    ),
    "40020": RuleEntry(
        "40020", "SQL Injection - Hypersonic SQL", RescanPolicy.ALWAYS,
        "Engine-specific SQLi, named by the WordPress SQLi markers. Routed like "
        "40018 — the engine in the rule name is ZAP's guess at the backend, not "
        "a fact, and sqlmap determines that itself.",
        tool="sqlmap",
    ),
    "40021": RuleEntry(
        "40021", "SQL Injection - Oracle", RescanPolicy.ALWAYS,
        "Engine-specific SQLi, named by the WordPress SQLi markers. Routed like "
        "40018.",
        tool="sqlmap",
    ),
    "40024": RuleEntry(
        "40024", "SQL Injection - SQLite", RescanPolicy.ALWAYS,
        "Engine-specific SQLi, named by the WordPress SQLi markers. Routed like "
        "40018.",
        tool="sqlmap",
    ),
    "90020": RuleEntry(
        "90020", "Remote OS Command Injection", RescanPolicy.ALWAYS,
        "The second rule on Gitea's `csrf-token-validation` marker (CWE-88, the "
        "argument injection into `git fetch` escaped in 1.16.7), and "
        "unenumerated until 2026-09-04. Command execution is the most severe "
        "class this pipeline can encounter and an independent probe is cheap "
        "against that, so ALWAYS regardless of confidence.",
        tool="nuclei",
    ),
    "90037": RuleEntry(
        "90037", "Remote OS Command Injection (Time Based)", RescanPolicy.ALWAYS,
        "The time-based variant of 90020, named by Cacti's "
        "`cacti-remote-agent-cmd-injection` marker (CVE-2022-46169). It is the "
        "rule that actually fires on the oracle-seeded `remote_agent.php` sink: "
        "ZAP confirms the blind injection by the server controlling the response "
        "timing (`poller_id=1;sleep 15;`). Same class and severity as 90020, so "
        "ALWAYS/nuclei for the same reason.",
        tool="nuclei",
    ),

    # --- noise the table had never judged -----------------------------------
    #
    # All four are passive (`sourceid=3`) findings about headers and page
    # configuration. Unenumerated, they escalate on risk alone through
    # `UNKNOWN_RULE_POLICY`, which flags for a rescan and names no tool — the bulk
    # of the unroutable flags on a passive-heavy target.
    # NEVER for the same reason 10021 and 10038 are: the proof is already in the
    # response ZAP captured, no external tool adds anything, and the judgement
    # about whether it matters belongs to the LLM arm.
    #
    # Checked before writing: none of them is named by any target's
    # `cve-markers.yml`, so no detection layer moves. That check is a test.

    "10020": RuleEntry(
        "10020", "Missing Anti-clickjacking Header", RescanPolicy.NEVER,
        "Passive, and decided entirely by whether a response header is present "
        "— which ZAP has already read. There is nothing for a second tool to "
        "reproduce, and whether a given page needs framing protection is a "
        "judgement about the application, not a probe.",
    ),
    "10037": RuleEntry(
        "10037", "Server Leaks Information via X-Powered-By", RescanPolicy.NEVER,
        "Passive information disclosure, and the single largest source of "
        "unroutable flags measured on the 2026-09-04 WordPress baseline: 118 of "
        "199. The header is either in the response or it is not; no external "
        "tool adjudicates that, and its severity is a context judgement.",
    ),
    "90003": RuleEntry(
        "90003", "Sub Resource Integrity Attribute Missing", RescanPolicy.NEVER,
        "Passive, and a statement about markup ZAP already has: a script tag "
        "either carries an `integrity` attribute or it does not. No probe adds "
        "evidence.",
    ),
    "10106": RuleEntry(
        "10106", "HTTP Only Site", RescanPolicy.NEVER,
        "Passive, and true by construction of this test environment — the "
        "targets are deliberately served over plain HTTP on loopback. Nothing "
        "to verify, and nothing a probe could say that the deployment does not "
        "already state.",
    ),
    "30001": RuleEntry(
        "30001", "Buffer Overflow", RescanPolicy.NEVER,
        "The one of this group that is NOT passive — `sourceid=1`, so the "
        "active scanner really did send a long string and watch the response, "
        "and 35 findings on the 2026-09-04 WordPress baseline came that way. "
        "It is still NEVER, and the distinction is worth the words: the rule "
        "concludes from a 500 or a dropped connection after an overlong value, "
        "which in PHP behind Apache means the application raised an error, not "
        "that memory was corrupted. None of the four tools here can test for "
        "memory corruption over HTTP — nuclei has no template class for it and "
        "the `injection` tag is the guess that produced class-miss refutations "
        "on 30002 — so a dispatch would spend budget to learn nothing. Whether "
        "the 500 itself matters is a question about the handler, which is the "
        "LLM arm's job given the source. Revisit if a target ever runs a "
        "memory-unsafe backend.",
    ),

    "10202": RuleEntry(
        "10202", "Absence of Anti-CSRF Tokens", RescanPolicy.NEVER,
        "Not yet observed here. Related to the 1.16.7 CSRF-validation bug, but "
        "the rule only checks whether a token field exists in the form — a "
        "deterministic parse. Whether the token is actually *validated* is the "
        "interesting question and no scanner answers it; that is squarely the "
        "LLM arm's job, given the handler source.",
    ),

    "2": RuleEntry(
        "2", "Private IP Disclosure", RescanPolicy.NEVER,
        "Fired on the first Grafana baseline (2026-09-11) and was unenumerated, "
        "so it flagged with no tool. Passive information disclosure: a private "
        "IP (10.x/192.168.x/…) is either in the response ZAP already captured or "
        "it is not, so no external tool re-reads it to any effect, and whether a "
        "disclosed internal address actually matters is a judgement about the "
        "deployment — the LLM arm's job, not a probe's. Same evidence class as "
        "10037 (X-Powered-By) and 10024 (sensitive info in URL). NEVER.",
    ),

    # --- SCA-class, belongs to the crosscheck not to DAST verification -------
    "10003": RuleEntry(
        "10003", "Vulnerable JS Library", RescanPolicy.NEVER,
        "Fired High on the first Grafana baseline (2026-09-11) on a "
        "/public/build/*.js bundle, and neither earlier target ever raised it — "
        "Grafana is the target the NEXT_SESSION note predicted would. It is the "
        "one High-risk passive rule that is NEVER, and the reason is what makes "
        "it interesting rather than noise. 10003 is a VERSION match: ZAP "
        "fingerprints a bundled JS library and compares its version to a "
        "known-vulnerable list. No DAST tool here can adjudicate 'library X at "
        "version Y is vulnerable' — that is a fact about a dependency, not about "
        "a request/response, and settling it is exactly OSV-Scanner's job (the "
        "SCA baseline). So this rule is not dispatched to sqlmap/nuclei/ffuf/"
        "browser; it is the live input to the SCA↔DAST join (§T4), where OSV "
        "flagging the same component IS the cross-tool confirmation. Routing it "
        "to a DAST prober would spend budget to learn nothing and, worse, a "
        "refutation there would read as 'not vulnerable' when the prober simply "
        "cannot see the question. NEVER, tool none, by design.",
    ),
}

# Policy for a plugin ID the table does not know. Stated as data, not buried in
# a branch, because "what happens to a rule nobody classified" is a question the
# evaluation has to answer for any target beyond Gitea.
#
# Erring toward rescan on an unknown *active* finding would be the safer
# security posture but the worse CI posture (unbounded verification cost from an
# unclassified rule). The compromise: rescan unknown rules only when they are
# both non-informational and not already High confidence.
UNKNOWN_RULE_POLICY = RescanPolicy.WHEN_UNCERTAIN
NON_RESCANNABLE_RISKS = frozenset({"Informational"})

#: Risks at which an *unenumerated* rule escalates regardless of confidence.
#: Not a severity threshold for the table's own rules — those carry a judged
#: policy each. This is the fallback for the case the table cannot speak to.
ESCALATE_UNKNOWN_RISKS = frozenset({"High", "Medium"})


def _confidence_of(alert: dict[str, Any]) -> str:
    return str(alert.get("confidence") or "").strip() or "Low"


def decide(alert: dict[str, Any]) -> RescanDecision:
    """Classify one raw ZAP alert dict. Deterministic; no I/O, no model."""
    plugin_id = str(alert.get("pluginId") or "").strip()
    confidence = _confidence_of(alert)
    risk = str(alert.get("risk") or "").strip()
    entry = RULES.get(plugin_id)

    if entry is None:
        if risk in NON_RESCANNABLE_RISKS:
            return RescanDecision(
                False,
                f"plugin {plugin_id or '?'} not in the table and Informational: "
                "not worth verification budget",
                UNKNOWN_RULE_POLICY, plugin_id, confidence, in_table=False,
            )
        # An unenumerated rule at real risk always escalates, WHATEVER ZAP's
        # confidence. Deferring to high confidence is a judgement the table makes
        # per rule and justifies per rule ("at High confidence ZAP has already
        # echoed its own payload back out of context, so a rescan adds nothing"),
        # and that justification does not exist for a rule nobody has assessed.
        # Applied to unknown rules it inverts: the more confident the scanner is
        # about something never judged, the less it gets verified.
        #
        # This is not hypothetical. Rule 90035 (Server Side Template Injection)
        # was once absent from the table and fired at High risk AND High
        # confidence — the corpus's single most severe finding. It took this
        # branch, was told "accept as reported", and was never dispatched. It was
        # found only because the LLM arm flagged it in every
        # run, which is the whole of what that arm's `llm-only` column ever was.
        if risk in ESCALATE_UNKNOWN_RISKS:
            return RescanDecision(
                True,
                f"plugin {plugin_id or '?'} is NOT in the table and reports "
                f"{risk} risk. No rule-specific judgement exists for it, so "
                f"ZAP's {confidence} confidence is not a reason to skip "
                "verification -- escalating on risk alone.",
                UNKNOWN_RULE_POLICY, plugin_id, confidence, in_table=False,
            )
        uncertain = confidence in UNCERTAIN_CONFIDENCES
        return RescanDecision(
            uncertain,
            f"plugin {plugin_id or '?'} not in the table; {risk or 'unknown'} risk at "
            f"{confidence} confidence -> {'rescan' if uncertain else 'accept as reported'}",
            UNKNOWN_RULE_POLICY, plugin_id, confidence, in_table=False,
        )

    if entry.policy is RescanPolicy.NEVER:
        return RescanDecision(
            False, entry.rationale, entry.policy, plugin_id, confidence, entry.tool
        )
    if entry.policy is RescanPolicy.ALWAYS:
        return RescanDecision(
            True, entry.rationale, entry.policy, plugin_id, confidence, entry.tool
        )

    uncertain = confidence in UNCERTAIN_CONFIDENCES
    reason = entry.rationale if uncertain else (
        f"{entry.name}: ZAP already reports {confidence} confidence, so an "
        "independent rescan would not change the verdict"
    )
    return RescanDecision(
        uncertain, reason, entry.policy, plugin_id, confidence, entry.tool
    )


def needs_rescan(alert: dict[str, Any]) -> bool:
    """The one-bit form of `decide`, as specified for the control arm."""
    return decide(alert).needs_rescan


def table_as_rows() -> list[dict[str, str]]:
    """The table in a form the report (and the thesis appendix) can render."""
    return [
        {
            "plugin_id": entry.plugin_id,
            "name": entry.name,
            "policy": entry.policy.value,
            "tool": entry.tool or "",
            "rationale": entry.rationale,
        }
        for entry in sorted(RULES.values(), key=lambda e: int(e.plugin_id))
    ]
