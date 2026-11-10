"""What to probe and how the result is bucketed: the dispatch budget and finding selection
(which tool, how many), and the final four-way disposition a reader acts on.

Part of the ``verification`` package (with ``outcomes`` and ``loop``); the package
``__init__`` re-exports every name, so ``verification.X`` is unchanged.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Iterable
from dast_orchestrator.domain import evidence_class
from dast_orchestrator.domain.verification.loop import NA_NO_TOOL
from dast_orchestrator.domain.verification.outcomes import *  # shared vocabulary  # noqa: F401,F403




# -- dispatch budget -------------------------------------------------------


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


#: A ceiling set to this is not enforced at all — **-1, not 0**.
#:
#: The distinction is load-bearing now that a cap can be set per rule: ``0`` has
#: to keep its arithmetic meaning, so ``--max-dispatch-rule 10031=0`` reads as
#: "never dispatch 10031" and not as "dispatch it without limit". A single
#: sentinel that meant both would make the most useful per-rule setting the one
#: you cannot express.
#:
#: Every cap defaults to a real number and should stay that way — an unbounded
#: verification stage is what this class exists to prevent. The sentinel is here so
#: the *opposite* run is expressible and measurable, since coverage on this workload
#: is set by the caps rather than by the tools or the clock.
NO_CAP = -1


def parse_rule_caps(assignments: "Iterable[str]") -> dict[str, int]:
    """Parse repeated ``--max-dispatch-rule ID=N`` arguments (and the env list).

    ``ID=N`` rather than two positional words, to match the shape this codebase
    already uses for repeatable key/value flags (``scan --path-var NAME=VALUE``,
    parsed by :func:`dast_orchestrator.adapters.noir_runner.parse_path_vars`). The env
    form is the same assignments comma-separated, so a harness sheet and a
    command line say the same thing the same way.

    :raises ValueError: on anything that is not ``ID=<integer>``. A malformed
        cap silently ignored would run the whole stage at a budget nobody chose.
    """
    caps: dict[str, int] = {}
    for assignment in assignments:
        for item in str(assignment).split(","):
            item = item.strip()
            if not item:
                continue
            rule, sep, raw = item.partition("=")
            rule = rule.strip()
            if not sep or not rule:
                raise ValueError(
                    f"--max-dispatch-rule expects ID=N, got {item!r}")
            try:
                caps[rule] = int(raw)
            except ValueError:
                raise ValueError(
                    f"--max-dispatch-rule cap for {rule!r} is not an "
                    f"integer: {raw!r}") from None
    return caps


@dataclass(frozen=True)
class DispatchBudget:
    """Every ceiling a verification run is bound by, resolved from the env.

    Defaults are sized for the Gitea Phase 2/3 workload — 31 findings in the
    union of both arms — with headroom, not for an adversarial run. The
    ``10031``-fires-348-times case is exactly what the per-rule caps and
    :attr:`max_dispatches_total` exist to bound; raise them deliberately, per
    run, rather than editing the defaults.

    **These are count ceilings, and they are what actually bounds coverage.**
    They never shorten the time a dispatched finding gets — every dispatch has
    the same :attr:`tool_timeout_seconds` and the same round allowance however
    many findings triage handed over. They decide which findings are dispatched
    **at all**, in :func:`dispatch_priority` order, leaving the rest
    :data:`NOT_ATTEMPTED`. So a triage arm that flags more does not give each
    finding less time; it pushes the tail off the end of the list.

    **Why the per-rule cap is two settings.** A single blanket number cannot say
    "let these two noisy rules have more, or less, without moving everything else":
    :attr:`rule_caps` names individual rules, and :attr:`max_dispatch_all_rules` is
    the blanket default for every rule not named.

    Any ceiling may be set to :data:`NO_CAP` (``-1``) to disable that one
    ceiling; ``0`` keeps its arithmetic meaning and refuses every dispatch it
    governs.

    :param tool_timeout_seconds: hard timeout for one tool invocation. A call
        that exceeds it is killed and recorded :data:`INCONCLUSIVE`.
    :param max_dispatch_all_rules: dispatches allowed for any single ZAP plugin
        id that :attr:`rule_caps` does not name.
    :param rule_caps: per-plugin-id overrides, as ``(id, cap)`` pairs. A tuple
        rather than a dict so the dataclass stays hashable like the rest of the
        pure-data layer.
    :param max_dispatches_total: hard ceiling on tool invocations for the whole
        run. **Cross-endpoint, not per endpoint** — one number for the stage,
        which is why it is named ``_total``.
    :param max_minutes: wall-clock ceiling for the dispatch stage; once passed,
        no new dispatch starts and the remainder is :data:`NOT_ATTEMPTED`.
    """

    tool_timeout_seconds: int = 150
    max_dispatch_all_rules: int = 15
    rule_caps: "tuple[tuple[str, int], ...]" = ()
    max_dispatches_total: int = 40
    max_minutes: int = 20

    def cap_for(self, plugin_id: str) -> int:
        """The dispatch ceiling that governs ``plugin_id``.

        A rule named in :attr:`rule_caps` uses its own number; everything else
        uses :attr:`max_dispatch_all_rules`. Sibling probes pass ``""`` and are
        exempt from the per-rule layer entirely — see
        :meth:`dast_orchestrator.stages.verify.Dispatcher.run`.
        """
        return dict(self.rule_caps).get(plugin_id, self.max_dispatch_all_rules)

    @classmethod
    def from_env(cls) -> "DispatchBudget":
        """The budget as the environment leaves it, before any CLI override."""
        return cls(
            tool_timeout_seconds=_env_int("VERIFY_TOOL_TIMEOUT_SECONDS", 150),
            max_dispatch_all_rules=_env_int("VERIFY_MAX_DISPATCH_ALL_RULES", 15),
            rule_caps=tuple(sorted(
                parse_rule_caps([os.getenv("VERIFY_MAX_DISPATCH_RULE") or ""])
                .items())),
            max_dispatches_total=_env_int("VERIFY_MAX_DISPATCHES_TOTAL", 40),
            max_minutes=_env_int("VERIFY_MAX_MINUTES", 20),
        )

    def override(self, **limits: Any) -> "DispatchBudget":
        """A copy with the given ceilings replaced; ``None`` keeps the current one.

        The budget is the one thing a run is most likely to want to change from
        the command line — raising a noisy rule's cap to get complete outcomes on
        it is a per-run decision, and every other knob in this pipeline is a flag
        with an env default. Making these env-only meant the one setting you tune
        per run was the one you could not pass as an argument.

        ``rule_caps`` **merges** rather than replaces, so naming one rule on the
        command line does not silently drop the ones an env file set.
        """
        from dataclasses import replace

        given = {k: v for k, v in limits.items() if v is not None}
        caps = given.pop("rule_caps", None)
        if caps:
            merged = {**dict(self.rule_caps), **dict(caps)}
            given["rule_caps"] = tuple(sorted(merged.items()))
        return replace(self, **given)

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool_timeout_seconds": self.tool_timeout_seconds,
            "max_dispatch_all_rules": self.max_dispatch_all_rules,
            "max_dispatch_rule": dict(self.rule_caps),
            "max_dispatches_total": self.max_dispatches_total,
            "max_minutes": self.max_minutes,
        }


# -- finding selection and prioritisation ----------------------------------

#: Risk ranking used to order dispatch. High-risk active-injection findings are
#: verified before the passive noise, so a budget that bites drops the noise.
_RISK_RANK = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}


def selected_tool(finding: dict[str, Any]) -> str | None:
    """The tool a flagged finding should be dispatched to, or ``None``.

    The deterministic arm's table names a tool for its rescan rules; the LLM arm
    names one too (``suggested_tool``). The table wins when both do — keyed on the
    ZAP rule, it is reproducible, where the model's is a per-run judgement that
    varies even at temperature 0 — and the LLM's choice is consulted only as the
    fallback, when the table named none. That fallback is load-bearing: it is what
    holds the dispatched population fixed, since a finding only the LLM flagged is
    still verified; the table-vs-model question is about *which* tool, never
    *whether* a finding is dispatched.

    (The model-picks-the-tool preference — the LLM's choice *overriding* the
    table — was removed 2026-11-02; tool choice is now always the lookup.)

    A finding neither arm flagged, or one whose only suggestion is ``none``,
    returns ``None`` and is not dispatched.
    """
    det = finding.get("deterministic") or {}
    llm = finding.get("llm") or {}
    det_flag = bool(det.get("needs_rescan"))
    llm_flag = bool(llm.get("needs_rescan"))
    if not (det_flag or llm_flag):
        return None

    table_choice = (str(det["tool"])
                    if det_flag and det.get("tool") in DISPATCHABLE_TOOLS else None)
    llm_choice = (str(llm["suggested_tool"])
                  if llm_flag and llm.get("suggested_tool") in DISPATCHABLE_TOOLS
                  else None)
    for choice in (table_choice, llm_choice):
        if choice:
            return choice
    # Flagged, but by an arm that named no dispatchable tool — e.g. the LLM
    # flagged it while suggesting ``none``, or the table row carries no tool.
    # Nothing to route to, so it is not dispatched.
    return None


def is_dispatchable(finding: dict[str, Any]) -> bool:
    return selected_tool(finding) is not None


#: ZAP stages whose alerts rest on an attack the scanner actually sent. An
#: independent tool can *reproduce* those; it cannot reproduce a passive
#: observation, because there was never an attack to repeat.
ATTACKING_SOURCES = frozenset({"active-scanner", "tool", "manual"})


def is_attack_backed(finding: dict[str, Any]) -> bool:
    """Did a scanner actually inject for this finding, or merely observe?

    The distinction the verification budget turns on. Rule 40018 fires because
    sqlmap-style payloads changed a response; rule 10031 fires because a
    parameter value *appears* in an HTML attribute — a hint of XSS, not an
    observation of one. Both route to a tool, but only the first is a claim a
    tool can settle by repeating the attack.

    Reads the alert's recorded ``source``. A finding from before that was
    carried — or one with an unrecognised source — is treated as not
    attack-backed, which sorts it later rather than dropping it: the cautious
    direction, since the cost of being wrong is a probe spent, not a finding
    lost.
    """
    return str((finding.get("alert") or {}).get("source") or "") in ATTACKING_SOURCES


def dispatch_priority(finding: dict[str, Any]) -> tuple[int, int, int, str]:
    """Sort key: most worth the budget first.

    Order: by risk, then **by whether a scanner actually attacked for it**, then
    agreement (findings both arms flagged before single-arm ones), then finding
    id for a stable tiebreak. The last key matters for reproducibility — without
    it two runs can dispatch the same budget in a different order and disagree
    about which findings fell off a cap.

    **Why provenance outranks agreement.** Without it the budget is spent where the
    tools can say least — passive hints (rule ``10031``) crowding out the findings a
    tool actually injected. Risk stays first (a High-risk passive finding matters more
    than a Low-risk active one); provenance breaks ties within a risk band, where the
    ``10031`` flood lives.
    """
    alert = finding.get("alert") or {}
    risk = _RISK_RANK.get(str(alert.get("risk") or ""), 4)
    attacked = 0 if is_attack_backed(finding) else 1
    det = bool((finding.get("deterministic") or {}).get("needs_rescan"))
    llm = bool((finding.get("llm") or {}).get("needs_rescan"))
    both_rank = 0 if (det and llm) else 1
    return (risk, attacked, both_rank, str(finding.get("finding_id") or ""))


# -- final disposition: the three buckets a reader acts on -----------------
#
# The report's job is to hand a human three lists: what is settled true, what is
# settled false, and what still needs a person. That synthesis spans all three
# layers — the deterministic table, the LLM triage arm, and the tool
# verification — and it is computed HERE, next to the outcome vocabulary the
# verification layer already owns, so nothing downstream re-derives it.

#: A genuine finding an independent tool reproduced, or one so self-evident from
#: the captured response that there is nothing for a tool to add.
DISPOSITION_CONFIRMED = "confirmed"
#: A tool ran and could not reproduce it, or the LLM triage arm argued it away
#: from the handler source citing a specific line. Either way, actually refuted.
DISPOSITION_REFUTED = "refuted"
#: The leftovers a person must look at: a tool was inconclusive or not run, a
#: finding was flagged but never settled, or the judgement is semantic and no
#: scanner can make it.
DISPOSITION_TRIAGE = "requires-triage"
#: Not a finding at all — an identification or descriptive rule (ZAP's session /
#: technology fingerprints). Reported separately so it never dilutes the three.
DISPOSITION_INFORMATIONAL = "informational"

DISPOSITIONS = (DISPOSITION_CONFIRMED, DISPOSITION_REFUTED,
                DISPOSITION_TRIAGE, DISPOSITION_INFORMATIONAL)

#: Evidence classes whose finding is self-evident from the response ZAP already
#: captured — a missing header or a cookie flag is either there or it is not, so
#: the finding is *confirmed by observation* and no tool could add anything.
_SELF_EVIDENT_CLASSES = frozenset({"header", "cookie"})
#: Evidence classes that are not findings: ZAP's identification / technology
#: fingerprints. They carry no security claim to confirm or refute.
_NON_FINDING_CLASSES = frozenset({"identification"})

#: A source-grounded refutation must point at the code it read. Without a
#: `file:line`, an LLM "no rescan" is an opinion, not a refutation — the
#: refutations that agree with the independent tools are the ones that cite a
#: concrete location like `auth.go:132`.
import re as _re
_CODE_CITE_RE = _re.compile(r"\b[\w./-]+\.(?:go|py|js|ts|php|rb|java)\b\s*:\s*\d+"
                            r"|\b[\w./-]+\.(?:go|py|js|ts|php|rb|java)\b\s*\(\d+")


def _cites_code(text: str) -> bool:
    return bool(_CODE_CITE_RE.search(text or ""))


def classify_finding(
    finding: dict[str, Any],
    verification: dict[str, Any] | None = None,
) -> tuple[str, str]:
    """The one true disposition of a finding across all three arms.

    Precedence is by *authority of evidence*, most authoritative first: a tool
    that actually ran outranks a model's reading, which outranks the response
    being self-evident, which outranks "nobody settled it". Returns the
    disposition and a one-line reason for the report to quote.

    :param finding: a correlation finding (its ``deterministic``, ``llm`` and
        ``alert`` blocks).
    :param verification: the matching record from ``verification.json``, or
        ``None`` when the finding was never dispatched.
    """
    alert = finding.get("alert") or {}
    klass = evidence_class.rule_class({
        "pluginId": alert.get("plugin_id"),
        "cweid": alert.get("cweid"),
        "name": alert.get("name"),
    })

    # 1. A tool that ran is the highest authority.
    outcome = (verification or {}).get("outcome")
    if outcome == CONFIRMED:
        return DISPOSITION_CONFIRMED, (
            f"an independent tool reproduced it "
            f"({(verification or {}).get('tool', 'tool')})")
    if outcome == REFUTED:
        return DISPOSITION_REFUTED, (
            f"a tool ran and could not reproduce it "
            f"({(verification or {}).get('tool', 'tool')})")

    llm = finding.get("llm") or {}
    reasoning = str(llm.get("reasoning") or "")

    # 2. A source-grounded LLM refutation — declined AND citing a line it could read.
    #    A record from before `had_source` existed keeps its old reading.
    if (llm and llm.get("needs_rescan") is False and llm.get("had_source", True)
            and _cites_code(reasoning)):
        return DISPOSITION_REFUTED, "the triage model refuted it from the " \
            "handler source, citing a line"

    # 3. Non-findings: identification / technology fingerprints.
    if klass in _NON_FINDING_CLASSES:
        return DISPOSITION_INFORMATIONAL, "an identification/technology rule, " \
            "not a vulnerability finding"

    # 4. A tool tried and could not settle it, or was never dispatched though it
    #    was flagged — the leftovers a person must judge. A header or cookie rule
    #    no tool exists for is not one: flagged or not, the response is its proof.
    no_tool_applies = (outcome == NOT_ATTEMPTED
                       and klass in _SELF_EVIDENT_CLASSES
                       and (verification or {}).get("not_attempted_reason") == NA_NO_TOOL)
    if not no_tool_applies:
        if outcome in (INCONCLUSIVE, NOT_ATTEMPTED):
            return DISPOSITION_TRIAGE, f"verification was {outcome}"
        flagged = bool((finding.get("deterministic") or {}).get("needs_rescan")) \
            or bool(llm.get("needs_rescan"))
        if flagged:
            return DISPOSITION_TRIAGE, "flagged for an independent rescan that has " \
                "not settled it"

    # 5. Self-evident passive findings: proven by the captured response. A rule
    #    ZAP itself rates informational claims no weakness for it to prove.
    if klass in _SELF_EVIDENT_CLASSES:
        if str(alert.get("risk") or "") == "Informational":
            return DISPOSITION_INFORMATIONAL, "a header/cookie rule ZAP rates " \
                "informational, so it claims no weakness"
        return DISPOSITION_CONFIRMED, "self-evident from the captured response " \
            "(a header/cookie weakness); no tool could add to it"

    # 6. Everything else is a semantic judgement no scanner can make.
    return DISPOSITION_TRIAGE, "a semantic judgement no scanner can settle"


def disposition_summary(
    findings: list[dict[str, Any]],
    verifications: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Bucket every finding into the three the report presents, plus counts.

    The join is by ``finding_id``; a finding with no verification record simply
    passes ``None`` to :func:`classify_finding`.
    """
    by_id = {v.get("finding_id"): v for v in (verifications or [])}
    buckets: dict[str, list[dict[str, Any]]] = {d: [] for d in DISPOSITIONS}
    for finding in findings:
        disposition, reason = classify_finding(
            finding, by_id.get(finding.get("finding_id")))
        buckets[disposition].append({
            "finding_id": finding.get("finding_id"),
            "rule": (finding.get("alert") or {}).get("name"),
            "plugin_id": (finding.get("alert") or {}).get("plugin_id"),
            "risk": (finding.get("alert") or {}).get("risk"),
            "path": finding.get("path"),
            "reason": reason,
        })
    return {
        "counts": {d: len(buckets[d]) for d in DISPOSITIONS},
        "buckets": buckets,
    }


#: Synthesis `suggested_tool` values that are not a dispatchable tool.
SYNTH_SELF_EVIDENT = frozenset({"self-evident", "none"})  # "none" is legacy
SYNTH_OUT_OF_SCOPE = "out-of-scope"


def classify_synthesis(
    claim: dict[str, Any],
    verif_record: dict[str, Any] | None = None,
    finding_dispositions: "dict[str, str] | None" = None,
) -> tuple[str, str]:
    """The disposition of one cross-endpoint synthesis claim — accountably.

    A synthesis claim reaches the report only under a disposition it earns, never
    silently equal to a confirmed finding (Phase 4). By its ``suggested_tool``:

    * a **dispatchable tool** → its verification verdict decides (confirmed →
      confirmed, refuted → refuted, anything else → triage);
    * **self-evident** → confirmed **only when every finding it cites is itself
      confirmed** — otherwise it drops to triage, because a claim declared
      provable whose evidence is not itself settled is exactly the silent
      over-claim this classification exists to catch;
    * **out-of-scope** → requires-triage, tagged *out of scope for automated
      verification* — the honest manual-evaluation set for the writeup.
    """
    tool = str(claim.get("suggested_tool") or "")
    if tool in DISPATCHABLE_TOOLS:
        outcome = (verif_record or {}).get("outcome")
        if outcome == CONFIRMED:
            return DISPOSITION_CONFIRMED, f"an independent tool reproduced it ({tool})"
        if outcome == REFUTED:
            return DISPOSITION_REFUTED, f"a tool ran and could not reproduce it ({tool})"
        return DISPOSITION_TRIAGE, (
            f"testable by {tool} but not settled "
            f"({outcome or 'not dispatched'})")
    if tool in SYNTH_SELF_EVIDENT:
        supporting = claim.get("supporting_finding_ids") or []
        disps = finding_dispositions or {}
        if supporting and all(disps.get(fid) == DISPOSITION_CONFIRMED
                              for fid in supporting):
            return DISPOSITION_CONFIRMED, (
                "self-evident: every finding it cites is itself confirmed")
        return DISPOSITION_TRIAGE, (
            "declared self-evident, but not all of its cited findings are "
            "confirmed — verify the claim by hand")
    return DISPOSITION_TRIAGE, (
        "out of scope for automated verification — manual evaluation")


def disposition_report(
    findings: list[dict[str, Any]],
    verifications: list[dict[str, Any]] | None = None,
    synthesis: list[dict[str, Any]] | None = None,
    correlated_verifications: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """The whole run's disposition: per-finding and cross-endpoint synthesis.

    Extends :func:`disposition_summary` with the synthesis claims, classified by
    :func:`classify_synthesis` — which needs the per-finding dispositions first
    (a self-evident claim is confirmed only when its cited findings are). Also
    surfaces the **out-of-scope** synthesis claims as their own list: the clean
    set the thesis evaluates by hand, never counted as confirmed.
    """
    base = disposition_summary(findings, verifications)
    # Per-finding disposition by id, for the self-evident check.
    finding_disp: dict[str, str] = {}
    for disp, rows in base["buckets"].items():
        for row in rows:
            finding_disp[row["finding_id"]] = disp

    corr_by_id = {v.get("finding_id"): v for v in (correlated_verifications or [])}
    synth_rows: dict[str, list[dict[str, Any]]] = {d: [] for d in DISPOSITIONS}
    out_of_scope: list[dict[str, Any]] = []
    for claim in (synthesis or []):
        disposition, reason = classify_synthesis(
            claim, corr_by_id.get(claim.get("finding_id")), finding_disp)
        row = {
            "finding_id": claim.get("finding_id"),
            "rule": claim.get("title"),
            "risk": (claim.get("severity") or "").capitalize(),
            "path": ", ".join(claim.get("affected_routes") or [])[:80],
            "reason": reason,
            "synthesis": True,
            "suggested_tool": claim.get("suggested_tool"),
        }
        synth_rows[disposition].append(row)
        base["buckets"][disposition].append(row)
        if str(claim.get("suggested_tool")) == SYNTH_OUT_OF_SCOPE:
            out_of_scope.append({
                "finding_id": claim.get("finding_id"),
                "title": claim.get("title"),
                "severity": claim.get("severity"),
                "pattern": claim.get("pattern"),
                "affected_routes": claim.get("affected_routes") or [],
                "reason": reason,
            })
    return {
        "counts": {d: len(base["buckets"][d]) for d in DISPOSITIONS},
        "buckets": base["buckets"],
        "synthesis_counts": {d: len(synth_rows[d]) for d in DISPOSITIONS},
        # The honest manual-evaluation set: read as data, not reconstructed from
        # report prose.
        "synthesis_out_of_scope": out_of_scope,
    }
