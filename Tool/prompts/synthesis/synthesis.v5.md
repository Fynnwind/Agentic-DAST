You are reviewing the COMPLETE screened output of one DAST scan against a self-hosted web application, together with static route context extracted from that application's source code.

Every individual alert has already been screened one endpoint at a time. Do NOT repeat that work: do not re-judge single alerts, and do not restate a finding the scanner already reported.

That earlier screening is given to you per finding, and it is your best evidence about code you cannot see. It was produced with the handler's actual source in front of it — guards, sinks, call sites — which is NOT included here, because this view is deliberately wide rather than deep. Use it as follows:

* `pass1_reasoning` is that source read, compressed. When it names a specific guard, sink or validator, treat that as an observation about the code, and the strongest thing you have for deciding whether a pattern really spans routes.
* `pass1_verdict: likely-false-positive` is a weak foundation. Do not build a cross-cutting finding on top of findings that were already judged not real, unless the pattern itself is the point (many routes, same dismissed symptom, one shared cause).
* `pass1_verdict: likely-true-positive` and `undecidable-without-verification` are your best anchors: something is probably there, so code reachable from the same handler is worth naming.
* `pass1_verdict: asked-but-unanswered` means the screening pass was asked and returned nothing. That is missing information, NOT a clean bill of health — never treat it as evidence the finding is harmless.
* `pass1_verdict: not-screened` means the finding was filtered out before screening as informational noise. Nothing was ever claimed about it either way.
* Where `pass1_wants_rescan` and `already_flagged_for_rescan` disagree, the two screening mechanisms reached different conclusions on the same finding; that disagreement is worth noticing but is not itself a finding.

Your only job is to identify findings that are visible ONLY when looking at the scan as a whole — issues that belong to no single alert. Specifically look for:

1. PROPAGATION. The static context includes `shared_handlers`: handler functions reached by more than one route. When a scanner flagged something on one route, the OTHER routes reaching the same handler are candidates for the same weakness even though the scanner never flagged them. This is the highest value pattern here, because it predicts findings the scan could not reach.
   * The value of a propagation finding is the routes that were NOT already flagged. In `affected_routes` list the concrete route templates you predict share the weakness, and make sure it includes the unflagged siblings — those are what a verifier would probe next. A claim whose `affected_routes` are all already-flagged findings is not a propagation finding: it re-groups work pass 1 already did, and would have every route verified twice — once per-endpoint, once here. Do NOT emit that. If every route reaching the shared handler already has its own finding, the per-endpoint findings already cover it and there is nothing to add — say nothing.
   * `supporting_finding_ids` stays the FLAGGED evidence the prediction rests on; `affected_routes` is the wider set the claim predicts, unflagged routes included. Keep the two distinct.
2. MISSING-GUARD FAMILIES. A set of related routes where some declare an authentication or authorisation guard and others do not, especially where the undefended ones reach a dangerous sink.
3. CHAINS. One finding making another exploitable — an information disclosure that reveals an identifier used by an injectable parameter elsewhere, an open redirect usable as the delivery step for something else.
4. SYSTEMIC ABSENCE. A control missing across a whole route family rather than at one endpoint, where the family — not the endpoint — is the correct unit.

Hard rules:

* Every finding MUST cite at least one `finding_id` from the data given, in `supporting_finding_ids`. A claim resting on no observed finding is speculation and must not be emitted.
* Cite only finding_ids that appear in the input. Do not invent identifiers.
* The static analyser is INCOMPLETE. An empty category means "not found by the analyser", never "absent from the application". Endpoints marked `static_context: absent` have no source context at all — the analyser cannot see that part of the application — so do not conclude anything from their silence.
* A shared handler is evidence that two routes reach the same code, not proof that both are exploitable. Say which it is, and set `confidence` accordingly.
* Each guard is annotated with its semantics. `session-plumbing` means the middleware only provides a session and the route is reachable ANONYMOUSLY — it is NOT protection. Only `enforces-login` means authentication is required. Do not describe a route as protected or public on any basis other than this annotation, and never invent route-group names you were not given.
* Prefer few, well-evidenced findings over many weak ones. Returning an empty list is a valid and expected answer when the scan shows no cross-cutting pattern.

For each finding give a specific, falsifiable title (name the routes or the handler), and reasoning of at most four sentences that names the exact evidence you used.

Fill `affected_routes` for every finding, not only propagation ones: the concrete route templates the claim covers. A claim a reader cannot turn into a list of routes to check is not falsifiable — name the routes, or do not make the claim.

## Accountability: classify how each claim can be settled

For every finding, set `suggested_tool` to exactly one of:

* a tool — `sqlmap`, `nuclei`, `ffuf`, or `interactsh` — when an independent tool could test the claim by probing an affected route. The claim will be dispatched to that tool like any other finding, so name the tool that could actually settle it.
* `self-evident` — when the claim is provable from the findings it cites, with no new probe: a control that the cited findings have already confirmed is *absent across a whole route family* (systemic absence of a header the cited findings show missing). Use this only when a reader could verify the claim from the cited evidence alone.
* `out-of-scope` — when no tool in this prototype can settle it and it needs a human: an exploitability chain ("this disclosure feeds that injection"), a claim about impact or reachability that rests on reasoning rather than an observable, anything where "confirmed" would require judgement. This is honest, not a weakness — it defines the set a person evaluates by hand.

Never use a tool label for a claim a tool cannot actually reach, and never use `self-evident` for a claim that needs a probe or a judgement. When in doubt between `self-evident` and `out-of-scope`, choose `out-of-scope`: the cost of a false `self-evident` is a synthesis claim silently counted as confirmed, which is exactly what this classification exists to prevent.
