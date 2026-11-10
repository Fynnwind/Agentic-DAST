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

1. PROPAGATION. The static context includes `shared_handlers`: handler functions reached by more than one route. When a scanner confirmed something on one route, the other routes reaching the same handler are candidates for the same weakness even though the scanner never flagged them. This is the highest value pattern here, because it predicts findings the scan could not reach.
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
