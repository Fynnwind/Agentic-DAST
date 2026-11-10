You have been given this target's KNOWN, DOCUMENTED VULNERABILITIES up front, before judging anything. This is oracle-guided mode: the run is measuring how much this pipeline can confirm when it already knows what is there.

**This is your first priority for this corpus, ahead of everything else you are asked to do.** Pass 1 has already been asked, endpoint by endpoint, whether a ZAP alert in front of it is the alert a described weakness would raise, and its answers are in `pass1_reasoning` and `pass1_verdict` on every finding. **Your job is the half pass 1 structurally cannot do: look for the SIGNS of those same weaknesses across the whole scan at once.**

Work outward from the descriptions:

* **Find the sink's route family.** A description names a handler, a view file or a request field. `shared_handlers` says which routes reach the same code, and the endpoint list says which of them the scan touched. Every route reaching a described sink is a candidate for the described weakness — including the ones the scanner never flagged, which is the class only this pass can name.
* **Read pass 1's answers as your evidence.** Where a pass-1 verdict says an alert matches a described weakness, that is the strongest anchor in the corpus and the claim you build on it is the one most worth verifying. Where pass 1 says a described sink is reachable but nothing was flagged on it, that is a gap worth a claim of its own if — and only if — some observed finding supports it.
* **Look for the same symptom under different rules.** A weakness described as landing inside a `<script>` element may surface as a DOM-XSS alert on one route, a reflection alert on another, and nothing at all on a third. The scanner sees three unrelated events; you are the only stage that can see one cause. Say which cause, and name the routes.
* **`affected_routes` is where this pays.** For a claim built on a described weakness, list the routes you predict share it, unflagged siblings included — those are the ones a verifier will actually probe, and a confirmation on one is a finding the scan could not produce.

**This does NOT license inventing findings, and a ceiling built on invention measures nothing.**

* Every claim still cites real `finding_id`s from this corpus and still rests on something observed. A documented vulnerability the scan produced no evidence for is a **gap**, not a claim: reporting it as a finding would make this pass a transcription of what you were told, and the run would report the answer key back to itself.
* Some descriptions say explicitly that a documented weakness is **already defended at this pinned version**. Do not build a propagation claim on one; if the cited findings are of that class, the honest claim is that they are false positives sharing a cause.
* Prefer few well-evidenced claims to many weak ones, exactly as in a blind run. Knowing what is there should make your claims *sharper*, not more numerous.
