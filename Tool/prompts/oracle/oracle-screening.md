You have been given this target's KNOWN, DOCUMENTED VULNERABILITIES up front, before judging anything. This is oracle-guided mode: the run is measuring how much this pipeline can confirm when it already knows what is there.

**This is your first priority for this endpoint, ahead of everything else you are asked to do.** Before you triage anything else on it, answer: does this endpoint, or the handler source in front of you, belong to one of the described weaknesses? And — the specific job of THIS stage — **is any ZAP alert in front of you the alert that weakness would raise?**

That question is what this stage contributes to the ceiling, so answer it deliberately rather than in passing:

* **Match the alert class to the weakness class.** A described reflected-XSS sink should make you read every XSS-class alert on this endpoint (`Cross Site Scripting`, `User Controllable HTML Element Attribute`, DOM-based) as a candidate for it rather than as routine noise. A described SQL injection should do the same for the injection rules. The description tells you which class to take seriously here.
* **Match the parameter.** The descriptions name the parameter or the request field the weakness travels on. An alert flagged on that exact parameter, at an endpoint the description reaches, is the strongest signal this stage can produce — say so in your reasoning, in those words, and flag it for rescan.
* **Match the sink to the source.** The descriptions say where the value lands — inside a `<script>` element, in an attribute, in a SQL statement. Check the handler source for that landing place. If it is there, the alert is very likely the real thing and your reasoning should cite the line.
* **A described weakness whose alert is NOT here is also an answer.** If this endpoint reaches a described sink and the scanner flagged nothing relevant on it, say that in your reasoning. A gap between "the bug is here" and "no alert reports it" is exactly what the ceiling run exists to locate, and it is invisible unless you name it.

**This does NOT license agreement, and the ceiling is worthless if you give it one.** The question is unchanged: is THIS alert, on THIS endpoint, a real instance of the weakness?

* Most alerts you see will have nothing to do with anything described. Judge those exactly as you would in a blind run — a false positive stays a false positive on a target that has real bugs elsewhere.
* Some descriptions explicitly say a documented weakness is **already defended at this pinned version**, naming the escaping or the guard that stops it. An alert of that class is then a FALSE POSITIVE and you should refute it, citing that. Confirming one would prove only that you read the heading and not the paragraph.
* The description tells you where to look and what class to take seriously. It never tells you what to answer. The evidence in front of you does that.
