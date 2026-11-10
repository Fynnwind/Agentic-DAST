You have been given this target's KNOWN, DOCUMENTED VULNERABILITIES up front, before probing anything. This is oracle-guided mode: the run is measuring how much this pipeline can confirm when it already knows what is there.

**Read this before the rest of your task, because it changes one of that task's rules.** In a blind run you are told nothing about what any earlier stage concluded, so that your check stays independent. In THIS mode you are told two things instead, and you are expected to act on both:

1. **The documented weakness** — what it is, which parameter carries it, where the value lands.
2. **`earlier_triage`** — what the triage stage concluded about *this* finding, including whether it judged the alert to be the one a described weakness would raise.

**Your first priority is to settle whether the described weakness is real HERE, and both of those are your starting evidence.**

* **Aim the probe at the mechanism the description names.** If the description says a value lands unescaped inside a `<script>` element, probe the parameter it names, in that place. If it says the injection point is an array-typed request field, direct the invocation at that field. You are not guessing where to look; you have been told.
* **Pick the tool whose oracle can settle THAT class.** This is the round most likely to be lost by a wrong choice. A weakness described as *executing* script is settled by an execution oracle and not by a string matcher — a payload can be altered in transit (WordPress slash-adds quotes) and still execute perfectly, which is exactly how this pipeline once refuted a live vulnerability. If the description says the payload survives escaping, that is a direct instruction to prefer `browser`.
* **Use what triage flagged.** Where `earlier_triage` says this alert matches a described weakness and cites a parameter or a source line, probe *that*. Where it argued the finding away because the described weakness is **already defended** at this pinned version, expect a refutation and design a probe that would actually show one — confirming one of those would mean the probe was wrong, not that the fix is absent.
* **Say in `reasoning` which description you are testing.** A ceiling run's value is per-finding traceability: a reader must be able to see which documented weakness each probe was aimed at.

**None of this licenses a confirmation. Knowing a bug is documented does NOT license one.**

* A category is still what the tool's own output shows. Knowing a bug is documented is not evidence that this probe reproduced it, and a confirmation the tool's machinery did not report is recorded as a disagreement, not as a confirmation. The resolution rule is unchanged.
* Knowing what to look for changes the probe. Only the probe changes the verdict.
* And note what this mode costs, so you do not overstate what you produce: because you were handed triage's conclusion, your check is **no longer independent of it**. That is an accepted trade for a ceiling measurement and it is the reason a ceiling number can never sit beside a blind run's.
