"""What kind of evidence a rule's verdict rests on — pure classification vocabulary answering
only *"which bytes would settle this alert?"* (not a severity, not a taxonomy).

Domain vocabulary: the ``context`` layer's storage/excerpt rules and the ``domain``
verification layer both ask it, so it lives here rather than in ``context.evidence`` (where
it forced an upward import). No I/O — a lookup over three static tables, in decreasing order
of confidence (explicit rule, then CWE, then name).
"""

from __future__ import annotations

import re
from typing import Any, Mapping

CLASS_HEADER = "header"
CLASS_COOKIE = "cookie"
CLASS_IDENTIFICATION = "identification"
CLASS_XSS = "xss"
CLASS_SSTI = "ssti"
CLASS_SQLI = "sqli"
CLASS_TRAVERSAL = "traversal"
CLASS_REDIRECT = "redirect"
CLASS_DISCLOSURE = "disclosure"
CLASS_INJECTION = "injection"
CLASS_OTHER = "other"

#: The nuclei DAST fuzzing tag that scopes a probe to a given evidence class, for
#: oracle-mode verification. Instead of running the whole DAST catalog against one
#: endpoint — slow, and on a blind-RCE sink self-saturating (each injected payload
#: spawns a resident process) before the OOB callback can land — an oracle probe
#: runs only its own class. Classes with no DAST-fuzzing analogue map to ``""``:
#: no scoping, the full set as before.
NUCLEI_DAST_TAGS: dict[str, str] = {
    CLASS_INJECTION: "cmdi",
    CLASS_XSS: "xss",
    CLASS_SSTI: "ssti",
    CLASS_SQLI: "sqli",
    CLASS_TRAVERSAL: "lfi",
}


def nuclei_dast_tag(alert: "Mapping[str, Any]") -> str:
    """The nuclei DAST tag scoping a probe to this finding's class, ``""`` if none."""
    return NUCLEI_DAST_TAGS.get(rule_class(alert), "")

#: Explicit, per rule, for every plugin observed against this project's targets.
#: An explicit row beats every heuristic below it — a rule someone has actually
#: looked at should not be reclassified when a CWE mapping shifts.
RULE_CLASSES: dict[str, str] = {
    "6": CLASS_TRAVERSAL,
    "33": CLASS_TRAVERSAL,
    "43": CLASS_TRAVERSAL,
    "10010": CLASS_COOKIE,
    "10011": CLASS_COOKIE,
    "10021": CLASS_HEADER,
    "10023": CLASS_DISCLOSURE,
    "10024": CLASS_DISCLOSURE,
    "10027": CLASS_DISCLOSURE,
    "10028": CLASS_REDIRECT,
    "10029": CLASS_COOKIE,
    "10031": CLASS_XSS,
    "10032": CLASS_DISCLOSURE,
    "10035": CLASS_HEADER,
    "10036": CLASS_HEADER,
    "10037": CLASS_HEADER,
    "10038": CLASS_HEADER,
    "10054": CLASS_COOKIE,
    "10055": CLASS_HEADER,
    "10058": CLASS_OTHER,
    "10062": CLASS_DISCLOSURE,
    "10063": CLASS_HEADER,
    "10096": CLASS_DISCLOSURE,
    "10098": CLASS_HEADER,
    "10104": CLASS_IDENTIFICATION,
    "10109": CLASS_IDENTIFICATION,
    "10111": CLASS_IDENTIFICATION,
    "10112": CLASS_IDENTIFICATION,
    "10202": CLASS_OTHER,
    "20019": CLASS_REDIRECT,
    "30002": CLASS_INJECTION,
    "40003": CLASS_INJECTION,
    "40012": CLASS_XSS,
    "40014": CLASS_XSS,
    "40016": CLASS_XSS,
    "40017": CLASS_XSS,
    "40018": CLASS_SQLI,
    "40019": CLASS_SQLI,
    "40020": CLASS_SQLI,
    "40021": CLASS_SQLI,
    "40022": CLASS_SQLI,
    "40024": CLASS_SQLI,
    "40026": CLASS_XSS,
    "40027": CLASS_SQLI,
    "90017": CLASS_INJECTION,
    "90019": CLASS_INJECTION,
    "90020": CLASS_INJECTION,
    "90037": CLASS_INJECTION,
    "90022": CLASS_DISCLOSURE,
    "90035": CLASS_SSTI,
    "90036": CLASS_SSTI,
}

#: Fallback by CWE, for a rule this project has never seen. Deliberately
#: coarse — its job is to keep a *new target's* rules out of :data:`CLASS_OTHER`
#: long enough that the storage rule errs generously, not to be a taxonomy.
CWE_CLASSES: dict[str, str] = {
    "22": CLASS_TRAVERSAL,
    "78": CLASS_INJECTION,
    "79": CLASS_XSS,
    "89": CLASS_SQLI,
    "90": CLASS_INJECTION,
    "93": CLASS_INJECTION,
    "94": CLASS_INJECTION,
    "113": CLASS_INJECTION,
    "134": CLASS_INJECTION,
    "200": CLASS_DISCLOSURE,
    "209": CLASS_DISCLOSURE,
    "497": CLASS_DISCLOSURE,
    "548": CLASS_DISCLOSURE,
    "550": CLASS_DISCLOSURE,
    "565": CLASS_COOKIE,
    "598": CLASS_DISCLOSURE,
    "601": CLASS_REDIRECT,
    "614": CLASS_COOKIE,
    "693": CLASS_HEADER,
    "1004": CLASS_COOKIE,
    "1275": CLASS_COOKIE,
    "1295": CLASS_DISCLOSURE,
    "1336": CLASS_SSTI,
}

#: Last resort: the rule's own name. Ordered, first match wins.
NAME_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern, re.I), klass)
    for pattern, klass in (
        (r"template injection", CLASS_SSTI),
        (r"sql injection", CLASS_SQLI),
        (r"cross site scripting|\bxss\b", CLASS_XSS),
        (r"path traversal|directory browsing|remote file", CLASS_TRAVERSAL),
        (r"redirect", CLASS_REDIRECT),
        (r"cookie", CLASS_COOKIE),
        (r"header", CLASS_HEADER),
        (r"injection|format string", CLASS_INJECTION),
        (r"disclosure|leak", CLASS_DISCLOSURE),
    )
)


def rule_class(alert: Mapping[str, Any]) -> str:
    """Which kind of evidence would settle this alert.

    Resolution order is explicit rule, then CWE, then the rule name, then
    :data:`CLASS_OTHER`. Each step is a weaker claim than the one before it, and
    the order matters more than any individual row: the storage rule only ever
    *drops* data for the classes it is certain about, so a misclassification into
    :data:`CLASS_OTHER` costs disk, never evidence.
    """
    plugin_id = str(alert.get("pluginId") or alert.get("plugin_id") or "").strip()
    explicit = RULE_CLASSES.get(plugin_id)
    if explicit:
        return explicit
    cwe = str(alert.get("cweid") or alert.get("cwe") or "").strip()
    by_cwe = CWE_CLASSES.get(cwe)
    if by_cwe:
        return by_cwe
    name = str(alert.get("name") or alert.get("alert") or alert.get("rule") or "")
    for pattern, klass in NAME_PATTERNS:
        if pattern.search(name):
            return klass
    return CLASS_OTHER
