"""Turn a triaged finding into a concrete probe a wrapper tool can run.

Builds a finding\'s dispatch (which tool, which URL, which injection point, how
the payload is marked), the sibling-route dispatches a propagation claim
predicts, and the :class:`Dispatcher` that calls a wrapper over stdio MCP.
Depends only on :mod:`~dast_orchestrator.stages.verify.common`.
"""
from __future__ import annotations
import json
import re
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any
from urllib.parse import (
    parse_qsl,
    quote,
    quote_plus,
    unquote,
    urlencode,
    urlparse,
    urlunparse,
)
from mcp import ClientSession, stdio_client
from dast_orchestrator.foundation import config
from dast_orchestrator.adapters import auth
from dast_orchestrator.analysis import join
from dast_orchestrator.adapters import noir_runner
from dast_orchestrator.domain import rescan_table
from dast_orchestrator.domain import evidence_class
from dast_orchestrator.adapters import targets
from dast_orchestrator.domain import verification
from dast_orchestrator.domain.verification import (
    DispatchBudget,
    INCONCLUSIVE,
    NOT_ATTEMPTED,
)
from .common import *

@dataclass(frozen=True)
class ProbeTarget:
    """What a verification tool should aim at, and how that was decided.

    ``ZAP's example_urls carry the attack payload`` — they are the URL of the
    request that *raised* the alert, not the endpoint's own URL. Handing that
    straight to another tool means re-probing an already-broken request: the
    baseline response is a 500 caused by the previous tool's payload, so the new
    tool measures nothing about the endpoint — it lands ``inconclusive``, the right
    verdict for the wrong reason.

    The payload is removed differently depending on where the parameter lives,
    because "the parameter" means two different things in ZAP's alerts:

    * a **query** parameter — ``param`` is a *name*, the payload sits in its
      value. The value is reset to something benign; the name and the rest of the
      URL are what the tool needs, and it substitutes its own values anyway.
    * a **path** parameter (ZAP's url-path injection, the mode this project turns
      on deliberately) — ``param`` is the segment *value* and ``attack`` is that
      value with the payload appended, so the payload strips off exactly.

    A full rebuild from the Noir route template was considered and rejected on
    the data: substituting the target's generic path vars would produce URLs like
    ``/commit/0000…0000.md`` that do not exist on the target, refuting findings
    for a *new* wrong reason, and no flagged finding in any recorded run has lacked
    an example URL for it to rescue. The template is used where it is genuinely
    authoritative instead — deciding which
    path segment is the parameter, in :func:`mark_path_injection`.

    **A payload can also be *substituted for* a path segment rather than appended
    to it**, and that case has no clean form. ZAP's format-string rule replaces
    the avatar hash outright, so the recorded URL is
    ``/avatars/ZAP%20%251!s%252!s…`` — the payload matches neither the flagged
    parameter (which is the *original* segment value, no longer present) nor a
    query name. It fell through both branches unchanged and was handed to nuclei
    as ``as-recorded``: the exact class the payload-stripping fix was written for
    was the one it missed. It is now recognised by finding ``attack`` in the
    path, and:

    * when ``param`` holds the pre-attack value, the segment is restored to it;
    * when it does not, there is nothing to restore the segment *to*, and the
      probe is **refused** (:data:`URL_PAYLOAD_UNRECOVERABLE`) rather than sent
      at a URL that is still an attack. Refusing yields ``not-attempted``, which
      is honest; probing anyway yields a verdict about a payload rather than
      about the endpoint.

    A refusal is expressed as an empty :attr:`url` with the reason in
    :attr:`url_source`, so the artifact records *why* nothing was probed in the
    same field that otherwise records how the probe was built.
    """

    url: str
    param: str
    injection_point: str
    url_source: str

    @property
    def probeable(self) -> bool:
        return bool(self.url)


def probe_target(finding: dict[str, Any],
                 fillers: dict[str, str] | None = None) -> ProbeTarget:
    """The clean URL to probe for one finding.

    Always returns a :class:`ProbeTarget`; check :attr:`ProbeTarget.probeable`,
    which is false when no safe URL could be derived and :attr:`url_source` then
    says why (:data:`URL_REFUSALS`).
    """
    alert = finding.get("alert") or {}
    urls = alert.get("example_urls") or []
    if not urls:
        return ProbeTarget("", "", "", URL_NONE_RECORDED)
    url = str(urls[0])
    param = str(alert.get("param") or "")
    attack = str(alert.get("attack") or "")
    method = str(alert.get("method") or finding.get("method") or "GET").upper()
    parsed = urlparse(url)

    query = parse_qsl(parsed.query, keep_blank_values=True)
    if param and any(name == param for name, _ in query):
        benign = (fillers or {}).get(param, BENIGN_PARAM_VALUE)
        rewritten = [(n, benign if n == param else v) for n, v in query]
        source = URL_QUERY_RESET if rewritten != query else URL_AS_RECORDED
        url = urlunparse(parsed._replace(query=urlencode(rewritten)))
        return ProbeTarget(url, param, INJECT_QUERY, source)

    restored, found = restore_path_payload(parsed.path, param, attack)
    if found:
        if restored is None:
            return ProbeTarget("", param, INJECT_PATH, URL_PAYLOAD_UNRECOVERABLE)
        return ProbeTarget(urlunparse(parsed._replace(path=restored)), param,
                           INJECT_PATH, URL_PATH_STRIPPED)

    # The flagged value is in the path and nothing was injected into it (ZAP
    # records this for its traversal rule): a path parameter, already clean.
    #
    # Unless the "parameter" is itself a payload. ZAP sometimes records the
    # injected string AS the param name (e.g. `"+__lm_logo+`), and then
    # `restore_path_payload` bails out (its first
    # line is `attack == param`) and this branch reads the segment as a clean
    # path parameter because the payload is, tautologically, present in the
    # path. Four of the fifteen sqlmap probes in that run were sent at URLs
    # like `http://target-wordpress/%22+__lm_logo+`, and every one came back
    # 404. The detector already existed; this branch just never asked it.
    if param and param in unquote(parsed.path):
        if looks_like_payload(param):
            return ProbeTarget("", param, INJECT_PATH, URL_PAYLOAD_UNRECOVERABLE)
        return ProbeTarget(url, param, INJECT_PATH, URL_AS_RECORDED)

    return ProbeTarget(url, param, INJECT_BODY if method != "GET" else "",
                       URL_AS_RECORDED)


def looks_like_payload(attack: str) -> bool:
    """Whether an ``attack`` string is recognisably a payload, not a plain value.

    See :data:`_PAYLOAD_SIGNALS` for why this test exists and why it is
    deliberately conservative.
    """
    return (
        len(attack) >= MIN_PAYLOAD_MATCH_CHARS
        and (bool(_PAYLOAD_SIGNALS & set(attack)) or ".." in attack)
    )


def restore_path_payload(path: str, param: str,
                         attack: str) -> tuple[str | None, bool]:
    """Put a path segment carrying an attack payload back to its clean value.

    One helper for both shapes ZAP produces, because they differ only in what
    the payload replaced:

    * **appended** — ``param`` is the segment's original value and ``attack`` is
      that value with the payload on the end (``/commit/<sha>.patch'``);
    * **substituted** — the segment *is* the payload and ``param`` holds what it
      replaced (``/avatars/ZAP%20%251!s…``, ``param`` the avatar hash).

    Either way the fix is the same: find the segment whose decoded form carries
    the attack, and put ``param`` back in it. Matching is done on the **decoded**
    segment, because the two encodings need not agree — ZAP recorded
    ``ZAP %1!s`` and sent ``ZAP%20%251!s``, where ``%`` is escaped and ``!`` is
    not, so neither :func:`quote` nor :func:`quote_plus` of the attack appears in
    the raw path.

    :returns: ``(restored_path, payload_found)``. ``payload_found`` is ``False``
        when no segment carries a recognisable payload — the URL is then clean
        already and the caller leaves it as recorded. When a payload *is* found
        but ``param`` is empty there is nothing to restore the segment to, and
        ``restored_path`` is ``None``: the caller must refuse the probe rather
        than aim a tool at a URL that is still an attack.
    """
    if attack == param or not looks_like_payload(attack):
        return path, False
    segments = path.split("/")
    for index, segment in enumerate(segments):
        if not segment or attack not in unquote(segment):
            continue
        if not param:
            return None, True
        segments[index] = quote(param, safe="")
        return "/".join(segments), True
    # A payload spanning segment boundaries (a traversal string, say) is not a
    # single segment; fall back to replacing it wherever it appears.
    for form in (attack, quote(attack, safe=""), quote_plus(attack)):
        if form and form in path:
            if not param:
                return None, True
            replacement = param if form == attack else quote(param, safe="")
            return path.replace(form, replacement, 1), True
    return path, False


def mark_path_injection(url: str, param: str, template: str = "") -> str | None:
    """Mark a path parameter with sqlmap's ``*`` injection point.

    A URL path segment has no name, so ``-p`` cannot address it and sqlmap
    otherwise tests nothing — which is why the commit ``.patch`` finding could
    never be settled however clean its URL was. sqlmap's answer is a marker in
    the URL, and the Noir route template is what says *which* segment may carry
    one: the segment whose template counterpart is a placeholder
    (``{sha:([a-f0-9]{7,40})}.{ext}``). Without a template, only a segment equal
    to the flagged value is marked — never a substring, so a literal path
    component that merely contains the value is left alone.

    The marker is **appended** to the segment
    (``/commit/663a2a0…fca.patch*``): see :data:`SQLMAP_INJECTION_MARKER` for why
    replacing the segment instead makes every request 404 before a test runs.

    :returns: the marked URL, or ``None`` when no segment can be marked safely —
        which the caller must treat as "not probeable this way" rather than
        falling back to an unmarked URL sqlmap would silently test nothing in.
    """
    parsed = urlparse(url)
    segments = parsed.path.split("/")
    template_segments = template.split(" ", 1)[-1].split("/") if template else []
    candidates = [
        index for index, segment in enumerate(segments)
        if segment and unquote(segment) == param
    ]
    if template_segments and len(template_segments) == len(segments):
        candidates = [i for i in candidates if _is_placeholder(template_segments[i])]
    if len(candidates) != 1:
        # Zero: the value is not a whole segment. More than one: the same value
        # appears twice (``/api/v1/settings/api``) and nothing says which one ZAP
        # injected, so marking either would probe a literal path component.
        # Both cases return None rather than guessing.
        return None
    marked = list(segments)
    marked[candidates[0]] += SQLMAP_INJECTION_MARKER
    return urlunparse(parsed._replace(path="/".join(marked)))


def _is_placeholder(template_segment: str) -> bool:
    """Whether a route-template segment is a parameter rather than a literal."""
    return "{" in template_segment or "*" in template_segment


#: A parameter name that could plausibly be an HTML form field: no whitespace,
#: no ``:``. Screens out ZAP's pseudo-params for header/cookie/User-Agent-fuzzer
#: alerts (e.g. ``Header User-Agent``), which are not form fields and, put into a
#: POST body, make the target reject the request — a false ``refuted``.
_FORM_FIELD_RE = re.compile(r"^[A-Za-z_][\w.\-]*$")

#: ``wpdm_login[log]`` -> ``log``. PHP's array-style form fields, which a
#: target's `form_fillers` name by their inner key. See :func:`filler_for`.
_ARRAY_FIELD_RE = re.compile(r"^[A-Za-z_][\w.\-]*\[(?P<key>[^\[\]]+)\]$")


def sqlmap_can_address(target: str, param: str, data: str) -> bool:
    """Whether sqlmap has an injection point it can actually reach.

    Three ways it can, and no others: the URL carries the
    :data:`SQLMAP_INJECTION_MARKER` (a marked path segment), the named parameter
    is in the query string, or it is in the form body. A probe that satisfies
    none of them is refused before dispatch rather than sent to discover the
    same thing at the cost of a slot — sqlmap does not fail loudly here, it
    reports that the target may have rejected the probe, which reads like a
    property of the application.

    The empty-parameter case is deliberately included: without a name and
    without a marker there is nothing to inject into, which the wrapper already
    refuses. Refusing it here too moves the refusal off the budget.
    """
    if SQLMAP_INJECTION_MARKER in (target or ""):
        return True
    param = (param or "").strip()
    if not param:
        return False
    query = dict(parse_qsl(urlparse(target or "").query, keep_blank_values=True))
    if param in query:
        return True
    return param in dict(parse_qsl(data or "", keep_blank_values=True))


def filler_for(name: str, fillers: dict[str, str]) -> "str | None":
    """A declared value for this form field, tolerating PHP array-style names.

    A target declares fillers by field name (``log``, ``pwd``). PHP forms post
    them inside an array — WP Download Manager's login is
    ``wpdm_login[log]`` / ``wpdm_login[pwd]`` — and an exact-match lookup misses
    every one, so the field falls back to the placeholder and the application
    rejects the request before any injectable code runs (a login-form SQLi probe
    then posts only ``wpdm_login[log]=ZAP&wpdm_login[pwd]=ZAP``).

    Exact match first, then the bracketed key, so a target can still declare
    ``wpdm_login[log]`` explicitly and have it win.
    """
    if name in fillers:
        return fillers[name]
    inner = _ARRAY_FIELD_RE.match(name)
    if inner and inner.group("key") in fillers:
        return fillers[inner.group("key")]
    return None


def _form_body(findings_by_endpoint: dict[Any, list[dict[str, Any]]],
               finding: dict[str, Any], fillers: dict[str, str],
               drop_names: set[str] = frozenset()) -> str:
    """Reconstruct a POST body from the endpoint's *real* form fields.

    Gathers the parameter names ZAP recorded on this endpoint and keeps only
    those shaped like form fields, dropping the pseudo-params ZAP attaches to
    header, cookie and User-Agent-fuzzer alerts (and the session cookie name in
    ``drop_names``). Without this filter the body carried junk fields like
    ``Header User-Agent=…`` that the target rejects, refuting a finding for a
    reason that has nothing to do with the vulnerability. The flagged parameter
    is always included; a valid anti-CSRF token is supplied separately by
    sqlmap's ``--csrf-url`` handling.
    """
    key = finding.get("endpoint_key") or (finding.get("method"), finding.get("path"))
    siblings = list(findings_by_endpoint.get(key, [finding])) + [finding]
    fields: dict[str, str] = {}
    for f in siblings:
        p = str((f.get("alert") or {}).get("param") or "")
        if not p or p in drop_names:
            continue
        if not (_FORM_FIELD_RE.match(p) or _ARRAY_FIELD_RE.match(p)):
            continue
        declared = filler_for(p, fillers)
        fields[p] = FORM_PLACEHOLDER if declared is None else declared
    return "&".join(f"{k}={v}" for k, v in sorted(fields.items()))


def placeholder_fields(body: str) -> list[str]:
    """Body fields that carry the placeholder rather than a declared value.

    Reported on the dispatch so a reader can weigh a refutation against how much
    of the request was invented. A field the target declares no filler for is
    sent as :data:`FORM_PLACEHOLDER`, which an application with any validation
    on that field will reject — and sqlmap then answers that the target may have
    rejected the probe, which reads like a fact about the application.
    """
    return sorted(
        name for name, value in parse_qsl(body or "", keep_blank_values=True)
        if value == FORM_PLACEHOLDER
    )


def _apply_auth(tool: str, args: dict[str, Any], method: str,
                auth_ctx: dict[str, Any] | None) -> None:
    """Give a tool the same auth capabilities ZAP has: session cookie + CSRF.

    The two are independent. A **session cookie** is added only in an
    authenticated (``--auth``) run. **CSRF handling** for a form POST is added
    whenever the target declares a CSRF field — *even unauthenticated* — because
    a form POST (a login SQLi probe, say) is rejected without a fresh token
    regardless of session, so sqlmap must do the same fetch-token-then-POST
    handshake ZAP does or it refutes for the wrong reason. The token is fetched
    from the probed page itself, which carries the form; ``auth_ctx["csrf_url"]``
    (the login page) is only the fallback for a probe with no target.

    In oracle (ceiling) mode ``auth_ctx`` may carry ``cookie_free_routes`` — the
    sink routes the markers mark UNAUTHENTICATED. This is the one place the
    session cookie is attached, so the cookie is dropped for an unauth sink's
    probe HERE — for every arm (the table dispatch, the model-directed loop,
    correlated and sibling probes) rather than in a single dispatch builder.
    """
    if not auth_ctx:
        return
    if auth_ctx.get("cookie"):
        args["cookie"] = auth_ctx["cookie"]
        # Do not force the scan's session cookie onto a probe for an
        # UNAUTHENTICATED sink: the session is not needed there, and on a
        # poller-auth bypass like Cacti's remote_agent.php a valid admin session
        # takes the request off its unauthenticated branch and suppresses the RCE.
        # The scan_headers reach (e.g. X-Forwarded-For) is applied below and
        # stays — that IS how the sink is reached. Verify remains authenticated
        # everywhere a sink actually needs it.
        cookie_free = auth_ctx.get("cookie_free_routes") or ()
        if cookie_free:
            route = (urlparse(str(args.get("target") or "")).path or "/").rstrip("/") or "/"
            if route in cookie_free:
                args.pop("cookie", None)
    # Fixed target request headers (the scan's `scan_headers`), so a tool reaches
    # a header-gated sink the same way ZAP did — Cacti's X-Forwarded-For bypass.
    # nuclei is the tool that confirms that target's command injection; other
    # tools ignore an argument they do not declare.
    if tool == "nuclei" and auth_ctx.get("headers"):
        args["headers"] = auth_ctx["headers"]
    if tool == "sqlmap" and method != "GET" and auth_ctx.get("csrf_field"):
        args["csrf_field"] = auth_ctx["csrf_field"]
        # Signed in, Cacti's login page has no token field; the form's own page does.
        page = str(args.get("target") or "").replace(SQLMAP_INJECTION_MARKER, "")
        args["csrf_url"] = page or auth_ctx.get("csrf_url", "")


def build_dispatch(finding: dict[str, Any],
                   findings_by_endpoint: dict[Any, list[dict[str, Any]]],
                   fillers: dict[str, str] | None = None,
                   auth_ctx: dict[str, Any] | None = None,
                   oob: bool = False,
                   oracle: bool = False) -> dict[str, Any] | None:
    """The tool + arguments a finding should be verified with.

    ``None`` means no arm named a dispatchable tool. A returned plan whose
    ``tool`` is ``None`` carries a ``refusal`` instead: a tool *was* named, but
    no URL could be derived that would answer a question about the endpoint
    rather than about a payload. Both are recorded, not silently dropped, by the
    caller — the distinction is the difference between "nothing routes here" and
    "we declined to probe this, for this reason".
    """
    tool = verification.selected_tool(finding)
    if tool is None:
        return None
    probe = probe_target(finding, fillers)
    if not probe.probeable:
        return {"tool": None, "refusal": probe.url_source}

    alert = finding.get("alert") or {}
    method = str(alert.get("method") or finding.get("method") or "GET").upper()
    target, param = probe.url, probe.param
    url_source = probe.url_source

    # A path parameter has no name to pass to ``-p``; sqlmap needs the injection
    # point marked in the URL instead, and the route template says which segment
    # may carry it. If no segment can be marked safely the probe is refused
    # rather than sent to test nothing — the caller records that as
    # not-attempted, which is honest, where an unmarked run would have produced
    # a meaningless "refuted".
    if tool == "sqlmap" and probe.injection_point == INJECT_PATH:
        marked = mark_path_injection(target, param, str(finding.get("endpoint_key") or ""))
        if marked is None:
            return {"tool": None, "refusal": PATH_NOT_MARKABLE}
        target, param = marked, ""
        url_source = f"{url_source}+injection-marker"

    args: dict[str, Any] = {"target": target, "param": param, "method": method}
    if tool == "nuclei":
        args["oob"] = oob
        # Oracle (ceiling) only: scope the DAST fuzz to the finding's own class
        # so the probe is a handful of relevant templates, not the whole catalog.
        # The full set exceeds VERIFY_TOOL_TIMEOUT_SECONDS on a blind-RCE sink and
        # self-saturates it (each injection spawns a resident process) before the
        # OOB callback lands. A blind run keeps the full set — scoping there would
        # inject triage's hypothesis and cost the loop's independence.
        if oracle:
            tag = evidence_class.nuclei_dast_tag(alert)
            if tag:
                args["tags"] = tag
    # The two wrappers that can carry a request body get one when the flagged
    # parameter lives there. sqlmap passes it to `--data`; the browser oracle
    # delivers it through a self-submitting bootstrap form, which is what lets a
    # form-field XSS be settled by EXECUTION rather than by string matching.
    if tool in BODY_CAPABLE_TOOLS and method != "GET":
        drop = {(auth_ctx or {}).get("session_cookie", "")} - {""}
        args["data"] = _form_body(findings_by_endpoint, finding, fillers or {}, drop)
    if tool == "sqlmap" and not sqlmap_can_address(
            target, param, str(args.get("data") or "")):
        return {"tool": None, "refusal": PARAM_NOT_IN_REQUEST}
    # The same refusal for the wrappers that send no body at all: a body-only
    # parameter is not in the request they make, so whatever they report is
    # about the query string they fuzzed instead. A body-capable tool that ended
    # up with no body to send is refused here too — it would otherwise fall
    # through to a URL-only probe of a parameter that is not in the URL.
    if probe.injection_point == INJECT_BODY and not args.get("data"):
        return {"tool": None, "refusal": PARAM_NOT_IN_TOOLS_REQUEST}
    _apply_auth(tool, args, method, auth_ctx)
    # Which body fields the target declared no value for. A refutation from a
    # request that was half-invented is weaker than one from a request the
    # application would accept, and only the artifact can say which this was.
    synthetic = placeholder_fields(str(args.get("data") or ""))
    return {
        "tool": tool,
        **({"placeholder_fields": synthetic} if synthetic else {}),
        "arguments": args,
        "plugin_id": str(alert.get("plugin_id") or ""),
        "url_source": url_source,
        "injection_point": probe.injection_point,
    }


# -- oracle-seeded (marker) dispatch ---------------------------------------
#
# `VERIFY_ORACLE_SEED_DISPATCH`, oracle mode only. A finding-derived dispatch
# needs a ZAP finding; when a documented marker's sink raised none — the active
# scanner never reached it within the cap — nothing routes to that sink and the
# CVE goes unconfirmed in-pipeline. This synthesises the dispatch FROM THE MARKER
# instead. It never runs blind (the caller gates it on the oracle block), it uses
# the tool the normal path would, and its verdict still goes through
# `verification.resolve_verdict`; only the probe's ORIGIN is the marker, not an
# alert.


def oracle_seed_tool(zap_rules: "Any") -> "str | None":
    """The tool the rescan table routes a marker's own rule(s) to, or ``None``.

    The same deterministic lookup :func:`~dast_orchestrator.domain.verification.selected_tool`
    uses for a flagged finding — keyed on the ZAP rule — so an oracle-seeded probe
    is dispatched to the tool the normal path would have chosen, not a second
    guess. The first of the marker's ``zap_rules`` that names a dispatchable tool
    wins; a marker whose rules route nowhere is not seeded.
    """
    for rule in zap_rules or ():
        tool = rescan_table.decide({"pluginId": str(rule)}).tool
        if tool in verification.DISPATCHABLE_TOOLS:
            return tool
    return None


def build_oracle_seed_dispatch(marker: "Any", target: "targets.Target",
                               auth_ctx: "dict[str, Any] | None" = None,
                               oob: bool = False) -> "dict[str, Any] | None":
    """Synthesise one verify dispatch from a ground-truth marker's own sink.

    ``None`` when the marker's rule routes to no dispatchable tool (nothing to
    probe with). Otherwise the plan mirrors :func:`build_dispatch`'s shape, built
    from the marker rather than from an observed alert — there is none:

    * the sink URL is the target's base plus the marker's documented ``probe``
      path (query and all), the one place a probe URL may come from a declared
      request rather than an observation, for the reason a sibling URL may come
      from a template (:func:`build_sibling_dispatches`): the sink raised no
      alert, so the marker is the only source;
    * the tool is :func:`oracle_seed_tool` of the marker's rule;
    * nuclei is scoped to the finding's class
      (:func:`~dast_orchestrator.domain.evidence_class.nuclei_dast_tag`) and OOB-armed
      exactly as the oracle branch of :func:`build_dispatch` does, so a blind-RCE
      sink is confirmed out of band inside the tool timeout instead of
      self-saturating the whole DAST catalog;
    * the marker's ``auth`` is honoured through :func:`_apply_auth` — the session
      cookie is dropped for an unauthenticated sink via
      ``auth_ctx['cookie_free_routes']`` (so a valid admin session cannot route
      Cacti's ``remote_agent.php`` off its unauthenticated branch and suppress the
      CVE), and the scan's fixed headers (the ``X-Forwarded-For`` reach) are added
      for nuclei, exactly as every other probe's are.

    The synthetic ``alert`` carries the marker's rule id and CWE only — enough for
    :func:`~dast_orchestrator.domain.verification.resolve_verdict`'s class gate to check
    a confirmation against the marker's class — and is never a ZAP alert; the
    record the caller builds says so (:data:`ORIGIN_ORACLE_SEED`).
    """
    tool = oracle_seed_tool(marker.zap_rules)
    if tool is None:
        return None
    method = str(marker.probe_method or "GET").upper()
    url = target.base_url.rstrip("/") + marker.probe_path
    alert = {
        "plugin_id": str(marker.zap_rules[0]) if marker.zap_rules else "",
        "cweid": marker.cwe,
        "name": marker.name,
        "method": method,
    }
    # nuclei carries its own payloads and fuzzes per template, so it is handed a
    # URL and no parameter — the same shape `build_dispatch` gives it.
    args: dict[str, Any] = {"target": url, "param": "", "method": method}
    if tool == "nuclei":
        args["oob"] = oob
        tag = evidence_class.nuclei_dast_tag(alert)
        if tag:
            args["tags"] = tag
    _apply_auth(tool, args, method, auth_ctx)
    return {
        "tool": tool,
        "arguments": args,
        "plugin_id": alert["plugin_id"],
        "url_source": URL_ORACLE_SEEDED,
        "alert": alert,
        "marker_id": marker.id,
        "cve": marker.cve,
        "auth": marker.auth,
        "zap_rules": list(marker.zap_rules),
        "sink": marker.probe_route,
    }


# -- correlated (namespace-2) dispatch -------------------------------------


def _oracle_upgrade(suggested: str, alert: dict[str, Any]) -> str:
    """Send an XSS-class claim to the execution oracle the model cannot name.

    The synthesis schema's ``suggested_tool`` enum predates ``browser`` and
    lists ``sqlmap``/``nuclei``/``ffuf``/``interactsh``, so a model looking at a
    reflected-XSS propagation claim can only ask for nuclei — and nuclei is a
    string matcher. That is the 40026 defect one level up: this pipeline once
    reported a live XSS *refuted* because output escaping altered the payload on
    the way back without preventing execution, and the fix was an oracle whose
    question is "did script run?" rather than "did my bytes come back?".

    So the anchor's own ZAP rule decides instead
    (:data:`~dast_orchestrator.domain.verification.XSS_RULES`), which is a
    deterministic lookup and costs nothing the model could have added: a
    propagation claim's contribution is the *routes*, not the tool.

    Deliberately scoped to the propagation dispatch. The routing of flagged
    findings stays :mod:`~dast_orchestrator.domain.rescan_table`'s, unchanged, so every
    stored comparison remains comparable.
    """
    if str(alert.get("plugin_id") or "") in verification.XSS_RULES:
        return "browser"
    return suggested


def build_correlated_dispatch(correlated: dict[str, Any],
                              findings_by_id: dict[str, dict[str, Any]],
                              auth_ctx: dict[str, str] | None = None,
                              oob: bool = False) -> dict[str, Any] | None:
    """Route a correlated finding by borrowing a supporting finding's concrete URL.

    A synthesis finding names route *templates*, not concrete URLs, so it cannot
    be probed directly. It does cite the per-endpoint findings it rests on, and
    those carry example URLs — verifying the cited evidence is the closest
    honest probe of a cross-endpoint claim. ``suggested_tool: none`` (e.g. the
    systemic-CSP finding) yields ``None``: there is nothing for a scanner to
    settle.
    """
    tool = correlated.get("suggested_tool")
    if tool not in verification.DISPATCHABLE_TOOLS:
        return None
    for fid in correlated.get("supporting_finding_ids") or []:
        support = findings_by_id.get(fid)
        if not support:
            continue
        probe = probe_target(support)
        if not probe.probeable:
            continue
        alert = support.get("alert") or {}
        tool = _oracle_upgrade(tool, alert)
        method = str(alert.get("method") or "GET").upper()
        args: dict[str, Any] = {"target": probe.url, "param": probe.param,
                                "method": method}
        # Mirrors `build_dispatch`. Without it the nuclei wrapper's own default
        # applied, so every correlated finding armed OAST against the interactsh
        # sink on runs whose configuration
        # said `VERIFY_OOB=0` — and whose artifact recorded `oob_enabled: false`
        # beside a command carrying `-iserver`. Six rounds in the stored corpus.
        if tool == "nuclei":
            args["oob"] = oob
        _apply_auth(tool, args, method, auth_ctx)
        return {"tool": tool, "arguments": args, "via_finding_id": fid,
                "url_source": probe.url_source}
    return None


# -- sibling routes: the dispatch half of a propagation claim ---------------
#
# Synthesis v5 shipped the *prompt* half: a propagation claim enumerates the
# route templates it predicts share the weakness, unflagged siblings included,
# and is forbidden from re-grouping findings pass 1 already produced. The routes
# that are the entire content of the prediction would otherwise never be touched
# (the claim verified only against the one flagged finding it cites); everything
# below probes them.

#: The one synthesis pattern whose ``affected_routes`` are a *prediction* rather
#: than a description of what was already found. A systemic-absence claim's
#: routes are the routes the finding was observed on; probing them verifies
#: nothing new, and there are dozens of them.
PROPAGATION_PATTERN = "propagation-shared-handler"

#: Sibling routes one claim may probe — **0, so the propagation dispatch is OFF
#: by default and is turned on with ``--max-siblings N`` / ``VERIFY_MAX_SIBLINGS``.**
#:
#: Off by default for the same reason an ensemble, OAST and pull retrieval are:
#: it changes what a ``verify`` run *does*, and the default has to stay the
#: thing every recorded number in this project was produced by. Three specific
#: costs make it a deliberate purchase rather than a free improvement:
#:
#: * it adds dispatches and a new finding class (``s-`` ids, its own report
#:   section), so a run with it is not comparable with a run without;
#: * the reachability pre-check needs the driver to reach the target over
#:   ``dast-net``, a precondition ``verify`` did not previously have;
#: * it is **unvalidated**. Two live runs, zero confirmations, and on the only
#:   corpus that exercises it not one probe reached the page its claim was
#:   about — five routes did not exist and the other seven redirected an
#:   unauthenticated request to the login page.
#:
#: When it IS on, 3 is the per-claim cap: a propagation claim can name a dozen
#: routes (``context.RepoRefCommit`` names seven on the Gitea corpus,
#: ``context.RepoRefTag`` six), and one broad claim must not exhaust a dispatch
#: budget the flagged findings also draw on. Three distinguishes "the prediction
#: holds on the family" from "it holds nowhere" while leaving room for the
#: per-endpoint work.
DEFAULT_MAX_SIBLINGS = 0

#: What ``--max-siblings`` means when it is switched on without a number.
SIBLINGS_WHEN_ENABLED = 3

#: A sibling probe's URL was BUILT from a route template, not observed. Recorded
#: on every sibling dispatch because it changes how its verdict must be read —
#: see :func:`build_sibling_dispatches`.
URL_ROUTE_TEMPLATE = "route-template"
#: …and the anchor's own observed URL supplied the placeholder values, which is
#: the difference between a probe and a 404.
URL_ROUTE_TEMPLATE_BOUND = "route-template+anchor-vars"

#: ``"GET /{username}/{reponame}/commits/*"`` — the shape of an entry in
#: ``affected_routes``, which is also a Noir ``endpoint_key``. Matched rather
#: than split, because the field is model-authored free text and the corpus
#: contains entries like ``"All 40+ routes with session-plumbing guard"``.
_ROUTE_ENTRY_RE = re.compile(r"^(?P<method>[A-Z]{3,7})\s+(?P<path>/\S*)$")


def parse_route(entry: str) -> "tuple[str, str] | None":
    """Split an ``affected_routes`` entry into method and route template.

    ``None`` for anything that is not one. The model writes this field, and on
    the stored corpus it has written prose into it — a claim whose routes a
    reader cannot turn into requests is exactly the claim the synthesis prompt
    forbids, and the honest handling is to probe the entries that are routes and
    leave the rest visible in the artifact rather than guess at them.
    """
    match = _ROUTE_ENTRY_RE.match(entry.strip())
    return (match["method"], match["path"]) if match else None


def sibling_url(base_url: str, template: str, path_vars: dict[str, str],
                param: str, value: str = BENIGN_PARAM_VALUE) -> str:
    """A concrete, probeable URL for a route the scanner never visited.

    The one place in this project that builds a probe URL from a template rather
    than from an observation, and it is legitimate here for the reason it is
    refused in :class:`ProbeTarget`: a sibling route HAS no observation, so the
    template is not a worse source than the alert — it is the only source.

    ``path_vars`` should carry the anchor route's own observed values
    (:func:`~dast_orchestrator.adapters.noir_runner.bind_path_vars`) on top of the
    target's defaults, so ``/{username}/{reponame}/commits/tag/*`` becomes
    ``/thesis/demo/commits/tag/master/search`` rather than
    ``/1/1/commits/tag/index``.
    """
    path = noir_runner.substitute_path(template, path_vars)
    if not path.startswith("/"):
        path = "/" + path
    parsed = urlparse(path)
    # A template may already carry a query string — WordPress's endpoint keys
    # are `/wp-admin/admin-ajax.php?action=<name>` — so the flagged parameter is
    # added to what is there rather than replacing it.
    query = [(n, v) for n, v in parse_qsl(parsed.query, keep_blank_values=True)
             if n != param]
    if param:
        query.append((param, value))
    return base_url.rstrip("/") + urlunparse(
        ("", "", parsed.path, "", urlencode(query), ""))


def build_sibling_dispatches(
        correlated: dict[str, Any],
        plan: "dict[str, Any] | None",
        support: "dict[str, Any] | None",
        target: "targets.Target | None",
        already_verified: "set[str]",
        cap: int = DEFAULT_MAX_SIBLINGS,
        auth_ctx: "dict[str, str] | None" = None,
        oob: bool = False) -> list[dict[str, Any]]:
    """One probe per unflagged sibling route a propagation claim predicts.

    **This is where a synthesis claim can produce a finding the scan could not.**
    The anchor probe re-tests a route ZAP already flagged and can at best agree
    with it; a sibling probe asks the question the claim actually makes — does
    the same weakness sit on a route the crawl never reached? A confirmation
    there is a real vulnerability that no part of the deterministic pipeline
    could have found, and :func:`sibling_finding` turns it into one.

    Four guards, each for a mistake that is easy to make here:

    * **Only propagation claims.** :data:`PROPAGATION_PATTERN` is the one whose
      routes are a prediction; the rest describe routes already observed.
    * **Never a route that already carries a finding this run is verifying.**
      That is the double-verification trap the v5 prompt forbids at claim level,
      enforced here at dispatch level: the route would be probed twice, once per
      endpoint and once as a sibling, and the two verdicts would be counted as
      independent. This is also the only guard that leaves the feature any work to
      do — most routes carry *some* finding (every crawled page is missing a CSP
      header) while few carry
      one selected for verification, so a guard on "has any finding" would skip
      every sibling of every claim.
    * **GET only.** The execution oracle loads a URL, and a synthesised POST
      body at a route nothing was ever observed on would be inventing the
      request as well as the URL.
    * **A per-claim cap** (:data:`DEFAULT_MAX_SIBLINGS`), so one broad claim
      cannot spend the dispatch budget the flagged findings share.

    **How a sibling verdict must be read, and it is asymmetric.** A confirmation
    is strong: the tool reached a real URL and reproduced the weakness there. A
    refutation is weak, because the URL was *constructed* — a 404 refutes the
    URL, not the claim.

    A **reachability pre-check** removes the worst of that asymmetry rather than
    only documenting it: one plain GET at the clean URL runs before the probe
    (:func:`route_checker`), and a route the application does not serve is
    recorded ``not-attempted`` with
    :data:`~dast_orchestrator.domain.verification.SIBLING_UNREACHABLE` — its **own
    outcome**, not ``not-attempted``, because "we did not get to it" and "we
    asked and the route does not exist" are opposite facts — instead of being
    probed and refuted. That is both the honest reading and a dispatch saved. It
    does not make a refutation strong — a page that exists is still not
    necessarily the page the claim meant — so every record carries the
    ``route_status`` its URL answered, :data:`URL_ROUTE_TEMPLATE` marks how the
    URL was built, the summary counts sibling probes apart from the flagged
    population, and only confirmations reach the report.
    """
    if plan is None or plan.get("tool") is None or target is None:
        return []
    if correlated.get("pattern") != PROPAGATION_PATTERN:
        return []
    support = support or {}
    tool = str(plan["tool"])
    param = str((support.get("alert") or {}).get("param") or "")
    # The execution oracle injects at a named query parameter and guesses none;
    # without one there is nothing to aim it at on a route with no observation.
    if tool == "browser" and not param:
        return []

    anchor_key = str(support.get("endpoint_key") or "")
    bound: dict[str, str] = {}
    _, _, anchor_template = anchor_key.partition(" ")
    anchor_url = str((plan.get("arguments") or {}).get("target") or "")
    if anchor_template and anchor_url:
        bound = noir_runner.bind_path_vars(
            anchor_template, urlparse(anchor_url).path) or {}
    path_vars = {**target.path_vars, **bound}
    url_source = URL_ROUTE_TEMPLATE_BOUND if bound else URL_ROUTE_TEMPLATE

    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in correlated.get("affected_routes") or []:
        if len(out) >= cap:
            break
        parsed = parse_route(str(entry))
        if parsed is None:
            continue
        method, template = parsed
        route = f"{method} {template}"
        if method != "GET" or route == anchor_key or route in already_verified:
            continue
        if route in seen:
            continue
        seen.add(route)
        args: dict[str, Any] = {
            "target": sibling_url(target.base_url, template, path_vars, param),
            "param": param,
            "method": method,
        }
        if tool == "nuclei":
            args["oob"] = oob
        _apply_auth(tool, args, method, auth_ctx)
        out.append({
            "tool": tool,
            "arguments": args,
            "route": route,
            "claim_id": correlated.get("finding_id"),
            "via_finding_id": plan.get("via_finding_id"),
            "plugin_id": str((support.get("alert") or {}).get("plugin_id") or ""),
            "url_source": url_source,
        })
    return out


#: How long the reachability pre-check waits for the target. Short on purpose:
#: it is one GET at a page the caller is about to spend a real probe on, and a
#: target that cannot answer in this long has told us nothing either way.
ROUTE_CHECK_TIMEOUT = 10.0


def route_checker(fetch=None, timeout: float = ROUTE_CHECK_TIMEOUT):
    """A ``url -> status`` callable for the sibling reachability pre-check.

    ``None`` from the returned callable means **we could not check**, which is
    deliberately not the same as "the route is absent": a docker failure, a
    timeout or a refused connection leaves the question open, and the probe then
    runs exactly as it would have before. A missing measurement must never be
    read as a measured 404 — the same rule every cost field here follows.

    :param fetch: the transport, defaulting to the one-shot curl container on
        ``dast-net`` (:func:`dast_orchestrator.adapters.auth.container_fetch`). The
        driver runs on the *host*, which cannot resolve ``target-gitea``, so
        this is the only transport that reaches the target the way the scanner
        and the verification wrappers do. Injected so the loop is testable
        without a container.
    """
    fetch = fetch or auth.container_fetch()

    def check(url: str) -> "int | None":
        try:
            status, _location, _body = fetch("GET", url, timeout)
        except Exception:  # noqa: BLE001 - any transport failure is "unknown"
            return None
        return status or None

    return check


def sibling_finding_id(claim_id: str, route: str) -> str:
    """A stable id for a finding reached by propagation, in its own ``s-`` space.

    Its own prefix beside ``f-`` (per-endpoint) and ``c-`` (synthesis claim),
    because it is a third thing: a concrete, confirmed vulnerability at one
    route that no ZAP alert underlies. Derived from the claim and the route, so
    two runs that confirm the same propagation agree on the id.
    """
    import hashlib

    digest = hashlib.sha256(f"{claim_id}|{route}".encode()).hexdigest()[:12]
    return f"s-{digest}"


def sibling_record(probe: dict[str, Any], result: dict[str, Any],
                   claim: dict[str, Any], cfg: dict[str, Any],
                   route_status: "int | None" = None,
                   not_attempted_reason: str = "") -> dict[str, Any]:
    """One sibling probe's verdict, with the provenance that makes it readable.

    A confirmed sibling carries its own ``finding_id`` and is a first-class
    finding: a real vulnerability at a route ZAP never flagged, because the
    crawl never reached it. ``found_by`` says how it was reached — synthesis
    propagation, verified at a URL built from the route template — so the
    detection-rate accounting can separate what the LLM layer reached from what
    ZAP's blind crawl did, without treating it as suspect. That provenance is
    bookkeeping; the finding itself is not second class.

    :param route_status: what a plain GET at the *clean* sibling URL answered
        before any payload was sent, or ``None`` when the check could not be
        made. It is on the record whatever the verdict, because it is what tells
        a reader whether a refutation is about the application or about a URL
        that was constructed and does not exist.
    :param not_attempted_reason: one of
        :data:`~dast_orchestrator.domain.verification.NA_REASONS` when nothing was
        dispatched.
    """
    outcome = str(result.get("outcome") or INCONCLUSIVE)
    record: dict[str, Any] = {
        "finding_id": sibling_finding_id(str(probe.get("claim_id") or ""),
                                         str(probe.get("route") or "")),
        "claim_id": probe.get("claim_id"),
        "pattern": claim.get("pattern"),
        "route": probe.get("route"),
        "via_finding_id": probe.get("via_finding_id"),
        "plugin_id": probe.get("plugin_id"),
        "rule_name": claim.get("title"),
        "severity": claim.get("severity"),
        "tool": probe.get("tool"),
        "target": (probe.get("arguments") or {}).get("target", ""),
        "param": (probe.get("arguments") or {}).get("param", ""),
        "method": (probe.get("arguments") or {}).get("method", "GET"),
        "url_source": probe.get("url_source"),
        # What a plain GET at the clean URL answered, before any payload. `None`
        # means the check itself failed, which is not the same as a reachable
        # route and is not the same as an absent one.
        "route_status": route_status,
        "outcome": outcome,
        "not_attempted_reason": not_attempted_reason or None,
        "tool_ran": verification.tool_ran(result),
        "detail": result.get("detail"),
        "evidence": result.get("evidence"),
        "config": cfg,
        "found_by": {
            "layer": "llm-cross-endpoint-synthesis",
            "mechanism": "propagation-sibling-probe",
            "route_never_flagged": True,
            "url_derivation": probe.get("url_source"),
            "route_status": route_status,
            # Said on the record rather than left to a reader: this probe's two
            # verdicts do not carry the same weight.
            "how_to_read": (
                "A confirmation is a vulnerability at a route the scan never "
                "flagged, reached by the LLM layer rather than by the crawl. A "
                "refutation is weaker than a refutation of a flagged finding: "
                "the URL was constructed from a route template, so it is only "
                "as good as `route_status` says the URL is. A route that "
                "answered 404/410 is never probed at all — it is recorded "
                f"`{verification.SIBLING_UNREACHABLE}`, which is a result about "
                "the claim (the predicted route does not exist) and not a "
                "not-attempted. A 3xx says "
                "the route exists and redirects — on an unauthenticated run "
                "that is usually a redirect to the login page, so the probe "
                "tested the login page and its refutation says nothing about "
                "the route. A null route_status means the check could not be "
                "made, which is not the same as either."
            ),
        },
    }
    record.update({k: result[k] for k in
                   ("command", "exit_code", "seconds", "timed_out",
                    "tool_warnings", "matched_templates", "stdout_excerpt",
                    "stderr_excerpt")
                   if result.get(k) is not None})
    return record


def verify_config(**values: Any) -> dict[str, Any]:
    """The verification settings that make two runs of one triage different.

    The budget is in here in full, and that is the point: the same correlation
    verified at ``max_dispatch_all_rules`` 15 and at 30 produces different
    ``not-attempted`` counts, and two such runs were once compared as though
    they described different *modes* rather than different budgets. A digest
    over these values is what makes that mistake visible in the name.
    """
    return values


# -- the async dispatch loop -----------------------------------------------


class Dispatcher:
    """Holds one persistent stdio session per tool and enforces the budget.

    Sessions are opened lazily — a run that dispatches only nuclei never spawns
    the sqlmap or ffuf wrapper — and closed together when the run ends.
    """

    def __init__(self, budget: DispatchBudget, stack: AsyncExitStack) -> None:
        self.budget = budget
        self._stack = stack
        self._sessions: dict[str, ClientSession] = {}
        self.started = time.monotonic()
        self.dispatched = 0
        self.per_rule: dict[str, int] = {}

    async def _session(self, tool: str) -> ClientSession:
        if tool not in self._sessions:
            read, write = await self._stack.enter_async_context(
                stdio_client(_wrapper_command(tool))
            )
            session = await self._stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            self._sessions[tool] = session
        return self._sessions[tool]

    def _budget_block(self, plugin_id: str, off_budget: bool = False) -> str | None:
        """The reason this dispatch is refused, or ``None`` to proceed.

        :param off_budget: the probe is outside the run-wide dispatch budget —
            skip the run-total cap AND the wall clock (the per-rule layer is
            skipped the usual way, by the caller passing ``plugin_id=""``). Set
            ONLY for the oracle-seeded dispatch: it is a bounded single-shot set
            (one probe per missed marker, each capped by ``tool_timeout_seconds``)
            that exists BECAUSE the in-band finding loop never reached the sink,
            so letting that same loop's budget starve it would defeat the reading
            the config is for. It cannot run away — there is no loop and the
            marker set is tiny — so neither the run total nor the wall clock,
            both there to bound the 249-finding loop, applies to it.

        Each ceiling is skipped when it is :data:`~dast_orchestrator.domain.verification.NO_CAP`
        (``-1``), which is what makes an exhaustive run expressible: on this workload
        most budget refusals are the per-rule cap on a couple of noisy rules rather
        than the run total or the clock. So "what would the unasked findings have
        said?" needs to be answerable without inventing a sentinel like ``99999``
        at the call site.

        **The order is the precedence, and it is deliberate.** The run total and
        the wall clock are checked *before* the per-rule layer, so:

        * a rule named in ``max_dispatch_rule`` overrides
          ``max_dispatch_all_rules`` **for that rule only**, and
        * no per-rule cap can outlive the run total — once
          ``max_dispatches_total`` is reached the stage is over, whatever any
          individual rule was still allowed.

        That is what makes the per-rule layer safe to raise: a sheet can give one
        noisy rule 200 dispatches without the run becoming unbounded, because
        the total still ends it. Reversing the order would let a generous
        per-rule cap quietly overrun the ceiling the stage was given.

        The per-rule layer is asked through
        :meth:`~dast_orchestrator.domain.verification.DispatchBudget.cap_for`, so a rule
        named individually gets its own ceiling and everything else gets the
        blanket one. The refusal text says **which** of the two refused it,
        because "raise the cap" is a different instruction in each case.
        """
        if (not off_budget and self.budget.max_minutes != verification.NO_CAP
                and (time.monotonic() - self.started) > self.budget.max_minutes * 60):
            return f"budget: run wall-clock cap ({self.budget.max_minutes} min) reached"
        if (not off_budget and self.budget.max_dispatches_total != verification.NO_CAP
                and self.dispatched >= self.budget.max_dispatches_total):
            return ("budget: run total cap "
                    f"({self.budget.max_dispatches_total} dispatches) reached")
        cap = self.budget.cap_for(plugin_id)
        if cap != verification.NO_CAP and self.per_rule.get(plugin_id, 0) >= cap:
            named = dict(self.budget.rule_caps)
            which = "rule cap" if plugin_id in named else "all-rules cap"
            return (f"budget: {which} ({cap}) reached for plugin {plugin_id}")
        return None

    def can_dispatch(self, plugin_id: str = "") -> bool:
        """Whether a probe on this rule could run right now, without running it.

        The budget is enforced inside :meth:`run`, which is where it belongs.
        This exists so a caller can ask *before* spending something the budget
        will then refuse — an LLM configuration pays for its proposal up front,
        and a proposal the executor discards unread is money for nothing.
        """
        return self._budget_block(plugin_id) is None

    async def run(self, tool: str, arguments: dict[str, Any],
                  plugin_id: str = "",
                  exempt_per_rule: bool = False,
                  off_budget: bool = False) -> dict[str, Any]:
        """Dispatch one tool call, or return a NOT_ATTEMPTED verdict if capped.

        :param exempt_per_rule: skip the per-rule cap (never the run-wide
            dispatch cap or the wall clock). Set for a **sibling probe**, and
            for nothing else. The per-rule cap exists to stop one prolific ZAP
            rule spending the budget on near-duplicates — 10031 fires 348 times
            on the Gitea corpus — but a sibling probe is not another instance of
            that rule. It visits a route no other probe visits, and it is the
            one thing this stage does that the scanner could not.

            Without it every sibling probe can come back ``not-attempted``, refused
            by the anchor rule's per-rule cap which the flagged findings already
            spent — leaving the propagation half hostage to how noisy its anchor's
            rule happens to be, which has nothing to do with it.
        :param off_budget: skip the run-total cap and the wall clock too (see
            :meth:`_budget_block`), and do not count toward the run total. Set
            ONLY for the oracle-seeded dispatch — the bounded single-shot probe
            at a documented sink the finding loop never reached, which that same
            loop's budget must not be able to starve.
        """
        block = self._budget_block("" if exempt_per_rule else plugin_id,
                                    off_budget=off_budget)
        if block is not None:
            return {"outcome": NOT_ATTEMPTED, "tool": tool, "detail": block,
                    "evidence": None}

        session = await self._session(tool)
        arguments = {**arguments, "timeout": self.budget.tool_timeout_seconds}
        # An off-budget probe (oracle-seeded) does not draw on the run total, so
        # it never shifts the finding loop's dispatch population — the loop keeps
        # exactly the budget the frozen ceiling gave it.
        if not off_budget:
            self.dispatched += 1
        if not exempt_per_rule:
            self.per_rule[plugin_id] = self.per_rule.get(plugin_id, 0) + 1
        # Each wrapper exposes its single tool as ``verify_<tool>``; the short
        # name is what the artifact and the routing table use.
        result = await session.call_tool(f"verify_{tool}", arguments)
        return _parse_tool_result(result, tool)




def _parse_tool_result(result: Any, tool: str) -> dict[str, Any]:
    """Extract the wrapper's JSON verdict from an MCP CallToolResult.

    A tool error (``is_error``) or unparseable output is surfaced verbatim in
    ``detail`` rather than flattened to a bare "inconclusive": masking it once
    hid a wrong tool name behind 25 identical inconclusive verdicts.
    """
    texts = []
    for content in getattr(result, "content", []) or []:
        text = getattr(content, "text", None)
        if not text:
            continue
        texts.append(text)
        if not getattr(result, "is_error", False):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                continue
    joined = " ".join(texts)[:400] or "no content"
    return {
        "outcome": INCONCLUSIVE, "tool": tool, "evidence": None,
        "detail": f"wrapper returned no parseable verdict ({joined})",
        # A wrapper that answered with something unreadable did not test
        # anything, and saying so is load-bearing: without it
        # `verification.tool_ran` falls through to its legacy reading and
        # returns True, so a wrapper ERROR could support a refutation — as when a
        # browser probe's tool name did not match the driver's and every round
        # recorded `tool_ran: True` behind "Unknown tool: verify_browser".
        "tested": False,
    }



__all__ = [
    'ProbeTarget',
    'probe_target',
    'looks_like_payload',
    'restore_path_payload',
    'mark_path_injection',
    '_is_placeholder',
    '_FORM_FIELD_RE',
    '_ARRAY_FIELD_RE',
    'sqlmap_can_address',
    'filler_for',
    '_form_body',
    'placeholder_fields',
    '_apply_auth',
    'build_dispatch',
    'oracle_seed_tool',
    'build_oracle_seed_dispatch',
    '_oracle_upgrade',
    'build_correlated_dispatch',
    'PROPAGATION_PATTERN',
    'DEFAULT_MAX_SIBLINGS',
    'SIBLINGS_WHEN_ENABLED',
    'URL_ROUTE_TEMPLATE',
    'URL_ROUTE_TEMPLATE_BOUND',
    '_ROUTE_ENTRY_RE',
    'parse_route',
    'sibling_url',
    'build_sibling_dispatches',
    'ROUTE_CHECK_TIMEOUT',
    'route_checker',
    'sibling_finding_id',
    'sibling_record',
    'verify_config',
    'Dispatcher',
    '_parse_tool_result',
]
