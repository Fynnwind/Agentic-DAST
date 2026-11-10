"""The evidence assembler: build the per-finding pack every LLM prompt carries.

The pack is **pushed, not pulled** — assembled deterministically and always attached, so
the same finding always yields the same pack (the baseline for the model-retrieval
experiment); ``Assembler`` is built once per run and read-only under concurrency.
**Storage is generous, excerpting strict**: a body dropped at scan time is unrecoverable,
but long irrelevant context degrades attention, so what reaches a prompt is as small as
the policy (``config/excerpts/``) allows. → DECISIONS.md.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]

#: Where the excerpt policies live. One YAML file per policy, selected by name,
#: copied verbatim into the artifact — the same shape ``prompts/`` already uses,
#: and for the same reason: a policy change must be a configuration diff and a
#: sheet row, never a source edit between two runs of one corpus.
POLICY_DIR = REPO_ROOT / "config" / "excerpts"

DEFAULT_POLICY = "balanced"

#: How a prompt's evidence gets there. Named here rather than imported from
#: :mod:`dast_orchestrator.adapters.retrieval` so the assembler stays free of the MCP
#: client — this module decides what a pack *contains*, that one how the missing
#: parts are fetched.
PUSH = "push"
PULL = "pull"

#: How an endpoint's handler source was reached, tried in this order.
#: ``callees``: the symbols Noir named for this endpoint. ``registration``: the
#: callable the endpoint's registration call names (:mod:`.dispatch`).
#: ``code_paths``: every definition in the file Noir located — only for a
#: technology whose endpoint IS its file (:data:`dispatch.FILE_DISPATCH`), so it
#: is file context, not a located handler. ``none``: nothing resolved.
RESOLVED_BY_CALLEES = "callees"
RESOLVED_BY_REGISTRATION = "registration"
RESOLVED_BY_CODE_PATHS = "code_paths"
RESOLVED_BY_NONE = "none"
RESOLUTION_TIERS = (RESOLVED_BY_CALLEES, RESOLVED_BY_REGISTRATION,
                    RESOLVED_BY_CODE_PATHS, RESOLVED_BY_NONE)
#: The tiers whose source is the endpoint's OWN handler — what "handler located"
#: means in the artifact, the metrics and the triage gate.
HANDLER_TIERS = frozenset({RESOLVED_BY_CALLEES, RESOLVED_BY_REGISTRATION})


class EvidenceError(RuntimeError):
    """Raised when an excerpt policy is missing or unreadable."""


# -- rule classification ---------------------------------------------------

# The evidence-class vocabulary (the CLASS_* constants, the rule/CWE/name tables
# and rule_class) is domain vocabulary, not a context concern — the storage and
# excerpt rules here ASK it what a finding needs, and domain.verification asks it
# the same. It lives in domain.evidence_class so this layer and domain can both
# read it downward. Re-exported here so this module's own references, and any
# `evidence.rule_class` / `evidence.CLASS_*` callers, keep working unchanged.
from dast_orchestrator.domain.evidence_class import (  # noqa: E402,F401
    CLASS_HEADER, CLASS_COOKIE, CLASS_IDENTIFICATION, CLASS_XSS, CLASS_SSTI,
    CLASS_SQLI, CLASS_TRAVERSAL, CLASS_REDIRECT, CLASS_DISCLOSURE,
    CLASS_INJECTION, CLASS_OTHER, RULE_CLASSES, CWE_CLASSES, NAME_PATTERNS,
    rule_class,
)


#: The only classes for which a response body can never change the verdict. A
#: missing CSP header is proven by its absence and no body will ever speak to
#: it; a Set-Cookie attribute is in the header or it is not; ZAP's
#: identification rules (``10112`` and friends) and its User-Agent fuzzer report
#: on the exchange's shape rather than its content.
#:
#: **Everything else keeps its body**, including Informational rules — ``10031``
#: is Informational and its whole proof is the reflected attribute in the body.
#: Erring the other way is what would make an excerpt experiment unrunnable.
BODYLESS_CLASSES = frozenset({CLASS_HEADER, CLASS_COOKIE, CLASS_IDENTIFICATION})


def retain_body(classes: Iterable[str]) -> bool:
    """Whether a stored message keeps its response body.

    :param classes: the rule classes of **every** alert that cites this message.
        One message commonly backs several alerts — a page that is missing a CSP
        header is usually also the page whose parameter was reflected — so the
        body is kept when *any* of them could need it.
    """
    return any(klass not in BODYLESS_CLASSES for klass in classes)


# -- the message sidecar ---------------------------------------------------

#: Ceiling on a single stored response body, in characters. Generous by design:
#: the largest body observed on this target is ~16 KB, so 256 KB truncates
#: nothing real and exists only so one pathological response cannot make the
#: sidecar unbounded. A truncated body says so in ``response_body_truncated``.
MAX_STORED_BODY_CHARS = 256 * 1024


def message_ids(alerts: Iterable[Mapping[str, Any]]) -> list[str]:
    """Every ZAP message id an alert points at, in first-seen order.

    Both ``messageId`` and ``sourceMessageId`` are collected: a passive rule
    alerts on the message it was raised from, but an active-scanner alert also
    names the *original* request its payload was derived from, and the two
    together are the before/after pair a reader of an injection finding needs.
    """
    ids: dict[str, None] = {}
    for alert in alerts:
        for key in ("messageId", "sourceMessageId"):
            value = str(alert.get(key) or "").strip()
            if value:
                ids.setdefault(value, None)
    return list(ids)


def build_message_sidecar(
    alerts: Iterable[Mapping[str, Any]],
    messages: Mapping[str, Mapping[str, Any]],
    max_body_chars: int = MAX_STORED_BODY_CHARS,
) -> dict[str, Any]:
    """Reduce fetched ZAP messages to the gitignored ``scan-zap-messages.json``.

    Headers are kept for **every** message; response bodies are kept unless
    every alert citing the message is in a :data:`BODYLESS_CLASSES` rule class.
    The counts of each decision travel in the artifact, because "the body was
    not stored" and "the response had no body" must not look alike to a later
    reader.

    :param alerts: the run's alerts, used only to work out which classes cite
        which message.
    :param messages: what :meth:`~dast_orchestrator.adapters.zap_client.ZapClient.messages_by_id`
        returned, keyed by id.
    """
    classes_by_message: dict[str, set[str]] = {}
    for alert in alerts:
        klass = rule_class(alert)
        for key in ("messageId", "sourceMessageId"):
            value = str(alert.get(key) or "").strip()
            if value:
                classes_by_message.setdefault(value, set()).add(klass)

    stored: dict[str, dict[str, Any]] = {}
    bodies_kept = bodies_dropped = truncated = 0
    for mid, message in messages.items():
        classes = classes_by_message.get(mid, {CLASS_OTHER})
        entry: dict[str, Any] = {
            "id": mid,
            "request_header": message.get("requestHeader") or "",
            "request_body": message.get("requestBody") or "",
            "response_header": message.get("responseHeader") or "",
            "rtt_ms": message.get("rtt"),
            # Which rule classes cite this exchange, so a reader can see why the
            # body decision below went the way it did.
            "cited_by_classes": sorted(classes),
        }
        if retain_body(classes):
            body = message.get("responseBody") or ""
            if len(body) > max_body_chars:
                body = body[:max_body_chars]
                entry["response_body_truncated"] = True
                truncated += 1
            entry["response_body"] = body
            bodies_kept += 1
        else:
            # Not an empty body: a body deliberately not stored. Spelled as its
            # own field so nothing downstream can read absence as emptiness.
            entry["response_body_omitted"] = (
                "no alert class citing this message can be settled by a body"
            )
            bodies_dropped += 1
        stored[mid] = entry

    return {
        "schema_version": 1,
        "storage_policy": {
            "bodyless_classes": sorted(BODYLESS_CLASSES),
            "max_body_chars": max_body_chars,
            "rationale": "Storage is generous and excerpting is strict: a body "
                         "dropped at scan time cannot be recovered without "
                         "re-scanning, and an excerpt policy can only be tuned "
                         "against data that was kept.",
        },
        "counts": {
            "messages": len(stored),
            "bodies_stored": bodies_kept,
            "bodies_omitted": bodies_dropped,
            "bodies_truncated": truncated,
        },
        "messages": stored,
    }


# -- reading a stored exchange ---------------------------------------------

#: A stored request header block starts with ZAP's request line, which carries
#: an absolute URI: ``GET http://target-gitea:3000/user/login HTTP/1.1``.
_REQUEST_LINE_RE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+HTTP/[\d.]+")
_STATUS_LINE_RE = re.compile(r"^HTTP/[\d.]+\s+(?P<status>\d{3})(?:\s+(?P<reason>.*))?")


@dataclass(frozen=True)
class Exchange:
    """One HTTP request/response pair, parsed out of the sidecar."""

    message_id: str
    method: str = ""
    uri: str = ""
    status: int | None = None
    reason: str = ""
    request_headers: tuple[tuple[str, str], ...] = ()
    response_headers: tuple[tuple[str, str], ...] = ()
    request_body: str = ""
    response_body: str = ""
    #: ``True`` when the body was deliberately not stored, which is a different
    #: fact from an empty body and is reported as such all the way to the prompt.
    body_omitted: bool = False

    def response_header(self, name: str) -> str:
        lowered = name.lower()
        for key, value in self.response_headers:
            if key.lower() == lowered:
                return value
        return ""


def _split_headers(block: str) -> tuple[str, tuple[tuple[str, str], ...]]:
    """Split a raw header block into its first line and its ``name: value`` pairs."""
    lines = [line for line in (block or "").replace("\r\n", "\n").split("\n")]
    if not lines:
        return "", ()
    first, rest = lines[0], lines[1:]
    pairs: list[tuple[str, str]] = []
    for line in rest:
        if not line.strip():
            continue
        name, _, value = line.partition(":")
        if _:
            pairs.append((name.strip(), value.strip()))
    return first, tuple(pairs)


def parse_exchange(message: Mapping[str, Any]) -> Exchange:
    """Turn one sidecar entry into a structured :class:`Exchange`."""
    mid = str(message.get("id") or "")
    request_line, request_headers = _split_headers(message.get("request_header", ""))
    status_line, response_headers = _split_headers(message.get("response_header", ""))
    method = uri = ""
    match = _REQUEST_LINE_RE.match(request_line)
    if match:
        method, uri = match.group("method"), match.group("uri")
    status: int | None = None
    reason = ""
    match = _STATUS_LINE_RE.match(status_line)
    if match:
        status = int(match.group("status"))
        reason = (match.group("reason") or "").strip()
    return Exchange(
        message_id=mid,
        method=method,
        uri=uri,
        status=status,
        reason=reason,
        request_headers=request_headers,
        response_headers=response_headers,
        request_body=message.get("request_body") or "",
        response_body=message.get("response_body") or "",
        body_omitted="response_body_omitted" in message,
    )


# -- what ZAP actually observed --------------------------------------------

#: The alert fields that can carry an observation, most specific first. ZAP has
#: no single "the proof" field and which one a plugin fills is a property of
#: that plugin: ``10031`` fills ``evidence``, ``40018`` and ``90035`` fill
#: ``other``, ``10038`` proves itself by an absence and fills neither.
OBSERVATION_FIELDS = ("evidence", "other", "otherinfo", "attack")


def rule_tags(group: Any) -> list[str]:
    """ZAP's own classification of the rule, as bare tag names.

    The values are documentation URLs and the names are the classification
    (``OWASP_2021_A03``, ``WSTG-v42-INPV-01``, ``CWE-79``), so only the names
    travel: the taxonomy is what places a rule in a family, and the link is 60
    characters the model cannot follow.
    """
    tags = getattr(group, "tags", None) or {}
    return sorted(str(name) for name in tags if str(name).strip())


def normalise_observation(alert: Mapping[str, Any]) -> dict[str, str]:
    """Collect whatever this plugin stored, labelled by the field it came from.

    Returning the field names rather than one merged string is the point: a
    reader (human or model) that is told *"ZAP recorded nothing in any
    observation field"* can weigh the finding differently from one handed an
    empty string, and the 90035 case is exactly why — its ``evidence`` was empty
    while its ``other`` held the proof.
    """
    found: dict[str, str] = {}
    for name in OBSERVATION_FIELDS:
        value = str(alert.get(name) or "").strip()
        if value:
            found[name] = value
    return found


# -- reachability, from observation rather than from guard labels ----------

#: Statuses that prove the request reached the handler rather than a gate.
_REACHED = frozenset({200, 201, 202, 204, 206, 400, 404, 409, 422, 500})
#: Statuses that are a gate answering instead of the handler.
_GATED = {401: "authentication required", 403: "forbidden"}


def reachability(auth_mode: str, exchange: Exchange | None) -> dict[str, Any]:
    """What the run itself proves about who can reach this route.

    Deliberately **not** derived from Noir's ``guards``. Noir tags Gitea's
    ``Go middleware sessioner`` as an ``auth_guard`` on routes like
    ``/explore/users`` that need no login at all — it is session plumbing, not an
    authentication requirement — and pass 2 once produced a documented
    confabulation reasoning from exactly that label. A status code observed on a
    run whose ``auth_mode`` is known is strictly better evidence: a ``200`` on an
    ``auth_mode: none`` run *is* proof the route is anonymously reachable.

    :param auth_mode: ``none`` / ``user`` / ``admin`` — the account the scan ran
        as, straight from ``scan-zap-alerts.json``.
    :param exchange: the exchange behind the finding, or ``None`` when the
        sidecar does not hold it.
    """
    block: dict[str, Any] = {"scan_authenticated_as": auth_mode or "none"}
    if exchange is None or exchange.status is None:
        block["observed"] = "no HTTP exchange was stored for this finding"
        return block
    block["observed_status"] = exchange.status
    anonymous = (auth_mode or "none") == "none"
    if exchange.status in _GATED:
        block["conclusion"] = (
            f"the request was refused by an access gate ({_GATED[exchange.status]}), "
            "so this finding concerns a route the scan did not actually enter"
        )
    elif exchange.status in (301, 302, 303, 307, 308):
        target = exchange.response_header("Location")
        block["redirected_to"] = target
        block["conclusion"] = (
            "the response was a redirect"
            + (f" to {target}" if target else "")
            + (
                "; on an unauthenticated scan a redirect to a login page means "
                "the handler was never reached"
                if anonymous else ""
            )
        )
    elif exchange.status in _REACHED:
        block["conclusion"] = (
            f"the handler answered ({exchange.status})"
            + (
                " on a scan that carried no session, so this route is reachable "
                "anonymously"
                if anonymous
                else f" while the scan was authenticated as {auth_mode}, so this "
                     "says nothing about anonymous reachability"
            )
        )
    else:
        block["conclusion"] = f"status {exchange.status}, not classified"
    return block


# -- the excerpt policy (configuration, not code) --------------------------

#: How a policy may treat a response body.
#:
#: ``none``
#:     Send no body. Correct for the classes whose proof is a header.
#: ``head``
#:     The first ``body_chars`` characters. Enough to show what kind of page
#:     answered without paying for the whole of it.
#: ``around-match``
#:     A window centred on where ZAP's observation appears in the body. This is
#:     the one that matters for reflection classes: the payload is usually deep
#:     inside a 16 KB page and the head would miss it entirely.
#: ``error-region``
#:     A window centred on the first database/stack-trace marker, falling back
#:     to ``around-match`` and then to ``head``.
BODY_MODES = ("none", "head", "around-match", "error-region")

#: Markers ``error-region`` centres on. Deliberately generic and few: this is
#: navigation, not detection — it decides which 600 characters to send, and a
#: miss costs a worse excerpt rather than a wrong verdict.
ERROR_MARKERS = (
    "SQL syntax", "SQLSTATE", "ORA-", "PSQLException", "pq:",
    "Traceback (most recent call last)", "panic:", "goroutine ",
    "Exception", "Fatal error", "Warning:", "runtime error",
)


@dataclass(frozen=True)
class ExcerptRule:
    """What one rule class gets in its prompt."""

    body: str = "head"
    body_chars: int = 800
    request_headers: str = "all"
    response_headers: str = "all"

    def validate(self, where: str) -> None:
        if self.body not in BODY_MODES:
            raise EvidenceError(
                f"{where}: body mode {self.body!r} is not one of {BODY_MODES}"
            )
        if self.body_chars < 0:
            raise EvidenceError(f"{where}: body_chars must not be negative")
        for name, value in (("request_headers", self.request_headers),
                            ("response_headers", self.response_headers)):
            if value not in ("all", "none", "line-only"):
                raise EvidenceError(
                    f"{where}: {name} must be all, none or line-only"
                )


@dataclass(frozen=True)
class ExcerptPolicy:
    """A named, file-backed policy, copied verbatim into every run's artifact.

    Following the pattern ``prompts/`` already established: the *filename* is
    the version, selection is ordinary configuration (``TRIAGE_HTTP_CONTEXT`` / the
    matching flag), and the raw text travels with the run so an artifact stays
    readable after the file is edited or deleted. It is part of the run's
    configuration digest, so two policies over one stored corpus are an A/B a
    sheet can run rather than a source edit between two runs.
    """

    name: str
    description: str
    default: ExcerptRule
    by_class: Mapping[str, ExcerptRule] = field(default_factory=dict)
    #: ``False`` attaches **no evidence pack at all** — no rule description, no
    #: normalised observation, no exchange, no reachability. That is the shape of
    #: an early, evidence-free run, kept as a *named policy*
    #: rather than a separate switch so the A/B baseline sits in the same
    #: vocabulary as ``TRIAGE_CODE_CONTEXT=none`` and ``TRIAGE_PEER_CONTEXT=none``, and so
    #: the artifact records it in the field that already exists.
    attach: bool = True
    #: The file exactly as it was read. Not re-serialised from the parsed form:
    #: a reader has to be able to see the comments that justify each row.
    source_text: str = ""
    path: Path | None = None

    def rule_for(self, klass: str) -> ExcerptRule:
        return self.by_class.get(klass, self.default)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "attaches_evidence": self.attach,
            "file": self.path.name if self.path else "",
            "text": self.source_text,
        }


def _rule_from(mapping: Mapping[str, Any], base: ExcerptRule,
               where: str) -> ExcerptRule:
    rule = ExcerptRule(
        body=str(mapping.get("body", base.body)),
        body_chars=int(mapping.get("body_chars", base.body_chars)),
        request_headers=str(mapping.get("request_headers", base.request_headers)),
        response_headers=str(mapping.get("response_headers", base.response_headers)),
    )
    rule.validate(where)
    return rule


def available_policies(policy_dir: Path | None = None) -> list[str]:
    directory = policy_dir or POLICY_DIR
    return sorted(p.stem for p in directory.glob("*.yml"))


def load_policy(name: str | None = None,
                policy_dir: Path | None = None) -> ExcerptPolicy:
    """Read ``config/excerpts/<name>.yml``.

    :param name: policy name; empty selects :data:`DEFAULT_POLICY`. Unlike the
        prompt loader there is no "newest on disk" default — a policy is not
        versioned by recency, and silently switching every run to whichever file
        was added last is exactly the failure adding ``triage.v4.md`` caused.
    """
    directory = policy_dir or POLICY_DIR
    chosen = (name or "").strip() or DEFAULT_POLICY
    path = directory / f"{chosen}.yml"
    if not path.is_file():
        raise EvidenceError(
            f"no excerpt policy {chosen!r} in {directory} "
            f"(available: {', '.join(available_policies(directory)) or 'none'})"
        )
    text = path.read_text()
    data = yaml.safe_load(text) or {}
    default = _rule_from(data.get("defaults") or {}, ExcerptRule(),
                         f"{path.name}:defaults")
    by_class = {
        klass: _rule_from(values or {}, default, f"{path.name}:classes.{klass}")
        for klass, values in (data.get("classes") or {}).items()
    }
    return ExcerptPolicy(
        name=str(data.get("name") or chosen),
        description=str(data.get("description") or "").strip(),
        default=default,
        by_class=by_class,
        attach=bool(data.get("attach", True)),
        source_text=text,
        path=path,
    )


# -- excerpting ------------------------------------------------------------

def _window(body: str, index: int, size: int) -> tuple[str, int]:
    """``size`` characters of ``body`` centred on ``index``; also its offset."""
    half = max(size // 2, 1)
    start = max(index - half, 0)
    return body[start:start + size], start


def _first_index(body: str, needles: Iterable[str]) -> int:
    for needle in needles:
        needle = (needle or "").strip()
        if len(needle) < 4:
            continue
        found = body.find(needle)
        if found >= 0:
            return found
        # ZAP records what it *sent*; the page may hold the encoded form.
        found = body.find(needle.replace("<", "&lt;").replace(">", "&gt;"))
        if found >= 0:
            return found
    return -1


def excerpt_body(body: str, rule: ExcerptRule,
                 needles: Iterable[str] = ()) -> dict[str, Any]:
    """Cut the slice this rule class needs, and say what was cut.

    Recording the truncation is what later makes *"the model asks for more if it
    wants it"* a small addition rather than a redesign: a pack that says
    ``"1 of 16 KB shown, from offset 9021"`` already describes the thing a
    follow-up request would ask for.
    """
    total = len(body)
    if rule.body == "none" or not body:
        return {
            "shown": "",
            "mode": rule.body,
            "total_chars": total,
            "shown_chars": 0,
            "truncated": total > 0,
            "why": "this rule class is settled by headers, so no body was sent"
                   if rule.body == "none" else "the response had no body",
        }

    needles = list(needles)
    offset = 0
    mode = rule.body
    if rule.body == "error-region":
        index = _first_index(body, ERROR_MARKERS)
        if index < 0:
            index = _first_index(body, needles)
            mode = "around-match" if index >= 0 else "head"
        shown, offset = (_window(body, index, rule.body_chars) if index >= 0
                         else (body[: rule.body_chars], 0))
    elif rule.body == "around-match":
        index = _first_index(body, needles)
        if index < 0:
            mode = "head"
            shown, offset = body[: rule.body_chars], 0
        else:
            shown, offset = _window(body, index, rule.body_chars)
    else:
        shown, offset = body[: rule.body_chars], 0

    return {
        "shown": shown,
        "mode": mode,
        "requested_mode": rule.body,
        "offset": offset,
        "total_chars": total,
        "shown_chars": len(shown),
        "truncated": len(shown) < total,
        "why": (
            f"{len(shown)} of {total} characters, from offset {offset}"
            if len(shown) < total else "the whole body"
        ),
    }


def render_headers(pairs: tuple[tuple[str, str], ...], mode: str) -> Any:
    if mode == "none":
        return []
    if mode == "line-only":
        return []
    return [f"{name}: {value}" for name, value in pairs]


def excerpt_exchange(exchange: Exchange, rule: ExcerptRule,
                     needles: Iterable[str] = ()) -> dict[str, Any]:
    """One exchange, cut to what the rule class needs."""
    block: dict[str, Any] = {
        "message_id": exchange.message_id,
        "request_line": f"{exchange.method} {exchange.uri}".strip(),
        "status": exchange.status,
    }
    if exchange.reason:
        block["reason"] = exchange.reason
    request_headers = render_headers(exchange.request_headers, rule.request_headers)
    if request_headers:
        block["request_headers"] = request_headers
    if exchange.request_body:
        block["request_body"] = exchange.request_body[: rule.body_chars]
    response_headers = render_headers(exchange.response_headers, rule.response_headers)
    if response_headers:
        block["response_headers"] = response_headers
    if exchange.body_omitted:
        block["response_body"] = {
            "shown": "",
            "mode": "not-stored",
            "why": "the scan did not store a body for this exchange: every rule "
                   "citing it is settled by headers. This is NOT an empty "
                   "response.",
        }
    else:
        block["response_body"] = excerpt_body(
            exchange.response_body, rule, needles
        )
    return block


# -- the pack --------------------------------------------------------------

class MessageStore:
    """The sidecar, loaded once and shared read-only by every worker.

    Pass 1 runs its calls concurrently and the invariant that a concurrent run's
    result is identical to a sequential one is load-bearing, so nothing here
    mutates after construction.
    """

    def __init__(self, messages: Mapping[str, Mapping[str, Any]] | None = None,
                 counts: Mapping[str, int] | None = None) -> None:
        self._messages = dict(messages or {})
        self.counts = dict(counts or {})

    def __len__(self) -> int:
        return len(self._messages)

    @classmethod
    def load(cls, path: Path) -> "MessageStore":
        """Read ``scan-zap-messages.json``; an absent sidecar yields an empty store.

        Absent rather than fatal on purpose: an early run may have alerts and no
        exchanges, and those corpora stay re-triageable. A pack built without one
        says so in
        ``http_exchange.missing`` instead of pretending the request never
        happened.
        """
        if not path.is_file():
            return cls()
        data = json.loads(path.read_text())
        return cls(data.get("messages") or {}, data.get("counts") or {})

    def exchange(self, ids: Iterable[str]) -> Exchange | None:
        for mid in ids:
            message = self._messages.get(str(mid))
            if message is not None:
                return parse_exchange(message)
        return None


def _needles(group: Any) -> list[str]:
    """Strings worth centring a body window on, most specific first."""
    candidates = [
        getattr(group, "evidence", "") or "",
        getattr(group, "attack", "") or "",
        getattr(group, "param", "") or "",
    ]
    return [c for c in candidates if c]


def build_pack(
    finding_id: str,
    group: Any,
    store: MessageStore,
    policy: ExcerptPolicy,
    auth_mode: str = "none",
    code_context: Mapping[str, Any] | None = None,
    retrieval_mode: str = PUSH,
) -> dict[str, Any]:
    """Everything a judgement of this finding is entitled to rest on.

    Deterministic: the same finding, sidecar and policy always produce the same
    pack. That is what makes an A/B over policies meaningful and what lets the
    pull mode below be compared against this push baseline.

    :param group: an :class:`~dast_orchestrator.analysis.join.AlertGroup`. Duck-typed
        rather than imported, so this module stays free of the join.
    :param code_context: per-finding navigation into the endpoint's source, when
        a code level asked for it. The *source blocks themselves* are attached
        once per endpoint by :class:`Assembler`, not repeated here: a six-alert
        chunk would otherwise carry the same 320 lines six times.
    :param retrieval_mode: :data:`PUSH` attaches the excerpted exchange, as it
        always has. :data:`PULL` replaces it with a manifest naming what can be
        retrieved, and the model asks the context server for the bytes. What
        stays in both is everything that is *small and decisive* — the rule's
        meaning, ZAP's own observation, the tags, reachability — because a pack
        cheap enough to push should not be paid for in a round trip.
    """
    alert = {
        "pluginId": getattr(group, "plugin_id", ""),
        "cweid": getattr(group, "cweid", ""),
        "name": getattr(group, "name", ""),
        "evidence": getattr(group, "evidence", ""),
        "other": getattr(group, "other", ""),
        "attack": getattr(group, "attack", ""),
    }
    klass = rule_class(alert)
    rule = policy.rule_for(klass)
    exchange = store.exchange(
        list(getattr(group, "message_ids", []))
        + list(getattr(group, "source_message_ids", []))
    )

    observed = normalise_observation(alert)
    pack: dict[str, Any] = {
        "finding_id": finding_id,
        "evidence_class": klass,
        # What ZAP says the rule *means*. The model was previously asked to
        # reason about a rule it was given only the name of.
        "rule_description": _collapse(getattr(group, "description", "")),
        "what_zap_observed": observed or {
            "none": "ZAP recorded no observation in any of "
                    f"{', '.join(OBSERVATION_FIELDS)}. For a rule proven by an "
                    "absence (a missing header) that is expected; for a "
                    "reflection or injection rule it means the alert rests on a "
                    "response comparison rather than on a quoted string."
        },
    }
    tags = rule_tags(group)
    if tags:
        pack["zap_rule_tags"] = tags
    injection_point = str(getattr(group, "input_vector", "") or "").strip()
    if injection_point:
        pack["zap_injection_point"] = injection_point
    solution = _collapse(getattr(group, "solution", ""))
    if solution:
        pack["zap_suggested_remediation"] = solution

    if exchange is None:
        pack["http_exchange"] = {
            "missing": "this run stored no exchange for the finding — either it "
                       "predates the message sidecar or ZAP no longer held the "
                       "message. Judge on the fields above alone.",
        }
    elif retrieval_mode == PULL:
        pack["retrievable_exchange"] = exchange_manifest(exchange)
    else:
        pack["http_exchange"] = excerpt_exchange(exchange, rule, _needles(group))
    pack["reachability"] = reachability(auth_mode, exchange)
    if code_context:
        pack.update(code_context)
    return pack


def exchange_manifest(exchange: Exchange) -> dict[str, Any]:
    """What is retrievable about this finding's exchange, without the bytes.

    The pull counterpart of :func:`excerpt_exchange`, and deliberately about a
    tenth of its size: the request line, the status, and an honest statement of
    what the body *is* — how many characters, or that the scan chose not to
    store one. Enough to decide whether pulling it would settle the finding,
    which is the only decision this block exists to support.

    The stored-versus-empty distinction survives here exactly as it does in the
    pushed pack. A model told "no body was stored" can pull nothing and must say
    so; a model told "the body is empty" has its answer already. Collapsing the
    two would invent evidence in the cheaper mode.
    """
    manifest: dict[str, Any] = {
        "message_id": exchange.message_id,
        "request_line": f"{exchange.method} {exchange.uri}".strip(),
        "status": exchange.status,
        "retrieve_with": "get_exchange(message_id) for the headers and the "
                         "request, get_response_body(message_id, contains=...) "
                         "for the response body",
    }
    if exchange.body_omitted:
        manifest["response_body"] = (
            "NOT STORED — the scan did not keep a body for this exchange, "
            "because no alert class citing it can be settled by one. Retrieving "
            "it will return nothing. This is not an empty response: nothing "
            "about the body is knowable from this run."
        )
    else:
        manifest["response_body_chars"] = len(exchange.response_body)
    if exchange.request_body:
        manifest["request_body_chars"] = len(exchange.request_body)
    return manifest


def _collapse(text: str, limit: int = 700) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


# -- the assembler ---------------------------------------------------------

class Assembler:
    """The one place a prompt's evidence comes from.

    Built once per run, before any call is dispatched, and read-only
    afterwards — the same invariant :func:`~dast_orchestrator.analysis.screening.build_cross_endpoint_context`
    keeps, and for the same reason: pass 1's calls run concurrently, and a
    concurrent run's result being *identical* to a sequential one is a property
    of this pipeline, not a coincidence to be spent on convenience.

    **Endpoint source is attached per endpoint, per-finding navigation per
    finding.** A chunk of six alerts on one route shares one handler, so
    repeating its 320 lines six times would multiply the one genuinely large
    part of the prompt by the chunk size for no added information. What *is*
    per-finding is where the flagged parameter appears, since ZAP flags a
    different parameter on each.
    """

    def __init__(
        self,
        store: MessageStore | None = None,
        policy: ExcerptPolicy | None = None,
        auth_mode: str = "none",
        code_level: str = "none",
        index: Any = None,
        source_dir: Path | None = None,
        max_hops: int = 1,
        max_lines: int = 600,
        retrieval_mode: str = PUSH,
    ) -> None:
        self.store = store or MessageStore()
        self.policy = policy or load_policy()
        self.auth_mode = auth_mode or "none"
        self.code_level = code_level or "none"
        self.index = index
        self.source_dir = source_dir
        self.max_hops = max_hops
        self.max_lines = max_lines
        self.retrieval_mode = retrieval_mode or PUSH
        self._blocks: dict[str, Any] = {}
        self._context: dict[str, dict[str, Any]] = {}
        #: Per endpoint: which tier resolved it and whether that is its own
        #: handler. Kept beside, never inside, the prompt block.
        self._resolution: dict[str, dict[str, Any]] = {}

    @property
    def code_enabled(self) -> bool:
        return (
            self.code_level != "none"
            and self.index is not None
            and self.source_dir is not None
        )

    def prepare(self, bundles: Iterable[Any]) -> None:
        """Resolve every candidate endpoint's handler source, once, up front.

        In pull mode this resolves the same symbols but reads none of them: what
        each endpoint gets is a manifest saying *what could be retrieved*, and
        the model asks for the bodies it wants.
        """
        if not self.code_enabled:
            return
        from dast_orchestrator.context import code_context as cc

        for bundle in bundles:
            key = getattr(bundle, "identifier", "")
            if key in self._context:
                continue
            roots = handler_symbols(bundle)
            if self.pulling:
                manifest = self._source_manifest(roots)
                resolved_by = RESOLVED_BY_CALLEES
                if not manifest["retrievable_symbols"]:
                    registration = self._registration(bundle)
                    if registration is not None and registration.symbol is not None:
                        manifest = self._source_manifest(
                            roots, located=[registration.symbol])
                        manifest["registered_at"] = _registered_at(registration)
                        resolved_by = RESOLVED_BY_REGISTRATION
                    elif registration is not None:
                        manifest.setdefault("not_resolved", []).append(
                            f"registration: {registration.reason}")
                self._context[key] = manifest
                available = manifest["retrievable_symbols"]
                self._record_resolution(
                    key,
                    resolved_by if available else RESOLVED_BY_NONE,
                    [a["symbol"] for a in available],
                    sum(a["lines"] for a in available),
                )
                continue
            blocks, unresolved = cc.extract(
                self.index, self.source_dir, roots,
                max_hops=self.max_hops, max_lines=self.max_lines,
            )
            resolved_by = RESOLVED_BY_CALLEES
            registration = None
            if not blocks:
                # Noir named no resolvable callee: ask the endpoint's
                # registration call which callable it hands the request to.
                registration = self._registration(bundle)
                if registration is not None and registration.symbol is not None:
                    reg_blocks, reg_unresolved = cc.extract_from_symbols(
                        self.index, self.source_dir, [registration.symbol],
                        max_hops=self.max_hops, max_lines=self.max_lines,
                    )
                    if reg_blocks:
                        blocks, resolved_by = reg_blocks, RESOLVED_BY_REGISTRATION
                    unresolved = unresolved + reg_unresolved
                elif registration is not None:
                    unresolved = unresolved + [f"registration: {registration.reason}"]
                if not blocks and registration is not None:
                    resolved_by = RESOLVED_BY_NONE
            if not blocks and _file_dispatch(bundle):
                # The endpoint IS its file (a framework-less PHP script): the
                # file's definitions are its code, attached as file context.
                code_paths = handler_code_paths(bundle)
                if code_paths:
                    fb_blocks, fb_unresolved = cc.extract_from_paths(
                        self.index, self.source_dir, code_paths,
                        max_hops=self.max_hops, max_lines=self.max_lines,
                    )
                    if fb_blocks:
                        blocks, unresolved, resolved_by = (
                            fb_blocks, fb_unresolved, RESOLVED_BY_CODE_PATHS)
            self._blocks[key] = blocks
            self._record_resolution(
                key,
                resolved_by if blocks else RESOLVED_BY_NONE,
                [b.symbol.qualified for b in blocks if b.depth == 0],
                sum(b.symbol.lines for b in blocks),
            )
            block: dict[str, Any] = {
                "scoped_by": roots,
                "resolved_by": resolved_by,
                "index": {
                    "tool": f"universal-ctags {self.index.provenance.get('version','')}",
                    "scope": self.index.provenance.get("scope", []),
                    "symbols": len(self.index),
                },
                "blocks": [b.as_dict() for b in blocks],
                "lines_included": sum(b.symbol.lines for b in blocks),
            }
            if registration is not None and registration.site:
                block["registered_at"] = _registered_at(registration)
            if unresolved:
                block["not_resolved"] = unresolved
            if not blocks and registration is not None:
                block["note"] = (
                    "Noir named no symbol for this endpoint and its registration "
                    "call did not lead to an indexed handler (see not_resolved). "
                    "No handler source is attached; that is a limit of what "
                    "static location found, not a statement that the handler "
                    "is empty."
                )
            elif not blocks:
                block["note"] = (
                    "Noir scoped this endpoint to the symbols above and the "
                    "index holds a definition for none of them — they are "
                    "outside the indexed handler tree (standard library, or "
                    "another part of the application). No handler source is "
                    "attached; that is a limit of the index's scope, not a "
                    "statement that the handler is empty."
                )
            if self.code_level == "handler+trace":
                chain = cc.call_chain(blocks)
                if chain:
                    block["call_chain"] = chain
            self._context[key] = block

    def _registration(self, bundle: Any) -> "Any | None":
        from dast_orchestrator.context import dispatch

        context = getattr(bundle, "static_context", None) or {}
        return dispatch.locate_handler(context, self.index, self.source_dir)

    def _record_resolution(self, key: str, resolved_by: str,
                           symbols: list[str], lines: int) -> None:
        self._resolution[key] = {
            "endpoint": key,
            "resolved_by": resolved_by,
            "handler_located": resolved_by in HANDLER_TIERS,
            "symbols": symbols,
            "lines_included": lines,
        }

    def has_source(self, bundle: Any) -> bool:
        """Whether this endpoint's prompt held handler source, or could retrieve it.

        :param bundle: a prepared endpoint; one never prepared has none.
        """
        context = self._context.get(getattr(bundle, "identifier", "")) or {}
        return bool(context.get("blocks") or context.get("retrievable_symbols"))

    def grounding(self, bundles: Iterable[Any] | None = None) -> dict[str, Any]:
        """How the prepared endpoints' source was reached, counted by tier.

        :param bundles: count only these endpoints; every prepared one when
            omitted. An endpoint that was never prepared is not counted.
        :returns: ``endpoints`` counted, ``handler_located`` (resolved by a
            :data:`HANDLER_TIERS` tier) and ``by_resolution`` — one count per
            :data:`RESOLUTION_TIERS` entry, zeros included.
        """
        if bundles is None:
            records = list(self._resolution.values())
        else:
            keys = {getattr(b, "identifier", "") for b in bundles}
            records = [r for k, r in self._resolution.items() if k in keys]
        by_resolution = {tier: 0 for tier in RESOLUTION_TIERS}
        for record in records:
            by_resolution[record["resolved_by"]] += 1
        return {
            "endpoints": len(records),
            "handler_located": sum(1 for r in records if r["handler_located"]),
            "by_resolution": by_resolution,
        }

    def _source_manifest(self, roots: list[str],
                         located: Iterable[Any] = ()) -> dict[str, Any]:
        """Which handler symbols this endpoint has, and where — not their bodies.

        The pull counterpart of the ``handler_source`` block, and the reason
        pull can be cheaper at all: the pushed block is the single largest part
        of a prompt (~320 lines on this target's median endpoint), while naming
        the same symbols with their locations and sizes costs a couple of lines.

        The **size** matters as much as the name. A model told
        ``repo.Issues (39 lines)`` and ``repo.issues (256 lines)`` can decide
        whether the handler is worth a round trip; one told only the names
        cannot, and would either pull everything — rebuilding the pushed pack at
        a higher latency — or nothing.
        """
        from dast_orchestrator.context import code_context as cc

        available: list[dict[str, Any]] = []
        unresolved: list[str] = []
        for root in roots:
            symbol = cc.resolve_reference(self.index, root)
            if symbol is None:
                unresolved.append(root)
                continue
            available.append({
                "symbol": symbol.qualified,
                "location": symbol.location,
                "signature": symbol.signature,
                "lines": symbol.lines,
            })
        for symbol in located:
            available.append({
                "symbol": symbol.qualified,
                "location": symbol.location,
                "signature": symbol.signature,
                "lines": symbol.lines,
            })
        manifest: dict[str, Any] = {
            "scoped_by": roots,
            "index": {
                "tool": f"universal-ctags {self.index.provenance.get('version','')}",
                "scope": self.index.provenance.get("scope", []),
                "symbols": len(self.index),
            },
            "retrievable_symbols": available,
            "retrieve_with": "get_symbol_source(symbol, hops=1) for a definition "
                             "and what it calls; search_source(pattern) to find "
                             "where a name appears in the indexed handler tree",
        }
        if unresolved:
            manifest["not_resolved"] = unresolved
        if not available:
            manifest["note"] = (
                "Noir scoped this endpoint to the symbols above and the index "
                "holds a definition for none of them — they are outside the "
                "indexed handler tree (standard library, or another part of the "
                "application). Retrieving them will return nothing; that is a "
                "limit of the index's scope, not a statement that the handler "
                "is empty."
            )
        return manifest

    def endpoint_context(self, bundle: Any) -> dict[str, Any] | None:
        return self._context.get(getattr(bundle, "identifier", ""))

    @property
    def endpoint_context_key(self) -> str:
        """What the endpoint block is called in the prompt.

        Named by mode rather than left as ``handler_source`` in both, because
        the two are different claims: one *is* the handler's source, the other
        says where it could be fetched from. A model handed a manifest under the
        name of the thing itself would reasonably report it had read the code.
        """
        return "retrievable_source" if self.pulling else "handler_source"

    def _navigation(self, bundle: Any, group: Any) -> dict[str, Any] | None:
        # Pull mode ships no parameter sites: a string search for the flagged
        # parameter is `search_source`, and pushing the answer to a question the
        # model can ask would leave the arm measuring a half-pull.
        if self.pulling:
            return None
        if self.code_level != "handler+trace" or not self.code_enabled:
            return None
        from dast_orchestrator.context import code_context as cc

        blocks = self._blocks.get(getattr(bundle, "identifier", "")) or []
        if not blocks:
            return None
        sites = cc.parameter_sites(blocks, getattr(group, "param", "") or "")
        return {
            "parameter_sites": sites,
            "navigation_note": (
                "A plain string search for the flagged parameter name in the "
                "handler source attached to this endpoint. It is navigation, "
                "not analysis: it says nothing about whether the value is "
                "validated, escaped, or reaches a sink. An empty list means the "
                "name does not appear in the included source, which may mean "
                "the parameter is read further in than the walk reached."
            ),
        }

    @property
    def pulling(self) -> bool:
        return self.retrieval_mode == PULL

    def pack(self, finding_id: str, group: Any,
             bundle: Any = None) -> dict[str, Any] | None:
        if not self.policy.attach:
            return None
        return build_pack(
            finding_id, group, self.store, self.policy, self.auth_mode,
            code_context=self._navigation(bundle, group) if bundle is not None else None,
            retrieval_mode=self.retrieval_mode,
        )

    def as_dict(self) -> dict[str, Any]:
        """Provenance for the artifact: what this run's prompts actually held."""
        block: dict[str, Any] = {
            "excerpt_policy": self.policy.as_dict(),
            "http_exchanges_available": len(self.store),
            "exchange_counts": dict(self.store.counts),
            "code_context_level": self.code_level,
            "retrieval_mode": self.retrieval_mode,
        }
        if self.code_enabled:
            block["code_index"] = {
                k: v for k, v in self.index.provenance.items() if k != "command"
            }
            block["code_context_max_hops"] = self.max_hops
            block["code_context_max_lines"] = self.max_lines
            block["endpoints_with_source"] = sum(
                1 for b in self._context.values() if b.get("blocks")
            )
            block["endpoints_without_source"] = sum(
                1 for b in self._context.values() if not b.get("blocks")
            )
            grounding = self.grounding()
            block["endpoints_handler_located"] = grounding["handler_located"]
            block["endpoints_by_resolution"] = grounding["by_resolution"]
            block["endpoint_resolution"] = [
                self._resolution[key] for key in sorted(self._resolution)
            ]
        return block


def _registered_at(registration: Any) -> dict[str, Any]:
    """Where an endpoint's registration call is, and what it says — WHERE only."""
    out: dict[str, Any] = {"site": registration.site, "call": registration.call}
    if registration.closure:
        out["callback"] = "a closure inside the definition attached"
    return out


def _file_dispatch(bundle: Any) -> bool:
    """Whether this endpoint's technology serves the endpoint AS its file."""
    from dast_orchestrator.context import dispatch

    context = getattr(bundle, "static_context", None) or {}
    return str(context.get("technology") or "") in dispatch.FILE_DISPATCH


def handler_symbols(bundle: Any) -> list[str]:
    """The symbol names Noir scoped this endpoint to.

    ``callees`` and nothing else: ``guards`` name middleware, ``signals`` name
    the route registration, and both point back at the registration file that
    the audit found occupying 504 of 523 context entries. The handler is what
    the finding is about.
    """
    context = getattr(bundle, "static_context", None) or {}
    callees = (context.get("ai_context") or {}).get("callees") or []
    names: list[str] = []
    for signal in callees:
        name = str(signal.get("name") or "").strip()
        if name and name not in names:
            names.append(name)
    return names


def handler_code_paths(bundle: Any) -> list[tuple[str, int]]:
    """The handler file(s) Noir located for this endpoint — the fallback for
    source resolution when Noir named no ``callees``.

    ``(path, line)`` pairs; a ``line`` of ``0`` means Noir has the file but not
    a definition line. Used only when :func:`handler_symbols` is empty: a
    framework whose dispatch Noir cannot follow to a named call still gets a
    file, so the handler source is reachable by file even when it is not by
    symbol name.
    """
    context = getattr(bundle, "static_context", None) or {}
    out: list[tuple[str, int]] = []
    for entry in context.get("code_paths") or []:
        path = str(entry.get("path") or "").strip()
        if not path:
            continue
        try:
            line = int(entry.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        out.append((path, line))
    return out


def assembler_for_run(
    zap_report: Mapping[str, Any],
    messages_path: Path,
    excerpt_policy: str = "",
    code_level: str = "none",
    target: Any = None,
    source_dir: Path | None = None,
    max_hops: int = 1,
    max_lines: int = 600,
    refresh_index: bool = False,
    retrieval_mode: str = PUSH,
) -> "Assembler":
    """Build the assembler a stage should use for one stored run.

    Everything it needs is on disk: the sidecar next to the alerts, the excerpt
    policy in ``config/excerpts``, the auth mode inside ``scan-zap-alerts.json``, and
    the target's own source tree. No stage re-derives any of it.

    A code level that cannot be honoured (no ``code_context`` in the target, no
    source tree, ctags unavailable) **degrades to ``none`` and says so** rather
    than failing the run — but the artifact then records ``none``, so nothing
    later reads a level the run did not have.
    """
    store = MessageStore.load(messages_path)
    policy = load_policy(excerpt_policy)
    auth_mode = str(zap_report.get("auth_mode") or "none")
    index = None
    if code_level != "none":
        from dast_orchestrator.context import code_context as cc
        from dast_orchestrator.foundation import ui

        config = getattr(target, "code_context", None)
        if target is None or config is None or not config.enabled:
            ui.warn(
                f"code context {code_level!r} was asked for, but "
                f"{getattr(target, 'name', 'this target')} declares no "
                "`code_context` scope — continuing with none."
            )
            code_level = "none"
        elif source_dir is None or not source_dir.is_dir():
            ui.warn(
                f"code context {code_level!r} was asked for, but the source tree "
                f"{source_dir} is not present — continuing with none."
            )
            code_level = "none"
        else:
            try:
                index = cc.load_or_build_index(
                    source_dir, config.scope, config.languages, config.kinds,
                    refresh=refresh_index,
                )
            except cc.CodeContextError as exc:
                ui.warn(f"could not build the symbol index ({exc}) — "
                        "continuing with none.")
                code_level = "none"
    return Assembler(
        store=store,
        policy=policy,
        auth_mode=auth_mode,
        code_level=code_level,
        index=index,
        source_dir=source_dir,
        max_hops=max_hops,
        max_lines=max_lines,
        retrieval_mode=retrieval_mode,
    )
