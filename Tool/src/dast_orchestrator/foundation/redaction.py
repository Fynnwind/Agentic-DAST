"""Strip stored credentials from on-disk artifacts (NFR-06).

A live scan or verification needs the session cookie and the target's seeded
login password to authenticate; the *stored* exchange does not. This scrubs them
the moment an artifact is serialised, and the same :func:`scrub` runs over
already-stored artifacts (the one-time pass over the corpus).

A credential reaches an artifact in four shapes, so four rules cover them:
  1. a raw-HTTP header line — ``Cookie: <value>`` inside a CRLF-joined block;
  2. a header passed in a tool command — ``curl -H 'Cookie: <value>'``;
  3. a structured header — the JSON object ``{"Cookie": "<value>"}``;
  4. a cookie flag — ``sqlmap --cookie <name>=<value>`` — or the seeded
     password in a replayed form body.
Rules 1–2 are the header-value regex, 3 is the header-keyed dict blank, and 4 is
the by-name cookie redaction plus the exact-string pass. The marker is
``==REDACTED==``: upper-case and delimited so it is obvious in a diff or an
evidence pack. → NFR-06.
"""

from __future__ import annotations

import re
from typing import Any, Iterable
from urllib.parse import quote, quote_plus

#: What a redacted value becomes. Deliberately loud and delimited.
PLACEHOLDER = "==REDACTED=="

#: Header names whose value is a credential. The value is matched anywhere (not
#: only at a line start), so a header passed inside a tool command is caught
#: too; it runs to the first line end OR quote OR backslash — which ends it both
#: in a raw CRLF-joined block and inside a quoted shell argument — keeping the
#: name's own casing and whatever follows. The lookbehind stops ``cookie``
#: matching the tail of a longer token.
_HEADER_VALUE = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])"
    r"(cookie|set-cookie|authorization|proxy-authorization)"
    r"([ \t]*:[ \t]*)[^\r\n\"'\\]*"
)

#: Dict keys (case-folded) whose value is a whole credential and is blanked
#: outright — a structured header like ``{"Cookie": "a=1; b=2"}``.
_HEADER_KEYS = frozenset(
    {"cookie", "set-cookie", "authorization", "proxy-authorization"}
)


def _name_value_patterns(cookie_names: tuple[str, ...]) -> list[re.Pattern]:
    #: ``<name>=<value>`` for a known session/CSRF cookie, in any context (a
    #: ``--cookie`` flag, a bare value), value ending at a cookie-pair delimiter.
    #: A name ending in ``_`` is a PREFIX (WordPress's ``wordpress_logged_in_``
    #: carries a per-install hash before ``=``), so its suffix is matched too;
    #: any other name is exact.
    patterns = []
    for name in cookie_names:
        stem = re.escape(name)
        if name.endswith("_"):
            stem += r"[A-Za-z0-9_]*"
        patterns.append(
            re.compile(r"(?i)(?<![A-Za-z0-9_-])(" + stem + r")=[^;,&\s\"'\\]*")
        )
    return patterns


def _secret_forms(secret: str) -> list[str]:
    """A seeded secret and the encodings it can appear under in stored evidence.

    A verification tool replays the password inside an
    ``application/x-www-form-urlencoded`` login body and echoes it back, so the
    bytes on disk are percent-encoded (``!`` -> ``%21``) — which a literal match
    misses. Redact the raw string and its URL-encoded variants.
    """
    forms = [secret, quote(secret, safe=""), quote_plus(secret)]
    seen: set[str] = set()
    return [f for f in forms if f and not (f in seen or seen.add(f))]


def scrub(obj: Any, secrets: Iterable[str] = (),
          cookie_names: Iterable[str] = ()) -> Any:
    """A copy of ``obj`` with credentials replaced by :data:`PLACEHOLDER`.

    :param secrets: strings to remove wherever they appear — each is redacted
        both raw and in its URL-encoded forms (a password replayed in a
        urlencoded login body reads ``!`` as ``%21``). The target's seeded
        passwords, and (at write time) the live session cookie values.
    :param cookie_names: session/CSRF cookie names whose ``name=value`` is
        redacted by name — for stored data, where the live value is unknown.

    The input is never mutated, so a caller scrubs only the copy it writes while
    the live object keeps the cookie it still needs.
    """
    forms: list[str] = []
    seen: set[str] = set()
    for secret in secrets:
        if not secret:
            continue
        for form in _secret_forms(secret):
            if form not in seen:
                seen.add(form)
                forms.append(form)
    # Longest first: an encoded form shares the raw alnums, so blanking the
    # longest match first keeps a shorter secret from clipping a longer one.
    secs = tuple(sorted(forms, key=len, reverse=True))
    name_res = _name_value_patterns(tuple(n for n in cookie_names if n))

    def scrub_text(text: str) -> str:
        text = _HEADER_VALUE.sub(
            lambda m: f"{m.group(1)}{m.group(2)}{PLACEHOLDER}", text
        )
        for pattern in name_res:
            text = pattern.sub(lambda m: f"{m.group(1)}={PLACEHOLDER}", text)
        for secret in secs:
            text = text.replace(secret, PLACEHOLDER)
        return text

    def walk(node: Any) -> Any:
        if isinstance(node, str):
            return scrub_text(node)
        if isinstance(node, dict):
            out: dict[Any, Any] = {}
            for key, value in node.items():
                if (isinstance(key, str) and key.lower() in _HEADER_KEYS
                        and isinstance(value, str)):
                    out[key] = PLACEHOLDER
                else:
                    out[key] = walk(value)
            return out
        if isinstance(node, list):
            return [walk(value) for value in node]
        return node

    return walk(obj)


def target_secrets(target: Any) -> list[str]:
    """The seeded secret strings a target's config carries — its login passwords.

    These ride in the form bodies a verification tool may replay into stored
    evidence; the session cookie is handled by :func:`target_cookie_names` and
    by header name, not here.
    """
    out: list[str] = []
    auth = getattr(target, "auth", None)
    if auth is not None:
        out += [
            u.password for u in getattr(auth, "users", ())
            if getattr(u, "password", "")
        ]
    for key, value in (getattr(target, "form_fillers", {}) or {}).items():
        if isinstance(value, str) and value and any(
            token in key.lower() for token in ("pass", "pwd")
        ):
            out.append(value)
    return _dedupe(out)


def target_cookie_names(target: Any) -> list[str]:
    """The session and CSRF cookie names a target's auth config names.

    Used to redact ``name=value`` in stored data (a ``--cookie`` flag, say),
    where the live token value is not known and so cannot be matched exactly.
    """
    auth = getattr(target, "auth", None)
    if auth is None:
        return []
    names = [getattr(auth, "session_cookie", ""), getattr(auth, "csrf_field", "")]
    # WordPress authenticates with a cookie FAMILY — ``wordpress_<hash>`` (the
    # wp-admin auth cookie), ``wordpress_sec_<hash>`` and ``wordpress_logged_in_
    # <hash>`` — that all share the ``wordpress_`` prefix. The config names only
    # the logged-in indicator, so add the family root to redact all of them.
    if any(n.startswith("wordpress_") for n in names):
        names.append("wordpress_")
    return _dedupe(names)


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out
