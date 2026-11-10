"""stdio MCP wrapper around headless Chromium: confirm XSS by EXECUTION, not reflection.

One tool, ``verify_browser`` — it substitutes quote-free breakout payloads into the
flagged position, loads the URL in a real browser, and reports CONFIRMED only when the
injected script actually runs (a per-invocation marker assigned to ``document.title`` and
matched EXACTLY; a substring match would confirm mere reflection). It exists because
string-matching probes refute genuinely-exploitable XSS that output-escaping mangles.
→ DECISIONS.md §"the verification layer refuted a true positive".
"""

from __future__ import annotations

import base64
import random
import re
import string
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _dispatch_common import (  # noqa: E402
    CONFIRMED,
    INCONCLUSIVE,
    REFUTED,
    outcome,
    run_container,
)

from mcp.server import MCPServer  # noqa: E402

#: The nuclei image, reused because it already ships an arm64 Chromium at
#: /usr/bin/chromium and is already pinned and pulled. Reusing it adds no image
#: to the stack; if nuclei is ever repinned, check the browser is still there.
BROWSER_IMAGE = "projectdiscovery/nuclei:v3.4.10"

#: Chromium flags this needs and why, since every one of them was necessary:
#: `--headless=new` (the old headless mode hangs on this target), `--no-sandbox`
#: (running as root in a container), `--disable-dev-shm-usage` (the default
#: /dev/shm is too small and the renderer dies), `--disable-gpu` and
#: `--virtual-time-budget` (let pending script settle, then dump deterministically
#: rather than racing a wall-clock sleep).
CHROME_FLAGS = (
    "--headless=new",
    "--no-sandbox",
    "--disable-gpu",
    "--disable-dev-shm-usage",
    "--virtual-time-budget=6000",
    "--dump-dom",
)

#: How the marker is smuggled in without a quote character anywhere: a regular
#: expression literal carries the text and `.source` reads it back as a string.
_ASSIGN = "document.title=/{marker}/.source"

#: Breakout contexts, in the order tried. Each is a template taking `{js}`.
#:
#: The first closes an enclosing `<script>` element, which is the context ZAP's
#: 40026 findings live in and the one a plain HTML-context payload cannot reach.
#: The rest are ordinary attribute and tag breakouts. Deliberately few and
#: high-signal: this confirms an already-suspected finding at a known point, so a
#: large payload list would buy noise and wall time rather than coverage.
PAYLOADS = (
    "</script><script>{js}</script>",
    "<script>{js}</script>",
    "></script><script>{js}</script>",
    "<img src onerror={js}>",
    "<svg onload={js}>",
)

#: `<title>...</title>` out of the dumped DOM. Chromium serialises the live DOM,
#: so this is the title *after* script ran, which is what makes it an oracle.
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

srv = MCPServer("browser-verify", version="0.1.0")


def new_marker(rng: "random.Random | None" = None) -> str:
    """A fresh per-invocation marker: letters then digits, no quotes, no slashes.

    Letters first because it is dropped into a regular-expression literal, and a
    leading digit reads oddly there; and it must be unique per call so a
    confirmation can only come from this call's own script running.
    """
    rng = rng or random.SystemRandom()
    letters = "".join(rng.choice(string.ascii_uppercase) for _ in range(6))
    digits = "".join(rng.choice(string.digits) for _ in range(6))
    return f"XSS{letters}{digits}"


def inject(target: str, param: str, payload: str) -> "str | None":
    """The target URL with ``payload`` in the flagged parameter's place.

    ``None`` when the parameter is not in the query string: unlike ffuf's
    traversal probe there is no sensible path-segment fallback here, because a
    path segment that reflects into a script context is a different finding and
    silently probing one while reporting on the other is the failure this
    project keeps writing down.
    """
    parsed = urlparse(target)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    if not (param and any(k == param for k, _ in query)):
        return None
    swapped = [(k, payload if k == param else v) for k, v in query]
    return urlunparse(parsed._replace(query=urlencode(swapped)))


#: Title of the bootstrap page that carries a POST into the browser, and the
#: reason a POST probe can be trusted at all.
#:
#: Chromium is navigated by URL, so a body-parameter finding cannot be probed by
#: building a URL. The bootstrap is a local page holding the endpoint's form with
#: the payload in the flagged field, which submits itself on load; what Chromium
#: then dumps is the *target's* response.
#:
#: **Unless the submit never happened** — the target refused the origin, the
#: navigation was blocked, virtual time ran out mid-flight. Then the dumped DOM
#: is still the bootstrap, and without this sentinel that reads as "the target's
#: page contained no marker", i.e. a refutation of a page that was never loaded.
#: That is precisely the class of false refutation this whole module exists to
#: correct, so the POST path is not allowed to reintroduce it: seeing this title
#: back is :data:`INCONCLUSIVE`, never :data:`REFUTED`.
BOOTSTRAP_TITLE = "dast-post-bootstrap"

#: The self-submitting form. Fields are emitted as hidden inputs, so the request
#: carries the endpoint's own shape and not just the flagged field — a lone
#: parameter is often rejected before it reaches the sink.
_BOOTSTRAP = (
    "<!doctype html><title>" + BOOTSTRAP_TITLE + "</title>"
    "<form id=f method=\"{method}\" action=\"{action}\">{fields}</form>"
    "<script>document.getElementById(String.fromCharCode(102)).submit()</script>"
)


def bootstrap_page(target: str, param: str, payload: str, data: str,
                   method: str = "POST") -> str:
    """The auto-submitting form that delivers ``payload`` in the request body.

    Every field of ``data`` is carried through with its recorded value, and the
    flagged one is replaced by the payload. A parameter absent from ``data`` is
    **added**, because ZAP flags fields the recorded body does not always
    contain and dropping it would probe the endpoint without the finding.
    """
    import html

    fields = dict(parse_qsl(data or "", keep_blank_values=True))
    fields[param] = payload
    inputs = "".join(
        f'<input type="hidden" name="{html.escape(name, quote=True)}" '
        f'value="{html.escape(value, quote=True)}">'
        for name, value in fields.items()
    )
    return _BOOTSTRAP.format(method=html.escape(method.upper(), quote=True),
                             action=html.escape(target, quote=True),
                             fields=inputs)


def title_of(dom: str) -> str:
    """The rendered document's title, or ``""``.

    Compared for **equality** against the marker by the caller, so leading and
    trailing whitespace is stripped and nothing else is normalised: any other
    difference is a real difference.
    """
    match = _TITLE.search(dom or "")
    return match.group(1).strip() if match else ""


@srv.tool(
    description=(
        "Confirm or refute a cross-site-scripting finding by EXECUTION rather "
        "than reflection: load the flagged URL in a headless Chromium with "
        "breakout payloads that set a unique marker from JavaScript, and report "
        "whether the marker reached the rendered DOM. Use this for XSS findings "
        "whose sink is script or HTML context, and in particular where a "
        "string-matching probe reports nothing — output escaping can defeat a "
        "matcher without preventing execution. Needs the flagged parameter to "
        "be in the URL's query string."
    )
)
def verify_browser(
    target: str,
    param: str = "",
    cookie: str = "",
    timeout: int = 120,
    data: str = "",
    method: str = "GET",
) -> dict:
    """Load ``target`` with each payload in turn until one executes.

    :param target: the URL ZAP flagged, with its original parameter values.
    :param param: the parameter to inject into. Required: this probe never
        guesses one.
    :param cookie: an authenticated session cookie (``name=value``) so the probe
        reaches routes behind login, matching the other wrappers.
    :param timeout: per-payload ceiling in seconds.
    :param data: the form body, ``a=1&b=2``. Given, the payload is delivered in
        the **request body** through a self-submitting bootstrap form rather
        than in the URL — see :func:`bootstrap_page`. This is what lets an XSS
        flagged on a form field be settled by execution at all: measured
        2026-09-08, 9 such findings on the WordPress baseline and 9 of Gitea's
        25 flagged ``10031`` findings are form fields, and every tool this
        pipeline had was handed a URL and nothing else.
    :param method: the form method for that submission. Ignored without
        ``data``.
    """
    if not param:
        return outcome(
            INCONCLUSIVE, "browser", None,
            "no parameter given, so there is nothing to inject into — this "
            "probe injects at a named parameter and does not guess one",
            tested=False,
        )

    marker = new_marker()
    js = _ASSIGN.format(marker=marker)
    attempted: list[str] = []
    last = None
    posting = bool(data)

    for template in PAYLOADS:
        payload = template.format(js=js)
        if posting:
            page = bootstrap_page(target, param, payload, data, method)
            loaded = "file:///tmp/probe.html"
            prelude = ("echo " + base64.b64encode(page.encode()).decode()
                       + " | base64 -d > /tmp/probe.html; ")
        else:
            url = inject(target, param, payload)
            if url is None:
                return outcome(
                    INCONCLUSIVE, "browser", None,
                    f"parameter {param!r} is not in the query string of "
                    f"{target!r} and no form body was given, so there is "
                    "nowhere to put the payload",
                    tested=False,
                )
            loaded, prelude = url, ""
        attempted.append(payload)
        args = ["-c", prelude + " ".join(
            ["exec", "chromium", *CHROME_FLAGS]
            + ([f"--header=Cookie:\\ {cookie}"] if cookie else [])
            + [f"'{loaded}'"]
        )]
        last = run_container(
            BROWSER_IMAGE, args, timeout=timeout, entrypoint="sh",
        )
        if last.timed_out:
            return outcome(
                INCONCLUSIVE, "browser", last,
                f"the browser was killed at the {timeout}s timeout before the "
                "page settled — unknown, not refuted",
                tested=False, payloads_tried=attempted,
            )
        rendered = title_of(last.stdout)
        # THE SUBMIT NEVER HAPPENED. What Chromium dumped is still the bootstrap
        # page, so the target's response was never examined — and reporting
        # "no marker found" here would refute a page that was never loaded,
        # which is exactly the false-refutation class this module exists to
        # correct. Not allowed to be reintroduced by its own POST path.
        if posting and rendered == BOOTSTRAP_TITLE:
            return outcome(
                INCONCLUSIVE, "browser", last,
                "the bootstrap form did not navigate: the dumped DOM is still "
                "the bootstrap page, so the target's response was never loaded "
                "and nothing here says anything about the finding. The target "
                "may have rejected the submission's origin, or virtual time ran "
                "out mid-navigation — unknown, and deliberately NOT refuted",
                tested=False, payloads_tried=attempted,
            )
        # Equality, never containment — see the module docstring. A reflected
        # payload can put the marker *in* the title without executing; only an
        # assignment replaces the title with it.
        if rendered == marker:
            return outcome(
                CONFIRMED, "browser", last,
                "injected JavaScript EXECUTED in a real browser: the payload "
                f"set document.title to this invocation's marker {marker}. The "
                "marker is generated per call, so nothing already on the page "
                "could have produced it.",
                evidence=payload,
                payloads_tried=attempted,
                # The class check (`verification.classification_match`) asks
                # whether the confirming evidence belongs to the flagged rule's
                # CWE family, and reads that off `matched_templates`. This probe
                # has no templates, but its class is fixed by construction — it
                # confirms JavaScript EXECUTION and nothing else — so it says so
                # rather than reporting nothing and landing as `class: unknown`,
                # which is what the first pipeline confirmation did. Declaring
                # it also keeps the check useful in the other direction: a
                # `confirmed` from this probe against a non-XSS rule is a real
                # class mismatch and should be flagged as one.
                matched_templates=[{
                    "template_id": "browser-execution-oracle",
                    "cwe": [79],
                    "tags": ["xss"],
                }],
            )

    if last is not None and last.exit_code != 0 and not title_of(last.stdout):
        return outcome(
            INCONCLUSIVE, "browser", last,
            f"the browser exited {last.exit_code} and rendered no document, so "
            "nothing was actually tested — unknown, not refuted",
            tested=False, payloads_tried=attempted,
        )
    return outcome(
        REFUTED, "browser", last,
        f"{len(attempted)} breakout payload(s) executed no JavaScript at "
        f"{param!r}. This says these payloads did not execute here; a sink "
        "needing a context this set does not cover would look the same.",
        payloads_tried=attempted,
    )


if __name__ == "__main__":
    srv.run("stdio")
