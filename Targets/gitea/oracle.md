# Gitea 1.16.0 — known vulnerabilities

What is actually wrong with this build, written for a reader who is about to go
looking for it. Every item is a fix that landed in a later 1.16.x, so it is live
and unpatched here.

This file is read **only** in oracle-guided (`--ceiling`) runs, where it is
handed to the LLM stages so the pipeline knows what it is looking for. It is
deliberately prose about the application: what the weakness is, which code it
lives in, and what an attacker would send. It names **no ZAP rule id, no finding
id and no verdict** — those belong to `cve-markers.yml`, which is the
measurement join and is never shown to a model, because handing over the rule
ids that the detection join uses would measure copying rather than detection.

Keep this file and `cve-markers.yml` in step by hand. Neither is generated from
the other, on purpose: one is written for a reader, the other is a contract for a
comparison.

---

## 1. Open redirect on the login flow (fixed 1.16.5)

`modules/context/context.go`, `RedirectToFirst`.

The function accepts a redirect location beginning `//` or `/\`, which a browser
resolves as a **scheme-relative URL to another host** rather than as a path on
this site. 1.16.5 adds an explicit check rejecting `loc[0]=='/'` followed by `/`
or `\`.

* **Where the attacker's value enters:** the `redirect_to` parameter on the login
  flow. It is stored in a cookie and honoured later.
* **What makes it hard to see from outside:** the vulnerable sink runs only after
  a *successful* login — valid CSRF token and valid credentials. An
  unauthenticated GET of the login page returns 200 and no `Location` header at
  all, so nothing distinguishes vulnerable from fixed until a session exists.

## 2. Path traversal in local storage — and why the web layer defends it (fixed 1.16.5)

`modules/storage/local.go`, `buildLocalPath`.

`LocalStorage.Open/Save/Stat` joined a caller-supplied path straight onto the
storage directory. 1.16.5 routes every path through `buildLocalPath`, which
`path.Clean`s a leading-slashed, backslash-normalised copy.

**Read this one carefully, because the obvious probe is a false positive.** The
`/avatars/*` and `/repo-avatars/*` handlers in `routers/web/base.go` already
`path.Clean` the request path *before* it reaches local storage, even on 1.16.0.
The gap in `buildLocalPath` is reachable through object names set **internally**
— release and issue attachment storage keys — not by manipulating any URL. A
traversal alert on an avatar URL is therefore a genuine false positive on this
build, and the source is where that can be seen.

## 3. Display-name autolink in activation emails (fixed 1.16.5)

`services/mailer`, activation-email rendering.

A user's display name containing URL-like text is autolinked by the recipient's
email client; 1.16.5 inserts zero-width-joiner characters to prevent it. The
tainted value is the account's full name.

**The sink is the email body, not an HTTP response.** A profile page does reflect
the display name, but the fix applies in the mailer, so no HTTP response
distinguishes vulnerable from fixed. Nothing observable over HTTP settles this.

## 4. Unescaped git-fetch remote during repository migration (fixed 1.16.7)

Escaping added to the remote passed to `git fetch` during migration — an
argument-injection / SSRF-adjacent issue, reached through the repository
migration flow.

* **Where the attacker's value enters:** the remote URL field of an
  authenticated repository migration POST. It is a git-remote string, not a
  typical web parameter.
* **What exploitation looks like:** a crafted remote plus an observed
  out-of-band git operation. No HTTP response differs.

## 5. Missing cross-repository permission checks on issues (fixed 1.16.9)

`models/issues`, project and milestone repository-id checks.

`addUpdateIssueProject` and neighbouring paths did not verify that a referenced
project or milestone belongs to the issue's own repository; 1.16.9 adds the
`RepoID` equality checks. An authenticated user can act across repository
boundaries.

**This is broken object-level authorisation.** A vulnerable instance accepts a
cross-repository project or milestone id on an issue-edit POST and returns
success; the fixed one returns an error. Telling those apart needs two accounts,
two repositories, and a model of which object belongs to which.

---

## The shape of this target, in one paragraph

Gitea 1.16.0's documented cluster is mostly **not** reachable by sending HTTP
requests and reading responses: two items need a completed authenticated action
(login, migration), one lives in an email, one is an authorisation semantics bug,
and the one traversal is already defended at the web layer it appears to sit on.
Its reflected-input surface is broad — `q`, `sort`, `state` and `type`
parameters reflected into HTML across the repository, explore and issue-list
route families — but Go's `html/template` escapes by default, so a reflection
there is usually inert. When judging an alert on this target, the source is the
evidence: a value reaching a template is not a value breaking out of one.
