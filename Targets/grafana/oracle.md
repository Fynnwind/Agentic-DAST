# Grafana 8.3.0 — known vulnerabilities

What is actually wrong with this build, written for a reader who is about to go
looking for it. Every item is a fix that landed in a later 8.3.x, so it is live
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

One thing about this target shapes everything below: **Grafana refuses anonymous
access** (a deployment choice, made in its compose file, not a quirk of the
build). An unauthenticated client is redirected to the login page for almost
every route. The unauthenticated surface is therefore small — the login page,
the static asset bundle, and the plugin asset route — and that last one is where
the one externally-decisive bug lives.

---

## 1. Unauthenticated directory traversal on the plugin asset route (fixed 8.3.1)

`pkg/api/plugins.go`, `getPluginAssets`.

The route that serves a plugin's static files — `/public/plugins/<plugin-id>/<file>`
— joins the caller-supplied file path onto the plugin's directory without
confining the result to that directory. A traversal sequence in the file portion
escapes the plugin directory and reads arbitrary local files.

* **Where the attacker's value enters:** the file portion of the asset URL, after
  a valid installed plugin id. Every core plugin id works — `prometheus`,
  `mysql`, `graph`, `text` — and none has to be enabled or configured first.
* **Why this one is different from the rest of the list:** it needs no login. The
  asset route answers anonymous clients, so the single most reachable thing on
  this target is also a real file-read vulnerability. The unambiguous proof is
  the content of a world-readable system file coming back in the response body.

## 2. Authenticated traversal for spreadsheet files via a developer datasource (fixed 8.3.2)

`pkg/tsdb/testdatasource`.

The same traversal *class* as item 1, but confined to one file extension
(comma-separated-value files) and reachable only through the TestData developer
datasource. **Read this one as the counterexample to item 1**: it is the same
kind of bug, yet it is not reachable on this instance, because it needs an
authenticated session, it needs the developer datasource to have been configured
(this fixture does not configure it), and it only ever yields that one file type.
Same weakness, defended by configuration and authentication.

## 3. Reading teams you do not belong to (fixed 8.3.5)

`pkg/api/team.go`, `GetTeamByID` and the team search and members paths.

The teams API did not fully check that the caller belongs to, or administers, the
team being requested. An authenticated low-privilege user could read another
team's record, the total team count, and — when an "editors can admin" option is
on — its members.

**This is broken object-level authorisation.** Telling a vulnerable instance from
a fixed one needs two accounts with different team memberships and a model of
which team each is allowed to see. Nothing in a single HTTP response, read
without that model, distinguishes the two. Probed with no session at all it is
simply unauthorised; the bug lives a layer past the login.

## 4. Cross-site scripting through the datasource proxy (fixed 8.3.5)

`pkg/api/pluginproxy` and the datasource proxy.

An attacker who controls a server-access HTTP datasource — or who persuades a
user to configure one pointing at attacker infrastructure — can have Grafana's
own proxy relay HTML that then executes in Grafana's origin.

**The tainted value does not arrive in the request.** It arrives in the *response*
of a datasource the instance has been configured to talk to, so there is no URL
an outside scanner sends that triggers it on a default install. Exploitation
presupposes both a session and a malicious datasource already present.

## 5. Stored cross-site scripting in the alerting UI (fixed 8.3.10)

`public/app/features/alerting`.

An authenticated user with alerting permissions can store a crafted value that
executes as script when another user later views the Unified Alerting interface.

**The sink is a stored value rendered later**, in a JavaScript-driven admin
interface, and the code that renders it is in the TypeScript frontend rather than
the Go backend. Distinguishing vulnerable from fixed needs an authenticated user
to store the payload and a second authenticated view to observe it — the
store-then-view flow a signature scanner does not model, in a part of the tree it
does not see.

---

## The shape of this target, in one paragraph

Grafana 8.3.0's documented cluster is, with one exception, **not** reachable by
sending HTTP requests and reading responses as an anonymous client: three items
need an authenticated session (and two of those also need prior configuration or
a second account), and one is a stored-then-rendered flow in a frontend the
backend code index does not cover. The exception is the plugin-asset traversal,
and it is a large exception — unauthenticated, a path-segment payload, and a
system-file oracle — which is what makes this the one target where a black-box
scanner is expected to confirm a real documented vulnerability at its own sink.
When judging an alert here, the anonymous surface is narrow and the login wall is
real: a finding on a route that actually answers a session-less request is worth
far more than one on a route that only ever returns a redirect to the login page.
