# WordPress 5.8.0 + WP Download Manager 3.2.33 — known vulnerabilities

What is actually wrong with this build, written for a reader who is about to go
looking for it. Every item is a fix that landed in a later release — core 5.8.1+
or plugin 3.2.34+ — so it is live and unpatched here.

This file is read **only** in oracle-guided (`--ceiling`) runs, where it is
handed to the LLM stages so the pipeline knows what it is looking for. It is
deliberately prose about the application: what the weakness is, which code it
lives in, and what an attacker would send. It names **no ZAP rule id, no finding
id and no verdict** — those belong to `cve-markers.yml`, which is the measurement
join and is never shown to a model.

**Read the "already hardened" section as carefully as the rest.** Three of the
items below are documented vulnerabilities that this *pinned version already
defends against*. They are here because a model told "this plugin has 59
advisories" and nothing else will confirm anything it is shown. The honest
picture is that most of them are not reachable here, and saying so is what keeps
the ceiling a measurement rather than a rubber stamp.

---

## Live and reachable over plain HTTP

### 1. Reflected XSS via `frameid` on the shortcode iframe (fixed in plugin 3.2.43)

`src/Package/views/shortcode-iframe.php`.

The shortcode iframe view echoes `$_REQUEST['frameid']` **three times, raw,
inside a `<script>` block**. 3.2.43 simply deletes the lines.

* **How the view is reached:** any front-end URL carrying `?__wpdmxp=1`. The hook
  is on `wp` in `src/Package/Hooks.php`, so the route is the site root plus a
  magic query parameter — nothing links to it and no crawler guesses it.
* **Why the usual escaping does not save it:** WordPress slash-adds `$_REQUEST`,
  so a bare quote arrives as `\"`. But the value sits *inside a `<script>`
  element* and neither `<` nor `>` is filtered, so `</script><script>…</script>`
  closes the script element and opens a new one regardless of the quote
  handling.
* **What this means for a verifier:** the payload does not come back verbatim —
  the slash-adding alters it — so a probe that matches its own bytes will find
  nothing while the injection executes perfectly. Only an execution oracle
  settles this one.

### 2. Reflected XSS via `REQUEST_URI` in the modal login form (fixed in plugin 3.2.53)

`src/User/views/modal-login-form.php`.

The modal login view echoes the raw `$_SERVER['REQUEST_URI']` into a hidden field
and into a `<script>` string literal (`var __lm_redirect_to = "..."`). 3.2.53
routes both through a validator.

* **Why it is not escaped:** `$_SERVER` is **not** slash-added by WordPress's
  magic quotes, so a `</script>` in the request URI reflects raw and breaks out
  of the script element.
* **How wide the surface is:** the view renders site-wide in the footer once the
  modal-login feature is enabled, so **any front-end URL's query string** reaches
  the sink — the reflection fires for any parameter on any page.

## Live, but behind an admin session

### 3. SQL injection via `user_ids` / `package_ids` on the stats view (fixed in plugin 3.2.34)

`src/Admin/views/stats/history.php`, `src/Admin/Menu/Packages.php`.

The admin download-history view passed the `user_ids` and `package_ids` request
**arrays** through `sanitize_text_field` only, then interpolated them into a SQL
statement. 3.2.34 casts every element to `int`.

Reachable only as an authenticated administrator, and through an array-typed
parameter (`package_ids[]=…`) on a `wp-admin` page a session-less scan neither
visits nor constructs. It is the plugin's only SQL-injection class.

## Documented, but already hardened at this pinned version

These are real advisories against the plugin that **do not reproduce at 3.2.33**.
An alert of this class here is a false positive, and the code is where that can
be seen.

### 4. `REQUEST_URI` in the *inline* login form (advisory fixed 3.2.44 / 3.2.53)

`src/User/views/login-form.php`. The inline `[wpdm_login_form]` view reflects the
request URI two ways — a `add_query_arg(REQUEST_URI)` "Forgot Password?" href and
a `redirect_to` hidden field built from `$log_redirect`. At 3.2.33 both are
already blunted: `add_query_arg` URL-encodes the href value, and `$log_redirect`
is `strip_tags`'d (so `<` is dropped) and quote-escaped for the JS string. The
still-raw sink of this class is the *modal* form in item 2, not this one.

### 5. `skw` / `search` on the package toolbars (advisory fixed 3.2.60)

`src/Package/views/*-shortcode-toolbar.php`. The toolbars echo
`wpdm_query_var('skw', 'txt')` into an `<input value="…">`. 3.2.60 changes the
filter from `txt` to `esc_attr` — but `wpdm_query_var`'s inner `sanitize_array`
**already** applies `esc_attr` to every `$_REQUEST` value at 3.2.33, so `skw` and
`search` come back HTML-entity-encoded and the attribute cannot be broken out of.
The 3.2.60 change is defence in depth.

### 6. Missing password-lock check on the download AJAX endpoint (fixed 3.2.35)

`src/Package/PackageLocks.php`. The password-check path did not early-return when
a package carried no password lock; 3.2.35 adds an explicit guard. The difference
is a **semantic authorisation outcome** — whether download data is returned for a
package in an unexpected lock state — not a byte pattern in any response.

## WordPress core 5.8.0 (fixed 5.8.1–5.8.3)

Four documented core issues are live here and **none is reachable by an
unauthenticated HTTP request**: SQL injection reachable only through
`WP_Query`/`WP_Meta_Query` arguments a plugin or theme must pass in, an
authenticated stored XSS through post slugs, and an admin-gated PHP object
injection. They are part of the pinned build's record; they are not part of its
attack surface from outside.

---

## The shape of this target, in one paragraph

The plugin carries 59 published advisories at 3.2.33, and reading the fix diffs
against the running instance reduces that to **two** unauthenticated
reflected-XSS sinks — `frameid` on the `?__wpdmxp=1` iframe, and `REQUEST_URI` in
the modal login form — plus one authenticated SQL injection. Both live XSS sinks
land inside a `<script>` element, and one of them has its payload altered in
transit by WordPress's slash-adding: reflection-matching probes will miss it
while it executes. Most of the site's reflected parameters (`s`, `orderby`,
`order`, `permalink`) are escaped correctly and an alert on one of them is
ordinary scanner noise.
