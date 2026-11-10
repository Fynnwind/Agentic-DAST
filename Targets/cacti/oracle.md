# Cacti 1.2.22 — known vulnerabilities

What is actually wrong with this build, written for a reader who is about to go
looking for it. Every item is a fix that landed in a later 1.2.x, so it is live
and unpatched here.

This file is read **only** in oracle-guided (`--oracle`) runs, where it is handed
to the LLM stages so the pipeline knows what it is looking for. It is
deliberately prose about the application: what the weakness is, which code it
lives in, and what an attacker would send. It names **no ZAP rule id, no finding
id and no verdict** — those belong to `cve-markers.yml`, which is the measurement
join and is never shown to a model, because handing over the rule ids that the
detection join uses would measure copying rather than detection.

Keep this file and `cve-markers.yml` in step by hand. Neither is generated from
the other, on purpose: one is written for a reader, the other is a contract for a
comparison.

One thing about this target shapes the headline bug: Cacti is a monitoring
application whose remote-poller endpoint trusts a proxy header to decide who is
calling. That single design choice turns an internal poller feature into an
unauthenticated remote-code-execution surface.

---

## 1. Unauthenticated OS command injection via the remote agent (fixed 1.2.23)

`remote_agent.php`, reached through `poll_for_data()`.

`remote_agent.php` decides whether a caller is an authorised poller by reading
the client IP from proxy headers — `X-Forwarded-For` first — and checking it
against the configured pollers. An attacker simply sets `X-Forwarded-For` to an
address that resolves back to the poller host (for a default install,
`127.0.0.1`, which reverse-resolves to `localhost`, the poller's own hostname),
and the authorisation check passes with no credentials at all.

Past that gate, the `polldata` action walks the data sources named by the request
and, for a data source backed by a PHP *script server*, builds a shell command
of the form `php -q .../script_server.php realtime <poller_id>` and runs it. The
`poller_id` value comes straight from the request with no filtering, so a shell
metacharacter in it runs arbitrary commands.

* **Where the attacker's value enters:** the `poller_id` query parameter of
  `remote_agent.php?action=polldata`, alongside `host_id` and a
  `local_data_ids[...]` that points at a script-server data source (on this
  instance, `local_data_ids[0]=6` — the "Device - Uptime" data source the fixture
  creates). The `X-Forwarded-For` header is what gets the request past the
  authorisation check.
* **Why this one is the point of the target:** it needs no login, and it is OS
  command execution — the most serious outcome a black-box scan can chase. It is
  also **blind**: the command runs but its output never comes back in the
  response body (the response is the poll result, a number or `U`). So the only
  way to *prove* it from outside is out of band — make the server call a
  collaborator you control (`poller_id=;curl <your-callback>`) and watch for the
  callback to land. That out-of-band confirmation is exactly what this target is
  here to exercise.

## 2. Authenticated OS command injection via SNMP options (fixed 1.2.25)

`lib/snmp.php`, the net-snmp binary path.

When a device is set to poll through the external net-snmp command-line tools
(rather than PHP's SNMP extension), Cacti assembles the `snmpget`/`snmpbulkwalk`
command line out of the device's own SNMP options — the community string, the
SNMPv3 username, context, and pass phrases — with escaping that is not thorough
enough. A user who can edit a device's SNMP options can smuggle a shell command
through one of those fields, which then runs when the poller next talks to that
device.

**Read this one as the counterexample to item 1.** It is the same kind of bug —
OS command injection — yet it is not reachable the same way: it needs an
authenticated session, it needs the device deliberately configured to use the
net-snmp binaries, and the command fires later inside the poller rather than in
any HTTP response an attacker can watch directly. Same weakness class, defended
by authentication and configuration.
