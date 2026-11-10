"""Target isolation: the orchestrator is target-agnostic, and the few things that are not
(base URL, the source tree Noir reads, route-placeholder values, POST-body fillers, the
login flow) are declared as data — one ``target.yml`` per target in its own directory.

A new target is one new directory plus one ``include:`` line in ``Targets/persistent.yml``.
Definitions are not package data (a wheel resolves no targets — honest, since a definition
points at a gitignored clone and a bind-mounted container); they live in the sibling
``Targets/`` dir, found through :data:`TARGETS_DIR` (``SHARED_TARGETS_DIR``), and the only
thing YAML cannot express is a login mechanism differing in kind (:class:`AuthProfile`).
→ docs/ARCHITECTURE.md.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml

from dast_orchestrator.foundation import ui

#: Repo root, four levels up from ``src/dast_orchestrator/targets/__init__.py``.
REPO_ROOT = Path(__file__).resolve().parents[4]

#: One directory per target, each holding ``target.yml``. At the repo root today,
#: but **configurable** so the tool can reach an example-targets checkout that
#: lives outside it — the whole point of the §R1 repo split, where targets become
#: a sibling repo. Set with ``SHARED_TARGETS_DIR`` (env) or ``--targets-dir`` (a
#: flag shared by scan/triage/verify/static-analysis, the four stages that read a
#: target's source); :func:`use_dir` re-points it and reloads the registry.
#:
#: The env is read at import so a standalone import (a test, `dast --help`) sees
#: the configured targets without a stage first running; a stage/`dast` invocation
#: then re-applies flag-or-env precedence early via :func:`use_dir`.
#:
#: This directory holds one ``<name>/`` subdirectory per target, each with its
#: ``target.yml`` and its ``src/`` tree; a target's ``source_dir`` is resolved
#: *within* its own directory (see :func:`target_source`), so nothing here depends
#: on the directory's name or on where it sits relative to the tool.
#:
#: The tool code lives in ``Implementation/Tool/`` and the targets in the sibling
#: top-level ``Implementation/Targets/`` — the tool/targets split. The default
#: prefers an in-repo ``targets/`` if one is present (older layouts, a vendored
#: copy) and otherwise the sibling ``../Targets`` beside the tool.
#: ``SHARED_TARGETS_DIR`` overrides it for a checkout anywhere else.
_IN_REPO_TARGETS = REPO_ROOT / "targets"
_SIBLING_TARGETS = REPO_ROOT.parent / "Targets"
DEFAULT_TARGETS_DIR = _IN_REPO_TARGETS if _IN_REPO_TARGETS.is_dir() else _SIBLING_TARGETS
TARGETS_DIR = Path(os.environ.get("SHARED_TARGETS_DIR") or DEFAULT_TARGETS_DIR)

#: Ground-truth markers, beside each target's definition.
MARKERS_NAME = "cve-markers.yml"

#: The definition file inside a target's directory.
DEFINITION_NAME = "target.yml"


@dataclass(frozen=True)
class AuthUser:
    """One seeded account the scan can log in as."""

    role: str        #: ``"user"`` or ``"admin"`` — the auth mode that selects it.
    username: str
    password: str


@dataclass(frozen=True)
class AuthProfile:
    """How to obtain and recognise an authenticated session on a target.

    Deliberately data, not code: the *mechanism* is a named strategy in
    :mod:`auth` (``strategy``); only these target-specific names live here.
    """

    login_path: str            #: e.g. ``"/user/login"``.
    csrf_field: str            #: hidden form field carrying the CSRF token, ``""`` if none.
    session_cookie: str        #: the cookie name that marks an authenticated session.
    logged_in_indicator: str   #: text present in a page only when authenticated.
    #: Path the post-login check fetches to look for ``logged_in_indicator``.
    #: Empty means the app root (``/``), which carries the indicator for most
    #: apps (Gitea/Cacti page chrome, WordPress's front-end admin bar). Set it
    #: only for a target whose root does not — e.g. a SPA whose root HTML is
    #: rendered client-side, which would need an authenticated endpoint instead.
    logged_in_check_path: str = ""
    users: tuple[AuthUser, ...] = ()
    strategy: str = "form"     #: named login mechanism in :mod:`auth`.
    #: The login form's own field names, which differ per app: Gitea posts
    #: ``user_name``/``password``, WordPress ``log``/``pwd``. Defaulting to
    #: Gitea's keeps every existing target unchanged; a new target overrides them.
    username_field: str = "user_name"
    password_field: str = "password"
    #: Fixed extra fields a login POST needs beyond the credentials — WordPress's
    #: ``wp-submit``, say. ``(name, value)`` pairs, posted verbatim.
    extra_login_fields: tuple[tuple[str, str], ...] = ()
    #: Literal substrings of a request URL that end the session (``/user/logout``,
    #: WordPress's ``action=logout``). The scan never sends one: the session is a
    #: fixed injected cookie, so one logout request ends it for the rest of the scan.
    #: An authenticated scan of a target that declares none refuses to start.
    logout_markers: tuple[str, ...] = ()
    #: Routes a logged-in crawl must not send because they wreck the account, the app or
    #: the marker fixtures (account settings, admin jobs, plugin editors, trash links).
    #: Same handling as ``logout_markers``, plus two forms: ``"POST /path"`` (only a POST
    #: to exactly that path) and ``"body:text"`` (text in a request body).
    destructive_markers: tuple[str, ...] = ()

    def user(self, role: str) -> AuthUser | None:
        for u in self.users:
            if u.role == role:
                return u
        return None


@dataclass(frozen=True)
class SourceAnalysis:
    """Which rule sets the standalone SAST pass runs against this target.

    Target data, because it follows from the target's languages (Gitea is Go
    with a JavaScript frontend; WordPress would be PHP). Each name is a
    directory of the pinned ``semgrep-rules`` checkout — never a registry pack
    like ``p/golang``, which would put an unpinned network fetch back into a
    static-analysis pass whose whole purpose is to be re-runnable.

    Only the SAST side needs declaring: OSV-Scanner discovers the dependency
    manifests itself, so an SCA pass needs no per-target configuration.
    """

    semgrep_rulesets: tuple[str, ...] = ()


@dataclass(frozen=True)
class CodeContext:
    """Where this target's route handlers live, for the scoped code extractor.

    Target data for the same reason :class:`SourceAnalysis` is: it follows from
    the target's language and layout (Gitea's web handlers are Go under
    ``routers/web``; WordPress's would be PHP elsewhere), so a new target stays
    one new YAML file.

    **The scope is the bound on how far a hop expansion walks**, and that is a
    design decision rather than a tuning knob. The walk saturates at one hop
    precisely *because* the calls that would go further leave the indexed tree;
    widening the scope to the whole repository would remove the property
    that makes a hop limit unnecessary.
    """

    #: Paths, relative to ``source_dir``, that ctags indexes. Empty means the
    #: whole tree, which is almost never what a target wants.
    scope: tuple[str, ...] = ()
    #: ctags language names to restrict the parse to (``["Go"]``).
    languages: tuple[str, ...] = ()
    #: ``{language: kind letters}``. ``f`` alone (functions) is what a route
    #: handler is in Go; a target whose handlers are methods would add more.
    kinds: dict[str, str] = field(default_factory=dict)

    @property
    def enabled(self) -> bool:
        return bool(self.scope)


@dataclass(frozen=True)
class Recovery:
    """How to bring a wedged target back to a loginable state (optional).

    Only a target that deadlocks under sustained scanning needs this — Cacti's
    CVE-2022-46169 RCE leaks MariaDB connections, and its 342-endpoint seed
    flakes ~1 in 3 and drops the connection mid-scan — so a target without a
    ``recovery:`` block is never auto-restarted. Readiness is not declared here:
    it is derived from :attr:`Target.auth` (the login page must serve its
    password field again), so this carries only *what to restart*.
    """

    #: docker container(s) to ``docker restart``, in order (app before its DB is
    #: irrelevant — restart takes them together).
    containers: tuple[str, ...]


@dataclass(frozen=True)
class Target:
    """One system under test, and the minimal per-target knobs the pipeline needs."""

    name: str
    #: URL ZAP and the verification tools reach the target at — a container name
    #: on ``dast-net``, not localhost, since they run inside their own containers.
    base_url: str
    #: Source tree (relative to the repo root) Noir analyses for endpoints.
    source_dir: str
    #: Values substituted into route-template placeholders so a seed is fetchable.
    path_vars: dict[str, str] = field(default_factory=dict)
    #: Benign values for form fields when reconstructing a POST body to probe.
    form_fillers: dict[str, str] = field(default_factory=dict)
    #: Login flow for authenticated scanning, or ``None`` for unauthenticated-only.
    auth: AuthProfile | None = None
    #: Configuration for the *independent* SAST/SCA static-analysis findings (``dast static-analysis``),
    #: which read this target's ``source_dir``. Not part of the DAST chain.
    source_analysis: SourceAnalysis = field(default_factory=SourceAnalysis)
    #: Where this target's handlers live, for the scoped code extractor that
    #: turns Noir's per-endpoint scope into actual source. Unset means the LLM
    #: stages get no handler source for this target — a stated limitation, not a
    #: silent one.
    code_context: CodeContext = field(default_factory=CodeContext)
    #: Noir ``technology`` classifications to drop from this target's endpoint
    #: set, on top of the always-ignored ones (``netlify``). The framework-blind
    #: PHP tagger emits a ``php_pure`` "endpoint" for every ``.php`` file — a
    #: source path a framework like WordPress never serves — so a WordPress
    #: target lists ``php_pure`` here to keep those out of the scan tree. A
    #: framework-less PHP app, whose files *are* routable, would leave it empty.
    #: Per-target rather than global for exactly that reason.
    noir_ignore_technologies: tuple[str, ...] = ()
    #: OpenAPI / Swagger specs whose routes seed the site tree, for targets whose
    #: router Noir cannot parse. Each is a served ``url`` or a committed ``file``
    #: (see :class:`~dast_orchestrator.adapters.openapi_import.OpenApiSpec`). A spec
    #: describes an application's declared API surface — not static-asset routes
    #: or anything absent from it — so this widens discovery beyond what Noir
    #: extracts, but is not a way to reach a route nothing declares (that is a
    #: marker's ``seed:`` in ``cve-markers.yml``, applied only under a scan's
    #: ``--oracle`` mode). Kept as ``(url, file, base_path)`` triples rather than
    #: parsed here to keep this module free of the import machinery; the loader
    #: below builds the typed objects.
    openapi_specs: tuple = ()
    #: Which crawlers suit this target, when a run does not say. A JS-driven
    #: admin surface needs a browser crawler to be seen at all, while a
    #: server-rendered app gains little for the minutes it costs — so the
    #: sensible default is a property of the application, not a global.
    #: `traditional` should stay in every list: it produced every recorded
    #: coverage number, and dropping it moves that baseline rather than adding
    #: to it.
    spiders: tuple[str, ...] = ()
    #: Query parameters ZAP should treat as part of a URL's IDENTITY rather than
    #: as values — its *structural parameters*.
    #:
    #: A property of how the application routes, so it belongs to the target and
    #: nowhere else. WordPress funnels ~90 plugin endpoints through one PHP file
    #: distinguished only by ``?action=<name>``, so without ``action`` here ZAP
    #: builds one site-tree node where the application has ninety, and the
    #: active scanner attacks one of them (dozens of ``?action=`` requests
    #: collapse into a handful of URLs without it).
    #:
    #: Setting this **changes what a scan contains**, so it is in the run's
    #: configuration digest and a run with it is not comparable with one without
    #: — see :mod:`dast_orchestrator.adapters.zap_context`.
    structural_parameters: tuple[str, ...] = ()
    #: Fixed request headers ZAP must add to EVERY request of the scan, injected
    #: as Replacer rules the same way the auth cookie is. For a header-gated
    #: surface a crawler cannot otherwise reach: Cacti's ``remote_agent.php``
    #: rejects any request whose ``X-Forwarded-For`` does not resolve to a
    #: configured poller, so ``{X-Forwarded-For: 127.0.0.1}`` here is what lets
    #: the scanner past that gate to the CVE-2022-46169 sink. Unlike
    #: :attr:`auth`, this is not a login — no session, no credential — just a
    #: static header the application trusts, so it belongs to the target rather
    #: than to a run flag.
    #:
    #: **Changes what a scan can reach**, so it is in the run's configuration
    #: digest and a run carrying one is not comparable with a run that does not.
    scan_headers: dict[str, str] = field(default_factory=dict)
    #: Per-rule active-scan settings, keyed by ZAP plugin id. See
    #: :class:`ScanRule` for what ZAP allows per rule and why the reason for
    #: each entry has to be about the application rather than about last run's
    #: yield.
    #:
    #: **Changes what a scan contains**, exactly like
    #: :attr:`structural_parameters`, so it is in the run's configuration digest
    #: and a run with it is not comparable with one without.
    scan_rules: tuple["ScanRule", ...] = ()
    #: Per-rule wall-clock ceiling for the active scanner, in minutes.
    #: :data:`dast_orchestrator.foundation.config.NO_LIMIT` (``-1``) means no ceiling, and
    #: **that is a deliberate choice, not a default** — ZAP applies this one
    #: number to every rule, so removing it lets a single slow rule consume the
    #: whole scan budget. ``0`` keeps its arithmetic meaning.
    #:
    #: Declared here because it is a property of how large the application's
    #: attack surface is; unset falls back to ``SCAN_ZAP_MAX_RULE_MINUTES``.
    max_rule_minutes: "int | None" = None
    #: How to restart this target when it wedges under sustained scanning, or
    #: ``None`` (the default) for a target that never needs it. A failure-path
    #: property only — it changes nothing a healthy scan does — so it is NOT in
    #: the configuration digest.
    recovery: "Recovery | None" = None

    def rule_settings(self) -> dict[str, "ScanRule"]:
        return {rule.plugin_id: rule for rule in self.scan_rules}


#: ZAP's per-rule attack strength: how many payloads an active rule sends. The
#: **request-based** limit, and the only one ZAP exposes per rule.
ATTACK_STRENGTHS = ("DEFAULT", "LOW", "MEDIUM", "HIGH", "INSANE")

#: ZAP's per-rule alert threshold: how much evidence a rule needs before it
#: raises. Not a limit on work; a limit on what counts as a finding.
ALERT_THRESHOLDS = ("DEFAULT", "OFF", "LOW", "MEDIUM", "HIGH")


@dataclass(frozen=True)
class ScanRule:
    """One active-scan rule's per-target settings.

    **What ZAP actually offers per rule, and what it does not.** Verified
    against the 2.17.0 daemon: ``ascan/action/setScannerAttackStrength`` and
    ``setScannerAlertThreshold`` take a plugin id, and ``disableScanners`` takes
    a list. There is **no per-rule time limit** — ``MaxRuleDurationInMins`` is
    one global number for every rule — so a per-rule ``max_minutes`` here would
    be a field this tool could not honour, and inventing one would be worse than
    not having it. Rule time is bounded by :attr:`Target.max_rule_minutes`,
    declared per target because it is a property of how big the application is.

    This exists because on a large tree the active-scan cap runs out on a handful
    of expensive rules that raise nothing, so the whole scan is bounded by them
    rather than by the rules that find something.

    **The reason belongs in `why`, and it must be about the APPLICATION.**
    Disabling a rule because it raised nothing last run is fitting the scanner
    to the answer key — the same mistake as tuning against a stored corpus, and
    it would make a detection rate meaningless. A defensible exclusion is
    grounded in what the target *is*: Gitea is Go with no exposed template
    engine, so template-injection rules cannot fire; a PostgreSQL-backed app has
    no Oracle or MsSQL timing surface. Written down, per target, and reviewable.

    :param enabled: ``False`` disables the rule for this target.
    :param strength: how many payloads it sends — the request-based limit.
    :param threshold: how much evidence it needs before raising.
    :param why: the application-level reason. Required for any rule that
        changes a default, and carried into the run's artifacts.
    """

    plugin_id: str
    enabled: bool = True
    strength: str = "DEFAULT"
    threshold: str = "DEFAULT"
    why: str = ""

    def is_default(self) -> bool:
        return (self.enabled and self.strength == "DEFAULT"
                and self.threshold == "DEFAULT")


class TargetError(RuntimeError):
    """Raised when a target definition is missing or malformed."""


# -- YAML loading ----------------------------------------------------------


def _require(data: dict, key: str, where: str):
    if key not in data:
        raise TargetError(f"target {where}: missing required key {key!r}")
    return data[key]


def _parse_openapi_specs(raw, where: str) -> tuple:
    """Build :class:`~dast_orchestrator.adapters.openapi_import.OpenApiSpec` objects.

    Imported lazily so this module carries no dependency on the import machinery
    (or its YAML/parsing code) when a target declares no spec — the common case.
    Each entry is a mapping with a ``url`` or a ``file`` (exactly one) and an
    optional ``base_path``.
    """
    if not raw:
        return ()
    from dast_orchestrator.adapters.openapi_import import OpenApiError, OpenApiSpec

    specs = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise TargetError(f"{where}: each openapi entry must be a mapping")
        try:
            specs.append(OpenApiSpec(
                url=str(entry.get("url", "")),
                file=str(entry.get("file", "")),
                base_path=str(entry.get("base_path", "")),
            ))
        except OpenApiError as exc:
            raise TargetError(f"{where}: openapi: {exc}") from exc
    return tuple(specs)


def target_from_dict(data: dict, where: str = "<dict>") -> Target:
    """Build a :class:`Target` from a parsed YAML mapping.

    Kept separate from file I/O so a definition can be validated in a test
    without touching disk, and so the required-key errors point at the offending
    field rather than surfacing as a random ``KeyError`` deep in a run.
    """
    if not isinstance(data, dict):
        raise TargetError(f"target {where}: expected a mapping, got {type(data).__name__}")

    auth = None
    auth_data = data.get("auth")
    if auth_data:
        users = tuple(
            AuthUser(role=str(u["role"]), username=str(u["username"]),
                     password=str(u["password"]))
            for u in auth_data.get("users", [])
        )
        auth = AuthProfile(
            login_path=str(_require(auth_data, "login_path", where)),
            csrf_field=str(auth_data.get("csrf_field", "")),
            session_cookie=str(_require(auth_data, "session_cookie", where)),
            logged_in_indicator=str(auth_data.get("logged_in_indicator", "")),
            logged_in_check_path=str(auth_data.get("logged_in_check_path", "")),
            users=users,
            strategy=str(auth_data.get("strategy", "form")),
            username_field=str(auth_data.get("username_field", "user_name")),
            password_field=str(auth_data.get("password_field", "password")),
            extra_login_fields=tuple(
                (str(k), str(v))
                for k, v in (auth_data.get("extra_login_fields") or {}).items()
            ),
            logout_markers=tuple(
                str(m) for m in (auth_data.get("logout_markers") or []) if str(m)),
            destructive_markers=tuple(
                str(m) for m in (auth_data.get("destructive_markers") or []) if str(m)),
        )

    analysis_data = data.get("source_analysis") or {}
    source_analysis = SourceAnalysis(
        semgrep_rulesets=tuple(
            str(r) for r in (analysis_data.get("semgrep_rulesets") or [])
        ),
    )

    code_data = data.get("code_context") or {}
    code_context = CodeContext(
        scope=tuple(str(p) for p in (code_data.get("scope") or [])),
        languages=tuple(str(l) for l in (code_data.get("languages") or [])),
        kinds={str(k): str(v) for k, v in (code_data.get("kinds") or {}).items()},
    )

    scan_data = data.get("zap_scan") or {}
    rules: list[ScanRule] = []
    for plugin_id, spec in (scan_data.get("rules") or {}).items():
        spec = spec or {}
        strength = str(spec.get("strength", "DEFAULT")).upper()
        threshold = str(spec.get("threshold", "DEFAULT")).upper()
        if strength not in ATTACK_STRENGTHS:
            raise TargetError(
                f"{where}: zap_scan.rules.{plugin_id}.strength must be one of "
                f"{', '.join(ATTACK_STRENGTHS)}, got {strength!r}")
        if threshold not in ALERT_THRESHOLDS:
            raise TargetError(
                f"{where}: zap_scan.rules.{plugin_id}.threshold must be one of "
                f"{', '.join(ALERT_THRESHOLDS)}, got {threshold!r}")
        rule = ScanRule(
            plugin_id=str(plugin_id),
            enabled=bool(spec.get("enabled", True)),
            strength=strength,
            threshold=threshold,
            why=str(spec.get("why", "")).strip(),
        )
        # A rule that changes a default without saying why is how a scan's shape
        # drifts: the next reader cannot tell a measured decision from a
        # leftover, and a detection rate computed over it means nothing.
        #
        # A WARNING, not a refusal. Refusing puts a documentation rule in the
        # path of a scan — someone mid-experiment loses the run rather than the
        # sentence, and the pressure that creates is to write "because" and move
        # on, which is worse than an empty field a reviewer can still spot.
        if not rule.is_default() and not rule.why:
            ui.warn(
                f"{where}: zap_scan.rules.{plugin_id} changes the scan and "
                "carries no `why`. Give the reason, and make it about the "
                "APPLICATION — 'raised nothing last run' is fitting the "
                "scanner to the answer key, and a detection rate computed over "
                "it means nothing.")
        rules.append(rule)

    max_rule_minutes = scan_data.get("max_rule_minutes")
    if max_rule_minutes is not None:
        max_rule_minutes = int(max_rule_minutes)

    recovery = None
    recovery_data = data.get("recovery")
    if recovery_data:
        containers = tuple(str(c) for c in (recovery_data.get("containers") or []))
        if not containers:
            raise TargetError(f"{where}: a recovery block needs at least one container")
        recovery = Recovery(containers=containers)

    return Target(
        name=str(_require(data, "name", where)),
        base_url=str(_require(data, "base_url", where)),
        source_dir=str(_require(data, "source_dir", where)),
        path_vars={str(k): str(v) for k, v in (data.get("path_vars") or {}).items()},
        form_fillers={str(k): str(v) for k, v in (data.get("form_fillers") or {}).items()},
        auth=auth,
        source_analysis=source_analysis,
        code_context=code_context,
        noir_ignore_technologies=tuple(
            str(t) for t in (data.get("noir_ignore_technologies") or [])
        ),
        openapi_specs=_parse_openapi_specs(data.get("openapi"), where),
        spiders=tuple(str(s) for s in (data.get("spiders") or [])),
        structural_parameters=tuple(
            str(p) for p in ((data.get("zap_context") or {})
                             .get("structural_parameters") or [])
        ),
        scan_headers={str(k): str(v) for k, v in (data.get("scan_headers") or {}).items()},
        scan_rules=tuple(sorted(rules, key=lambda r: r.plugin_id)),
        max_rule_minutes=max_rule_minutes,
        recovery=recovery,
    )


def load_target(path: Path) -> Target:
    """Parse one ``targets/<name>/target.yml`` into a :class:`Target`."""
    try:
        data = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise TargetError(f"target {path.name}: invalid YAML: {exc}") from exc
    where = f"{path.parent.name}/{path.name}"
    target = target_from_dict(data, where=where)
    # The directory is the target's identity — it is what holds the source
    # clone, the compose service and the seed scripts — so a `name:` that
    # disagrees with it would make two things claim to be the same target.
    if target.name != path.parent.name:
        raise TargetError(
            f"target {where}: name {target.name!r} must match its directory "
            f"{path.parent.name!r}"
        )
    return target


# -- registry --------------------------------------------------------------

REGISTRY: dict[str, Target] = {}


def register(target: Target) -> Target:
    REGISTRY[target.name] = target
    return target


def marker_rule_ids(targets_dir: "Path | None" = None) -> frozenset[str]:
    """Every ZAP rule id any target's ``cve-markers.yml`` names.

    The set the detection join depends on, read across **all** targets rather
    than the one being scanned: a rule disabled for its quality label would make
    a marker report undetected and be wrong about why, and a scan of one target
    should not silently narrow what another target's ground truth can measure.

    Reads the YAML directly instead of going through
    :mod:`dast_orchestrator.stages.ground_truth`, which imports the metrics layer —
    this is needed inside the scan driver, before any of that exists.

    A malformed or missing markers file yields nothing rather than raising: this
    guards a *safety* check, and failing a scan because a file it does not
    otherwise need is unreadable would be the wrong trade. `dast cve` (assess)
    is where a broken markers file must fail loudly.
    """
    targets_dir = targets_dir or TARGETS_DIR
    found: set[str] = set()
    for path in sorted(targets_dir.glob(f"*/{MARKERS_NAME}")):
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except (OSError, yaml.YAMLError):
            continue
        for marker in (data.get("markers") or []):
            for rule in ((marker or {}).get("zap_rules") or []):
                found.add(str(rule))
    return frozenset(found)


def load_all(targets_dir: "Path | None" = None) -> None:
    """(Re)load every ``<name>/target.yml`` under ``targets_dir``.

    Keyed on the directory rather than on a flat glob, so a target's definition
    is found next to the things it describes and a stray YAML elsewhere in the
    tree can never be mistaken for one.
    """
    targets_dir = targets_dir or TARGETS_DIR
    REGISTRY.clear()
    for path in sorted(Path(targets_dir).glob(f"*/{DEFINITION_NAME}")):
        register(load_target(path))


def use_dir(targets_dir: "str | Path | None") -> Path:
    """Point discovery and source resolution at ``targets_dir`` and reload.

    The one entry point a stage or ``dast`` calls once its configuration is known
    (flag beats ``SHARED_TARGETS_DIR`` beats the built-in default), before it
    resolves a target — so an override reaches the registry that
    :func:`resolve_positional` and :func:`get` read, and :func:`target_source`
    with it. ``None`` or the current value is a no-op reload; idempotent.
    """
    global TARGETS_DIR
    resolved = Path(targets_dir) if targets_dir else DEFAULT_TARGETS_DIR
    TARGETS_DIR = resolved
    load_all(resolved)
    return resolved


def target_source(target: Target) -> Path:
    """The absolute path to a target's source tree, under the configured dir.

    A target's ``source_dir`` is relative to its **own** directory
    (``<TARGETS_DIR>/<name>/``) — usually just ``src`` — so pointing
    :data:`TARGETS_DIR` elsewhere moves the definitions and the source they name
    together, whatever that directory is called. This is the single reader every
    stage uses instead of ``REPO_ROOT / target.source_dir``.
    """
    return TARGETS_DIR / target.name / target.source_dir


def get(name: str) -> Target:
    if name not in REGISTRY:
        raise KeyError(
            f"unknown target {name!r}; known: {sorted(REGISTRY)}. "
            f"Add one as {TARGETS_DIR}/<name>/{DEFINITION_NAME}."
        )
    return REGISTRY[name]


def for_url(url: str, default: str = "gitea") -> Target:
    """The registered target whose base URL has the same host, else the default.

    Lets a driver that only has the recorded scan URL (verify, report) pick the
    right target's data without threading the name through every artifact.
    """
    host = urlparse(url or "").hostname
    if host:
        for target in REGISTRY.values():
            if urlparse(target.base_url).hostname == host:
                return target
    return get(default)


load_all()

#: The default target when none is named. Falls back gracefully if ``gitea`` was
#: renamed/removed so an empty registry gives an actionable error, not a KeyError.
DEFAULT: Target = REGISTRY.get("gitea") or next(iter(REGISTRY.values()), None)
