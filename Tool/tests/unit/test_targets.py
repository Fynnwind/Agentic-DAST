"""The target registry and the Gitea descriptor."""

from __future__ import annotations

import pytest

from dast_orchestrator.adapters import targets


def test_gitea_is_registered_and_default():
    assert "gitea" in targets.REGISTRY
    assert targets.DEFAULT.name == "gitea"


def test_get_unknown_target_is_actionable():
    with pytest.raises(KeyError):
        targets.get("nonesuch")


def test_for_url_matches_by_host():
    assert targets.for_url("http://target-gitea:3000/user/login").name == "gitea"
    # unknown host falls back to the default rather than raising
    assert targets.for_url("http://example.invalid/").name == "gitea"


def test_gitea_auth_profile_has_both_roles():
    auth = targets.get("gitea").auth
    assert auth.session_cookie == "i_like_gitea"
    assert auth.csrf_field == "_csrf"
    assert auth.user("user").username == "dastuser"
    assert auth.user("admin").username == "dastadmin"
    assert auth.user("nobody") is None


def test_gitea_carries_path_vars_and_fillers():
    gitea = targets.get("gitea")
    assert gitea.path_vars["username"] == "thesis"
    assert gitea.form_fillers["password"] == "Password123!"
    assert gitea.source_dir == "src"


def test_gitea_is_loaded_from_its_own_directory():
    # A target is a directory holding everything it needs — its definition, its
    # source clone, its container and its fixtures.
    home = targets.TARGETS_DIR / "gitea"
    assert (home / targets.DEFINITION_NAME).is_file()
    assert (home / "env" / "compose.yml").is_file()
    assert (home / "env" / "seed-users.sh").is_file()


def test_use_dir_relocates_discovery_and_source_resolution(tmp_path):
    # The tool/targets-split lever: point the tool at a targets dir anywhere.
    # `use_dir` re-loads the registry from there, and `target_source` resolves a
    # target's `source_dir` within its own <name>/ dir — so one setting moves both.
    import yaml

    root = tmp_path / "Targets"
    home = root / "demo"
    home.mkdir(parents=True)
    (home / targets.DEFINITION_NAME).write_text(yaml.safe_dump(
        {"name": "demo", "base_url": "http://demo:8080", "source_dir": "src"}
    ))
    try:
        targets.use_dir(root)
        assert "demo" in targets.REGISTRY and "gitea" not in targets.REGISTRY
        assert targets.target_source(targets.get("demo")) == root / "demo" / "src"
    finally:
        targets.use_dir(targets.DEFAULT_TARGETS_DIR)
    # Restored: the real registry is back for every other test.
    assert "gitea" in targets.REGISTRY


def test_a_markerless_target_is_registered_and_scannable(tmp_path):
    # Ground truth is OPTIONAL (user, 2026-09-29): a target with no cve-markers.yml
    # is a first-class, fully scannable target — it simply has no detection
    # numbers. The registry globs target.yml, so registration never depended on
    # markers; this pins that the ground-truth layer no-ops rather than raising.
    import yaml

    from dast_orchestrator.stages import ground_truth as gt

    root = tmp_path / "Targets"
    home = root / "plain"
    home.mkdir(parents=True)
    (home / targets.DEFINITION_NAME).write_text(yaml.safe_dump(
        {"name": "plain", "base_url": "http://plain:8080", "source_dir": "src"}
    ))
    try:
        targets.use_dir(root)
        assert "plain" in targets.REGISTRY               # registers with no markers
        assert targets.marker_rule_ids() == frozenset()  # scan driver tolerates it
        assert not gt.has_markers("plain")               # the optional-mode guard
        with pytest.raises(FileNotFoundError):
            gt.MarkerSet.load("plain")                    # explicit load still loud
    finally:
        targets.use_dir(targets.DEFAULT_TARGETS_DIR)


def test_a_definition_must_agree_with_its_directory(tmp_path):
    # The directory is the identity; a `name:` that disagreed would make two
    # things claim to be the same target.
    import yaml

    home = tmp_path / "wordpress"
    home.mkdir()
    (home / targets.DEFINITION_NAME).write_text(yaml.safe_dump(
        {"name": "gitea", "base_url": "http://x:1", "source_dir": "s"}
    ))
    with pytest.raises(targets.TargetError, match="must match its directory"):
        targets.load_target(home / targets.DEFINITION_NAME)


# -- the YAML loader -------------------------------------------------------

_MINIMAL = {"name": "demo", "base_url": "http://demo:8080", "source_dir": "demo-src"}


def test_target_from_dict_minimal():
    t = targets.target_from_dict(_MINIMAL)
    assert t.name == "demo" and t.auth is None and t.path_vars == {}


def test_target_from_dict_missing_key_is_actionable():
    with pytest.raises(targets.TargetError):
        targets.target_from_dict({"name": "demo"})  # no base_url / source_dir


def test_target_from_dict_coerces_scalars_to_str():
    t = targets.target_from_dict({**_MINIMAL, "path_vars": {"size": 84, "id": 1}})
    assert t.path_vars == {"size": "84", "id": "1"}


def test_target_from_dict_builds_auth_with_default_strategy():
    t = targets.target_from_dict({
        **_MINIMAL,
        "auth": {"login_path": "/login", "session_cookie": "sid",
                 "users": [{"role": "user", "username": "u", "password": "p"}]},
    })
    assert t.auth.strategy == "form"        # default when unspecified
    assert t.auth.user("user").username == "u"


def test_target_from_dict_parses_a_recovery_block():
    t = targets.target_from_dict({
        **_MINIMAL, "recovery": {"containers": ["target-demo", "target-demo-db"]}})
    assert t.recovery == targets.Recovery(containers=("target-demo", "target-demo-db"))


def test_target_without_a_recovery_block_has_none():
    assert targets.target_from_dict(_MINIMAL).recovery is None


def test_a_recovery_block_needs_at_least_one_container():
    with pytest.raises(targets.TargetError, match="recovery"):
        targets.target_from_dict({**_MINIMAL, "recovery": {"containers": []}})


def test_load_all_roundtrips_a_written_yaml(tmp_path):
    import yaml
    (tmp_path / "wp").mkdir()
    (tmp_path / "wp" / targets.DEFINITION_NAME).write_text(yaml.safe_dump({
        "name": "wp", "base_url": "http://wp:80", "source_dir": "wp-src",
        "auth": {"login_path": "/wp-login.php", "session_cookie": "wordpress_logged_in",
                 "strategy": "form", "users": [{"role": "admin", "username": "a", "password": "b"}]},
    }))
    saved = dict(targets.REGISTRY)
    try:
        targets.load_all(tmp_path)
        assert targets.get("wp").auth.login_path == "/wp-login.php"
    finally:
        targets.REGISTRY.clear()
        targets.REGISTRY.update(saved)


# -- oracle (ceiling) seeds live on the CVE marker -------------------------


def test_marker_seeds_expose_a_sink_no_extractor_can_reach():
    """A sink nothing crawls to is not undetectable — it was never tested.

    WordPress's `?__wpdmxp=1` shortcode iframe and Grafana's plugin-asset route
    are ordinary surfaces Noir extracts no endpoint for and the spider cannot
    guess. Their benign reachability seed now lives on the CVE marker (`seed:`)
    and is applied only under a scan's --oracle mode, so a blind run's tree is
    what discovery alone produced — the honest baseline the ceiling is measured
    against.
    """
    from dast_orchestrator.stages import ground_truth

    wp = ground_truth.MarkerSet.load("wordpress")
    assert "/?__wpdmxp=1&frameid=1" in wp.oracle_seeds()
    grafana = ground_truth.MarkerSet.load("grafana")
    assert "/public/plugins/prometheus/plugin.json" in grafana.oracle_seeds()


def test_a_marker_seed_must_land_at_its_own_sink():
    """A seed that is not the marker's sink would let --oracle seed a surface
    unrelated to the CVE it claims to expose — the free surface-widening the
    seeding rule forbids. Validated at load, so a stray seed fails loudly."""
    import pytest as _pytest
    from dast_orchestrator.stages import ground_truth

    for name in sorted(targets.REGISTRY):
        ms = ground_truth.MarkerSet.load(name)      # loading validates every seed
        for m in ms.markers:
            for s in m.seed:
                assert m.serves(s), f"{name}/{m.id}: seed {s!r} not at its sink"


def test_openapi_specs_are_opt_in_and_parse_to_typed_specs():
    # absent by default — no existing target regresses
    plain = targets.target_from_dict(
        {"name": "x", "base_url": "http://x", "source_dir": "s"}, where="x")
    assert plain.openapi_specs == ()
    # declared: url and file entries become typed OpenApiSpec objects
    tgt = targets.target_from_dict({
        "name": "x", "base_url": "http://x", "source_dir": "s",
        "openapi": [
            {"url": "http://x/openapi.json"},
            {"file": "specs/api.yaml", "base_path": "/v1"},
        ],
    }, where="x")
    assert len(tgt.openapi_specs) == 2
    assert tgt.openapi_specs[0].url == "http://x/openapi.json"
    assert tgt.openapi_specs[1].file == "specs/api.yaml"
    assert tgt.openapi_specs[1].base_path == "/v1"


def test_an_openapi_spec_with_both_url_and_file_is_a_target_error():
    with pytest.raises(targets.TargetError):
        targets.target_from_dict({
            "name": "x", "base_url": "http://x", "source_dir": "s",
            "openapi": [{"url": "http://x/s.json", "file": "s.yaml"}],
        }, where="x")


def test_oracle_seeds_are_deduplicated_and_empty_without_markers():
    from dast_orchestrator.stages import ground_truth

    # gitea's markers are all not-reachable / semantic — none declares a seed
    assert ground_truth.MarkerSet.load("gitea").oracle_seeds() == []


# -- per-target active-scan rules -------------------------------------------


def _target_yaml(tmp_path, body: str):
    """A minimal target on disk. The directory name is the target's identity,
    so it has to agree with `name:` — `load_target` enforces that."""
    from dast_orchestrator.adapters import targets as t

    home = tmp_path / "demo"
    home.mkdir(exist_ok=True)
    path = home / "target.yml"
    path.write_text(
        "name: demo\nbase_url: http://demo:80\nsource_dir: x\n" + body)
    return t.load_target(path)


def test_a_target_may_weaken_or_disable_one_active_rule(tmp_path):
    """The request-based limit, and the only one ZAP offers per rule.

    Measured on the 2026-09-08 Gitea scan: 30 of 52 enabled rules ran inside the
    45-minute cap and produced 7 alerts, two rules produced all of them, and
    ~1,700 s went to rules that raised nothing. Which rules are worth their time
    is a property of what the application IS, so it belongs to the target.
    """
    target = _target_yaml(tmp_path, """
zap_scan:
  max_rule_minutes: 10
  rules:
    "40026":
      enabled: false
      why: "Gitea is server-rendered Go; no DOM sink this rule can reach"
    "90019":
      strength: low
      threshold: high
      why: "no server-side template engine takes user input here"
""")
    assert target.max_rule_minutes == 10
    settings = target.rule_settings()
    assert settings["40026"].enabled is False
    assert settings["90019"].strength == "LOW"
    assert settings["90019"].threshold == "HIGH"
    assert not settings["90019"].is_default()


def test_a_rule_that_changes_the_scan_is_warned_about_when_it_says_no_why(
        tmp_path, capsys):
    """Warned, and NOT refused — the scan still runs.

    Without a reason the next reader cannot tell a measured decision from a
    leftover, and the reason has to be about the APPLICATION: disabling a rule
    because it raised nothing last run is fitting the scanner to the answer key.

    But refusing would put a documentation rule in the path of a scan, so
    someone mid-experiment loses the run rather than the sentence — and the
    pressure that creates is to type "because" and move on, which is worse than
    an empty field a reviewer can still spot.
    """
    target = _target_yaml(tmp_path, """
zap_scan:
  rules:
    "40026":
      enabled: false
""")
    assert target.rule_settings()["40026"].enabled is False
    # `ui.warn` wraps, so match on fragments that survive a line break.
    warned = " ".join(capsys.readouterr().err.split())
    assert "zap_scan.rules.40026 changes the scan and carries no `why`" in warned


def test_a_rule_left_at_its_defaults_needs_no_reason(tmp_path):
    """Listing a rule without changing it is a no-op, not a decision."""
    target = _target_yaml(tmp_path, """
zap_scan:
  rules:
    "40026": {}
""")
    assert target.rule_settings()["40026"].is_default()


def test_an_unknown_strength_or_threshold_is_refused(tmp_path):
    """These are ZAP enums; a typo would be silently ignored by the daemon."""
    from dast_orchestrator.adapters import targets as t

    for field, value in (("strength", "EXTREME"), ("threshold", "SOMETIMES")):
        with pytest.raises(t.TargetError, match=field):
            _target_yaml(tmp_path, f"""
zap_scan:
  rules:
    "40026":
      {field}: {value}
      why: "because"
""")


def test_a_tuned_rule_changes_the_runs_configuration_digest(tmp_path):
    """Same reasoning as a structural parameter: it changes what a scan CONTAINS.

    A run with a rule disabled and one without are different experiments, and
    two experiments must not share a directory name — the digest is what stops
    them.
    """
    from dast_orchestrator.foundation import run_paths

    base = {"target": "demo", "max_scan_minutes": 45, "scan_rules": ""}
    off = {**base, "scan_rules": "40026=off:default:default"}
    weak = {**base, "scan_rules": "40026=on:low:default"}

    digests = {run_paths.config_digest(c) for c in (base, off, weak)}
    assert len(digests) == 3, (
        "a disabled or weakened rule must move the digest, or two different "
        "scans share a run id")


def test_marker_rule_ids_reads_every_targets_ground_truth():
    """The set a quality filter must never disable.

    Read across ALL targets, not just the one being scanned: a rule turned off
    for its quality label would make a marker report undetected and be wrong
    about why, and scanning one target must not narrow what another target's
    ground truth can measure.
    """
    from dast_orchestrator.adapters import targets as t

    ids = t.marker_rule_ids()
    assert ids, "no marker rules found — the check would be vacuous"
    assert all(i.isdigit() for i in ids), ids
    # The rules behind this project's only confirmed CVE and its SQLi class.
    assert {"40026", "40018"} <= ids


def test_a_missing_or_broken_markers_file_yields_nothing_rather_than_raising(
        tmp_path):
    """This guards a safety check; it must not be able to fail a scan.

    A markers file that cannot be read has to fail loudly in
    `dast cve` (assess), which is where it is the subject. Inside the scan
    driver it is a file the run does not otherwise need.
    """
    from dast_orchestrator.adapters import targets as t

    (tmp_path / "broken").mkdir()
    (tmp_path / "broken" / t.MARKERS_NAME).write_text("{[not yaml")
    assert t.marker_rule_ids(tmp_path) == frozenset()
    assert t.marker_rule_ids(tmp_path / "does-not-exist") == frozenset()
