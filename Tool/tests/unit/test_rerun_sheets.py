"""The repeats band's and G5's first sample is the matrix's admin cell.

``rerun-repeats.yml`` runs 3 per row and counts G1's admin-blind and G2's
admin-ceiling cells as the band's 4th sample (author, 2026-11-02); G5
(``rerun-g5-model-repeats.yml``) repeats triage and verify 3 times on G1's
admin-blind scan, whose own triage and verify are the 4th. That holds only while
each pair is one configuration, so this pins it: same stages, base env and
effective env (sheet defaults overlaid by the row, as the harness merges them).
→ DECISIONS.md §"The repeats band's first sample is the matrix cell", §"G5 restored".

Read as YAML rather than through ``load_sheet``, which also requires the gitignored
``config/scanner/.env`` to exist.
"""

from pathlib import Path

import yaml

HARNESS = Path(__file__).resolve().parents[2] / "config" / "harness"
BAND_N = 4


def _admin_rows(sheet: str) -> dict[tuple[str, str], dict]:
    data = yaml.safe_load((HARNESS / sheet).read_text())
    defaults = data["defaults"]
    rows = {}
    for entry in data["rows"]:
        env = {**(defaults.get("env") or {}), **(entry.get("env") or {})}
        env = {str(k): str(v) for k, v in env.items()}
        if env.get("SHARED_AUTH_MODE") != "admin":
            continue
        rows[(entry["target"], env.get("SHARED_ORACLE", "off"))] = {
            "stages": entry.get("stages"),
            "base_env": defaults.get("base_env"),
            "timeout": entry.get("timeout_minutes") or defaults.get("timeout_minutes"),
            "env": env,
            "repeat": int(entry.get("repeat") or 1),
        }
    return rows


def test_every_band_row_is_its_matrix_cell_repeated():
    band = _admin_rows("rerun-repeats.yml")
    matrix = {**_admin_rows("rerun-g1-blind-matrix.yml"),
              **_admin_rows("rerun-g2-ceiling-matrix.yml")}
    assert len(band) == 7                      # Cacti's ceiling band is the driver's
    for key, row in band.items():
        cell = matrix[key]
        assert cell["repeat"] == 1, key
        assert row["repeat"] + cell["repeat"] == BAND_N, key
        for field in ("stages", "base_env", "timeout", "env"):
            assert row[field] == cell[field], (key, field)


def test_every_model_repeat_row_is_its_g1_admin_blind_cell_repeated():
    data = yaml.safe_load((HARNESS / "rerun-g5-model-repeats.yml").read_text())
    g1 = _admin_rows("rerun-g1-blind-matrix.yml")
    targets = set()
    for entry in data["rows"]:
        target = entry["name"].split("-")[0]
        targets.add(target)
        cell = g1[(target, "off")]
        env = {**(data["defaults"].get("env") or {}), **(entry.get("env") or {})}
        assert {str(k): str(v) for k, v in env.items()} == cell["env"], target
        assert data["defaults"]["base_env"] == cell["base_env"], target
        assert entry["stages"] == ["triage", "verify"], target
        assert set(entry["stages"]) <= set(cell["stages"]), target
        assert int(entry["repeat"]) + cell["repeat"] == BAND_N, target
    assert targets == {"grafana", "wordpress", "cacti", "gitea"}


def test_the_cacti_ceiling_driver_runs_the_rest_of_its_band():
    # G2's admin Cacti ceiling is one run of the same sheet the driver repeats.
    driver = (HARNESS / "rerun-cacti-ceiling-driver.sh").read_text()
    assert f'N="${{1:-{BAND_N - 1}}}"' in driver
    assert 'SHEET="${2:-config/harness/rerun-cacti-ceiling.yml}"' in driver


def test_the_trimmed_smoke_is_two_rows_of_the_full_smoke_unchanged():
    full = yaml.safe_load((HARNESS / "rerun-ceiling-smoke.yml").read_text())
    trimmed = yaml.safe_load((HARNESS / "rerun-ceiling-smoke-auth.yml").read_text())
    assert trimmed["defaults"] == full["defaults"]
    rows = {r["name"]: r for r in full["rows"]}
    assert [r["name"] for r in trimmed["rows"]] == ["wordpress-admin-ceiling",
                                                     "cacti-admin-ceiling"]
    assert all(r == rows[r["name"]] for r in trimmed["rows"])


def test_the_wordpress_gate_row_alone_is_the_smokes_row_unchanged():
    full = yaml.safe_load((HARNESS / "rerun-ceiling-smoke.yml").read_text())
    alone = yaml.safe_load((HARNESS / "rerun-ceiling-smoke-auth-wp.yml").read_text())
    assert alone["defaults"] == full["defaults"]
    rows = {r["name"]: r for r in full["rows"]}
    assert alone["rows"] == [rows["wordpress-admin-ceiling"]]


def test_the_signed_in_cacti_rerun_is_g1s_two_rows_unchanged():
    g1 = yaml.safe_load((HARNESS / "rerun-g1-blind-matrix.yml").read_text())
    again = yaml.safe_load((HARNESS / "rerun-g1-cacti-signed-in.yml").read_text())
    assert again["defaults"] == g1["defaults"]
    rows = {r["name"]: r for r in g1["rows"]}
    assert again["rows"] == [rows["cacti-user-blind"], rows["cacti-admin-blind"]]


def test_the_gitea_admin_rerun_is_g1s_row_unchanged():
    g1 = yaml.safe_load((HARNESS / "rerun-g1-blind-matrix.yml").read_text())
    again = yaml.safe_load((HARNESS / "rerun-g1-gitea-admin.yml").read_text())
    assert again["defaults"] == g1["defaults"]
    rows = {r["name"]: r for r in g1["rows"]}
    assert again["rows"] == [rows["gitea-admin-blind"]]


def test_the_cacti_cross_level_ceilings_differ_from_the_admin_one_only_in_auth():
    # G2's Cacti auth axis reads the three ceilings side by side, so the three
    # sheets must be one method at three auth levels.
    admin = yaml.safe_load((HARNESS / "rerun-cacti-ceiling.yml").read_text())
    (admin_row,) = admin["rows"]
    for level in ("none", "user"):
        sheet = yaml.safe_load((HARNESS / f"rerun-cacti-ceiling-{level}.yml").read_text())
        assert sheet["defaults"] == admin["defaults"], level
        (row,) = sheet["rows"]
        assert row["name"] == f"cacti-{level}-ceiling"
        assert row["env"] == {**admin_row["env"], "SHARED_AUTH_MODE": level}, level
        assert {k: v for k, v in row.items() if k not in ("name", "env")} == {
            k: v for k, v in admin_row.items() if k not in ("name", "env")}, level


def test_the_frameid_probe_is_g2s_wordpress_none_cell_with_only_the_caps_raised():
    g2 = yaml.safe_load((HARNESS / "rerun-g2-ceiling-matrix.yml").read_text())
    probe = yaml.safe_load((HARNESS / "rerun-wp-frameid-rulecap-probe.yml").read_text())
    assert probe["defaults"] == g2["defaults"]
    cell = {r["name"]: r for r in g2["rows"]}["wordpress-none-ceiling"]
    (row,) = probe["rows"]
    assert row["target"] == cell["target"]
    assert row["stages"] == ["scan"]
    assert row["env"] == {**cell["env"], "SCAN_ZAP_MAX_RULE_MINUTES": "30",
                          "SCAN_ZAP_MAX_ACTIVE_SCAN_MINUTES": "90"}


def test_the_openapi_demo_is_g1s_gitea_admin_cell_scan_only():
    g1 = yaml.safe_load((HARNESS / "rerun-g1-gitea-admin.yml").read_text())
    demo = yaml.safe_load((HARNESS / "rerun-openapi-demo.yml").read_text())
    assert demo["defaults"] == g1["defaults"]
    (cell,) = g1["rows"]
    (row,) = demo["rows"]
    assert row["target"] == cell["target"] == "gitea"
    assert row["env"] == cell["env"]
    assert row["stages"] == ["scan"]
