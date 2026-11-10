"""`dast commands` regenerates the reference from the parsers, reproducibly."""
from pathlib import Path

from dast_orchestrator.cli import command_docs

COMMANDS_MD = Path(__file__).resolve().parents[2] / "docs" / "COMMANDS.md"


def test_committed_commands_md_is_in_sync_with_the_generator():
    """The committed doc must equal what `dast commands` produces right now.

    Without this, the reference silently drifts: a new flag, a reworded `help=`,
    or a renamed command leaves `docs/COMMANDS.md` stale and nothing fails —
    which is exactly how a `dast cve` row for a command that does not exist, and
    opening sentences cut off mid-word, reached the committed doc. The fix is to
    run `dast commands` (writes docs/COMMANDS.md) and commit the result.
    """
    assert COMMANDS_MD.read_text() == command_docs.render(), (
        "docs/COMMANDS.md is out of sync with the parsers — run `dast commands` "
        "and commit the regenerated file."
    )


def test_render_covers_every_command_and_reads_from_the_parsers():
    md = command_docs.render()
    assert md.startswith("# DAST CLI — command & flag reference")
    # The four chain stages are numbered and named (the stage, not the CLI verb),
    # and the standalone static-analysis command is not numbered.
    for header in ("Stage 1 · Scan — `dast scan",
                   "Stage 2 · Triage — `dast triage",
                   "Stage 3 · Verify — `dast verify",
                   "Stage 4 · Report — `dast report",
                   "Static-analysis — `dast static-analysis"):
        assert header in md
    assert "## 2 · Shared flags" in md
    # A representative flag and its env var, proving rows come from the parser.
    assert "--max-active-scan-minutes" in md and "SCAN_ZAP_MAX_ACTIVE_SCAN_MINUTES" in md


def test_render_is_deterministic_and_does_not_leak_the_shell_env(monkeypatch):
    # A flag env var exported in the shell must not reach the doc: defaults come
    # from the env file (or the built-in fallback), so the reference is the same
    # on any machine.
    monkeypatch.setenv("SCAN_ZAP_MAX_ACTIVE_SCAN_MINUTES", "9999")
    first = command_docs.render()
    second = command_docs.render()
    assert first == second
    assert "9999" not in first
    # The environment is restored after each render — no leak into the caller.
    assert "SCAN_ZAP_MAX_ACTIVE_SCAN_MINUTES" in __import__("os").environ


def test_secret_backed_defaults_are_never_rendered():
    md = command_docs.render()
    assert "`<from SCAN_ZAP_API_KEY>`" in md
