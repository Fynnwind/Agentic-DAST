"""End-to-end CLI + figure rendering over the frozen corpus."""

from dast_analyzer import cli, figures
from dast_analyzer.index import build_index


def _run(args, data_root, out=None):
    argv = ["--data", str(data_root)] + args
    if out:
        argv += ["-o", str(out)]
    return cli.main(argv)


def test_list_and_table(data_root, capsys):
    assert _run(["list"], data_root) == 0
    assert "two-arm" in capsys.readouterr().out


def test_table_csv_carries_provenance(data_root, tmp_path):
    out = tmp_path / "ladder.csv"
    assert _run(["-f", "csv", "table", "detection-ladder"], data_root, out) == 0
    text = out.read_text()
    assert text.startswith("# generated_at")
    assert "corpus_commit: bc30e8d" in text
    assert "ALL" in text  # the detection ladder's overall row


def test_select_group_by_with_metrics(data_root, tmp_path):
    out = tmp_path / "sel.csv"
    assert _run(["-f", "csv", "select", "--named", "reference-scans",
                 "--group-by", "target", "--metrics", "results.alerts"], data_root, out) == 0
    text = out.read_text()
    assert "results.alerts.min" in text and "results.alerts.max" in text


def test_digest_is_complete(data_root, tmp_path):
    out = tmp_path / "digest.md"
    assert _run(["digest"], data_root, out) == 0
    md = out.read_text()
    assert md.count("\n## ") >= 15  # all headline sections
    assert "no data:" not in md  # none of the cuts failed
    assert "CVE-2022-46169" in md  # the G10 standalone record


def test_figures_render(data_root, tmp_path):
    index = build_index(data_root)
    written = figures.render_all(index, tmp_path, formats=("png",))
    assert len(written) == len(figures.FIGURES)
    assert all(p.exists() and p.stat().st_size > 0 for p in written)
