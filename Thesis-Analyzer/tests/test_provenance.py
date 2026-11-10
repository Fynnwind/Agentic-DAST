"""Provenance stamping + the served (routed) synthesis provider."""

from dast_analyzer import provenance as P
from dast_analyzer.selection import apply_named


def test_header_states_runs_and_commit(index):
    h = P.provenance_header(apply_named(index, "matrix-blind"))
    assert h["corpus_commit"] == "bc30e8d"
    assert h["n_executions"] > 0
    assert len(h["run_ids"]) == 12  # the 12 blind cells
    assert set(h["targets"]) == {"cacti", "gitea", "grafana", "wordpress"}
    # the header renders to comment lines without raising
    assert any("run_ids" in line for line in P.header_lines(h))


def test_served_synthesis_provider_is_read_from_the_call_log(index):
    sp = P.served_synthesis_providers(apply_named(index, "matrix-blind"))
    # config pin is empty by design (preference-routed); the served provider is
    # recorded per call — the mid-campaign routing amendment shows both providers
    assert (sp["synthesis_provider_config"] == "(empty — routed)").all()
    served = " ".join(sp["served_providers"])
    assert "Baidu" in served and "Friendli" in served
