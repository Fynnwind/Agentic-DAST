"""The handler-source join (RUN-PLAN §8) against the frozen corpus."""

from dast_analyzer import g9


def test_handler_source_join_shape_and_attrition(index):
    hs = g9.handler_source_join(index)
    assert len(hs) == 12  # one row per blind matrix cell
    by = hs.set_index(["target", "auth"])
    # grafana refutes nothing (nothing to join)
    assert int(by.loc[("grafana", "user"), "refuted"]) == 0
    # gitea refuted findings DO resolve to a handler source (route file)
    assert int(by.loc[("gitea", "none"), "refuted_mapped"]) > 0
    # wordpress refuted findings are unmatched ZAP alerts (no endpoint) -> 0 mapped
    assert int(by.loc[("wordpress", "user"), "refuted"]) > 0
    assert int(by.loc[("wordpress", "user"), "refuted_mapped"]) == 0


def test_handler_source_sast_overlap_is_zero(index):
    # the join's finding: SAST and DAST-refutation do not meet on the same source
    # file (Go resolves to the router; wordpress refuted are unmapped)
    hs = g9.handler_source_join(index)
    assert int(hs["refuted_source_in_sast"].sum()) == 0
