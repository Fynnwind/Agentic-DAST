"""The vendored price table must reproduce the recorded actuals (module contract)."""

from dast_analyzer.metrics import _stage_record, _substage_cost
from dast_analyzer.prices import computed_cost, price_for
from dast_analyzer.selection import default_valid


def test_minimax_reproduces_a_call_exactly():
    # minimax fit is exact (resid 0): a cache-aware recompute of a known tally.
    p = price_for("minimax/minimax-m2.5")
    assert p is not None
    # 1M prompt (0 cached) + 0 completion at $0.30/Mtok = $0.30
    assert abs(computed_cost(1_000_000, 0, 0, "minimax/minimax-m2.5", cache=True) - 0.30) < 1e-9
    # args are (prompt, completion, cached): 500k cached at $0.06 + 500k uncached
    # at $0.30 = $0.18 with caching; no-cache bills all 1M prompt at $0.30 = $0.30
    assert abs(computed_cost(1_000_000, 0, 500_000, "minimax/minimax-m2.5", cache=True) - 0.18) < 1e-9
    assert abs(computed_cost(1_000_000, 0, 500_000, "minimax/minimax-m2.5", cache=False) - 0.30) < 1e-9


def test_nocache_is_never_cheaper_than_actual():
    assert computed_cost(1000, 100, 800, "deepseek/deepseek-v4-flash-0731", cache=False) >= computed_cost(
        1000, 100, 800, "deepseek/deepseek-v4-flash-0731", cache=True
    )


def test_unknown_model_returns_none():
    assert price_for("") is None
    assert computed_cost(1, 1, 0, "no/such-model") is None


def test_default_models_reproduce_corpus_cost_in_aggregate(valid):
    """Cache-aware recompute of all default-model stages is within a few % of the
    billed total — the sense in which the fitted rates are the list prices."""
    actual = recompute = 0.0
    for r in valid[valid["stage"].isin(["triage", "verify"])].itertuples(index=False):
        rec = _stage_record(r.run_dir, r.stage, getattr(r, "suffix", "") or "")
        if rec is None:
            continue
        # skip the frontier (Opus) stages — priced from §7, not fitted
        models = {(rec.get("config") or {}).get(k) for k in ("screening_model", "synthesis_model", "model")}
        if any(m and m.startswith("anthropic/") for m in models):
            continue
        c = _substage_cost(rec, cache=True)
        if c is None:
            continue
        recompute += c
        actual += (rec.get("results") or {}).get("cost_usd") or 0.0
    assert actual > 10  # sanity: we summed real spend
    assert abs(recompute - actual) / actual < 0.05
