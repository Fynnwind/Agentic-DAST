"""Vendored model list-prices and the cost computation they feed.

The analyzer never re-prices the *actual* spend — every record already carries
``results.cost_usd``, OpenRouter's billed figure with the cache discount applied.
This table exists for the two places RUN-PLAN §9 asks for a *computed* number:

  - the **no-cache** cost-per-finding figure (what a run would cost with caching
    off), and
  - the **G8 frontier projection** (default-model token volumes re-priced at a
    frontier model's rates; SHEET-CATALOG's method).

Both are labelled "computed" wherever they surface. Rates are $/Mtok.

Provenance of each rate is in ``Price.source``:
  - The frontier models are the RUN-PLAN §7 pinned list prices (the campaign only
    ran Opus; Sonnet / GPT rows are for the projection's "what if" column).
  - The three default-stage models are not priced in §7, so their rates are
    **fitted from the corpus call logs** (per-call prompt / cached / completion
    tokens against the billed ``cost_usd``) and reproduce the recorded actuals —
    exactly for minimax, within provider rounding for the two deepseek models
    (whose unit price can step mid-run). ``test_prices`` pins that reproduction.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Price:
    """List price of one model, $/Mtok, plus where the number comes from."""

    input: float  # uncached prompt tokens
    cached_input: float  # cache-read prompt tokens
    output: float  # completion tokens (reasoning billed here)
    source: str


# Keyed by the served model id (``model_served`` in the call log / ``config``).
PRICES: dict[str, Price] = {
    # Default stage models — fitted from the corpus (see module docstring).
    "deepseek/deepseek-v4-flash-0731": Price(0.1195, 0.0875, 0.2490, "fitted-from-corpus"),
    "deepseek/deepseek-v3.2": Price(0.2622, 0.1913, 1.6897, "fitted-from-corpus"),
    "minimax/minimax-m2.5": Price(0.30, 0.06, 1.20, "fitted-from-corpus"),
    # Frontier probe / projection models — RUN-PLAN §7 pinned list prices
    # (2026-10-07). Opus' cached-read 0.40 is the SHEET-CATALOG re-pricing rate
    # that reproduced the gitea actuals; Sonnet/GPT cached-read follow the
    # vendor's standard 0.1x-input and are only used by the hypothetical column.
    "anthropic/claude-opus-5.5": Price(4.0, 0.40, 20.0, "RUN-PLAN §7"),
    "anthropic/claude-sonnet-5.5": Price(2.0, 0.20, 10.0, "RUN-PLAN §7"),
    "openai/gpt-6.1-sol": Price(2.0, 0.20, 10.0, "RUN-PLAN §7"),
}


def price_for(model: str) -> Price | None:
    """The price of ``model``, exact match first then an id-prefix fallback."""
    if not model:
        return None
    if model in PRICES:
        return PRICES[model]
    for mid, price in PRICES.items():
        if model.startswith(mid) or mid.startswith(model):
            return price
    return None


def computed_cost(
    prompt_tokens: float,
    completion_tokens: float,
    cached_prompt_tokens: float,
    model: str,
    *,
    cache: bool = True,
) -> float | None:
    """Re-price one token tally at ``model``'s list rates; None if unknown model.

    ``cache=True`` reproduces the billed cost: cache-read tokens at the cheaper
    ``cached_input`` rate, the rest at ``input``. ``cache=False`` is the no-cache
    figure: *every* prompt token at the full ``input`` rate.
    """
    price = price_for(model)
    if price is None:
        return None
    p = float(prompt_tokens or 0)
    comp = float(completion_tokens or 0)
    cached = float(cached_prompt_tokens or 0) if cache else 0.0
    cost = (
        (p - cached) * price.input
        + cached * price.cached_input
        + comp * price.output
    )
    return cost / 1e6
