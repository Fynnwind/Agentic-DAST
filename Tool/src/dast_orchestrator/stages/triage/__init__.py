"""Triage a finished scan: join ZAP alerts to Noir endpoints, then run the deterministic arm
and the LLM arm; writes ``triage.json``.

Reads artifacts off disk instead of running inside ``scan``, for two reasons: triage can
be re-run against a stored scan without paying for another active scan, and the control arm
can be evaluated with ``--no-llm`` on a machine with no API key. The LLM arm is two passes —
screening (per-endpoint) and synthesis (whole-corpus). See docs/ARCHITECTURE.md.
"""
from dast_orchestrator.stages.triage.common import *
from dast_orchestrator.stages.triage.arms import *
from dast_orchestrator.stages.triage.driver import *
from dast_orchestrator.stages.triage import common, arms, driver
