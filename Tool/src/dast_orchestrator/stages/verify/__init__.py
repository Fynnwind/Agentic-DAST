"""Verify triaged findings with independent tools — one bounded loop per finding, the third
and last reading (after the deterministic table and LLM triage): a tool actually trying
the attack, recorded confirmed / refuted / inconclusive / not-attempted.

Reads ``triage.json`` off disk (never re-scans) and writes ``verification.json``, talking
to the tools over stdio MCP. One loop whose single axis is ``VERIFY_INVOCATION``
(``llm``|``deterministic``, how the tool is called); which tool is always the
deterministic lookup, and ``deterministic`` invocation is the free, key-less control
that stays first-class. → DECISIONS.md.
"""
from dast_orchestrator.stages.verify.common import *
from dast_orchestrator.stages.verify.probes import *
from dast_orchestrator.stages.verify.records import *
from dast_orchestrator.stages.verify.driver import *
from dast_orchestrator.stages.verify import common, probes, records, driver
