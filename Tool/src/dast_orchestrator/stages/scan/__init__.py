"""Scan a target: Noir static extraction seeds ZAP's site tree, then a bounded spider and
active scan write the raw alerts and an HTTP-exchange sidecar.

Target-agnostic — which system is scanned comes from a :class:`~targets.Target`
(``--target-name``, default ``gitea``), supplying the base URL, source tree, placeholder
substitutions and login flow. Flow: Noir extraction → seed → spider → passive drain →
bounded active scan → fetch alerts → write ``data/<run-id>/`` (``--no-noir`` reproduces the
spider-only behaviour, and the coverage delta is itself a result). → docs/ARCHITECTURE.md.
"""
from dast_orchestrator.stages.scan.common import *
from dast_orchestrator.stages.scan.pipeline import *
from dast_orchestrator.stages.scan.driver import *
from dast_orchestrator.stages.scan import common, pipeline, driver
