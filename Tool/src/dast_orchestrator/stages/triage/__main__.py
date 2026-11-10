"""Entry point for ``python -m dast_orchestrator.stages.triage``."""
from dast_orchestrator.stages.triage.driver import main

if __name__ == "__main__":
    raise SystemExit(main())
