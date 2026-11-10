"""Entry point for ``python -m dast_orchestrator.stages.scan``."""
from dast_orchestrator.stages.scan.driver import main

if __name__ == "__main__":
    raise SystemExit(main())
