"""Entry point for ``python -m dast_orchestrator.stages.verify``."""
from dast_orchestrator.stages.verify.driver import main

if __name__ == "__main__":
    raise SystemExit(main())
