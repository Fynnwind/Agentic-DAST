"""Entry point for ``python -m dast_orchestrator.cli``.

The console script ``dast`` and this ``-m`` form are the same front end. The
harness spawns a row through the ``-m`` form so the row runs under the very
interpreter the sheet was started with, not whatever ``dast`` resolves to.
"""
from dast_orchestrator.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
