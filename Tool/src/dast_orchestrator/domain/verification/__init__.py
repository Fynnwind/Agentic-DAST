"""Verification: outcomes + resolution vocabulary and logic.

Split into submodules (outcomes / dispatch / loop); this __init__ re-exports every public name so `from dast_orchestrator.domain import verification`
and `verification.X` keep working exactly as before.
"""
from dast_orchestrator.domain.verification.outcomes import *  # noqa: F401,F403
from dast_orchestrator.domain.verification.dispatch import *  # noqa: F401,F403
from dast_orchestrator.domain.verification.loop import *  # noqa: F401,F403
from dast_orchestrator.domain.verification.worklist import *  # noqa: F401,F403
