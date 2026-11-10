"""The test pyramid: what each tier is allowed to touch, and why.

    tests/
      unit/          one module's own logic. No I/O beyond tmp_path.
      integration/   several modules wired together: a driver end to end, an
                     argv or subprocess boundary, artifacts written and read
                     back. Containers and networks are stubbed.
      e2e/           the real thing: live containers, the running target, the
                     pinned tool images. Deselected by default.

**The tiers are about what a failure tells you, not about size.** A unit test
that fails names the function that broke. An integration test that fails says
two parts stopped agreeing — which is where most of this project's real bugs
have been: a flag that arrived as a string, a run id that reached the wrong
stage, a prompt version that never left the driver. An e2e failure says the
system does not work against the actual target, which no amount of mocking can
tell you and which is exactly what a DAST prototype's credibility rests on.

**e2e is opt-in** (`-m e2e`) because it needs Docker, the persistent target
stack and the pinned images, and because it is slow enough that nobody would run
the suite if it were not. `uv run pytest` stays fast and hermetic; CI and a
pre-release check run `uv run pytest -m e2e` as well.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

#: Where the live target and the ZAP daemon answer when the stacks are up.
TARGET_URL = "http://127.0.0.1:3000"
ZAP_URL = "http://127.0.0.1:8080"


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "e2e: needs live containers (Docker, the target stack, the pinned tool "
        "images). Deselected by default; run with `-m e2e`.",
    )


def _reachable(url: str, seconds: int = 3) -> bool:
    """Whether something answers at ``url`` — any status, not a healthy one."""
    import urllib.error
    import urllib.request

    try:
        urllib.request.urlopen(url, timeout=seconds)
        return True
    except urllib.error.HTTPError:
        return True          # answered, just not with 200 — good enough
    except Exception:
        return False


@pytest.fixture(scope="session")
def docker_available() -> bool:
    return bool(shutil.which("docker")) and subprocess.run(
        ["docker", "info"], capture_output=True
    ).returncode == 0


@pytest.fixture(scope="session")
def live_target(docker_available):
    """The persistent target stack, or a skip naming how to start it."""
    if not docker_available:
        pytest.skip("docker is not available")
    if not _reachable(TARGET_URL):
        pytest.skip(
            f"no target at {TARGET_URL} — "
            "`docker compose -f Targets/persistent.yml up -d`"
        )
    return TARGET_URL


@pytest.fixture(scope="session")
def live_zap(docker_available):
    """The ephemeral ZAP daemon, plus the API key, or a skip naming the fix."""
    if not docker_available:
        pytest.skip("docker is not available")
    if not _reachable(ZAP_URL):
        pytest.skip(
            f"no ZAP at {ZAP_URL} — `docker compose -f docker/ephemeral.yml "
            "--env-file config/scanner/.env up -d`"
        )
    from dast_orchestrator.foundation import config

    key = config.parse_env_file(config.DEFAULT_ENV_DIR / ".env").get("SCAN_ZAP_API_KEY")
    if not key:
        pytest.skip("SCAN_ZAP_API_KEY is not in config/scanner/.env")
    return ZAP_URL, key
