from pathlib import Path

import pytest

# Every corpus lives under this root. The tests read the frozen campaign corpus
# (commit bc30e8d, P7 pin), the analyzer's default scope, and assert against its
# known shape, so they double as a regression anchor on the index build. The thesis
# reports the rescan, which its scripts/analyzer_rescan.py selects from outside.
DATA_ROOT = Path(__file__).resolve().parents[2] / "Tool" / "data"


@pytest.fixture(scope="session")
def data_root() -> Path:
    if not DATA_ROOT.exists():
        pytest.skip(f"corpus not found at {DATA_ROOT}")
    return DATA_ROOT


@pytest.fixture(scope="session")
def index(data_root):
    from dast_analyzer.index import build_index

    return build_index(data_root)


@pytest.fixture(scope="session")
def valid(index):
    from dast_analyzer.selection import default_valid

    return default_valid(index)
