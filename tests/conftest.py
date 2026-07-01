"""Shared test fixtures.

The scripts under ``scripts/`` are standalone tools (not an installable
package), so tests load them by file path via importlib.
"""
import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"


def _load(rel_path: str, module_name: str):
    path = SCRIPTS_DIR / rel_path
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def load_script():
    """Return a loader: load_script('static_analysis/secret_finder.py', 'secret_finder')."""
    return _load
