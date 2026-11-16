"""Test suite. Run from the repository root with:  python -m unittest

The package is imported from src/ so that the tests work on a plain checkout,
without installing anything.
"""
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
