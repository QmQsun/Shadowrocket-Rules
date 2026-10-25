"""Fail explicitly if discovery finds no tests."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
suite = unittest.defaultTestLoader.discover(str(ROOT / "Tests"), pattern="test_*.py")
if suite.countTestCases() == 0:
    raise SystemExit("No tests discovered")
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
