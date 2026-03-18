"""
tests/conftest.py — shared pytest fixtures and setup
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Point all services at an in-memory / temp DB by default during tests
# Individual tests that need a real file DB use the tmp_db fixture.
os.environ.setdefault("DB_PATH", ":memory:")
os.environ.setdefault("RULES_DIR", os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules"))
