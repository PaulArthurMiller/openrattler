"""Smoke test: verify the openrattler package is importable and exports a version string."""

import openrattler


def test_version_is_string() -> None:
    """The package must export a non-empty __version__ string."""
    assert isinstance(openrattler.__version__, str)
    assert openrattler.__version__ != ""
