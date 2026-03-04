"""Tests for built-in task templates (agents/templates.py)."""

from __future__ import annotations

import pytest

from openrattler.agents.templates import TASK_TEMPLATES
from openrattler.models.agents import TaskTemplate

# ---------------------------------------------------------------------------
# Presence checks
# ---------------------------------------------------------------------------

_REQUIRED_TEMPLATES = {"research", "coding", "execution", "analysis"}


def test_all_built_in_templates_present() -> None:
    assert _REQUIRED_TEMPLATES <= set(TASK_TEMPLATES.keys())


def test_no_extra_unexpected_keys() -> None:
    """All keys must be from the known set (guards against typos)."""
    assert set(TASK_TEMPLATES.keys()) == _REQUIRED_TEMPLATES


# ---------------------------------------------------------------------------
# Schema validity — every template must be a valid TaskTemplate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(_REQUIRED_TEMPLATES))
def test_template_is_task_template_instance(name: str) -> None:
    assert isinstance(TASK_TEMPLATES[name], TaskTemplate)


@pytest.mark.parametrize("name", sorted(_REQUIRED_TEMPLATES))
def test_template_name_matches_key(name: str) -> None:
    assert TASK_TEMPLATES[name].name == name


@pytest.mark.parametrize("name", sorted(_REQUIRED_TEMPLATES))
def test_template_has_non_empty_system_prompt(name: str) -> None:
    assert TASK_TEMPLATES[name].system_prompt.strip()


@pytest.mark.parametrize("name", sorted(_REQUIRED_TEMPLATES))
def test_template_has_required_tools(name: str) -> None:
    assert len(TASK_TEMPLATES[name].required_tools) >= 1


@pytest.mark.parametrize("name", sorted(_REQUIRED_TEMPLATES))
def test_template_has_suggested_model(name: str) -> None:
    model = TASK_TEMPLATES[name].suggested_model
    assert "/" in model, f"Expected provider/model format, got {model!r}"


@pytest.mark.parametrize("name", sorted(_REQUIRED_TEMPLATES))
def test_template_complexity_range_valid(name: str) -> None:
    lo, hi = TASK_TEMPLATES[name].typical_complexity_range
    assert 0 <= lo <= hi <= 10


@pytest.mark.parametrize("name", sorted(_REQUIRED_TEMPLATES))
def test_template_cost_limit_positive(name: str) -> None:
    assert TASK_TEMPLATES[name].suggested_cost_limit > 0


@pytest.mark.parametrize("name", sorted(_REQUIRED_TEMPLATES))
def test_template_has_workflow(name: str) -> None:
    workflow = TASK_TEMPLATES[name].workflow
    assert workflow is not None and len(workflow) >= 2


# ---------------------------------------------------------------------------
# Specific template content checks
# ---------------------------------------------------------------------------


def test_research_uses_web_tools() -> None:
    tools = TASK_TEMPLATES["research"].required_tools
    assert "web_search" in tools
    assert "web_fetch" in tools


def test_coding_tools_set() -> None:
    tools = TASK_TEMPLATES["coding"].required_tools
    assert len(tools) >= 1


def test_execution_tools_set() -> None:
    tools = TASK_TEMPLATES["execution"].required_tools
    assert len(tools) >= 1


def test_analysis_uses_file_read() -> None:
    tools = TASK_TEMPLATES["analysis"].required_tools
    assert "file_read" in tools
