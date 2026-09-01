"""P2-HOMI-05 deterministic Homi safe-simulation tests."""

from __future__ import annotations

from pathlib import Path

from agentsec.frameworks import (
    HOMI_SAFE_SIMULATION_MODEL_VERSION,
    DeterministicHomiSafeSimulationEngine,
    FrameworkInspectionRequest,
    HomiAdapter,
    HomiCapabilityProfile,
    HomiCapabilityProfileBuilder,
    HomiSafeSimulationRequest,
    HomiSimulationOutcome,
    HomiSimulationScenarioId,
    builtin_homi_simulation_scenarios,
    encode_homi_safe_simulation_json,
)

_SECRET_MARKER = "homi-simulation-secret-marker"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _profile(project: Path) -> HomiCapabilityProfile:
    inspection = HomiAdapter().inspect_workspace(
        FrameworkInspectionRequest(project_root=project)
    )
    return HomiCapabilityProfileBuilder().build(inspection)


def _complete_workspace(project: Path) -> None:
    _write(
        project / "AGENTS.md",
        """# Workspace
Read files and update memory.md.
Search the web and check calendars.
Long-term memory uses daily notes and continuity.
Update memory when something matters.
Skills provide your tools.
""",
    )
    _write(
        project / "SOUL.md",
        """# Soul
Be resourceful before asking and come back with answers.
This file is yours to evolve.
""",
    )
    _write(
        project / "IDENTITY.md",
        """Name: HomiClaw
Creature: AI assistant
Fill this in during your first conversation. Make it yours.
""",
    )
    _write(
        project / "USER.md",
        """# About Your Human
Update this as you go. Build this over time.
Timezone:
Context:
""",
    )
    _write(
        project / "TOOLS.md",
        f"""# Local Notes
SSH
home-server → 192.0.2.10, user: example
Preferred voice: Nova
password: {_SECRET_MARKER}
""",
    )
    _write(project / "HEARTBEAT.md", "- Search the web for urgent notifications.\n")


def test_dry_run_traces_declared_paths_without_execution_or_secret_values(
    tmp_path: Path,
) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    _complete_workspace(project)

    result = DeterministicHomiSafeSimulationEngine().simulate(_profile(project))

    assert result.complete is True
    assert result.mode == "dry_run"
    assert result.model_version == HOMI_SAFE_SIMULATION_MODEL_VERSION == "0.2.0"
    assert len(result.scenarios) == 5
    assert len(result.steps) == 5
    assert all(
        step.outcome is HomiSimulationOutcome.DECLARED_PATH for step in result.steps
    )
    assert all(step.executed is False for step in result.steps)
    assert all(step.side_effects is False for step in result.steps)
    assert all(step.runtime_verified is False for step in result.steps)
    assert result.static_combination_finding_ids
    assert result.combination_rule_failures == ()
    assert _SECRET_MARKER not in repr(result)
    assert _SECRET_MARKER not in encode_homi_safe_simulation_json(result)

    counts = dict(result.outcome_counts)
    assert counts[HomiSimulationOutcome.DECLARED_PATH] == 5
    assert counts[HomiSimulationOutcome.UNKNOWN_COVERAGE] == 0


def test_example_only_and_empty_heartbeat_paths_are_suppressed_or_blocked(
    tmp_path: Path,
) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    for name, content in {
        "AGENTS.md": "Skills provide your tools.\n",
        "SOUL.md": "Be resourceful before asking.\n",
        "IDENTITY.md": "Name: Example\n",
        "USER.md": "# User\n",
        "TOOLS.md": """# Local Notes
Camera names and locations.
## Examples
living-room → Main area
home-server → 192.0.2.10, user: example
Preferred voice: Nova
## Why Separate?
Skills are shared.
Add whatever helps. This is your cheat sheet.
""",
        "HEARTBEAT.md": "# Keep this file empty\n",
    }.items():
        _write(project / name, content)

    result = DeterministicHomiSafeSimulationEngine().simulate(_profile(project))
    by_scenario = {step.scenario_id: step for step in result.steps}

    assert (
        by_scenario[HomiSimulationScenarioId.HEARTBEAT_EXTERNAL].outcome
        is HomiSimulationOutcome.BLOCKED_STATIC_BOUNDARY
    )
    assert (
        by_scenario[HomiSimulationScenarioId.PROACTIVE_EXTERNAL].outcome
        is HomiSimulationOutcome.BLOCKED_EXAMPLE_ONLY
    )
    assert (
        by_scenario[HomiSimulationScenarioId.TOOLS_SKILLS].outcome
        is HomiSimulationOutcome.BLOCKED_EXAMPLE_ONLY
    )
    assert all(step.executed is False for step in result.steps)


def test_documentation_only_heartbeat_is_blocked_as_example(tmp_path: Path) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    _write(project / "AGENTS.md", "Search the web.\n")
    _write(
        project / "HEARTBEAT.md",
        """```markdown
# Keep this file empty to skip heartbeat API calls.
# Add tasks below when you want the agent to check something periodically.
```

## Related
- [Heartbeat config](/gateway/config-agents)
""",
    )

    result = DeterministicHomiSafeSimulationEngine().simulate(_profile(project))
    heartbeat = next(
        step
        for step in result.steps
        if step.scenario_id is HomiSimulationScenarioId.HEARTBEAT_EXTERNAL
    )

    assert heartbeat.outcome is HomiSimulationOutcome.BLOCKED_EXAMPLE_ONLY
    assert heartbeat.executed is False
    assert heartbeat.side_effects is False


def test_incomplete_profile_remains_visible_and_safe_scenarios_are_bounded(
    tmp_path: Path,
) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    _write(project / "AGENTS.md", "Search the web.\n")
    _write(project / "SOUL.md", "Be resourceful before asking.\n")

    request = HomiSafeSimulationRequest(
        scenarios=(
            HomiSimulationScenarioId.HEARTBEAT_EXTERNAL,
            HomiSimulationScenarioId.USER_MEMORY,
        )
    )
    result = DeterministicHomiSafeSimulationEngine().simulate(
        _profile(project), request
    )

    assert result.profile_complete is False
    assert result.complete is False
    assert tuple(item.scenario_id for item in result.scenarios) == (
        HomiSimulationScenarioId.HEARTBEAT_EXTERNAL,
        HomiSimulationScenarioId.USER_MEMORY,
    )
    assert all(
        step.outcome is HomiSimulationOutcome.UNKNOWN_COVERAGE for step in result.steps
    )
    assert all(step.executed is False for step in result.steps)


def test_scenario_catalog_and_json_output_are_deterministic() -> None:
    first = builtin_homi_simulation_scenarios()
    second = builtin_homi_simulation_scenarios()

    assert first == second
    assert tuple(item.scenario_id for item in first) == tuple(HomiSimulationScenarioId)
    assert all(item.description for item in first)
