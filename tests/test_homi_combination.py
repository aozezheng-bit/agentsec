"""P2-HOMI-04 deterministic Homi cross-file combination rule tests."""

from __future__ import annotations

from pathlib import Path

from agentsec.domain import (
    EvidenceConfidence,
    FindingCategory,
    ImpactLevel,
    LikelihoodLevel,
    Severity,
)
from agentsec.frameworks import (
    DeterministicHomiCombinationRuleEngine,
    FrameworkInspectionRequest,
    HomiAdapter,
    HomiCapabilityKind,
    HomiCapabilityProfile,
    HomiCapabilityProfileBuilder,
    HomiCapabilityState,
    HomiCombinationLanguage,
    HomiCombinationRuleEvaluation,
    HomiCombinationRuleId,
    HomiCombinationRuleMetadata,
    HomiCombinationRuleText,
    HomiEvidenceMethod,
    builtin_homi_combination_rules,
)
from agentsec.risk import ImpactDimension, ImpactRating

_SECRET_MARKER = "homi-combination-secret-marker"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _profile(project: Path) -> HomiCapabilityProfile:
    inspection = HomiAdapter().inspect_workspace(
        FrameworkInspectionRequest(project_root=project)
    )
    return HomiCapabilityProfileBuilder().build(inspection)


def _complete_combination_workspace(project: Path) -> None:
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


def test_detects_all_deterministic_homi_combinations_without_runtime_authority(
    tmp_path: Path,
) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    _complete_combination_workspace(project)

    profile = _profile(project)
    result = DeterministicHomiCombinationRuleEngine().run(profile)

    assert result.complete is True
    assert result.failures == ()
    assert tuple(result.evaluated_rule_ids) == tuple(
        item.value for item in HomiCombinationRuleId
    )
    assert {finding.rule_id for finding in result.findings} == {
        item.value for item in HomiCombinationRuleId
    }
    assert all(finding.report_only is True for finding in result.findings)
    assert all(finding.runtime_verified is False for finding in result.findings)
    assert all(
        finding.confidence is EvidenceConfidence.D for finding in result.findings
    )
    assert all(
        finding.severity in {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}
        for finding in result.findings
    )
    assert _SECRET_MARKER not in repr(result)
    assert _SECRET_MARKER not in str(result.to_dict())

    self_mod = next(
        item
        for item in result.findings
        if item.rule_id == HomiCombinationRuleId.SELF_MODIFICATION.value
    )
    assert self_mod.related_signal_ids == (
        "identity_self_modification",
        "self_evolution",
    )
    assert self_mod.text_for(HomiCombinationLanguage.ZH).title


def test_reference_heartbeat_template_does_not_trigger_external_combination(
    tmp_path: Path,
) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    _complete_combination_workspace(project)
    _write(
        project / "HEARTBEAT.md",
        "\n".join(
            [
                "---",
                "summary: Workspace template for HEARTBEAT.md",
                "title: HEARTBEAT.md template",
                "read_when:",
                "- Bootstrapping a workspace manually",
                "---",
                "",
                "# HEARTBEAT.md template",
                "",
                (
                    "`HEARTBEAT.md` lives in the agent workspace and holds the "
                    "periodic heartbeat checklist. Keep it empty to skip the "
                    "heartbeat model call."
                ),
                "",
                "Shipped default content:",
                "",
                "```markdown",
                "# Keep this file empty to skip heartbeat API calls.",
                (
                    "# Add tasks below when you want the agent to check something "
                    "periodically."
                ),
                "```",
                "",
                (
                    "Add short tasks below the comment lines only when you want "
                    "periodic checks. Keep it small."
                ),
                "",
                (
                    "For due-only checks instead of a plain checklist, use "
                    "a structured `tasks:` block."
                ),
                "",
                "## Related",
                "- [Heartbeat config](/gateway/config-agents)",
            ]
        )
        + "\n",
    )

    profile = _profile(project)
    result = DeterministicHomiCombinationRuleEngine().run(profile)

    assert profile.heartbeat.state is HomiCapabilityState.EXAMPLE_ONLY
    assert profile.heartbeat.tasks_present is False
    assert "HOMI-COMB-002" not in {finding.rule_id for finding in result.findings}


def test_example_only_tool_notes_are_suppressed_not_escalated(tmp_path: Path) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    for name, content in {
        "AGENTS.md": "Skills provide your tools.\n",
        "SOUL.md": "# Soul\n",
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
        "HEARTBEAT.md": "# disabled\n",
    }.items():
        _write(project / name, content)

    profile = _profile(project)
    result = DeterministicHomiCombinationRuleEngine().run(profile)

    assert result.suppressed_example_capabilities == (
        HomiCapabilityKind.CAMERA_ACCESS,
        HomiCapabilityKind.SSH_ACCESS,
        HomiCapabilityKind.TTS_OUTPUT,
    )
    assert HomiCombinationRuleId.TOOLS_SKILLS.value not in {
        finding.rule_id for finding in result.findings
    }
    assert profile.tools.ssh.state is HomiCapabilityState.EXAMPLE_ONLY
    assert profile.tools.ssh.method is HomiEvidenceMethod.STATIC_TEMPLATE_CLASSIFICATION


def test_incomplete_profile_is_visible_but_rules_still_run(tmp_path: Path) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    _write(project / "AGENTS.md", "Search the web.\n")
    _write(project / "SOUL.md", "Be resourceful before asking.\n")

    profile = _profile(project)
    result = DeterministicHomiCombinationRuleEngine().run(profile)

    assert profile.complete is False
    assert result.profile_complete is False
    assert result.complete is False
    assert result.failures == ()
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == HomiCombinationRuleId.PROACTIVE_EXTERNAL.value


def test_registry_is_deterministic_and_localized() -> None:
    rules = builtin_homi_combination_rules()
    rule_ids = tuple(rule.metadata.rule_id for rule in rules)

    assert rule_ids == tuple(item.value for item in HomiCombinationRuleId)
    for rule in rules:
        assert tuple(text.language for text in rule.metadata.texts) == (
            HomiCombinationLanguage.EN,
            HomiCombinationLanguage.ZH,
        )
        assert rule.metadata.report_only is True


def test_rule_failure_is_isolated_without_exposing_exception_details(
    tmp_path: Path,
) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    _write(project / "AGENTS.md", "# Workspace\n")
    profile = _profile(project)

    class BrokenRule:
        metadata = HomiCombinationRuleMetadata(
            rule_id="HOMI-COMB-999",
            category=FindingCategory.OTHER,
            texts=(
                HomiCombinationRuleText(
                    language=HomiCombinationLanguage.EN,
                    title="Broken",
                    description="Broken",
                    recommendations=("Review",),
                ),
                HomiCombinationRuleText(
                    language=HomiCombinationLanguage.ZH,
                    title="Broken",
                    description="Broken",
                    recommendations=("Review",),
                ),
            ),
            likelihood=LikelihoodLevel.LOW,
            impact_ratings=(
                ImpactRating(
                    dimension=ImpactDimension.INTEGRITY,
                    level=ImpactLevel.LOW,
                    rationale="test",
                ),
            ),
        )

        def evaluate(self, profile: object) -> HomiCombinationRuleEvaluation:
            raise RuntimeError("untrusted detail must not escape")

    result = DeterministicHomiCombinationRuleEngine((BrokenRule(),)).run(profile)

    assert result.complete is False
    assert result.findings == ()
    assert result.failures[0].rule_id == "HOMI-COMB-999"
    assert "untrusted detail" not in repr(result)
