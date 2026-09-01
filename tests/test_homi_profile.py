"""P2-HOMI-03 Homi Capability Profile tests."""

from __future__ import annotations

from pathlib import Path

from agentsec.domain import EvidenceConfidence
from agentsec.frameworks import (
    FrameworkInspectionRequest,
    HomiAdapter,
    HomiAvatarKind,
    HomiCapabilityKind,
    HomiCapabilityProfileBuilder,
    HomiCapabilityState,
    HomiEvidenceMethod,
    HomiObservationCode,
    HomiResolutionStatus,
    HomiWorkspacePolicyResolver,
)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _request(project: Path) -> FrameworkInspectionRequest:
    return FrameworkInspectionRequest(project_root=project)


def _full_workspace(project: Path) -> None:
    _write(
        project / "AGENTS.md",
        """# Workspace

Read files and update memory.md.
Search the web and check calendars.
Sending emails requires asking first.
Skills provide your tools; be careful in group chats.
""",
    )
    _write(
        project / "SOUL.md",
        """# Soul

Be resourceful before asking. Have opinions and disagree when needed.
Private things stay private. When in doubt, ask before external actions.
You are not the user's voice in group chats.
This file is yours to evolve.
""",
    )
    _write(
        project / "IDENTITY.md",
        """Name: HomiClaw
Creature: AI assistant
Vibe: calm
Emoji: ✨
Avatar: https://example.invalid/avatar.png
Fill this in during your first conversation. Make it yours.
""",
    )
    _write(
        project / "USER.md",
        """# About Your Human

Update this as you go. Build this over time.
Name:
Timezone:
Context:
""",
    )
    _write(
        project / "TOOLS.md",
        """# Local Notes

## What Goes Here
Camera names and locations.

## Examples
home-server → 192.0.2.10, user: example
Preferred voice: Nova

## Why Separate?
Skills are shared.

Add whatever helps. This is your cheat sheet.
""",
    )
    _write(
        project / "HEARTBEAT.md",
        "# Keep this file empty (or with only comments) to skip heartbeat API calls.\n",
    )


def test_builds_homi_capability_and_behavior_profiles(tmp_path: Path) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    _full_workspace(project)
    inspection = HomiAdapter().inspect_workspace(_request(project))

    profile = HomiCapabilityProfileBuilder().build(inspection)

    assert profile.complete is True
    assert profile.resolution.status is HomiResolutionStatus.RESOLVED
    assert profile.identity.name_present is True
    assert profile.identity.creature_present is True
    assert profile.identity.avatar_kind is HomiAvatarKind.REMOTE_URL
    assert profile.identity.identity_disclosure.state is HomiCapabilityState.PRESENT
    assert profile.identity.self_assignment.state is HomiCapabilityState.PRESENT
    assert profile.user_privacy.main_session_only is True
    assert profile.user_privacy.shared_context_allowed is False
    assert profile.user_privacy.persistence.state is HomiCapabilityState.PRESENT
    assert profile.tools.ssh.state is HomiCapabilityState.EXAMPLE_ONLY
    assert profile.tools.ssh.method is HomiEvidenceMethod.STATIC_TEMPLATE_CLASSIFICATION
    assert profile.tools.camera.state is HomiCapabilityState.EXAMPLE_ONLY
    assert profile.tools.tts.state is HomiCapabilityState.EXAMPLE_ONLY
    assert profile.tools.runtime_authority is False
    assert profile.heartbeat.state is HomiCapabilityState.ABSENT
    assert profile.heartbeat.tasks_present is False
    assert profile.heartbeat.api_calls_enabled_by_file is False

    external = profile.capability_for(HomiCapabilityKind.EXTERNAL_NETWORK_READ)
    assert external.signal.state is HomiCapabilityState.PRESENT
    assert external.signal.confidence is EvidenceConfidence.D
    assert external.signal.method is HomiEvidenceMethod.STATIC_DECLARATION
    assert external.signal.runtime_verified is False

    send = profile.capability_for(HomiCapabilityKind.EXTERNAL_MESSAGE_SEND)
    assert send.signal.state is HomiCapabilityState.CONDITIONAL
    assert (
        profile.capability_for(HomiCapabilityKind.HEARTBEAT_SCHEDULE).signal.confidence
        is EvidenceConfidence.B
    )
    assert profile.capability_for(HomiCapabilityKind.OAUTH_ACCESS).signal.state is (
        HomiCapabilityState.UNKNOWN
    )
    assert any(signal.signal_id == "resourceful" for signal in profile.persona.signals)
    assert any(
        signal.signal_id == "self_evolution" for signal in profile.persona.signals
    )


def test_profile_preserves_conflict_observations_without_runtime_authority(
    tmp_path: Path,
) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    _write(project / "AGENTS.md", "Do not manually reread startup files.\n")
    _write(project / "SOUL.md", "Each session, read them.\n")
    _write(project / "HEARTBEAT.md", "# disabled\n")
    inspection = HomiAdapter().inspect_workspace(_request(project))
    resolution = HomiWorkspacePolicyResolver().resolve(inspection)

    profile = HomiCapabilityProfileBuilder().build(inspection, resolution)

    assert profile.complete is False
    assert any(
        observation.code is HomiObservationCode.STARTUP_READ_POLICY_CONFLICT
        for observation in profile.observations
    )
    assert all(
        not capability.signal.runtime_verified for capability in profile.capabilities
    )
    assert profile.tools.runtime_authority is False


def test_heartbeat_template_is_non_active_example_only(tmp_path: Path) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
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
    inspection = HomiAdapter().inspect_workspace(_request(project))

    profile = HomiCapabilityProfileBuilder().build(inspection)
    heartbeat = profile.capability_for(HomiCapabilityKind.HEARTBEAT_SCHEDULE)

    assert heartbeat.signal.state is HomiCapabilityState.EXAMPLE_ONLY
    assert heartbeat.signal.method is HomiEvidenceMethod.STATIC_TEMPLATE_CLASSIFICATION
    assert heartbeat.signal.confidence is EvidenceConfidence.D
    assert profile.heartbeat.state is HomiCapabilityState.EXAMPLE_ONLY
    assert profile.heartbeat.tasks_present is False
    assert profile.heartbeat.api_calls_enabled_by_file is False


def test_missing_homi_files_produce_unknown_profile_entries(tmp_path: Path) -> None:
    project = tmp_path / "homi-agent"
    project.mkdir()
    _write(project / "AGENTS.md", "# Workspace\n")
    inspection = HomiAdapter().inspect_workspace(_request(project))

    profile = HomiCapabilityProfileBuilder().build(inspection)

    assert profile.complete is False
    assert profile.user_privacy.file_state.value == "missing"
    assert profile.user_privacy.persistence.state is HomiCapabilityState.UNKNOWN
    assert profile.identity.self_assignment.state is HomiCapabilityState.UNKNOWN
    assert (
        profile.identity.self_assignment.method is HomiEvidenceMethod.RUNTIME_UNVERIFIED
    )
    assert profile.capability_for(HomiCapabilityKind.SSH_ACCESS).signal.state is (
        HomiCapabilityState.UNKNOWN
    )
    assert profile.capability_for(
        HomiCapabilityKind.HEARTBEAT_SCHEDULE
    ).signal.state is (HomiCapabilityState.UNKNOWN)
    assert profile.capability_for(HomiCapabilityKind.SSH_ACCESS).signal.sources == ()
