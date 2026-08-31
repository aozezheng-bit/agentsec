"""P2-11 explicit Unknown and Capability Diff tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agentsec.frameworks import CodexAdapter, FrameworkInspectionRequest
from agentsec.manifests import (
    AgentManifest,
    AgentManifestBuilder,
    CapabilityChangeType,
    CapabilityDiffer,
    CapabilityDiffError,
    CapabilityDiffValidationCode,
    CapabilityDiffValidationError,
    CapabilityDimension,
    CapabilityExtractor,
    ConfigurationResolver,
    InstructionResolver,
    ManifestUnknownDimension,
    ManifestUnknownReason,
    RelationshipExtractor,
    UnknownExtractor,
    decode_capability_diff_json,
    encode_capability_diff_json,
    export_capability_diff_json_schema,
    validate_capability_diff_payload,
)
from agentsec.versioning import CAPABILITY_DIFF_SCHEMA_VERSION

SECRET_MARKER = "p2-11-secret-must-not-be-copied"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _analyze(project: Path, *, agent_id: str = "release-agent") -> AgentManifest:
    inspection = CodexAdapter().inspect(
        FrameworkInspectionRequest(project_root=project)
    )
    manifest = AgentManifestBuilder().build(inspection, agent_id=agent_id)
    manifest = InstructionResolver().resolve(manifest)
    manifest = ConfigurationResolver().resolve(manifest)
    manifest = CapabilityExtractor().extract(manifest, inspection)
    manifest = RelationshipExtractor().extract(manifest, inspection)
    return UnknownExtractor().extract(manifest)


def test_unknown_extractor_materializes_profile_and_item_uncertainty(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")
    _write(project / ".agents" / "skills" / "review" / "SKILL.md", "# Review\n")

    first = _analyze(project)
    second = UnknownExtractor().extract(first)

    assert first == second
    assert first.unknowns
    assert tuple(unknown.unknown_id for unknown in first.unknowns) == tuple(
        sorted(unknown.unknown_id for unknown in first.unknowns)
    )
    assert any(
        unknown.dimension is ManifestUnknownDimension.IDENTITY
        and unknown.field == "identity.resolution"
        for unknown in first.unknowns
    )
    assert any(
        unknown.dimension is ManifestUnknownDimension.TOOLS
        and unknown.field == "tools.skill:review.side_effects"
        and unknown.reason is ManifestUnknownReason.UNSUPPORTED_FIELD
        for unknown in first.unknowns
    )
    assert any(
        unknown.dimension is ManifestUnknownDimension.RUNTIME_IDENTITIES
        and unknown.reason is ManifestUnknownReason.MISSING_SOURCE
        for unknown in first.unknowns
    )
    assert all(SECRET_MARKER not in (unknown.field or "") for unknown in first.unknowns)


def test_capability_diff_detects_added_removed_and_modified_facts_without_values(
    tmp_path: Path,
) -> None:
    before_project = tmp_path / "before"
    after_project = tmp_path / "after"
    before_project.mkdir()
    after_project.mkdir()
    _write(
        before_project / "AGENTS.md",
        """
---
delegates_to: [research]
---
# Agent
""".lstrip(),
    )
    _write(
        before_project / ".agents" / "skills" / "review" / "SKILL.md",
        "# Review\n",
    )
    _write(
        before_project / ".codex" / "config.toml",
        f"""
[mcp_servers.docs]
command = "before-{SECRET_MARKER}"
enabled = true
enabled_tools = ["search"]
""".lstrip(),
    )

    _write(
        after_project / "AGENTS.md",
        """
---
delegates_to: [writer]
---
# Agent
""".lstrip(),
    )
    _write(
        after_project / ".codex" / "config.toml",
        f"""
[mcp_servers.docs]
command = "after-{SECRET_MARKER}"
enabled = false
disabled_tools = ["search"]

[mcp_servers.remote]
url = "https://example.invalid/mcp?token={SECRET_MARKER}"
auth = "oauth"
""".lstrip(),
    )

    before = _analyze(before_project)
    after = _analyze(after_project)
    differ = CapabilityDiffer()
    first = differ.compare(before=before, after=after)
    second = differ.compare(before=before, after=after)

    assert first == second
    assert first.complete is True
    assert first.has_changes is True
    changes = {(change.dimension, change.item_id): change for change in first.changes}
    assert changes[(CapabilityDimension.TOOL, "skill:review")].change_type is (
        CapabilityChangeType.REMOVED
    )
    assert changes[(CapabilityDimension.TOOL, "mcp-server:remote")].change_type is (
        CapabilityChangeType.ADDED
    )
    docs_change = changes[(CapabilityDimension.TOOL, "mcp-server:docs")]
    assert docs_change.change_type is CapabilityChangeType.MODIFIED
    assert "availability" in docs_change.changed_fields
    assert (
        changes[
            (
                CapabilityDimension.RELATIONSHIP,
                "relation:delegates_to:agent:research",
            )
        ].change_type
        is CapabilityChangeType.REMOVED
    )
    assert (
        changes[
            (
                CapabilityDimension.RELATIONSHIP,
                "relation:delegates_to:agent:writer",
            )
        ].change_type
        is CapabilityChangeType.ADDED
    )
    assert any(
        change.dimension is CapabilityDimension.CONTROL
        and change.change_type is CapabilityChangeType.MODIFIED
        for change in first.changes
    )

    encoded = encode_capability_diff_json(first)
    assert SECRET_MARKER not in encoded
    assert "example.invalid" not in encoded
    assert "before-" not in encoded
    assert decode_capability_diff_json(encoded) == first


def test_capability_diff_marks_incomplete_coverage_and_profile_transition(
    tmp_path: Path,
) -> None:
    before_project = tmp_path / "before"
    after_project = tmp_path / "after"
    before_project.mkdir()
    after_project.mkdir()
    _write(before_project / "AGENTS.md", "# Agent\n")
    _write(after_project / "AGENTS.md", "# Agent\n")
    (after_project / "AGENTS.override.md").write_bytes(b"\xff\xfe")

    before = _analyze(before_project)
    after = _analyze(after_project)
    result = CapabilityDiffer().compare(before=before, after=after)

    assert result.before_coverage_complete is True
    assert result.after_coverage_complete is False
    assert result.complete is False
    coverage_change = next(
        change
        for change in result.profile_changes
        if change.profile.value == "coverage"
    )
    assert (coverage_change.before, coverage_change.after) == (
        "complete",
        "incomplete",
    )
    assert any(
        change.dimension is CapabilityDimension.UNKNOWN
        and change.change_type is CapabilityChangeType.ADDED
        for change in result.changes
    )


def test_capability_diff_rejects_different_agent_identity(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")
    before = _analyze(project, agent_id="before-agent")
    after = _analyze(project, agent_id="after-agent")

    with pytest.raises(CapabilityDiffError):
        CapabilityDiffer().compare(before=before, after=after)


def test_capability_diff_validation_is_compatibility_first_and_schema_is_strict(
    tmp_path: Path,
) -> None:
    payload = {
        "schema_version": "0.2.0",
        "agent_id": SECRET_MARKER,
    }
    with pytest.raises(CapabilityDiffValidationError) as captured:
        validate_capability_diff_payload(payload)
    assert captured.value.code is (
        CapabilityDiffValidationCode.UNSUPPORTED_SCHEMA_VERSION
    )
    assert SECRET_MARKER not in str(captured.value)

    with pytest.raises(CapabilityDiffValidationError) as invalid_json:
        decode_capability_diff_json(
            '{"schema_version":"0.1.0","secret":"' + SECRET_MARKER + '" invalid}'
        )
    assert invalid_json.value.code is CapabilityDiffValidationCode.INVALID_JSON
    assert SECRET_MARKER not in str(invalid_json.value)

    unsafe_payload = {
        "schema_version": CAPABILITY_DIFF_SCHEMA_VERSION,
        SECRET_MARKER: True,
    }
    with pytest.raises(CapabilityDiffValidationError) as unsafe_field:
        validate_capability_diff_payload(unsafe_payload)
    assert unsafe_field.value.code is CapabilityDiffValidationCode.INVALID_PAYLOAD
    assert SECRET_MARKER not in str(unsafe_field.value)
    assert "<field>" in unsafe_field.value.field_paths

    first = export_capability_diff_json_schema(tmp_path / "first")
    second = export_capability_diff_json_schema(tmp_path / "second")
    assert first.read_bytes() == second.read_bytes()
    schema: dict[str, Any] = json.loads(first.read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["x-agentsec-capability-diff-schema-version"] == (
        CAPABILITY_DIFF_SCHEMA_VERSION
    )
    assert schema["additionalProperties"] is False
