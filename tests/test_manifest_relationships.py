"""P2-10 Sub-Agent and memory relationship tests."""

from __future__ import annotations

from pathlib import Path

from agentsec.frameworks import CodexAdapter, FrameworkInspectionRequest
from agentsec.manifests import (
    AgentManifest,
    AgentManifestBuilder,
    ManifestRelationKind,
    ManifestRelationState,
    ManifestResolutionStatus,
    RelationshipExtractor,
    encode_agent_manifest_json,
)

SECRET_MARKER = "p2-10-secret-must-not-be-copied"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _extract(project: Path) -> AgentManifest:
    inspection = CodexAdapter().inspect(
        FrameworkInspectionRequest(project_root=project)
    )
    manifest = AgentManifestBuilder().build(inspection)
    return RelationshipExtractor().extract(manifest, inspection)


def test_extracts_declared_sub_agent_and_memory_relations_with_provenance(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(
        project / "AGENTS.md",
        """
---
sub_agents:
  - research
  - agent:writer
memory:
  read: session
  write: scratch
  persist: long_term
---
# Agent
""".lstrip(),
    )

    manifest = _extract(project)
    relations = {
        relation.target_id: relation for relation in manifest.relationships.relations
    }

    assert manifest.relationships.resolution is ManifestResolutionStatus.RESOLVED
    assert relations["agent:research"].kind is ManifestRelationKind.DELEGATES_TO
    assert relations["agent:research"].state is ManifestRelationState.DECLARED
    assert relations["agent:writer"].kind is ManifestRelationKind.DELEGATES_TO
    assert relations["memory:session"].kind is ManifestRelationKind.READS_MEMORY
    assert relations["memory:scratch"].kind is ManifestRelationKind.WRITES_MEMORY
    assert relations["memory:long_term"].kind is ManifestRelationKind.PERSISTS_MEMORY
    assert relations["agent:research"].source_agent_id == "codex:project"
    assert relations["agent:research"].sources[0].field_path == (
        "$.frontmatter.sub_agents[0]"
    )
    assert relations["memory:session"].sources[0].field_path == (
        "$.frontmatter.memory.read[0]"
    )
    assert all(relation.sources for relation in manifest.relationships.relations)


def test_relation_ids_and_sources_are_deterministic_and_duplicate_declarations_merge(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(
        project / "AGENTS.md",
        """
---
delegates_to: [research]
---
# Agent
""".lstrip(),
    )
    _write(
        project / ".agents" / "skills" / "review" / "SKILL.md",
        """
---
delegates_to: [research]
---
# Review
""".lstrip(),
    )

    inspection = CodexAdapter().inspect(
        FrameworkInspectionRequest(project_root=project)
    )
    manifest = AgentManifestBuilder().build(inspection)
    extractor = RelationshipExtractor()
    first = extractor.extract(manifest, inspection)
    second = extractor.extract(manifest, inspection)

    assert first == second
    assert encode_agent_manifest_json(first) == encode_agent_manifest_json(second)
    research = next(
        relation
        for relation in first.relationships.relations
        if relation.target_id == "agent:research"
    )
    assert research.kind is ManifestRelationKind.DELEGATES_TO
    assert len(research.sources) == 2
    assert [source.locator.path for source in research.sources] == [
        ".agents/skills/review/SKILL.md",
        "AGENTS.md",
    ]


def test_unsupported_or_malformed_relationship_declarations_fail_closed(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(
        project / "AGENTS.md",
        f"""
---
delegates_to:
  name: {SECRET_MARKER}
memory: true
---
# Agent
""".lstrip(),
    )

    manifest = _extract(project)

    assert manifest.relationships.resolution is ManifestResolutionStatus.PARTIAL
    assert any(
        relation.state is ManifestRelationState.UNKNOWN
        and relation.kind is ManifestRelationKind.DELEGATES_TO
        for relation in manifest.relationships.relations
    )
    assert any(
        relation.state is ManifestRelationState.UNKNOWN
        and relation.kind is ManifestRelationKind.OTHER
        for relation in manifest.relationships.relations
    )
    encoded = encode_agent_manifest_json(manifest)
    assert SECRET_MARKER not in encoded
    assert "frontmatter.name" not in encoded


def test_unsafe_target_values_are_hashed_without_dereferencing_paths_or_urls(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(
        project / "AGENTS.md",
        """
---
delegates_to:
  - ../other-agent/SKILL.md
  - https://example.invalid/sub-agent
memory_write:
  - /tmp/persistent-store
---
# Agent
""".lstrip(),
    )

    manifest = _extract(project)
    relations = manifest.relationships.relations

    assert manifest.relationships.resolution is ManifestResolutionStatus.PARTIAL
    assert all(
        relation.state is ManifestRelationState.UNKNOWN for relation in relations
    )
    assert all("other-agent" not in relation.target_id for relation in relations)
    assert all("example.invalid" not in relation.target_id for relation in relations)
    assert all("persistent-store" not in relation.target_id for relation in relations)
    encoded = encode_agent_manifest_json(manifest)
    assert "example.invalid" not in encoded
    assert "/tmp" not in encoded


def test_no_explicit_relationship_declaration_preserves_previous_resolution(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")

    manifest = _extract(project)

    assert manifest.relationships.resolution is ManifestResolutionStatus.UNRESOLVED
    assert manifest.relationships.relations == ()
