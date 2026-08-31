"""P2I-01 full Agent Manifest analysis pipeline tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.application import (
    AgentAnalysisEngine,
    AgentAnalysisError,
    AgentAnalysisErrorCode,
    AgentAnalysisPipeline,
    AgentAnalysisRequest,
    AgentAnalysisStage,
    AnalysisStageStatus,
)
from agentsec.frameworks import (
    CodexAdapter,
    FrameworkAdapterMetadata,
    FrameworkInspectionRequest,
    FrameworkInspectionResult,
)
from agentsec.manifests import (
    AgentManifest,
    AgentManifestBuilder,
    AssociationExtractor,
    CapabilityExtractionError,
    CapabilityExtractor,
    ConfigurationResolver,
    InstructionResolver,
    ManifestUnknownDimension,
    RelationshipExtractionError,
    RelationshipExtractor,
    UnknownExtractor,
    encode_agent_manifest_json,
)
from agentsec.versioning import current_versions

_SECRET_MARKER = "p2i-01-secret-must-not-leak"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _request(project: Path, *, agent_id: str = "release-agent") -> AgentAnalysisRequest:
    return AgentAnalysisRequest(project_root=project, agent_id=agent_id)


def test_pipeline_matches_legacy_p2_04_through_p2_11_chain_and_is_deterministic(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(
        project / "AGENTS.md",
        """
---
delegates_to: [deployer]
persists_memory: release_state
---
# Release Agent
""".lstrip(),
    )
    _write(
        project / ".agents" / "skills" / "review" / "SKILL.md",
        "# Review\n",
    )
    _write(
        project / ".codex" / "rules" / "default.rules",
        'prefix_rule(pattern=["git", "status"], decision="prompt")\n',
    )
    _write(
        project / ".codex" / "config.toml",
        f"""
[mcp_servers.release]
command = "release-{_SECRET_MARKER}"
enabled = true
required = true
bearer_token_env_var = "RELEASE_TOKEN"
enabled_tools = ["publish"]
default_tools_approval_mode = "prompt"
""".lstrip(),
    )

    inspection = CodexAdapter().inspect(
        FrameworkInspectionRequest(project_root=project)
    )
    legacy = AgentManifestBuilder().build(inspection, agent_id="release-agent")
    legacy = InstructionResolver().resolve(legacy)
    legacy = ConfigurationResolver().resolve(legacy)
    legacy = CapabilityExtractor().extract(legacy, inspection)
    legacy = RelationshipExtractor().extract(legacy, inspection)
    legacy = UnknownExtractor().extract(legacy)

    pipeline = AgentAnalysisPipeline()
    first = pipeline.analyze(_request(project))
    second = pipeline.analyze(_request(project))

    assert first == second
    assert first.manifest == legacy
    assert encode_agent_manifest_json(first.manifest) == encode_agent_manifest_json(
        legacy
    )
    assert first.complete is True
    assert first.versions == current_versions()
    assert isinstance(pipeline, AgentAnalysisEngine)
    assert len(first.stages) == 9
    assert tuple(stage.stage for stage in first.stages) == tuple(AgentAnalysisStage)
    assert all(stage.status is AnalysisStageStatus.COMPLETED for stage in first.stages)
    assert _SECRET_MARKER not in encode_agent_manifest_json(first.manifest)


def test_pipeline_invokes_every_semantic_stage_once_and_uses_associated_entrypoints(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")
    _write(project / ".agents" / "skills" / "review" / "SKILL.md", "# Review\n")

    events: list[str] = []

    class RecordingAdapter:
        metadata: FrameworkAdapterMetadata = CodexAdapter.metadata

        def inspect(
            self,
            request: FrameworkInspectionRequest,
        ) -> FrameworkInspectionResult:
            events.append("inspect")
            return CodexAdapter().inspect(request)

    class RecordingBuilder:
        def build(
            self,
            inspection: FrameworkInspectionResult,
            *,
            subject_root_id: str = "project",
            agent_id: str | None = None,
        ) -> AgentManifest:
            events.append("build")
            return AgentManifestBuilder().build(
                inspection,
                subject_root_id=subject_root_id,
                agent_id=agent_id,
            )

    class RecordingInstructionResolver:
        def resolve(self, manifest: AgentManifest) -> AgentManifest:
            events.append("instructions")
            return InstructionResolver().resolve(manifest)

    class RecordingConfigurationResolver:
        def resolve(self, manifest: AgentManifest) -> AgentManifest:
            events.append("configuration")
            return ConfigurationResolver().resolve(manifest)

    class RecordingAssociationExtractor:
        def extract(
            self,
            manifest: AgentManifest,
            inspection: FrameworkInspectionResult,
        ) -> AgentManifest:
            events.append("associations")
            return AssociationExtractor().extract(manifest, inspection)

    class RecordingCapabilityExtractor:
        def extract_associated(
            self,
            manifest: AgentManifest,
            inspection: FrameworkInspectionResult,
        ) -> AgentManifest:
            events.append("capabilities")
            return CapabilityExtractor().extract_associated(manifest, inspection)

    class RecordingRelationshipExtractor:
        def extract_associated(
            self,
            manifest: AgentManifest,
            inspection: FrameworkInspectionResult,
        ) -> AgentManifest:
            events.append("relationships")
            return RelationshipExtractor().extract_associated(manifest, inspection)

    class RecordingUnknownExtractor:
        def extract(self, manifest: AgentManifest) -> AgentManifest:
            events.append("unknowns")
            return UnknownExtractor().extract(manifest)

    result = AgentAnalysisPipeline(
        adapter=RecordingAdapter(),
        manifest_builder=RecordingBuilder(),
        instruction_resolver=RecordingInstructionResolver(),
        configuration_resolver=RecordingConfigurationResolver(),
        association_extractor=RecordingAssociationExtractor(),
        capability_extractor=RecordingCapabilityExtractor(),
        relationship_extractor=RecordingRelationshipExtractor(),
        unknown_extractor=RecordingUnknownExtractor(),
    ).analyze(_request(project))

    assert events == [
        "inspect",
        "build",
        "instructions",
        "configuration",
        "associations",
        "capabilities",
        "relationships",
        "unknowns",
    ]
    assert result.manifest.tools.tools
    assert result.complete is True


def test_optimized_extractor_entrypoints_preserve_public_api_behavior(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "---\ndelegates_to: [reviewer]\n---\n# Agent\n")
    _write(project / ".agents" / "skills" / "review" / "SKILL.md", "# Review\n")
    inspection = CodexAdapter().inspect(
        FrameworkInspectionRequest(project_root=project)
    )
    base = AgentManifestBuilder().build(inspection)
    associated = AssociationExtractor().extract(base, inspection)

    legacy_capabilities = CapabilityExtractor().extract(base, inspection)
    optimized_capabilities = CapabilityExtractor().extract_associated(
        associated,
        inspection,
    )
    assert optimized_capabilities == legacy_capabilities

    legacy_relationships = RelationshipExtractor().extract(
        optimized_capabilities,
        inspection,
    )
    optimized_relationships = RelationshipExtractor().extract_associated(
        optimized_capabilities,
        inspection,
    )
    assert optimized_relationships == legacy_relationships

    with pytest.raises(CapabilityExtractionError):
        CapabilityExtractor().extract_associated(base, inspection)
    with pytest.raises(RelationshipExtractionError):
        RelationshipExtractor().extract_associated(base, inspection)


def test_pipeline_honors_explicit_codex_home_without_environment_inference(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    codex_home = tmp_path / "managed-codex-home"
    project.mkdir()
    codex_home.mkdir()
    _write(project / "AGENTS.md", "# Project Agent\n")
    _write(codex_home / "AGENTS.md", "# User Agent\n")

    result = AgentAnalysisPipeline().analyze(
        AgentAnalysisRequest(
            project_root=project,
            codex_home=codex_home,
            agent_id="release-agent",
        )
    )

    assert {source.locator.root_id for source in result.manifest.sources} == {
        "project",
        "codex_home",
    }
    assert [
        reference.locator.root_id
        for reference in result.manifest.instructions.effective_order
    ] == ["codex_home", "project"]


def test_pipeline_returns_usable_partial_manifest_and_safe_partial_trace(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")
    (project / "AGENTS.override.md").write_bytes(b"\xff\xfe")

    result = AgentAnalysisPipeline().analyze(_request(project))

    assert result.complete is False
    assert result.manifest.coverage.complete is False
    assert all(stage.status is AnalysisStageStatus.PARTIAL for stage in result.stages)
    assert any(
        unknown.dimension is ManifestUnknownDimension.COVERAGE
        for unknown in result.manifest.unknowns
    )
    assert result.stages[0].output_items == 1
    assert result.stages[-1].output_items == 1


def test_pipeline_wraps_required_stage_failure_without_copying_dependency_error(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")

    class FailingInstructionResolver:
        def resolve(self, manifest: AgentManifest) -> AgentManifest:
            del manifest
            raise RuntimeError(f"unsafe dependency error: {_SECRET_MARKER}")

    pipeline = AgentAnalysisPipeline(instruction_resolver=FailingInstructionResolver())

    with pytest.raises(AgentAnalysisError) as captured:
        pipeline.analyze(_request(project))

    error = captured.value
    assert error.stage is AgentAnalysisStage.INSTRUCTION_RESOLUTION
    assert error.code is AgentAnalysisErrorCode.REQUIRED_STAGE_FAILURE
    assert error.stages[-1].status is AnalysisStageStatus.FAILED
    assert error.stages[-1].error_code is AgentAnalysisErrorCode.REQUIRED_STAGE_FAILURE
    assert _SECRET_MARKER not in str(error)
    assert "unsafe dependency error" not in str(error)
