"""Complete deterministic Phase 2 Agent Manifest analysis orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol, runtime_checkable

from agentsec.frameworks import (
    CodexAdapter,
    FrameworkAdapter,
    FrameworkInspectionLimits,
    FrameworkInspectionRequest,
    FrameworkInspectionResult,
)
from agentsec.manifests import (
    AgentManifest,
    AgentManifestBuilder,
    AssociationExtractor,
    CapabilityExtractor,
    ConfigurationResolver,
    InstructionResolver,
    RelationshipExtractor,
    UnknownExtractor,
)
from agentsec.versioning import VersionSet, current_versions


class AgentAnalysisStage(StrEnum):
    """Stable ordered stages in the Phase 2 Manifest analysis pipeline."""

    ADAPTER_INSPECTION = "adapter_inspection"
    MANIFEST_BUILD = "manifest_build"
    INSTRUCTION_RESOLUTION = "instruction_resolution"
    CONFIGURATION_RESOLUTION = "configuration_resolution"
    ASSOCIATION_EXTRACTION = "association_extraction"
    CAPABILITY_EXTRACTION = "capability_extraction"
    RELATIONSHIP_EXTRACTION = "relationship_extraction"
    UNKNOWN_EXTRACTION = "unknown_extraction"
    FINAL_VALIDATION = "final_validation"


class AnalysisStageStatus(StrEnum):
    """Safe operational status for one deterministic analysis stage."""

    COMPLETED = "completed"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    FAILED = "failed"


class AgentAnalysisErrorCode(StrEnum):
    """Safe public failure codes that never contain dependency diagnostics."""

    ADAPTER_FAILURE = "adapter_failure"
    REQUIRED_STAGE_FAILURE = "required_stage_failure"
    FINAL_VALIDATION_FAILURE = "final_validation_failure"


@dataclass(frozen=True, slots=True)
class AgentAnalysisRequest:
    """Explicit roots, identity, and limits for one Agent analysis."""

    project_root: Path
    working_directory: Path | None = None
    user_home: Path | None = None
    codex_home: Path | None = None
    agent_id: str | None = None
    limits: FrameworkInspectionLimits = FrameworkInspectionLimits()

    def __post_init__(self) -> None:
        if not isinstance(self.project_root, Path):
            raise TypeError("project_root must be a Path")
        for name, value in (
            ("working_directory", self.working_directory),
            ("user_home", self.user_home),
            ("codex_home", self.codex_home),
        ):
            if value is not None and not isinstance(value, Path):
                raise TypeError(f"{name} must be a Path when provided")
        if self.agent_id is not None and not isinstance(self.agent_id, str):
            raise TypeError("agent_id must be a string when provided")
        if not isinstance(self.limits, FrameworkInspectionLimits):
            raise TypeError("limits must be FrameworkInspectionLimits")


@dataclass(frozen=True, slots=True)
class AnalysisStageResult:
    """Bounded stage metadata without scanned values or dependency messages."""

    stage: AgentAnalysisStage
    status: AnalysisStageStatus
    input_items: int
    output_items: int
    error_code: AgentAnalysisErrorCode | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.stage, AgentAnalysisStage):
            raise TypeError("stage must be AgentAnalysisStage")
        if not isinstance(self.status, AnalysisStageStatus):
            raise TypeError("status must be AnalysisStageStatus")
        if self.input_items < 0 or self.output_items < 0:
            raise ValueError("stage item counts must not be negative")
        if self.status is AnalysisStageStatus.FAILED:
            if not isinstance(self.error_code, AgentAnalysisErrorCode):
                raise ValueError("failed stage requires a safe error code")
        elif self.error_code is not None:
            raise ValueError("successful stage must not carry an error code")


@dataclass(frozen=True, slots=True)
class AgentAnalysisResult:
    """Final validated Manifest plus deterministic operational provenance."""

    manifest: AgentManifest
    stages: tuple[AnalysisStageResult, ...]
    complete: bool
    versions: VersionSet

    def __post_init__(self) -> None:
        if not isinstance(self.manifest, AgentManifest):
            raise TypeError("manifest must be AgentManifest")
        if not isinstance(self.stages, tuple) or any(
            not isinstance(stage, AnalysisStageResult) for stage in self.stages
        ):
            raise TypeError("stages must be a typed tuple")
        if tuple(stage.stage for stage in self.stages) != tuple(AgentAnalysisStage):
            raise ValueError(
                "analysis stages must be complete and deterministically ordered"
            )
        if any(stage.status is AnalysisStageStatus.FAILED for stage in self.stages):
            raise ValueError("successful analysis result cannot contain a failed stage")
        if self.complete != self.manifest.coverage.complete:
            raise ValueError("analysis completion must match Manifest Coverage")
        if not isinstance(self.versions, VersionSet):
            raise TypeError("versions must be VersionSet")


class AgentAnalysisError(RuntimeError):
    """Safe required-stage failure retaining only stage and stable code."""

    def __init__(
        self,
        *,
        stage: AgentAnalysisStage,
        code: AgentAnalysisErrorCode,
        stages: tuple[AnalysisStageResult, ...],
    ) -> None:
        self.stage = stage
        self.code = code
        self.stages = stages
        super().__init__(
            f"Agent analysis failed in required stage '{stage.value}' ({code.value})."
        )


@runtime_checkable
class AgentAnalysisEngine(Protocol):
    """Application seam consumed by future CLI and report integrations."""

    def analyze(self, request: AgentAnalysisRequest) -> AgentAnalysisResult:
        """Produce one final deterministic Agent Manifest analysis result."""


class _ManifestBuilder(Protocol):
    def build(
        self,
        inspection: FrameworkInspectionResult,
        *,
        subject_root_id: str = "project",
        agent_id: str | None = None,
    ) -> AgentManifest: ...


class _ManifestResolver(Protocol):
    def resolve(self, manifest: AgentManifest) -> AgentManifest: ...


class _InspectionExtractor(Protocol):
    def extract(
        self,
        manifest: AgentManifest,
        inspection: FrameworkInspectionResult,
    ) -> AgentManifest: ...


class _ManifestExtractor(Protocol):
    def extract(self, manifest: AgentManifest) -> AgentManifest: ...


class _AssociatedExtractor(Protocol):
    def extract_associated(
        self,
        manifest: AgentManifest,
        inspection: FrameworkInspectionResult,
    ) -> AgentManifest: ...


class AgentAnalysisPipeline:
    """Compose P2-04 through P2-11 exactly once into one application service."""

    def __init__(
        self,
        *,
        adapter: FrameworkAdapter | None = None,
        manifest_builder: _ManifestBuilder | None = None,
        instruction_resolver: _ManifestResolver | None = None,
        configuration_resolver: _ManifestResolver | None = None,
        association_extractor: _InspectionExtractor | None = None,
        capability_extractor: _AssociatedExtractor | None = None,
        relationship_extractor: _AssociatedExtractor | None = None,
        unknown_extractor: _ManifestExtractor | None = None,
    ) -> None:
        self._adapter = adapter
        self._manifest_builder = manifest_builder or AgentManifestBuilder()
        self._instruction_resolver = instruction_resolver or InstructionResolver()
        self._configuration_resolver = configuration_resolver or ConfigurationResolver()
        self._association_extractor = association_extractor or AssociationExtractor()
        self._capability_extractor = capability_extractor or CapabilityExtractor()
        self._relationship_extractor = relationship_extractor or RelationshipExtractor()
        self._unknown_extractor = unknown_extractor or UnknownExtractor()

    def analyze(self, request: AgentAnalysisRequest) -> AgentAnalysisResult:
        """Run the complete non-executing Manifest analysis pipeline."""

        if not isinstance(request, AgentAnalysisRequest):
            raise TypeError("request must be AgentAnalysisRequest")

        stages: list[AnalysisStageResult] = []
        adapter = self._adapter or CodexAdapter(codex_home=request.codex_home)
        inspection_request = FrameworkInspectionRequest(
            project_root=request.project_root,
            user_home=request.user_home,
            working_directory=request.working_directory,
            limits=request.limits,
        )

        try:
            inspection = adapter.inspect(inspection_request)
        except Exception as error:
            self._raise_failure(
                stages,
                stage=AgentAnalysisStage.ADAPTER_INSPECTION,
                code=AgentAnalysisErrorCode.ADAPTER_FAILURE,
                input_items=0,
                error=error,
            )
        stages.append(
            self._success_stage(
                AgentAnalysisStage.ADAPTER_INSPECTION,
                input_items=0,
                output_items=inspection.inspected_assets,
                complete=inspection.complete,
            )
        )

        try:
            manifest = self._manifest_builder.build(
                inspection,
                agent_id=request.agent_id,
            )
        except Exception as error:
            self._raise_failure(
                stages,
                stage=AgentAnalysisStage.MANIFEST_BUILD,
                code=AgentAnalysisErrorCode.REQUIRED_STAGE_FAILURE,
                input_items=inspection.inspected_assets,
                error=error,
            )
        stages.append(
            self._success_stage(
                AgentAnalysisStage.MANIFEST_BUILD,
                input_items=inspection.inspected_assets,
                output_items=len(manifest.sources),
                complete=manifest.coverage.complete,
            )
        )

        instruction_inputs = len(manifest.instructions.candidates)
        try:
            manifest = self._instruction_resolver.resolve(manifest)
        except Exception as error:
            self._raise_failure(
                stages,
                stage=AgentAnalysisStage.INSTRUCTION_RESOLUTION,
                code=AgentAnalysisErrorCode.REQUIRED_STAGE_FAILURE,
                input_items=instruction_inputs,
                error=error,
            )
        stages.append(
            self._success_stage(
                AgentAnalysisStage.INSTRUCTION_RESOLUTION,
                input_items=instruction_inputs,
                output_items=len(manifest.instructions.effective_order),
                complete=manifest.coverage.complete,
            )
        )

        configuration_inputs = len(manifest.configuration.candidates)
        try:
            manifest = self._configuration_resolver.resolve(manifest)
        except Exception as error:
            self._raise_failure(
                stages,
                stage=AgentAnalysisStage.CONFIGURATION_RESOLUTION,
                code=AgentAnalysisErrorCode.REQUIRED_STAGE_FAILURE,
                input_items=configuration_inputs,
                error=error,
            )
        stages.append(
            self._success_stage(
                AgentAnalysisStage.CONFIGURATION_RESOLUTION,
                input_items=configuration_inputs,
                output_items=len(manifest.configuration.effective_order),
                complete=manifest.coverage.complete,
            )
        )

        association_inputs = len(manifest.sources)
        try:
            manifest = self._association_extractor.extract(manifest, inspection)
        except Exception as error:
            self._raise_failure(
                stages,
                stage=AgentAnalysisStage.ASSOCIATION_EXTRACTION,
                code=AgentAnalysisErrorCode.REQUIRED_STAGE_FAILURE,
                input_items=association_inputs,
                error=error,
            )
        stages.append(
            self._success_stage(
                AgentAnalysisStage.ASSOCIATION_EXTRACTION,
                input_items=association_inputs,
                output_items=(
                    len(manifest.tools.tools) + len(manifest.relationships.relations)
                ),
                complete=manifest.coverage.complete,
            )
        )

        capability_inputs = len(manifest.tools.tools)
        try:
            manifest = self._capability_extractor.extract_associated(
                manifest,
                inspection,
            )
        except Exception as error:
            self._raise_failure(
                stages,
                stage=AgentAnalysisStage.CAPABILITY_EXTRACTION,
                code=AgentAnalysisErrorCode.REQUIRED_STAGE_FAILURE,
                input_items=capability_inputs,
                error=error,
            )
        stages.append(
            self._success_stage(
                AgentAnalysisStage.CAPABILITY_EXTRACTION,
                input_items=capability_inputs,
                output_items=(
                    len(manifest.permissions.permissions)
                    + len(manifest.controls.controls)
                    + len(manifest.runtime_identities.identities)
                ),
                complete=manifest.coverage.complete,
            )
        )

        relationship_inputs = len(manifest.relationships.declaration_sources)
        try:
            manifest = self._relationship_extractor.extract_associated(
                manifest,
                inspection,
            )
        except Exception as error:
            self._raise_failure(
                stages,
                stage=AgentAnalysisStage.RELATIONSHIP_EXTRACTION,
                code=AgentAnalysisErrorCode.REQUIRED_STAGE_FAILURE,
                input_items=relationship_inputs,
                error=error,
            )
        stages.append(
            self._success_stage(
                AgentAnalysisStage.RELATIONSHIP_EXTRACTION,
                input_items=relationship_inputs,
                output_items=len(manifest.relationships.relations),
                complete=manifest.coverage.complete,
            )
        )

        unknown_inputs = self._manifest_fact_count(manifest)
        try:
            manifest = self._unknown_extractor.extract(manifest)
        except Exception as error:
            self._raise_failure(
                stages,
                stage=AgentAnalysisStage.UNKNOWN_EXTRACTION,
                code=AgentAnalysisErrorCode.REQUIRED_STAGE_FAILURE,
                input_items=unknown_inputs,
                error=error,
            )
        stages.append(
            self._success_stage(
                AgentAnalysisStage.UNKNOWN_EXTRACTION,
                input_items=unknown_inputs,
                output_items=len(manifest.unknowns),
                complete=manifest.coverage.complete,
            )
        )

        try:
            manifest = AgentManifest.model_validate(manifest.model_dump(mode="python"))
        except Exception as error:
            self._raise_failure(
                stages,
                stage=AgentAnalysisStage.FINAL_VALIDATION,
                code=AgentAnalysisErrorCode.FINAL_VALIDATION_FAILURE,
                input_items=1,
                error=error,
            )
        stages.append(
            self._success_stage(
                AgentAnalysisStage.FINAL_VALIDATION,
                input_items=1,
                output_items=1,
                complete=manifest.coverage.complete,
            )
        )

        return AgentAnalysisResult(
            manifest=manifest,
            stages=tuple(stages),
            complete=manifest.coverage.complete,
            versions=current_versions(),
        )

    @staticmethod
    def _success_stage(
        stage: AgentAnalysisStage,
        *,
        input_items: int,
        output_items: int,
        complete: bool,
    ) -> AnalysisStageResult:
        return AnalysisStageResult(
            stage=stage,
            status=(
                AnalysisStageStatus.COMPLETED
                if complete
                else AnalysisStageStatus.PARTIAL
            ),
            input_items=input_items,
            output_items=output_items,
        )

    @staticmethod
    def _raise_failure(
        stages: list[AnalysisStageResult],
        *,
        stage: AgentAnalysisStage,
        code: AgentAnalysisErrorCode,
        input_items: int,
        error: Exception,
    ) -> None:
        failed = AnalysisStageResult(
            stage=stage,
            status=AnalysisStageStatus.FAILED,
            input_items=input_items,
            output_items=0,
            error_code=code,
        )
        raise AgentAnalysisError(
            stage=stage,
            code=code,
            stages=(*stages, failed),
        ) from error

    @staticmethod
    def _manifest_fact_count(manifest: AgentManifest) -> int:
        return sum(
            (
                len(manifest.sources),
                len(manifest.instructions.effective_order),
                len(manifest.configuration.effective_order),
                len(manifest.tools.tools),
                len(manifest.permissions.permissions),
                len(manifest.controls.controls),
                len(manifest.runtime_identities.identities),
                len(manifest.relationships.relations),
            )
        )
