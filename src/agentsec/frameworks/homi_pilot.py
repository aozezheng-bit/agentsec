"""Real-project, report-only Homi Pilot orchestration (P2-HOMI-06).

The Pilot accepts one explicit external Homi workspace root, runs only the
safe Homi adapter/profile/rule/simulation layers, and emits value-minimized
JSON/Text artifacts.  It never executes the target project or writes into it.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from enum import StrEnum
from html import escape
from pathlib import Path
from typing import Literal

from agentsec.frameworks.base import (
    FrameworkInspectionLimits,
    FrameworkInspectionRequest,
)
from agentsec.frameworks.homi import (
    HOMI_ADAPTER_VERSION,
    HomiAdapter,
    HomiFileState,
    HomiWorkspaceInspection,
)
from agentsec.frameworks.homi_combination import (
    HOMI_COMBINATION_RULE_PACK_VERSION,
    DeterministicHomiCombinationRuleEngine,
    HomiCombinationFinding,
    HomiCombinationLanguage,
    HomiCombinationRunResult,
)
from agentsec.frameworks.homi_policy import (
    HomiObservationCode,
    HomiObservationKind,
    HomiResolutionStatus,
    HomiWorkspacePolicyResolver,
    HomiWorkspaceResolution,
)
from agentsec.frameworks.homi_profile import (
    HOMI_PROFILE_MODEL_VERSION,
    HomiCapabilityProfile,
    HomiCapabilityProfileBuilder,
    HomiCapabilityState,
    HomiEvidenceMethod,
    HomiProfileSignal,
)
from agentsec.frameworks.homi_simulation import (
    HOMI_SAFE_SIMULATION_FORMAT_VERSION,
    HOMI_SAFE_SIMULATION_MODEL_VERSION,
    DeterministicHomiSafeSimulationEngine,
    HomiSafeSimulationRequest,
    HomiSafeSimulationResult,
)

HOMI_PILOT_FORMAT: Literal["agentsec-homi-report-only-pilot"] = (
    "agentsec-homi-report-only-pilot"
)
HOMI_PILOT_FORMAT_VERSION = "0.2.0"
HOMI_PILOT_EVIDENCE_MODE: Literal["external_report_only"] = "external_report_only"
HOMI_PILOT_MAX_PROJECT_NAME = 160
_HOMI_PILOT_ID_PATTERN = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")


class HomiPilotStatus(StrEnum):
    """Coverage status of one external Homi report-only run."""

    COMPLETE = "complete"
    PARTIAL = "partial"


class HomiPilotLanguage(StrEnum):
    """Text report languages supported by the Pilot renderer."""

    EN = "en"
    ZH = "zh"


class HomiPilotError(ValueError):
    """Safe Homi Pilot input/output failure without scanned content."""


@dataclass(frozen=True, slots=True)
class HomiPilotRequest:
    """Explicit external target and controlled artifact destination."""

    pilot_id: str
    project_name: str
    owner: str
    target_root: Path
    output_root: Path
    reviewer_ids: tuple[str, ...] = ()
    limits: FrameworkInspectionLimits = FrameworkInspectionLimits()
    simulation_request: HomiSafeSimulationRequest = HomiSafeSimulationRequest()

    def __post_init__(self) -> None:
        if _HOMI_PILOT_ID_PATTERN.fullmatch(self.pilot_id) is None:
            raise ValueError("Homi Pilot ID is invalid")
        _require_text(self.project_name, "Homi Pilot project_name")
        if len(self.project_name) > HOMI_PILOT_MAX_PROJECT_NAME:
            raise ValueError("Homi Pilot project_name is too long")
        _require_text(self.owner, "Homi Pilot owner")
        if not isinstance(self.target_root, Path):
            raise TypeError("Homi Pilot target_root must be Path")
        if not isinstance(self.output_root, Path):
            raise TypeError("Homi Pilot output_root must be Path")
        if self.reviewer_ids != tuple(sorted(set(self.reviewer_ids))):
            raise ValueError("Homi Pilot reviewer_ids must be sorted and unique")
        if any(
            not isinstance(item, str) or not item.strip() for item in self.reviewer_ids
        ):
            raise ValueError("Homi Pilot reviewer_ids must contain non-empty text")
        if not isinstance(self.limits, FrameworkInspectionLimits):
            raise TypeError("Homi Pilot limits must be FrameworkInspectionLimits")
        if not isinstance(self.simulation_request, HomiSafeSimulationRequest):
            raise TypeError("Homi Pilot simulation_request is invalid")


@dataclass(frozen=True, slots=True)
class HomiPilotFileSummary:
    """Value-minimized state and digest for one standard Homi file."""

    name: str
    state: HomiFileState
    content_sha256: str | None
    size_bytes: int | None
    line_count: int | None
    issue_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_text(self.name, "Homi Pilot file name")
        if not isinstance(self.state, HomiFileState):
            raise TypeError("Homi Pilot file state is invalid")
        if self.content_sha256 is not None and (
            len(self.content_sha256) != 64
            or any(char not in "0123456789abcdef" for char in self.content_sha256)
        ):
            raise ValueError("Homi Pilot file digest is invalid")
        if self.size_bytes is not None and self.size_bytes < 0:
            raise ValueError("Homi Pilot file size must not be negative")
        if self.line_count is not None and self.line_count < 0:
            raise ValueError("Homi Pilot file line count must not be negative")
        if self.issue_codes != tuple(sorted(set(self.issue_codes))):
            raise ValueError("Homi Pilot file issue codes must be sorted and unique")

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "state": self.state.value,
            "content_sha256": self.content_sha256,
            "size_bytes": self.size_bytes,
            "line_count": self.line_count,
            "issue_codes": list(self.issue_codes),
        }


@dataclass(frozen=True, slots=True)
class HomiPilotSignalSummary:
    """Value-minimized capability/persona signal summary."""

    signal_id: str
    state: HomiCapabilityState
    confidence: str
    method: HomiEvidenceMethod
    source_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_text(self.signal_id, "Homi Pilot signal ID")
        if not isinstance(self.state, HomiCapabilityState):
            raise TypeError("Homi Pilot signal state is invalid")
        _require_text(self.confidence, "Homi Pilot signal confidence")
        if not isinstance(self.method, HomiEvidenceMethod):
            raise TypeError("Homi Pilot signal method is invalid")
        if self.source_paths != tuple(sorted(set(self.source_paths))):
            raise ValueError("Homi Pilot signal source paths must be sorted and unique")

    @classmethod
    def from_signal(cls, signal: HomiProfileSignal) -> HomiPilotSignalSummary:
        """Project a static signal without copying source content."""

        return cls(
            signal_id=signal.signal_id,
            state=signal.state,
            confidence=signal.confidence.value,
            method=signal.method,
            source_paths=tuple(sorted(source.path for source in signal.sources)),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "signal_id": self.signal_id,
            "state": self.state.value,
            "confidence": self.confidence,
            "method": self.method.value,
            "source_paths": list(self.source_paths),
        }


@dataclass(frozen=True, slots=True)
class HomiPilotObservationSummary:
    """Safe policy observation summary without source excerpts."""

    code: HomiObservationCode
    kind: HomiObservationKind
    roles: tuple[str, ...]
    source_paths: tuple[str, ...]
    resolution: str

    def __post_init__(self) -> None:
        if not isinstance(self.code, HomiObservationCode):
            raise TypeError("Homi Pilot observation code is invalid")
        if not isinstance(self.kind, HomiObservationKind):
            raise TypeError("Homi Pilot observation kind is invalid")
        if self.roles != tuple(sorted(set(self.roles))):
            raise ValueError("Homi Pilot observation roles must be sorted and unique")
        if self.source_paths != tuple(sorted(set(self.source_paths))):
            raise ValueError("Homi Pilot observation paths must be sorted and unique")
        _require_text(self.resolution, "Homi Pilot observation resolution")

    @classmethod
    def from_observation(cls, observation: object) -> HomiPilotObservationSummary:
        """Project a policy observation through a typed runtime check."""

        from agentsec.frameworks.homi_policy import HomiPolicyObservation

        if not isinstance(observation, HomiPolicyObservation):
            raise TypeError("Homi Pilot observation is invalid")
        return cls(
            code=observation.code,
            kind=observation.kind,
            roles=tuple(sorted(role.value for role in observation.roles)),
            source_paths=tuple(sorted(source.path for source in observation.sources)),
            resolution=observation.resolution,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code.value,
            "kind": self.kind.value,
            "roles": list(self.roles),
            "source_paths": list(self.source_paths),
            "resolution": self.resolution,
        }


@dataclass(frozen=True, slots=True)
class HomiPilotReport:
    """Value-minimized report-only output for one explicit Homi target."""

    format: Literal["agentsec-homi-report-only-pilot"]
    format_version: str
    adapter_version: str
    profile_model_version: str
    pilot_id: str
    project_name: str
    owner: str
    evidence_mode: Literal["external_report_only"]
    status: HomiPilotStatus
    inspection_complete: bool
    profile_complete: bool
    all_standard_files_present: bool
    resolution_status: HomiResolutionStatus
    files: tuple[HomiPilotFileSummary, ...]
    capabilities: tuple[HomiPilotSignalSummary, ...]
    persona_signals: tuple[HomiPilotSignalSummary, ...]
    identity: dict[str, object]
    user_privacy: dict[str, object]
    tools: dict[str, object]
    heartbeat: dict[str, object]
    observations: tuple[HomiPilotObservationSummary, ...]
    combination_result: HomiCombinationRunResult
    simulation_result: HomiSafeSimulationResult
    limitations: tuple[str, ...]
    reviewer_ids: tuple[str, ...] = ()
    report_only: Literal[True] = True
    runtime_verified: Literal[False] = False
    ci_blocked: Literal[False] = False

    def __post_init__(self) -> None:
        if self.format != HOMI_PILOT_FORMAT:
            raise ValueError("Homi Pilot report format is unsupported")
        if self.format_version != HOMI_PILOT_FORMAT_VERSION:
            raise ValueError("Homi Pilot report version is unsupported")
        if self.adapter_version != HOMI_ADAPTER_VERSION:
            raise ValueError("Homi Pilot adapter version is unsupported")
        if self.profile_model_version != HOMI_PROFILE_MODEL_VERSION:
            raise ValueError("Homi Pilot Profile model version is unsupported")
        _require_text(self.pilot_id, "Homi Pilot report pilot_id")
        _require_text(self.project_name, "Homi Pilot report project_name")
        _require_text(self.owner, "Homi Pilot report owner")
        if self.evidence_mode != HOMI_PILOT_EVIDENCE_MODE:
            raise ValueError("Homi Pilot report evidence mode is unsupported")
        if not isinstance(self.status, HomiPilotStatus):
            raise TypeError("Homi Pilot report status is invalid")
        if not isinstance(self.inspection_complete, bool) or not isinstance(
            self.profile_complete, bool
        ):
            raise TypeError("Homi Pilot completion flags must be bool")
        if self.profile_complete and not self.inspection_complete:
            raise ValueError("complete Profile requires complete inspection")
        if self.status is HomiPilotStatus.COMPLETE and not self.profile_complete:
            raise ValueError("complete Homi Pilot report requires complete Profile")
        if not self.files:
            raise ValueError("Homi Pilot report requires file summaries")
        if tuple(item.name for item in self.files) != tuple(
            sorted(item.name for item in self.files)
        ):
            raise ValueError("Homi Pilot file summaries must be sorted")
        if tuple(item.signal_id for item in self.capabilities) != tuple(
            sorted(item.signal_id for item in self.capabilities)
        ):
            raise ValueError("Homi Pilot capability summaries must be sorted")
        if tuple(item.signal_id for item in self.persona_signals) != tuple(
            sorted(item.signal_id for item in self.persona_signals)
        ):
            raise ValueError("Homi Pilot persona summaries must be sorted")
        if self.observations != tuple(
            sorted(
                self.observations,
                key=lambda item: (item.code.value, item.source_paths),
            )
        ):
            raise ValueError("Homi Pilot observations must be sorted")
        _require_text_tuple(self.limitations, "Homi Pilot limitations")
        if self.reviewer_ids != tuple(sorted(set(self.reviewer_ids))):
            raise ValueError("Homi Pilot report reviewer IDs must be sorted/unique")
        if self.report_only is not True or self.runtime_verified is not False:
            raise ValueError("Homi Pilot authority flags are invalid")
        if self.ci_blocked is not False:
            raise ValueError("Homi Pilot cannot block CI")

    @property
    def acceptance_ready(self) -> bool:
        """Return false: external human/runtime evidence is outside this run."""

        return False

    @property
    def coverage_metrics(self) -> dict[str, object]:
        """Return explicitly scoped static, manifest, and runtime metrics."""

        capability_states = [item.state for item in self.capabilities]
        file_states = [item.state for item in self.files]
        return {
            "capability_total": len(capability_states),
            "capability_known_count": sum(
                state is not HomiCapabilityState.UNKNOWN for state in capability_states
            ),
            "capability_unknown_count": sum(
                state is HomiCapabilityState.UNKNOWN for state in capability_states
            ),
            "capability_example_only_count": sum(
                state is HomiCapabilityState.EXAMPLE_ONLY for state in capability_states
            ),
            "standard_file_total": len(file_states),
            "standard_file_missing_count": sum(
                state is HomiFileState.MISSING for state in file_states
            ),
            "standard_file_skipped_count": sum(
                state is HomiFileState.SKIPPED for state in file_states
            ),
            "manifest_unknown_count": None,
            "runtime_unknown_count": None,
            "runtime_attestation_status": "not_collected",
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "format_version": self.format_version,
            "adapter_version": self.adapter_version,
            "profile_model_version": self.profile_model_version,
            "pilot_id": self.pilot_id,
            "project_name": self.project_name,
            "owner": self.owner,
            "evidence_mode": self.evidence_mode,
            "status": self.status.value,
            "acceptance_ready": self.acceptance_ready,
            "inspection_complete": self.inspection_complete,
            "profile_complete": self.profile_complete,
            "all_standard_files_present": self.all_standard_files_present,
            "resolution_status": self.resolution_status.value,
            "coverage_metrics": self.coverage_metrics,
            "files": [item.to_dict() for item in self.files],
            "capabilities": [item.to_dict() for item in self.capabilities],
            "persona_signals": [item.to_dict() for item in self.persona_signals],
            "identity": self.identity,
            "user_privacy": self.user_privacy,
            "tools": self.tools,
            "heartbeat": self.heartbeat,
            "observations": [item.to_dict() for item in self.observations],
            "combination": self.combination_result.to_dict(),
            "simulation": self.simulation_result.to_dict(),
            "limitations": list(self.limitations),
            "reviewer_ids": list(self.reviewer_ids),
            "report_only": self.report_only,
            "runtime_verified": self.runtime_verified,
            "ci_blocked": self.ci_blocked,
        }


class DeterministicHomiReportOnlyPilot:
    """Run the Homi stack against one explicit external workspace."""

    def __init__(self) -> None:
        self._adapter = HomiAdapter()
        self._policy_resolver = HomiWorkspacePolicyResolver()
        self._profile_builder = HomiCapabilityProfileBuilder()
        self._combination_engine = DeterministicHomiCombinationRuleEngine()
        self._simulation_engine = DeterministicHomiSafeSimulationEngine()

    def run(self, request: HomiPilotRequest) -> HomiPilotReport:
        """Inspect and report on a target without executing or modifying it."""

        if not isinstance(request, HomiPilotRequest):
            raise TypeError("Homi Pilot request is invalid")
        target = _validated_directory(request.target_root, "Homi Pilot target root")
        output_parent = request.output_root.parent.resolve(strict=True)
        if request.output_root.exists() and request.output_root.is_symlink():
            raise HomiPilotError("Homi Pilot output root cannot be a symbolic link")
        output_candidate = request.output_root.resolve(strict=False)
        if _overlaps(target, output_candidate):
            raise HomiPilotError(
                "Homi Pilot output root must be outside the scanned target root"
            )
        if not output_parent.is_dir():
            raise HomiPilotError(
                "Homi Pilot output parent must be an existing directory"
            )

        inspection = self._adapter.inspect_workspace(
            FrameworkInspectionRequest(project_root=target, limits=request.limits)
        )
        resolution = self._policy_resolver.resolve(inspection)
        profile = self._profile_builder.build(inspection, resolution)
        combination = self._combination_engine.run(profile)
        simulation = self._simulation_engine.simulate(
            profile, request.simulation_request
        )
        return _build_report(
            request=request,
            inspection=inspection,
            resolution=resolution,
            profile=profile,
            combination=combination,
            simulation=simulation,
        )

    def run_and_write(self, request: HomiPilotRequest) -> HomiPilotReport:
        """Run a Pilot and write controlled JSON/Text artifacts without clobbering."""

        report = self.run(request)
        output_root = _prepare_output_root(request.output_root)
        json_path = output_root / "homi-pilot-report.json"
        text_path = output_root / "homi-pilot-report.md"
        if json_path.exists() or text_path.exists():
            raise HomiPilotError("Homi Pilot output artifacts already exist")
        json_path.write_text(encode_homi_pilot_json(report), encoding="utf-8")
        text_path.write_text(render_homi_pilot_text(report), encoding="utf-8")
        return report


def _build_report(
    *,
    request: HomiPilotRequest,
    inspection: HomiWorkspaceInspection,
    resolution: HomiWorkspaceResolution,
    profile: HomiCapabilityProfile,
    combination: HomiCombinationRunResult,
    simulation: HomiSafeSimulationResult,
) -> HomiPilotReport:
    files = tuple(
        sorted(
            (
                HomiPilotFileSummary(
                    name=item.name,
                    state=item.state,
                    content_sha256=item.content_sha256,
                    size_bytes=item.size_bytes,
                    line_count=item.line_count,
                    issue_codes=tuple(code.value for code in item.issue_codes),
                )
                for item in inspection.files
            ),
            key=lambda item: item.name,
        )
    )
    capabilities = tuple(
        sorted(
            (
                HomiPilotSignalSummary.from_signal(item.signal)
                for item in profile.capabilities
            ),
            key=lambda item: item.signal_id,
        )
    )
    persona_signals = tuple(
        sorted(
            (
                HomiPilotSignalSummary.from_signal(item)
                for item in profile.persona.signals
            ),
            key=lambda item: item.signal_id,
        )
    )
    observations = tuple(
        sorted(
            (
                HomiPilotObservationSummary.from_observation(item)
                for item in profile.observations
            ),
            key=lambda item: (item.code.value, item.source_paths),
        )
    )
    identity: dict[str, object] = {
        "name_present": profile.identity.name_present,
        "creature_present": profile.identity.creature_present,
        "vibe_present": profile.identity.vibe_present,
        "emoji_present": profile.identity.emoji_present,
        "avatar_kind": profile.identity.avatar_kind.value,
        "identity_disclosure": HomiPilotSignalSummary.from_signal(
            profile.identity.identity_disclosure
        ).to_dict(),
        "self_assignment": HomiPilotSignalSummary.from_signal(
            profile.identity.self_assignment
        ).to_dict(),
    }
    user_privacy: dict[str, object] = {
        "file_state": profile.user_privacy.file_state.value,
        "template_present": profile.user_privacy.template_present,
        "persistence": HomiPilotSignalSummary.from_signal(
            profile.user_privacy.persistence
        ).to_dict(),
        "main_session_only": profile.user_privacy.main_session_only,
        "shared_context_allowed": profile.user_privacy.shared_context_allowed,
        "observed_field_names": list(profile.user_privacy.observed_field_names),
    }
    tools: dict[str, object] = {
        "runtime_authority": profile.tools.runtime_authority,
        "bindings": {
            name: HomiPilotSignalSummary.from_signal(signal).to_dict()
            for name, signal in sorted(
                (
                    ("camera", profile.tools.camera),
                    ("mcp", profile.tools.mcp),
                    ("oauth", profile.tools.oauth),
                    ("secret_access", profile.tools.secret_access),
                    ("ssh", profile.tools.ssh),
                    ("tts", profile.tools.tts),
                )
            )
        },
    }
    heartbeat: dict[str, object] = {
        "state": profile.heartbeat.state.value,
        "tasks_present": profile.heartbeat.tasks_present,
        "api_calls_enabled_by_file": profile.heartbeat.api_calls_enabled_by_file,
        "runtime_verified": profile.heartbeat.runtime_verified,
        "signal": HomiPilotSignalSummary.from_signal(
            profile.heartbeat.signal
        ).to_dict(),
    }
    limitations = (
        "This is an external report-only Pilot; acceptance_ready is always false.",
        (
            "The target workspace is untrusted input and no project code, hooks, "
            "skills, commands, MCP, or scheduler was executed."
        ),
        (
            "Static Homi declarations do not prove runtime Tool, OAuth, permission, "
            "identity, scheduler, or exploit reachability."
        ),
        (
            "No raw User, tool, credential, IP address, URL, Avatar, or Secret "
            "value is included in the report."
        ),
        "Human review and real runtime attestation are outside this Pilot run.",
    )
    return HomiPilotReport(
        format=HOMI_PILOT_FORMAT,
        format_version=HOMI_PILOT_FORMAT_VERSION,
        adapter_version=HOMI_ADAPTER_VERSION,
        profile_model_version=HOMI_PROFILE_MODEL_VERSION,
        pilot_id=request.pilot_id,
        project_name=request.project_name,
        owner=request.owner,
        evidence_mode=HOMI_PILOT_EVIDENCE_MODE,
        status=(
            HomiPilotStatus.COMPLETE if profile.complete else HomiPilotStatus.PARTIAL
        ),
        inspection_complete=inspection.complete,
        profile_complete=profile.complete,
        all_standard_files_present=inspection.all_standard_files_present,
        resolution_status=resolution.status,
        files=files,
        capabilities=capabilities,
        persona_signals=persona_signals,
        identity=identity,
        user_privacy=user_privacy,
        tools=tools,
        heartbeat=heartbeat,
        observations=observations,
        combination_result=combination,
        simulation_result=simulation,
        limitations=limitations,
        reviewer_ids=request.reviewer_ids,
    )


def encode_homi_pilot_json(report: HomiPilotReport) -> str:
    """Encode a value-minimized Homi Pilot report as deterministic JSON."""

    if not isinstance(report, HomiPilotReport):
        raise TypeError("Homi Pilot JSON encoder requires HomiPilotReport")
    return (
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


def render_homi_pilot_text(
    report: HomiPilotReport,
    *,
    language: HomiPilotLanguage = HomiPilotLanguage.EN,
) -> str:
    """Render a bounded management/developer-facing Homi Pilot summary."""

    if not isinstance(report, HomiPilotReport):
        raise TypeError("Homi Pilot text renderer requires HomiPilotReport")
    if not isinstance(language, HomiPilotLanguage):
        raise TypeError("Homi Pilot language is invalid")
    if language is HomiPilotLanguage.ZH:
        return _render_zh(report)
    return _render_en(report)


def _simulation_count(report: HomiPilotReport, outcome: str) -> int:
    return next(
        (
            count
            for item, count in report.simulation_result.outcome_counts
            if item.value == outcome
        ),
        0,
    )


def _render_en(report: HomiPilotReport) -> str:
    lines = [
        "AgentSec Homi Real-project Report-only Pilot",
        f"Pilot: {report.pilot_id}",
        f"Project: {report.project_name}",
        f"Status: {report.status.value}",
        "Mode: external_report_only; acceptance_ready=false; CI blocking=false",
        "",
        "Coverage",
        f"  Inspection complete: {report.inspection_complete}",
        f"  Profile complete: {report.profile_complete}",
        f"  Standard files present: {report.all_standard_files_present}",
        f"  Resolution: {report.resolution_status.value}",
        "",
        "Unknown Metrics (scoped)",
        (
            "  Capability unknown: "
            f"{report.coverage_metrics['capability_unknown_count']}"
        ),
        (
            "  Capability example-only: "
            f"{report.coverage_metrics['capability_example_only_count']}"
        ),
        (
            "  Standard files missing: "
            f"{report.coverage_metrics['standard_file_missing_count']}"
        ),
        "  Runtime unknown: not collected",
        "  Manifest unknown: not supplied to this report",
        "",
        "Combination Findings",
        f"  Findings: {len(report.combination_result.findings)}",
        f"  Rule failures: {len(report.combination_result.failures)}",
        "",
        "Safe Simulation",
        f"  Declared paths: {_simulation_count(report, 'declared_path')}",
        f"  Unknown coverage: {_simulation_count(report, 'unknown_coverage')}",
        f"  Example-only blocked: {_simulation_count(report, 'blocked_example_only')}",
        (
            "  Static-boundary blocked: "
            f"{_simulation_count(report, 'blocked_static_boundary')}"
        ),
        "  Executed: false",
        "  Side effects: false",
        "  Runtime verified: false",
        "",
        "Limitations",
    ]
    lines.extend(f"  - {item}" for item in report.limitations)
    return "\n".join(lines) + "\n"


def _render_zh(report: HomiPilotReport) -> str:
    values = {
        name: _simulation_count(report, name)
        for name in (
            "declared_path",
            "unknown_coverage",
            "blocked_example_only",
            "blocked_static_boundary",
        )
    }
    lines = [
        "AgentSec Homi 真实项目仅报告试点",
        f"Pilot：{report.pilot_id}",
        f"项目：{report.project_name}",
        f"状态：{report.status.value}",
        "模式：external_report_only；不可用于验收；不阻断 CI",
        "",
        "覆盖情况",
        f"  扫描完整：{report.inspection_complete}",
        f"  能力画像完整：{report.profile_complete}",
        f"  六类标准文件均存在：{report.all_standard_files_present}",
        f"  解析状态：{report.resolution_status.value}",
        "",
        "Unknown 指标（口径分离）",
        (f"  能力 Unknown：{report.coverage_metrics['capability_unknown_count']}"),
        (
            "  能力 example_only："
            f"{report.coverage_metrics['capability_example_only_count']}"
        ),
        (f"  标准文件缺失：{report.coverage_metrics['standard_file_missing_count']}"),
        "  运行时 Unknown：未采集运行时证明",
        "  Manifest Unknown：本报告未提供 Manifest",
        "",
        "组合风险",
        f"  Findings：{len(report.combination_result.findings)}",
        f"  Rule Failures：{len(report.combination_result.failures)}",
        "",
        "安全模拟",
        f"  声明路径：{values.get('declared_path', 0)}",
        f"  Unknown 覆盖：{values.get('unknown_coverage', 0)}",
        f"  示例阻断：{values.get('blocked_example_only', 0)}",
        f"  静态边界阻断：{values.get('blocked_static_boundary', 0)}",
        "  已执行：false",
        "  已产生副作用：false",
        "  已完成运行时验证：false",
        "",
        "限制",
    ]
    lines.extend(f"  - {item}" for item in report.limitations)
    return "\n".join(lines) + "\n"


def render_homi_pilot_html(
    report: HomiPilotReport,
    *,
    language: HomiPilotLanguage = HomiPilotLanguage.ZH,
) -> str:
    """Render a self-contained, source-free HTML Homi security report."""

    if not isinstance(report, HomiPilotReport):
        raise TypeError("Homi Pilot HTML renderer requires HomiPilotReport")
    if not isinstance(language, HomiPilotLanguage):
        raise TypeError("Homi Pilot language is invalid")

    from importlib.resources import files
    from string import Template

    chinese = language is HomiPilotLanguage.ZH
    metrics = report.coverage_metrics
    findings = report.combination_result.findings
    title = (
        "AgentSec Homi Agent 安全报告"
        if chinese
        else "AgentSec Homi Agent Security Report"
    )
    copy = _html_copy(chinese)
    standard_total = _metric_int(metrics, "standard_file_total")
    standard_missing = _metric_int(metrics, "standard_file_missing_count")
    substitutions = {
        "language": "zh-CN" if chinese else "en",
        "title": escape(title),
        "project_name": escape(report.project_name),
        "pilot_id": escape(report.pilot_id),
        "status_label": escape(_homi_status_label(report, chinese)),
        "highest_risk": escape(_highest_homi_risk(findings)),
        "finding_count": str(len(findings)),
        "summary_title": escape(copy["summary_title"]),
        "summary": escape(copy["summary"]),
        "coverage_title": escape(copy["coverage_title"]),
        "capability_total_label": escape(copy["capability_total"]),
        "capability_total": str(metrics["capability_total"]),
        "capability_unknown_label": escape(copy["capability_unknown"]),
        "capability_unknown": str(metrics["capability_unknown_count"]),
        "example_only_label": escape(copy["example_only"]),
        "example_only": str(metrics["capability_example_only_count"]),
        "standard_files_label": escape(copy["standard_files"]),
        "standard_files": f"{standard_total - standard_missing}/{standard_total}",
        "runtime_unknown_label": escape(copy["runtime_unknown"]),
        "runtime_unknown": escape("未采集" if chinese else "Not collected"),
        "manifest_unknown_label": escape(copy["manifest_unknown"]),
        "manifest_unknown": escape("未提供" if chinese else "Not supplied"),
        "findings_title": escape(copy["findings_title"]),
        "finding_cards": _render_homi_finding_cards(report, chinese),
        "capabilities_title": escape(copy["capabilities_title"]),
        "state_label": escape(copy["state"]),
        "confidence_label": escape(copy["confidence"]),
        "evidence_files_label": escape(copy["evidence_files"]),
        "capability_rows": _render_homi_capability_rows(report),
        "files_title": escape(copy["files_title"]),
        "file_rows": _render_homi_file_rows(report),
        "boundary_title": escape(copy["boundary_title"]),
        "simulation": escape(copy["simulation"]),
        "runtime_verified": escape(copy["runtime_verified"]),
        "ci_blocked": escape(copy["ci_blocked"]),
        "limitations_title": escape(copy["limitations_title"]),
        "limitations": "".join(
            f"<li>{escape(item)}</li>" for item in report.limitations
        ),
        "footer": escape(copy["footer"]),
        "adapter_version": escape(report.adapter_version),
        "evidence_mode": escape(report.evidence_mode),
    }
    template = files("agentsec").joinpath("templates/homi_pilot_report.html")
    return Template(template.read_text(encoding="utf-8")).safe_substitute(substitutions)


def _metric_int(metrics: dict[str, object], key: str) -> int:
    value = metrics.get(key)
    if not isinstance(value, int):
        raise ValueError(f"Homi coverage metric {key} must be an integer")
    return value


def _homi_status_label(report: HomiPilotReport, chinese: bool) -> str:
    if chinese:
        return "完整" if report.status.value == "complete" else "部分"
    return report.status.value.title()


def _highest_homi_risk(findings: tuple[HomiCombinationFinding, ...]) -> str:
    rank = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    values = [item.impact.value for item in findings]
    return max(values, key=lambda value: rank.get(value, 0), default="none")


def _html_copy(chinese: bool) -> dict[str, str]:
    if chinese:
        return {
            "summary_title": "结论摘要",
            "summary": (
                "这是一次只读、静态、报告型安全评估。"
                "它展示 Agent 文件表达的能力和组合风险，"
                "不证明运行时可达性，也不会自动修改 Agent 或阻断 CI。"
            ),
            "coverage_title": "覆盖与 Unknown 指标",
            "capability_total": "能力总数",
            "capability_unknown": "能力 Unknown",
            "example_only": "示例能力",
            "standard_files": "标准文件",
            "runtime_unknown": "运行时 Unknown",
            "manifest_unknown": "Manifest Unknown",
            "findings_title": "风险 Findings",
            "capabilities_title": "能力画像",
            "files_title": "标准文件状态",
            "boundary_title": "安全模拟与边界",
            "simulation": "模拟只生成内存中的决策路径，不执行任何外部动作。",
            "runtime_verified": "运行时验证：",
            "ci_blocked": "CI 阻断：",
            "limitations_title": "限制",
            "state": "状态",
            "confidence": "证据置信度",
            "evidence_files": "证据文件",
            "footer": "不读取或展示原始 Secret 值。",
        }
    return {
        "summary_title": "Executive Summary",
        "summary": (
            "This is a read-only static report-only assessment. "
            "It shows capabilities expressed by Agent files and combination risks; "
            "it does not prove runtime reachability, modify the Agent, or block CI."
        ),
        "coverage_title": "Coverage and Unknown Metrics",
        "capability_total": "Capabilities total",
        "capability_unknown": "Capability unknown",
        "example_only": "Example-only",
        "standard_files": "Standard files",
        "runtime_unknown": "Runtime unknown",
        "manifest_unknown": "Manifest unknown",
        "findings_title": "Risk Findings",
        "capabilities_title": "Capability Profile",
        "files_title": "Standard File Status",
        "boundary_title": "Safe Simulation and Boundaries",
        "simulation": (
            "Simulation produces in-memory decision paths only; "
            "no external action is executed."
        ),
        "runtime_verified": "Runtime verified: ",
        "ci_blocked": "CI blocked: ",
        "limitations_title": "Limitations",
        "state": "State",
        "confidence": "Confidence",
        "evidence_files": "Evidence files",
        "footer": "Raw secret values are not read or displayed.",
    }


def _render_homi_finding_cards(report: HomiPilotReport, chinese: bool) -> str:
    findings = report.combination_result.findings
    if not findings:
        label = "暂无组合风险 Finding。" if chinese else "No combination Findings."
        return f"<div class='empty'>{escape(label)}</div>"
    language = HomiCombinationLanguage.ZH if chinese else HomiCombinationLanguage.EN
    cards: list[str] = []
    for finding in findings:
        text = finding.text_for(language)
        paths = sorted(
            {
                source.path
                for evidence in finding.evidence
                for source in evidence.sources
            }
        )
        evidence = "".join(f"<li>{escape(path)}</li>" for path in paths)
        severity = escape(finding.impact.value)
        limitation = (
            "静态声明不证明运行时 Tool、权限或能力可达性。"
            if chinese
            else (
                "Static declarations do not prove runtime Tool, permission, or "
                "capability reachability."
            )
        )
        cards.append(
            "<article class='finding finding-{severity}'>"
            "<div class='finding-head'>"
            "<span class='badge badge-{severity}'>{severity}</span>"
            "<strong>{rule_id}</strong>"
            "<span class='score'>score {score:.1f}</span></div>"
            "<h3>{title}</h3><p>{description}</p>"
            "<div class='finding-meta'>"
            "<span>{confidence}: {confidence_value}</span>"
            "<span>{likelihood}: {likelihood_value}</span></div>"
            "<details><summary>{evidence_label}</summary>"
            "<ul>{evidence}</ul><p class='muted'>{limitation}</p>"
            "</details></article>".format(
                severity=severity,
                rule_id=escape(finding.rule_id),
                score=finding.score,
                title=escape(text.title),
                description=escape(text.description),
                confidence="证据置信度" if chinese else "Evidence confidence",
                confidence_value=escape(finding.confidence.value),
                likelihood="可能性" if chinese else "Likelihood",
                likelihood_value=escape(finding.likelihood.value),
                evidence_label="查看证据位置" if chinese else "View evidence locations",
                evidence=evidence or "<li>—</li>",
                limitation=escape(limitation),
            )
        )
    return "".join(cards)


def _render_homi_capability_rows(report: HomiPilotReport) -> str:
    rows = []
    for item in report.capabilities:
        state = item.state.value
        state_class = escape(state.replace("_", "-"))
        sources = ", ".join(item.source_paths) or "—"
        rows.append(
            f"<tr><td>{escape(item.signal_id)}</td>"
            f"<td><span class='state state-{state_class}'>{escape(state)}</span></td>"
            f"<td>{escape(item.confidence)}</td>"
            f"<td>{escape(sources)}</td></tr>"
        )
    return "".join(rows)


def _render_homi_file_rows(report: HomiPilotReport) -> str:
    rows = []
    for item in report.files:
        state = item.state.value
        size = str(item.size_bytes) if item.size_bytes is not None else "—"
        lines = str(item.line_count) if item.line_count is not None else "—"
        rows.append(
            f"<tr><td>{escape(item.name)}</td>"
            f"<td><span class='state state-{escape(state)}'>{escape(state)}</span></td>"
            f"<td>{size}</td><td>{lines}</td></tr>"
        )
    return "".join(rows)


def _validated_directory(path: Path, label: str) -> Path:
    if not isinstance(path, Path):
        raise TypeError(f"{label} must be Path")
    if path.is_symlink():
        raise HomiPilotError(f"{label} must not be a symbolic link")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise HomiPilotError(f"{label} is missing or unsafe") from error
    if not resolved.is_dir():
        raise HomiPilotError(f"{label} must be an existing directory")
    mode = os.stat(resolved, follow_symlinks=False).st_mode
    if not stat.S_ISDIR(mode):
        raise HomiPilotError(f"{label} must be a directory")
    return resolved


def _prepare_output_root(path: Path) -> Path:
    if path.exists() and path.is_symlink():
        raise HomiPilotError("Homi Pilot output root cannot be a symbolic link")
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise HomiPilotError("Homi Pilot output root must be a directory")
    return path.resolve(strict=True)


def _overlaps(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _require_text(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text")


def _require_text_tuple(values: tuple[str, ...], label: str) -> None:
    if not isinstance(values, tuple) or not values:
        raise ValueError(f"{label} must be a non-empty tuple")
    if any(not isinstance(item, str) or not item.strip() for item in values):
        raise ValueError(f"{label} must contain non-empty text")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} must be unique")


__all__ = [
    "HOMI_ADAPTER_VERSION",
    "HOMI_COMBINATION_RULE_PACK_VERSION",
    "HOMI_PILOT_EVIDENCE_MODE",
    "HOMI_PILOT_FORMAT",
    "HOMI_PILOT_FORMAT_VERSION",
    "HOMI_PROFILE_MODEL_VERSION",
    "HOMI_SAFE_SIMULATION_FORMAT_VERSION",
    "HOMI_SAFE_SIMULATION_MODEL_VERSION",
    "DeterministicHomiReportOnlyPilot",
    "HomiPilotError",
    "HomiPilotFileSummary",
    "HomiPilotLanguage",
    "HomiPilotObservationSummary",
    "HomiPilotReport",
    "HomiPilotRequest",
    "HomiPilotSignalSummary",
    "HomiPilotStatus",
    "encode_homi_pilot_json",
    "render_homi_pilot_html",
    "render_homi_pilot_text",
]
