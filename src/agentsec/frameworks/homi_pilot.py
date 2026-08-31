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
    "render_homi_pilot_text",
]
