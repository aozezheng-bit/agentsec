"""Deterministic Phase 3 entry and candidate promotion review (P2-EXIT-08A)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import ValidationError

from agentsec import __version__
from agentsec.pilot import (
    PILOT_EXTERNAL_MIN_PR_SCANS,
    PILOT_EXTERNAL_MIN_SCANS,
    PILOT_EXTERNAL_REQUIRED_DRILLS,
    PilotReport,
)
from agentsec.release_bundle import (
    ReleaseBundleValidationError,
    validate_provenance_bundle,
)

PHASE3_ENTRY_REVIEW_FORMAT: Literal["agentsec-phase3-entry-review"] = (
    "agentsec-phase3-entry-review"
)
PHASE3_ENTRY_REVIEW_FORMAT_VERSION = "0.2.0"
PHASE3_CANDIDATE_VERSION = "0.4.0"
_CANDIDATE_VERIFICATION_FORMAT = "agentsec-candidate-verification-report"
_CANDIDATE_VERIFICATION_FORMAT_VERSION = "0.1.0"
_RECONCILIATION_FORMAT = "agentsec-candidate-artifact-reconciliation-report"
_RECONCILIATION_FORMAT_VERSION = "0.2.0"
_RECONCILIATION_TASK_ID = "P3-REL-03"
_MAX_CONTROL_REPORT_BYTES = 1_048_576

_AUTHORITY_BOUNDARY = {
    "llm_candidate_evidence_only": True,
    "llm_allow_block": False,
    "llm_rule_publication": False,
    "llm_waiver_approval": False,
    "runtime_unverified_authority": False,
    "deterministic_rules_retain_authority": True,
    "ci_blocking_requires_explicit_policy": True,
}


class Phase3ReviewStage(StrEnum):
    """Explicit stage in the Phase 3 promotion state machine."""

    ENTRY_READINESS = "entry_readiness"
    CANDIDATE_ACCEPTANCE = "candidate_acceptance"


class Phase3PromotionState(StrEnum):
    """Auditable state reached by one deterministic review run."""

    ENTRY_NO_GO = "entry_no_go"
    READY_FOR_CANDIDATE = "ready_for_candidate"
    CANDIDATE_UNDER_REVIEW = "candidate_under_review"
    CANDIDATE_NO_GO = "candidate_no_go"
    CANDIDATE_GO = "candidate_go"


class Phase3ReviewStatus(StrEnum):
    """Coarse review result retained for report compatibility."""

    GO = "go"
    CONDITIONAL = "conditional"
    NO_GO = "no_go"


class Phase3CheckStatus(StrEnum):
    """Status of one deterministic review check."""

    PASS = "pass"
    PENDING = "pending"
    FAIL = "fail"


class Phase3ReviewLanguage(StrEnum):
    """Text report languages for the review."""

    EN = "en"
    ZH = "zh"


@dataclass(frozen=True, slots=True)
class Phase3ReviewCheck:
    """One bounded Go/No-Go check with explicit requiredness."""

    check_id: str
    area: str
    status: Phase3CheckStatus
    required: bool
    evidence: tuple[str, ...]
    rationale: str

    def __post_init__(self) -> None:
        _require_text(self.check_id, "Phase 3 check ID")
        _require_text(self.area, "Phase 3 check area")
        if not isinstance(self.status, Phase3CheckStatus):
            raise TypeError("Phase 3 check status is invalid")
        if not isinstance(self.required, bool):
            raise TypeError("Phase 3 check required must be bool")
        _require_text_tuple(self.evidence, "Phase 3 check evidence")
        _require_text(self.rationale, "Phase 3 check rationale")

    def to_dict(self) -> dict[str, object]:
        return {
            "check_id": self.check_id,
            "area": self.area,
            "status": self.status.value,
            "required": self.required,
            "evidence": list(self.evidence),
            "rationale": self.rationale,
        }


@dataclass(frozen=True, slots=True)
class Phase3EntryReviewRequest:
    """Explicit review stage and root-contained evidence artifacts."""

    repository_root: Path
    stage: Phase3ReviewStage = Phase3ReviewStage.ENTRY_READINESS
    candidate_version: str = PHASE3_CANDIDATE_VERSION
    external_pilot_report: Path | None = None
    entry_readiness_report: Path | None = None
    candidate_verification_report: Path | None = None
    reconciled_candidate_report: Path | None = None
    release_provenance_bundle: Path | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.repository_root, Path):
            raise TypeError("Phase 3 repository_root must be Path")
        if not isinstance(self.stage, Phase3ReviewStage):
            raise TypeError("Phase 3 review stage is invalid")
        if self.candidate_version != PHASE3_CANDIDATE_VERSION:
            raise ValueError("Phase 3 candidate_version must be 0.4.0")
        for value, label in (
            (self.external_pilot_report, "external_pilot_report"),
            (self.entry_readiness_report, "entry_readiness_report"),
            (self.candidate_verification_report, "candidate_verification_report"),
            (self.reconciled_candidate_report, "reconciled_candidate_report"),
            (self.release_provenance_bundle, "release_provenance_bundle"),
        ):
            if value is not None and not isinstance(value, Path):
                raise TypeError(f"{label} must be Path")
        if self.stage is Phase3ReviewStage.ENTRY_READINESS and (
            self.entry_readiness_report is not None
            or self.candidate_verification_report is not None
            or self.reconciled_candidate_report is not None
            or self.release_provenance_bundle is not None
        ):
            raise ValueError("entry_readiness does not accept candidate-stage evidence")
        if self.stage is Phase3ReviewStage.CANDIDATE_ACCEPTANCE and (
            self.external_pilot_report is not None
        ):
            raise ValueError(
                "candidate_acceptance consumes an approved entry-readiness report, "
                "not an external Pilot report"
            )


@dataclass(frozen=True, slots=True)
class Phase3EntryReviewReport:
    """Versioned report for the two-stage 0.4.0 promotion state machine."""

    format: Literal["agentsec-phase3-entry-review"]
    format_version: str
    review_stage: Phase3ReviewStage
    state: Phase3PromotionState
    candidate_version: str
    current_package_version: str
    status: Phase3ReviewStatus
    acceptance_ready: bool
    ready_for_candidate_promotion: bool
    ready_for_candidate_build: bool
    ready_for_phase3_shadow: bool
    ready_for_release: bool
    checks: tuple[Phase3ReviewCheck, ...]
    authority_boundary: dict[str, bool]
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.format != PHASE3_ENTRY_REVIEW_FORMAT:
            raise ValueError("Phase 3 review format is unsupported")
        if self.format_version != PHASE3_ENTRY_REVIEW_FORMAT_VERSION:
            raise ValueError("Phase 3 review format version is unsupported")
        if not isinstance(self.review_stage, Phase3ReviewStage):
            raise TypeError("Phase 3 review stage is invalid")
        if not isinstance(self.state, Phase3PromotionState):
            raise TypeError("Phase 3 promotion state is invalid")
        if self.candidate_version != PHASE3_CANDIDATE_VERSION:
            raise ValueError("Phase 3 candidate version is unsupported")
        _require_text(self.current_package_version, "current package version")
        if not isinstance(self.status, Phase3ReviewStatus):
            raise TypeError("Phase 3 review status is invalid")
        if not self.checks:
            raise ValueError("Phase 3 review requires checks")
        check_ids = tuple(item.check_id for item in self.checks)
        if check_ids != tuple(sorted(set(check_ids))):
            raise ValueError("Phase 3 checks must be sorted and unique")
        if self.authority_boundary != _AUTHORITY_BOUNDARY:
            raise ValueError("Phase 3 authority boundary is inconsistent")
        _require_text_tuple(self.limitations, "Phase 3 review limitations")
        self._validate_state_flags()

    def _validate_state_flags(self) -> None:
        promotion_ready = self.state in {
            Phase3PromotionState.READY_FOR_CANDIDATE,
            Phase3PromotionState.CANDIDATE_UNDER_REVIEW,
            Phase3PromotionState.CANDIDATE_NO_GO,
            Phase3PromotionState.CANDIDATE_GO,
        }
        expected = {
            "acceptance_ready": self.state
            in {
                Phase3PromotionState.READY_FOR_CANDIDATE,
                Phase3PromotionState.CANDIDATE_GO,
            },
            "ready_for_candidate_promotion": promotion_ready,
            "ready_for_candidate_build": promotion_ready,
            "ready_for_phase3_shadow": promotion_ready,
            "ready_for_release": self.state is Phase3PromotionState.CANDIDATE_GO,
        }
        observed = {
            "acceptance_ready": self.acceptance_ready,
            "ready_for_candidate_promotion": self.ready_for_candidate_promotion,
            "ready_for_candidate_build": self.ready_for_candidate_build,
            "ready_for_phase3_shadow": self.ready_for_phase3_shadow,
            "ready_for_release": self.ready_for_release,
        }
        if observed != expected:
            raise ValueError("Phase 3 readiness flags are inconsistent with state")
        expected_status = {
            Phase3PromotionState.ENTRY_NO_GO: Phase3ReviewStatus.NO_GO,
            Phase3PromotionState.READY_FOR_CANDIDATE: Phase3ReviewStatus.GO,
            Phase3PromotionState.CANDIDATE_UNDER_REVIEW: (
                Phase3ReviewStatus.CONDITIONAL
            ),
            Phase3PromotionState.CANDIDATE_NO_GO: Phase3ReviewStatus.NO_GO,
            Phase3PromotionState.CANDIDATE_GO: Phase3ReviewStatus.GO,
        }[self.state]
        if self.status is not expected_status:
            raise ValueError("Phase 3 status is inconsistent with state")
        if (
            self.review_stage is Phase3ReviewStage.ENTRY_READINESS
            and self.state
            not in {
                Phase3PromotionState.ENTRY_NO_GO,
                Phase3PromotionState.READY_FOR_CANDIDATE,
            }
        ):
            raise ValueError("Entry readiness produced a candidate-only state")
        if (
            self.review_stage is Phase3ReviewStage.CANDIDATE_ACCEPTANCE
            and self.state is Phase3PromotionState.READY_FOR_CANDIDATE
        ):
            raise ValueError("Candidate acceptance produced an entry-only state")

    @property
    def blocking_checks(self) -> tuple[Phase3ReviewCheck, ...]:
        """Return required checks that are not passing."""

        return tuple(
            item
            for item in self.checks
            if item.required and item.status is not Phase3CheckStatus.PASS
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "format_version": self.format_version,
            "review_stage": self.review_stage.value,
            "state": self.state.value,
            "candidate_version": self.candidate_version,
            "current_package_version": self.current_package_version,
            "status": self.status.value,
            "acceptance_ready": self.acceptance_ready,
            "ready_for_candidate_promotion": self.ready_for_candidate_promotion,
            "ready_for_candidate_build": self.ready_for_candidate_build,
            "ready_for_phase3_shadow": self.ready_for_phase3_shadow,
            "ready_for_release": self.ready_for_release,
            "checks": [item.to_dict() for item in self.checks],
            "blocking_checks": [item.check_id for item in self.blocking_checks],
            "authority_boundary": self.authority_boundary,
            "limitations": list(self.limitations),
        }


class DeterministicPhase3EntryReview:
    """Evaluate Phase 3 promotion stages without running scanned content."""

    def run(self, request: Phase3EntryReviewRequest) -> Phase3EntryReviewReport:
        """Produce a deterministic report for exactly one promotion stage."""

        if not isinstance(request, Phase3EntryReviewRequest):
            raise TypeError("Phase 3 review request is invalid")
        root = _validated_root(request.repository_root)
        if request.stage is Phase3ReviewStage.ENTRY_READINESS:
            checks = self._entry_readiness_checks(root, request)
            state = self._entry_state(checks)
        else:
            checks = self._candidate_acceptance_checks(root, request)
            state = self._candidate_state(checks)
        ordered = tuple(sorted(checks, key=lambda item: item.check_id))
        status = {
            Phase3PromotionState.ENTRY_NO_GO: Phase3ReviewStatus.NO_GO,
            Phase3PromotionState.READY_FOR_CANDIDATE: Phase3ReviewStatus.GO,
            Phase3PromotionState.CANDIDATE_UNDER_REVIEW: (
                Phase3ReviewStatus.CONDITIONAL
            ),
            Phase3PromotionState.CANDIDATE_NO_GO: Phase3ReviewStatus.NO_GO,
            Phase3PromotionState.CANDIDATE_GO: Phase3ReviewStatus.GO,
        }[state]
        promotion_ready = state in {
            Phase3PromotionState.READY_FOR_CANDIDATE,
            Phase3PromotionState.CANDIDATE_UNDER_REVIEW,
            Phase3PromotionState.CANDIDATE_NO_GO,
            Phase3PromotionState.CANDIDATE_GO,
        }
        return Phase3EntryReviewReport(
            format=PHASE3_ENTRY_REVIEW_FORMAT,
            format_version=PHASE3_ENTRY_REVIEW_FORMAT_VERSION,
            review_stage=request.stage,
            state=state,
            candidate_version=request.candidate_version,
            current_package_version=__version__,
            status=status,
            acceptance_ready=state
            in {
                Phase3PromotionState.READY_FOR_CANDIDATE,
                Phase3PromotionState.CANDIDATE_GO,
            },
            ready_for_candidate_promotion=promotion_ready,
            ready_for_candidate_build=promotion_ready,
            ready_for_phase3_shadow=promotion_ready,
            ready_for_release=state is Phase3PromotionState.CANDIDATE_GO,
            checks=ordered,
            authority_boundary=dict(_AUTHORITY_BOUNDARY),
            limitations=self._limitations(ordered, request.stage, state),
        )

    def _entry_readiness_checks(
        self, root: Path, request: Phase3EntryReviewRequest
    ) -> list[Phase3ReviewCheck]:
        return [
            self._phase2_task_check(root),
            self._package_api_check(root),
            self._supply_chain_check(root),
            self._authority_boundary_check(root),
            self._external_pilot_check(root, request.external_pilot_report),
        ]

    def _candidate_acceptance_checks(
        self, root: Path, request: Phase3EntryReviewRequest
    ) -> list[Phase3ReviewCheck]:
        return [
            self._entry_readiness_approval_check(root, request.entry_readiness_report),
            self._phase2_task_check(root),
            self._package_api_check(root),
            self._supply_chain_check(root),
            self._authority_boundary_check(root),
            self._candidate_version_check(),
            self._candidate_artifact_check(root, request.reconciled_candidate_report),
            self._candidate_verification_check(
                root,
                request.candidate_verification_report,
                request.reconciled_candidate_report,
            ),
            self._release_provenance_bundle_check(
                root,
                request.release_provenance_bundle,
                request.reconciled_candidate_report,
            ),
            self._release_signature_check(root),
        ]

    @staticmethod
    def _entry_state(checks: list[Phase3ReviewCheck]) -> Phase3PromotionState:
        if all(
            item.status is Phase3CheckStatus.PASS for item in checks if item.required
        ):
            return Phase3PromotionState.READY_FOR_CANDIDATE
        return Phase3PromotionState.ENTRY_NO_GO

    @staticmethod
    def _candidate_state(checks: list[Phase3ReviewCheck]) -> Phase3PromotionState:
        by_id = {item.check_id: item for item in checks}
        entry_approved = (
            by_id["entry_readiness_approval"].status is Phase3CheckStatus.PASS
        )
        required = tuple(item for item in checks if item.required)
        if not entry_approved:
            return Phase3PromotionState.ENTRY_NO_GO
        if all(item.status is Phase3CheckStatus.PASS for item in required):
            return Phase3PromotionState.CANDIDATE_GO
        if any(item.status is Phase3CheckStatus.FAIL for item in required):
            return Phase3PromotionState.CANDIDATE_NO_GO
        return Phase3PromotionState.CANDIDATE_UNDER_REVIEW

    @staticmethod
    def _phase2_task_check(root: Path) -> Phase3ReviewCheck:
        task_ids = tuple(f"P2-EXIT-{index:02d}" for index in range(1, 8))
        paths = tuple(
            sorted(
                str(path.relative_to(root))
                for path in (root / "docs" / "tasks").glob("P2-EXIT-*.md")
                if path.is_file() and any(task_id in path.name for task_id in task_ids)
            )
        )
        missing = tuple(
            task_id
            for task_id in task_ids
            if not any(task_id in path for path in paths)
        )
        if missing:
            return _check(
                "phase2_task_records",
                "phase2_exit",
                Phase3CheckStatus.FAIL,
                True,
                paths or ("docs/tasks",),
                f"Missing required task records: {', '.join(missing)}.",
            )
        return _check(
            "phase2_task_records",
            "phase2_exit",
            Phase3CheckStatus.PASS,
            True,
            paths,
            "P2-EXIT-01 through P2-EXIT-07 task records are present.",
        )

    @staticmethod
    def _package_api_check(root: Path) -> Phase3ReviewCheck:
        required = (
            root / "src" / "agentsec" / "api.py",
            root / "src" / "agentsec" / "py.typed",
            root / "src" / "agentsec" / "exit_codes.py",
        )
        ready = all(path.is_file() for path in required)
        return _check(
            "package_api_and_typing",
            "package",
            Phase3CheckStatus.PASS if ready else Phase3CheckStatus.FAIL,
            True,
            tuple(str(path.relative_to(root)) for path in required),
            (
                "Curated API, CLI-independent ExitCode, and py.typed are present."
                if ready
                else "Public API or PEP 561 marker is missing."
            ),
        )

    @staticmethod
    def _supply_chain_check(root: Path) -> Phase3ReviewCheck:
        required = (
            root / "requirements" / "runtime.lock",
            root / "requirements" / "dev.lock",
            root / "supply-chain" / "sbom.cdx.json",
            root / "supply-chain" / "license-inventory.json",
            root / "supply-chain" / "lockfiles.sha256",
            root / "supply-chain" / "build-provenance.json",
        )
        ready = all(path.is_file() for path in required)
        return _check(
            "supply_chain_evidence",
            "supply_chain",
            Phase3CheckStatus.PASS if ready else Phase3CheckStatus.FAIL,
            True,
            tuple(str(path.relative_to(root)) for path in required),
            (
                "Exact lockfiles, CycloneDX/license evidence, and build "
                "provenance are present."
                if ready
                else "Required supply-chain evidence is incomplete."
            ),
        )

    @staticmethod
    def _authority_boundary_check(root: Path) -> Phase3ReviewCheck:
        paths = (
            root / "docs" / "phase2-exit-hardening-plan.md",
            root / "src" / "agentsec" / "provenance.py",
            root / "src" / "agentsec" / "policy" / "ci_enforcement.py",
        )
        text = "\n".join(
            path.read_text(encoding="utf-8") for path in paths if path.is_file()
        ).lower()
        markers = (
            "llm output = candidate evidence only",
            "allow_llm_authority",
            "runtime_unverified_authority",
            "deterministic rules retain authorization authority",
        )
        ready = all(marker in text for marker in markers)
        return _check(
            "authority_boundary",
            "security_governance",
            Phase3CheckStatus.PASS if ready else Phase3CheckStatus.FAIL,
            True,
            tuple(str(path.relative_to(root)) for path in paths),
            (
                "LLM, runtime-unverified authority, and deterministic CI "
                "boundaries are documented/enforced."
                if ready
                else "One or more Phase 3 authority-boundary markers are missing."
            ),
        )

    @staticmethod
    def _external_pilot_check(
        root: Path, evidence_path: Path | None
    ) -> Phase3ReviewCheck:
        if evidence_path is None:
            return _check(
                "external_pilot_evidence",
                "external_evidence",
                Phase3CheckStatus.PENDING,
                True,
                ("P2-EXIT-06 external evidence not supplied",),
                "No external real-project Pilot report was supplied.",
            )
        try:
            resolved, payload = _load_control_json(root, evidence_path)
            report = PilotReport.model_validate(payload)
        except (ValueError, ValidationError):
            return _check(
                "external_pilot_evidence",
                "external_evidence",
                Phase3CheckStatus.FAIL,
                True,
                ("explicit external pilot path",),
                "The external Pilot report is invalid, oversized, or outside root.",
            )
        accepted = (
            report.evidence_mode == "external_repository"
            and report.status == "complete"
            and report.metrics.acceptance_ready is True
            and report.metrics.scope_complete is True
            and report.metrics.human_labels_complete is True
            and report.metrics.failed_cases == 0
            and report.metrics.cases >= PILOT_EXTERNAL_MIN_SCANS
            and report.metrics.pull_request_scans >= PILOT_EXTERNAL_MIN_PR_SCANS
            and len(report.cases) == report.metrics.cases
            and all(item.passed for item in report.cases)
            and all(
                report.metrics.drill_counts.get(drill, 0) >= 1
                for drill in PILOT_EXTERNAL_REQUIRED_DRILLS
            )
            and report.human_label_source == "independent_reviewer"
            and bool(report.human_reviewer_ids)
        )
        if accepted:
            rationale = "External Pilot report is complete and acceptance-ready."
        elif (
            report.evidence_mode == "external_repository"
            and report.metrics.scope_complete is True
            and report.metrics.failed_cases == 0
            and report.metrics.human_labels_complete is False
        ):
            rationale = (
                "External Pilot machine scope is complete, but independent human "
                "labels and the final reviewed replay are pending."
            )
        else:
            rationale = "External Pilot report exists but is not acceptance-ready."
        return _check(
            "external_pilot_evidence",
            "external_evidence",
            Phase3CheckStatus.PASS if accepted else Phase3CheckStatus.PENDING,
            True,
            (str(resolved.relative_to(root)),),
            rationale,
        )

    @staticmethod
    def _entry_readiness_approval_check(
        root: Path, report_path: Path | None
    ) -> Phase3ReviewCheck:
        if report_path is None:
            return _check(
                "entry_readiness_approval",
                "release",
                Phase3CheckStatus.PENDING,
                True,
                ("approved entry-readiness report not supplied",),
                "Candidate acceptance requires an explicit ready-for-candidate report.",
            )
        try:
            resolved, payload = _load_control_json(root, report_path)
        except ValueError:
            return _check(
                "entry_readiness_approval",
                "release",
                Phase3CheckStatus.FAIL,
                True,
                ("explicit entry-readiness report path",),
                "The entry-readiness report is invalid, oversized, or outside root.",
            )
        accepted = (
            payload.get("format") == PHASE3_ENTRY_REVIEW_FORMAT
            and payload.get("format_version") == PHASE3_ENTRY_REVIEW_FORMAT_VERSION
            and payload.get("review_stage") == Phase3ReviewStage.ENTRY_READINESS.value
            and payload.get("state") == Phase3PromotionState.READY_FOR_CANDIDATE.value
            and payload.get("status") == Phase3ReviewStatus.GO.value
            and payload.get("candidate_version") == PHASE3_CANDIDATE_VERSION
            and payload.get("acceptance_ready") is True
            and payload.get("ready_for_candidate_promotion") is True
            and payload.get("ready_for_candidate_build") is True
            and payload.get("ready_for_phase3_shadow") is True
            and payload.get("ready_for_release") is False
            and payload.get("authority_boundary") == _AUTHORITY_BOUNDARY
            and payload.get("blocking_checks") == []
        )
        return _check(
            "entry_readiness_approval",
            "release",
            Phase3CheckStatus.PASS if accepted else Phase3CheckStatus.FAIL,
            True,
            (str(resolved.relative_to(root)),),
            (
                "Entry readiness is explicitly approved for candidate promotion."
                if accepted
                else "The supplied report does not authorize candidate promotion."
            ),
        )

    @staticmethod
    def _candidate_version_check() -> Phase3ReviewCheck:
        ready = __version__ == PHASE3_CANDIDATE_VERSION
        return _check(
            "candidate_version_promotion",
            "release",
            Phase3CheckStatus.PASS if ready else Phase3CheckStatus.PENDING,
            True,
            ("src/agentsec/versioning.py", f"current={__version__}"),
            (
                "Package version is promoted to 0.4.0."
                if ready
                else "Package is not yet promoted to the 0.4.0 candidate version."
            ),
        )

    @classmethod
    def _candidate_artifact_check(
        cls, root: Path, reconciliation_path: Path | None
    ) -> Phase3ReviewCheck:
        if reconciliation_path is not None:
            return cls._reconciled_candidate_artifact_check(root, reconciliation_path)
        release_dir = root / "dist" / PHASE3_CANDIDATE_VERSION
        wheel = release_dir / f"agentsec-{PHASE3_CANDIDATE_VERSION}-py3-none-any.whl"
        sdist = release_dir / f"agentsec-{PHASE3_CANDIDATE_VERSION}.tar.gz"
        checksums = release_dir / "SHA256SUMS"
        expected = (wheel, sdist, checksums)
        evidence = tuple(str(path.relative_to(root)) for path in expected)
        if not all(path.is_file() for path in expected):
            return _check(
                "candidate_artifacts",
                "release",
                Phase3CheckStatus.PENDING,
                True,
                evidence,
                "0.4.0 candidate Wheel, sdist, or checksum file is missing.",
            )
        try:
            observed = _parse_sha256sums(checksums)
        except (OSError, UnicodeError, ValueError):
            return _check(
                "candidate_artifacts",
                "release",
                Phase3CheckStatus.FAIL,
                True,
                evidence,
                "Candidate checksum evidence is malformed.",
            )
        expected_hashes = {
            wheel.name: hashlib.sha256(wheel.read_bytes()).hexdigest(),
            sdist.name: hashlib.sha256(sdist.read_bytes()).hexdigest(),
        }
        ready = observed == expected_hashes
        return _check(
            "candidate_artifacts",
            "release",
            Phase3CheckStatus.PASS if ready else Phase3CheckStatus.FAIL,
            True,
            evidence,
            (
                "0.4.0 Wheel, sdist, and checksum evidence are consistent."
                if ready
                else "Candidate artifact checksums are stale, incomplete, or invalid."
            ),
        )

    @classmethod
    def _reconciled_candidate_artifact_check(
        cls, root: Path, report_path: Path
    ) -> Phase3ReviewCheck:
        try:
            resolved, payload = _load_control_json(root, report_path)
            candidate_dir = cls._reconciled_candidate_directory(root, payload)
            artifact_names = (
                f"agentsec-{PHASE3_CANDIDATE_VERSION}-py3-none-any.whl",
                f"agentsec-{PHASE3_CANDIDATE_VERSION}.tar.gz",
            )
            artifacts = tuple(candidate_dir / name for name in artifact_names)
            checksums = candidate_dir / "SHA256SUMS"
            if not all(path.is_file() for path in (*artifacts, checksums)):
                raise ValueError("reconciled candidate artifacts are missing")
            observed = _parse_sha256sums(checksums)
            expected_hashes = {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in artifacts
            }
            report_artifacts = payload.get("artifacts")
            if not isinstance(report_artifacts, dict):
                raise ValueError("reconciliation artifact evidence is malformed")
            for path in artifacts:
                record = report_artifacts.get(path.name)
                if not isinstance(record, dict):
                    raise ValueError("reconciliation artifact evidence is incomplete")
                if record.get("sha256") != expected_hashes[path.name]:
                    raise ValueError("reconciliation artifact digest is stale")
                if record.get("size_bytes") != path.stat().st_size:
                    raise ValueError("reconciliation artifact size is stale")
            if observed != expected_hashes:
                raise ValueError("reconciled candidate checksums are stale")
            accepted = cls._reconciliation_payload_is_accepted(root, payload)
        except (OSError, UnicodeError, ValueError, RuntimeError):
            accepted = False
            candidate_dir = None
        evidence_items = [_safe_relative_evidence(root, report_path)]
        if candidate_dir is not None:
            evidence_items.extend(
                str(path.relative_to(root))
                for path in (
                    candidate_dir
                    / f"agentsec-{PHASE3_CANDIDATE_VERSION}-py3-none-any.whl",
                    candidate_dir / f"agentsec-{PHASE3_CANDIDATE_VERSION}.tar.gz",
                    candidate_dir / "SHA256SUMS",
                )
            )
        return _check(
            "candidate_artifacts",
            "release",
            Phase3CheckStatus.PASS if accepted else Phase3CheckStatus.FAIL,
            True,
            tuple(evidence_items),
            (
                "Reconciled Candidate artifacts, digests, and source/package "
                "checks are valid."
                if accepted
                else "Reconciled Candidate evidence or artifact digests are invalid."
            ),
        )

    @staticmethod
    def _reconciliation_payload_is_accepted(
        root: Path, payload: dict[str, object]
    ) -> bool:
        checks = payload.get("artifact_checks")
        check_values = checks.get("checks") if isinstance(checks, dict) else None
        smoke = payload.get("installed_cli_smoke")
        smoke_values = smoke if isinstance(smoke, dict) else None
        content_checks = payload.get("content_checks")
        content_values = content_checks if isinstance(content_checks, dict) else None
        artifact_checks_payload = checks if isinstance(checks, dict) else None
        artifact_content_checks = (
            artifact_checks_payload.get("content_checks")
            if artifact_checks_payload is not None
            else None
        )
        reproducible = payload.get("reproducible_build")
        inventory_count, inventory_sha256 = _current_reconciliation_inventory(root)
        required_content_matches = {
            "wheel_content_match": True,
            "sdist_content_match": True,
            "schema_content_match": True,
            "metadata_content_match": True,
        }
        required_content_checks = {
            **required_content_matches,
            "mismatched_wheel_files": [],
            "mismatched_sdist_files": [],
            "mismatched_sdist_schema_files": [],
            "mismatched_sdist_metadata_files": [],
        }
        return (
            payload.get("format") == _RECONCILIATION_FORMAT
            and payload.get("format_version") == _RECONCILIATION_FORMAT_VERSION
            and payload.get("task_id") == _RECONCILIATION_TASK_ID
            and payload.get("status") == "reconciled"
            and payload.get("package_version") == PHASE3_CANDIDATE_VERSION
            and payload.get("source_inventory_file_count") == inventory_count
            and payload.get("source_inventory_sha256") == inventory_sha256
            and payload.get("candidate_directory") == "dist/candidates/0.4.0-p3-rel-01"
            and payload.get("preserved_candidate_directory")
            == f"dist/{PHASE3_CANDIDATE_VERSION}"
            and payload.get("preserved_candidate_unchanged") is True
            and payload.get("candidate_artifacts_differ_from_preserved") is True
            and payload.get("report_only") is True
            and payload.get("runtime_verified") is False
            and payload.get("network_accessed") is False
            and payload.get("scanned_content_executed") is False
            and isinstance(check_values, dict)
            and bool(check_values)
            and all(value is True for value in check_values.values())
            and content_values == required_content_checks
            and artifact_content_checks == required_content_checks
            and isinstance(smoke_values, dict)
            and bool(smoke_values)
            and all(value is True for value in smoke_values.values())
            and isinstance(reproducible, dict)
            and reproducible.get("source_date_epoch") == 0
            and reproducible.get("byte_identical") is True
        )

    @staticmethod
    def _reconciled_candidate_directory(root: Path, payload: dict[str, object]) -> Path:
        value = payload.get("candidate_directory")
        if not isinstance(value, str) or not value:
            raise ValueError("reconciliation candidate directory is missing")
        relative = PurePosixPath(value)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("reconciliation candidate directory is unsafe")
        candidate = (root / Path(*relative.parts)).resolve(strict=True)
        candidate.relative_to(root)
        if candidate.is_symlink() or not candidate.is_dir():
            raise ValueError("reconciliation candidate directory is unsafe")
        return candidate

    @classmethod
    def _candidate_verification_check(
        cls,
        root: Path,
        report_path: Path | None,
        reconciliation_path: Path | None,
    ) -> Phase3ReviewCheck:
        if reconciliation_path is not None:
            try:
                resolved, payload = _load_control_json(root, reconciliation_path)
                accepted = cls._reconciliation_payload_is_accepted(root, payload)
            except (OSError, UnicodeError, ValueError, RuntimeError):
                resolved = reconciliation_path
                accepted = False
            return _check(
                "candidate_verification",
                "release",
                Phase3CheckStatus.PASS if accepted else Phase3CheckStatus.FAIL,
                True,
                (_safe_relative_evidence(root, resolved),),
                (
                    "Reconciled Candidate package verification and installed CLI "
                    "smoke evidence are complete."
                    if accepted
                    else "Reconciled Candidate verification evidence is incomplete "
                    "or inconsistent."
                ),
            )
        if report_path is None:
            return _check(
                "candidate_verification",
                "release",
                Phase3CheckStatus.PENDING,
                True,
                ("candidate verification report not supplied",),
                "Candidate acceptance requires explicit package verification evidence.",
            )
        try:
            resolved, payload = _load_control_json(root, report_path)
        except ValueError:
            return _check(
                "candidate_verification",
                "release",
                Phase3CheckStatus.FAIL,
                True,
                ("explicit candidate verification report path",),
                "Candidate verification evidence is invalid or outside root.",
            )
        required_checks = {
            "package_hardening": True,
            "reproducible_build": True,
            "clean_install": True,
            "public_api_import": True,
            "checksums_verified": True,
        }
        accepted = (
            payload.get("format") == _CANDIDATE_VERIFICATION_FORMAT
            and payload.get("format_version") == _CANDIDATE_VERIFICATION_FORMAT_VERSION
            and payload.get("candidate_version") == PHASE3_CANDIDATE_VERSION
            and payload.get("status") == "complete"
            and payload.get("acceptance_ready") is True
            and payload.get("checks") == required_checks
        )
        return _check(
            "candidate_verification",
            "release",
            Phase3CheckStatus.PASS if accepted else Phase3CheckStatus.FAIL,
            True,
            (str(resolved.relative_to(root)),),
            (
                "Candidate package verification evidence is complete."
                if accepted
                else "Candidate verification evidence is incomplete or inconsistent."
            ),
        )

    @staticmethod
    def _release_provenance_bundle_check(
        root: Path,
        bundle_path: Path | None,
        reconciliation_path: Path | None,
    ) -> Phase3ReviewCheck:
        required = reconciliation_path is not None
        if bundle_path is None:
            return _check(
                "release_manifest_and_provenance_bundle",
                "release",
                Phase3CheckStatus.PENDING,
                required,
                ("P3-REL-04 release manifest/provenance bundle not supplied",),
                (
                    "The P3-REL-03 Candidate requires a P3-REL-04 release "
                    "manifest and provenance bundle."
                    if required
                    else (
                        "Legacy Candidate verification does not require the "
                        "P3-REL-04 bundle."
                    )
                ),
            )
        try:
            resolved = bundle_path.resolve(strict=True)
            validate_provenance_bundle(root, resolved)
        except (OSError, RuntimeError, ValueError, ReleaseBundleValidationError):
            return _check(
                "release_manifest_and_provenance_bundle",
                "release",
                Phase3CheckStatus.FAIL,
                required,
                (_safe_relative_evidence(root, bundle_path),),
                "The P3-REL-04 release manifest or provenance bundle is invalid.",
            )
        return _check(
            "release_manifest_and_provenance_bundle",
            "release",
            Phase3CheckStatus.PASS,
            required,
            (_safe_relative_evidence(root, resolved),),
            "Release manifest, provenance bundle, and integrity checks are valid.",
        )

    @staticmethod
    def _release_signature_check(root: Path) -> Phase3ReviewCheck:
        provenance = root / "supply-chain" / "build-provenance.json"
        if not provenance.is_file():
            return _check(
                "release_signature_and_provenance",
                "release",
                Phase3CheckStatus.FAIL,
                False,
                ("supply-chain/build-provenance.json",),
                "Build provenance policy is missing.",
            )
        try:
            payload = json.loads(provenance.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return _check(
                "release_signature_and_provenance",
                "release",
                Phase3CheckStatus.FAIL,
                False,
                ("supply-chain/build-provenance.json",),
                "Build provenance policy is invalid.",
            )
        claimed = payload.get("artifact_signature") not in {None, "not_claimed"}
        return _check(
            "release_signature_and_provenance",
            "release",
            Phase3CheckStatus.PASS if claimed else Phase3CheckStatus.PENDING,
            False,
            ("supply-chain/build-provenance.json",),
            (
                "Artifact signature/provenance is supplied by the release system."
                if claimed
                else (
                    "Local build evidence is present; signatures and SLSA "
                    "provenance are explicitly not claimed."
                )
            ),
        )

    @staticmethod
    def _limitations(
        checks: tuple[Phase3ReviewCheck, ...],
        stage: Phase3ReviewStage,
        state: Phase3PromotionState,
    ) -> tuple[str, ...]:
        limitations = [
            "This review does not execute scanned Agent content or grant runtime "
            "authority.",
            "LLM semantic analysis remains outside the authorization path; any "
            "future LLM output must remain candidate evidence.",
            "Version and report records carry no authorization authority; "
            "deterministic Rules and reviewed Policy retain decision authority.",
        ]
        if stage is Phase3ReviewStage.ENTRY_READINESS:
            limitations.append(
                "Entry readiness can authorize candidate promotion/build and "
                "Phase 3 shadow-only work, but never release or production authority."
            )
        if state is Phase3PromotionState.ENTRY_NO_GO:
            limitations.append(
                "Candidate promotion and Phase 3 shadow-only entry remain blocked."
            )
        elif state is Phase3PromotionState.READY_FOR_CANDIDATE:
            limitations.append(
                "An explicit release-owner action is still required before version "
                "promotion or candidate artifact creation."
            )
        elif state is Phase3PromotionState.CANDIDATE_UNDER_REVIEW:
            limitations.append(
                "Candidate construction is authorized, but release remains blocked "
                "until all required candidate checks pass."
            )
        elif state is Phase3PromotionState.CANDIDATE_NO_GO:
            limitations.append(
                "Entry readiness remains valid, but candidate acceptance failed and "
                "release is blocked until the failed evidence is corrected."
            )
        else:
            limitations.append(
                "Candidate acceptance does not claim remote publication, production "
                "deployment, runtime attestation, signatures, or SLSA provenance."
            )
        if any(
            item.check_id == "external_pilot_evidence"
            and item.status is not Phase3CheckStatus.PASS
            for item in checks
        ):
            limitations.append("External real-project Pilot evidence is pending.")
        return tuple(limitations)


def _check(
    check_id: str,
    area: str,
    status: Phase3CheckStatus,
    required: bool,
    evidence: tuple[str, ...],
    rationale: str,
) -> Phase3ReviewCheck:
    return Phase3ReviewCheck(
        check_id=check_id,
        area=area,
        status=status,
        required=required,
        evidence=evidence,
        rationale=rationale,
    )


def render_phase3_entry_review_text(
    report: Phase3EntryReviewReport,
    *,
    language: Phase3ReviewLanguage = Phase3ReviewLanguage.EN,
) -> str:
    """Render a bounded state-machine review for release owners."""

    if not isinstance(report, Phase3EntryReviewReport):
        raise TypeError("Phase 3 review text renderer requires a report")
    if language is Phase3ReviewLanguage.ZH:
        lines = [
            "AgentSec Phase 3 入口准备度 / 0.4.0 候选晋级审查",
            f"审查阶段：{report.review_stage.value}",
            f"状态机状态：{report.state.value}",
            f"结论：{report.status.value}",
            f"当前包版本：{report.current_package_version}",
            f"候选版本：{report.candidate_version}",
            f"本阶段可验收：{report.acceptance_ready}",
            f"可晋级候选版本：{report.ready_for_candidate_promotion}",
            f"可构建候选产物：{report.ready_for_candidate_build}",
            f"可进入 Phase 3 Shadow-only：{report.ready_for_phase3_shadow}",
            f"可发布：{report.ready_for_release}",
            "",
            "检查项",
        ]
    else:
        lines = [
            "AgentSec Phase 3 Entry Readiness / 0.4.0 Candidate Promotion",
            f"Review stage: {report.review_stage.value}",
            f"Promotion state: {report.state.value}",
            f"Decision: {report.status.value}",
            f"Current package: {report.current_package_version}",
            f"Candidate: {report.candidate_version}",
            f"Stage acceptance ready: {report.acceptance_ready}",
            f"Ready for candidate promotion: {report.ready_for_candidate_promotion}",
            f"Ready for candidate build: {report.ready_for_candidate_build}",
            f"Ready for Phase 3 shadow-only: {report.ready_for_phase3_shadow}",
            f"Ready for release: {report.ready_for_release}",
            "",
            "Checks",
        ]
    lines.extend(
        f"  {item.check_id}: {item.status.value} "
        f"({'required' if item.required else 'optional'}) - {item.rationale}"
        for item in report.checks
    )
    lines.extend(("", "Limitations"))
    lines.extend(f"  - {item}" for item in report.limitations)
    return "\n".join(lines) + "\n"


def encode_phase3_entry_review_json(report: Phase3EntryReviewReport) -> str:
    """Encode a deterministic JSON promotion-state report."""

    if not isinstance(report, Phase3EntryReviewReport):
        raise TypeError("Phase 3 review JSON encoder requires a report")
    return (
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


def _validated_root(path: Path) -> Path:
    if path.is_symlink():
        raise ValueError("Phase 3 repository root must not be a symbolic link")
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("Phase 3 repository root must be a directory")
    return resolved


def _load_control_json(root: Path, path: Path) -> tuple[Path, dict[str, object]]:
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
        if (
            not resolved.is_file()
            or resolved.stat().st_size > _MAX_CONTROL_REPORT_BYTES
        ):
            raise ValueError("control report is missing or oversized")
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, RuntimeError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("control report is unreadable") from error
    if not isinstance(payload, dict):
        raise ValueError("control report must be a JSON object")
    return resolved, payload


def _parse_sha256sums(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            raise ValueError("checksum line must contain digest and filename")
        digest, filename = parts
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or Path(filename).name != filename
            or filename in entries
        ):
            raise ValueError("checksum entry is invalid")
        entries[filename] = digest
    return entries


def _current_reconciliation_inventory(root: Path) -> tuple[int, str]:
    """Return the current source inventory contract shared with P3-REL-01."""

    paths = [
        root / "pyproject.toml",
        root / "MANIFEST.in",
        *sorted((root / "src" / "agentsec").rglob("*.py")),
        *sorted((root / "schemas").rglob("*.json")),
    ]
    if any(not path.is_file() for path in paths):
        raise ValueError("reconciliation source inventory is incomplete")
    records = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in paths
    ]
    encoded = json.dumps(
        records, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return len(records), hashlib.sha256(encoded).hexdigest()


def _safe_relative_evidence(root: Path, path: Path) -> str:
    """Render a bounded evidence path without leaking an external absolute path."""

    try:
        return str(path.resolve().relative_to(root.resolve()))
    except (OSError, RuntimeError, ValueError):
        return "explicit report path"


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
    "PHASE3_CANDIDATE_VERSION",
    "PHASE3_ENTRY_REVIEW_FORMAT",
    "PHASE3_ENTRY_REVIEW_FORMAT_VERSION",
    "DeterministicPhase3EntryReview",
    "Phase3CheckStatus",
    "Phase3EntryReviewReport",
    "Phase3EntryReviewRequest",
    "Phase3PromotionState",
    "Phase3ReviewCheck",
    "Phase3ReviewLanguage",
    "Phase3ReviewStage",
    "Phase3ReviewStatus",
    "encode_phase3_entry_review_json",
    "render_phase3_entry_review_text",
]
