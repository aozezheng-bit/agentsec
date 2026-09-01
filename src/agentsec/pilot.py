"""Bounded Pilot configuration, execution, and evidence reporting."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from yaml.tokens import AliasToken, AnchorToken, TagToken

from agentsec.rules import BUILTIN_MARKDOWN_RULE_IDS

PILOT_PLAN_FORMAT = "agentsec-pilot-plan"
PILOT_PLAN_SCHEMA_VERSION = "0.1.0"
PILOT_REPORT_FORMAT = "agentsec-pilot-report"
PILOT_REPORT_OUTPUT_VERSION = "0.1.0"
PILOT_HUMAN_LABELS_FORMAT = "agentsec-pilot-human-labels"
PILOT_HUMAN_LABELS_SCHEMA_VERSION = "0.1.0"
PILOT_EXTERNAL_MIN_SCANS = 20
PILOT_EXTERNAL_MIN_PR_SCANS = 10
PILOT_EXTERNAL_REQUIRED_DRILLS = (
    "incomplete_coverage",
    "risky_change",
    "waiver_lifecycle",
)
PILOT_MAX_PLAN_BYTES = 2_097_152


class PilotError(ValueError):
    """Safe pilot plan or execution failure."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class PilotCase(_Strict):
    """One inert project state with reviewed expected scanner outcomes."""

    case_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")]
    title: Annotated[str, Field(min_length=1, max_length=160)]
    project_root: Annotated[str, Field(min_length=1, max_length=512)]
    policy_path: Annotated[str, Field(min_length=1, max_length=512)]
    expected_exit: Literal[0, 1, 2]
    expected_coverage: Literal["complete", "incomplete"]
    expected_rule_ids: tuple[str, ...] = ()
    scan_kind: Literal["baseline", "pull_request"] = "baseline"
    drill: Literal["incomplete_coverage", "risky_change", "waiver_lifecycle"] | None = (
        None
    )
    max_duration_ms: Annotated[int, Field(ge=1, le=600_000)] = 10_000

    @field_validator("project_root", "policy_path")
    @classmethod
    def paths_must_be_relative(cls, value: str) -> str:
        candidate = Path(value)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError("pilot paths must be repository-relative")
        return candidate.as_posix()

    @field_validator("expected_rule_ids")
    @classmethod
    def rules_must_be_known_sorted_unique(
        cls, values: tuple[str, ...]
    ) -> tuple[str, ...]:
        if values != tuple(sorted(set(values))):
            raise ValueError("expected_rule_ids must be sorted and unique")
        if set(values) - set(BUILTIN_MARKDOWN_RULE_IDS):
            raise ValueError("expected_rule_ids contains unsupported Rule IDs")
        return values

    @model_validator(mode="after")
    def coverage_and_exit_must_agree(self) -> PilotCase:
        if self.expected_coverage == "incomplete" and self.expected_exit != 2:
            raise ValueError("incomplete pilot cases must expect exit 2")
        if self.expected_coverage == "complete" and self.expected_exit == 2:
            raise ValueError("complete pilot cases cannot expect exit 2")
        return self


class PilotPlan(_Strict):
    """Explicit local pilot contract; never discovered from scanned content."""

    format: Literal["agentsec-pilot-plan"]
    schema_version: Literal["0.1.0"]
    pilot_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9._-]{0,127}$")]
    project_name: Annotated[str, Field(min_length=1, max_length=160)]
    owner: Annotated[str, Field(min_length=1, max_length=128)]
    evidence_mode: Literal["internal_integration", "external_repository"]
    cases: Annotated[tuple[PilotCase, ...], Field(min_length=1, max_length=1000)]
    security_reviewer: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    minimum_scans: Annotated[int, Field(ge=1, le=100_000)] | None = None
    minimum_pr_scans: Annotated[int, Field(ge=1, le=100_000)] | None = None
    required_drills: tuple[
        Literal["incomplete_coverage", "risky_change", "waiver_lifecycle"], ...
    ] = ()

    @model_validator(mode="after")
    def cases_must_be_sorted_unique(self) -> PilotPlan:
        case_ids = tuple(item.case_id for item in self.cases)
        if case_ids != tuple(sorted(set(case_ids))):
            raise ValueError("pilot cases must be sorted and unique by case_id")
        drills = tuple(self.required_drills)
        if drills != tuple(sorted(set(drills))):
            raise ValueError("required_drills must be sorted and unique")
        if self.evidence_mode == "external_repository":
            if (
                self.minimum_scans is None
                or self.minimum_scans < PILOT_EXTERNAL_MIN_SCANS
            ):
                raise ValueError("external pilots must require at least 20 scans")
            if (
                self.minimum_pr_scans is None
                or self.minimum_pr_scans < PILOT_EXTERNAL_MIN_PR_SCANS
            ):
                raise ValueError(
                    "external pilots must require at least 10 pull-request scans"
                )
            if set(self.required_drills) != set(PILOT_EXTERNAL_REQUIRED_DRILLS):
                raise ValueError(
                    "external pilots must require risky, incomplete-Coverage, "
                    "and Waiver lifecycle drills"
                )
            if len(self.cases) < self.minimum_scans:
                raise ValueError("external pilot cases do not meet minimum scan count")
            if sum(item.scan_kind == "pull_request" for item in self.cases) < (
                self.minimum_pr_scans
            ):
                raise ValueError(
                    "external pilot cases do not meet minimum pull-request scan count"
                )
        return self


class PilotCaseResult(_Strict):
    case_id: str
    title: str
    expected_exit: Literal[0, 1, 2]
    observed_exit: int
    expected_coverage: Literal["complete", "incomplete"]
    observed_coverage: Literal["complete", "incomplete", "unavailable"]
    expected_rule_ids: tuple[str, ...]
    observed_rule_ids: tuple[str, ...]
    true_positive_rule_ids: tuple[str, ...]
    false_positive_rule_ids: tuple[str, ...]
    false_negative_rule_ids: tuple[str, ...]
    duration_ms: int
    max_duration_ms: int
    json_bytes: int
    sarif_bytes: int
    sarif_valid: bool
    decision_agreement: bool
    coverage_agreement: bool
    detection_agreement: bool
    performance_within_limit: bool
    passed: bool
    scan_kind: Literal["baseline", "pull_request"] = "baseline"
    drill: Literal["incomplete_coverage", "risky_change", "waiver_lifecycle"] | None = (
        None
    )


class PilotMetrics(_Strict):
    cases: int
    passed_cases: int
    failed_cases: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float | None
    recall: float | None
    decision_accuracy: float
    coverage_accuracy: float
    detection_accuracy: float
    total_duration_ms: int
    mean_duration_ms: float
    p50_duration_ms: int
    p95_duration_ms: int
    max_duration_ms: int
    baseline_scans: int = 0
    pull_request_scans: int = 0
    drill_counts: dict[str, int] = Field(default_factory=dict)
    scope_scans_target: int | None = None
    scope_pr_scans_target: int | None = None
    scope_complete: bool = False
    human_labels_complete: bool = False
    acceptance_ready: bool = False


class PilotReport(_Strict):
    format: Literal["agentsec-pilot-report"] = "agentsec-pilot-report"
    format_version: Literal["0.1.0"] = "0.1.0"
    status: Literal["complete", "failed", "evidence_pending"]
    pilot_id: str
    project_name: str
    owner: str
    evidence_mode: Literal["internal_integration", "external_repository"]
    plan_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    agentsec_executable: str
    metrics: PilotMetrics
    cases: tuple[PilotCaseResult, ...]
    limitations: tuple[str, ...]
    human_label_source: Literal["none", "plan", "independent_reviewer"] = "none"
    human_reviewer_ids: tuple[str, ...] = ()


class PilotHumanLabelCase(_Strict):
    """One independently reviewed expected outcome for an external Pilot case."""

    case_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")]
    expected_exit: Literal[0, 1, 2]
    expected_coverage: Literal["complete", "incomplete"]
    expected_rule_ids: tuple[str, ...] = ()

    @field_validator("expected_rule_ids")
    @classmethod
    def rules_must_be_known_sorted_unique(
        cls, values: tuple[str, ...]
    ) -> tuple[str, ...]:
        if values != tuple(sorted(set(values))):
            raise ValueError("expected_rule_ids must be sorted and unique")
        if set(values) - set(BUILTIN_MARKDOWN_RULE_IDS):
            raise ValueError("expected_rule_ids contains unsupported Rule IDs")
        return values

    @model_validator(mode="after")
    def coverage_and_exit_must_agree(self) -> PilotHumanLabelCase:
        if self.expected_coverage == "incomplete" and self.expected_exit != 2:
            raise ValueError("incomplete labels must expect exit 2")
        if self.expected_coverage == "complete" and self.expected_exit == 2:
            raise ValueError("complete labels cannot expect exit 2")
        return self


class PilotHumanLabels(_Strict):
    """Independent, value-minimized TP/FP/FN ground truth for a Pilot."""

    format: Literal["agentsec-pilot-human-labels"]
    schema_version: Literal["0.1.0"]
    pilot_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9._-]{0,127}$")]
    reviewer_id: Annotated[str, Field(min_length=1, max_length=128)]
    independence_statement: Annotated[str, Field(min_length=20, max_length=1000)]
    cases: Annotated[
        tuple[PilotHumanLabelCase, ...], Field(min_length=1, max_length=1000)
    ]

    @model_validator(mode="after")
    def cases_must_be_sorted_unique(self) -> PilotHumanLabels:
        case_ids = tuple(item.case_id for item in self.cases)
        if case_ids != tuple(sorted(set(case_ids))):
            raise ValueError("human label cases must be sorted and unique")
        return self


@dataclass(frozen=True, slots=True)
class LoadedPilotPlan:
    plan: PilotPlan
    path: Path
    sha256: str


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise PilotError("pilot plan contains a duplicate YAML key")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


def load_pilot_plan(
    path: Path,
    *,
    repository_root: Path,
    target_root: Path | None = None,
    trust_root: Path | None = None,
) -> LoadedPilotPlan:
    """Load a bounded explicit plan and verify every referenced path.

    The plan is always controlled by the AgentSec repository. For an external
    repository Pilot, project paths are resolved against an explicitly supplied
    target root and Policy paths against a separately supplied trust root.
    Neither root is discovered from scanned content.
    """

    resolved_path = path.resolve(strict=True)
    root = _validated_root(repository_root, "AgentSec repository root")
    _require_within(resolved_path, root, "pilot plan")
    if path.is_symlink():
        raise PilotError("pilot plan cannot be a symbolic link")
    mode = os.stat(resolved_path, follow_symlinks=False).st_mode
    if not stat.S_ISREG(mode):
        raise PilotError("pilot plan must be a regular file")
    size_bytes = os.stat(resolved_path, follow_symlinks=False).st_size
    if size_bytes > PILOT_MAX_PLAN_BYTES:
        raise PilotError("pilot plan exceeds the maximum size")
    content = resolved_path.read_bytes()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PilotError("pilot plan must be UTF-8") from error
    try:
        for token in yaml.scan(text):
            if isinstance(token, (AliasToken, AnchorToken, TagToken)):
                raise PilotError(
                    "pilot plan cannot contain YAML aliases, anchors, or tags"
                )
        raw = yaml.load(text, Loader=_UniqueKeyLoader)
        plan = PilotPlan.model_validate(raw)
    except PilotError:
        raise
    except Exception as error:
        raise PilotError("pilot plan is invalid") from error

    target = _validated_root(target_root or root, "Pilot target root")
    if plan.evidence_mode == "external_repository":
        if target_root is None or trust_root is None:
            raise PilotError(
                "external pilots require explicit --target-root and --trust-root"
            )
        trust = _validated_root(trust_root, "Pilot trust root")
        if target == trust:
            raise PilotError("external target and trust roots must be different")
    else:
        trust = _validated_root(trust_root or root, "Pilot trust root")

    for case in plan.cases:
        project = (target / case.project_root).resolve(strict=True)
        policy = (trust / case.policy_path).resolve(strict=True)
        _require_within(project, target, "pilot project")
        _require_within(policy, trust, "pilot policy")
        if not project.is_dir() or (target / case.project_root).is_symlink():
            raise PilotError("pilot project must be a non-symlink directory")
        if not policy.is_file() or (trust / case.policy_path).is_symlink():
            raise PilotError("pilot policy must be a non-symlink regular file")
    return LoadedPilotPlan(
        plan=plan,
        path=resolved_path,
        sha256=hashlib.sha256(content).hexdigest(),
    )


def load_human_labels(path: Path, *, repository_root: Path) -> PilotHumanLabels:
    """Load an explicit, bounded independent human-label file."""

    resolved_path = path.resolve(strict=True)
    root = _validated_root(repository_root, "AgentSec repository root")
    _require_within(resolved_path, root, "human labels")
    if path.is_symlink():
        raise PilotError("human labels cannot be a symbolic link")
    mode = os.stat(resolved_path, follow_symlinks=False).st_mode
    if not stat.S_ISREG(mode):
        raise PilotError("human labels must be a regular file")
    if os.stat(resolved_path, follow_symlinks=False).st_size > PILOT_MAX_PLAN_BYTES:
        raise PilotError("human labels exceed the maximum size")
    try:
        raw = json.loads(resolved_path.read_text(encoding="utf-8"))
        return PilotHumanLabels.model_validate(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise PilotError("human labels are invalid") from error


def _validated_root(path: Path, label: str) -> Path:
    if not isinstance(path, Path):
        raise TypeError(f"{label} must be a Path")
    if path.is_symlink():
        raise PilotError(f"{label} must not be a symbolic link")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise PilotError(f"{label} is missing or unsafe") from error
    if not resolved.is_dir():
        raise PilotError(f"{label} must be an existing directory")
    return resolved


def _require_within(path: Path, root: Path, label: str) -> None:
    try:
        path.relative_to(root)
    except ValueError as error:
        raise PilotError(f"{label} escapes the repository root") from error


class PilotRunner:
    """Execute the reviewed CI wrapper and collect value-minimized pilot data."""

    def run(
        self,
        loaded: LoadedPilotPlan,
        *,
        repository_root: Path,
        agentsec_executable: Path,
        output_root: Path,
        target_root: Path | None = None,
        trust_root: Path | None = None,
        expect_policy_sha256: str | None = None,
        human_labels: PilotHumanLabels | None = None,
    ) -> PilotReport:
        root = _validated_root(repository_root, "AgentSec repository root")
        executable = agentsec_executable.resolve(strict=True)
        runner = root / "scripts" / "run-agentsec-ci.sh"
        if not runner.is_file() or not os.access(runner, os.X_OK):
            raise PilotError("P2-29 CI Runner is unavailable")
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise PilotError("AgentSec executable is unavailable")
        if output_root.exists() and output_root.is_symlink():
            raise PilotError("pilot output root cannot be a symbolic link")
        output_root.mkdir(parents=True, exist_ok=True)

        target = _validated_root(target_root or root, "Pilot target root")
        if loaded.plan.evidence_mode == "external_repository":
            if target_root is None or trust_root is None:
                raise PilotError(
                    "external pilots require explicit --target-root and --trust-root"
                )
            trust = _validated_root(trust_root, "Pilot trust root")
            if target == trust:
                raise PilotError("external target and trust roots must be different")
        else:
            trust = _validated_root(trust_root or root, "Pilot trust root")

        labels_by_case: dict[str, PilotHumanLabelCase] = {}
        if human_labels is not None:
            if human_labels.pilot_id != loaded.plan.pilot_id:
                raise PilotError("human labels pilot_id does not match the plan")
            labels_by_case = {item.case_id: item for item in human_labels.cases}
            plan_case_ids = {item.case_id for item in loaded.plan.cases}
            if set(labels_by_case) - plan_case_ids:
                raise PilotError("human labels contain an unknown case_id")

        if expect_policy_sha256 is not None:
            from agentsec.trust import validate_expected_sha256_option

            validate_expected_sha256_option(expect_policy_sha256, label="policy")

        results = tuple(
            self._run_case(
                case,
                expected=labels_by_case.get(case.case_id),
                root=root,
                target_root=target,
                trust_root=trust
                if loaded.plan.evidence_mode == "external_repository"
                else None,
                runner=runner,
                executable=executable,
                output_root=output_root,
                expect_policy_sha256=expect_policy_sha256,
            )
            for case in loaded.plan.cases
        )
        labels_complete = human_labels is not None and set(labels_by_case) == {
            item.case_id for item in loaded.plan.cases
        }
        metrics = _metrics(
            results,
            plan=loaded.plan,
            human_labels_complete=labels_complete,
        )
        if loaded.plan.evidence_mode == "external_repository":
            status: Literal["complete", "failed", "evidence_pending"] = (
                "failed"
                if metrics.failed_cases
                else "complete"
                if metrics.acceptance_ready
                else "evidence_pending"
            )
        else:
            status = "complete" if metrics.failed_cases == 0 else "failed"

        limitations: list[str] = []
        if loaded.plan.evidence_mode == "internal_integration":
            limitations.append(
                "This checked-in run is an internal integration pilot, not "
                "remote production repository evidence."
            )
        else:
            limitations.extend(
                (
                    "External evidence is report-only; no CI blocking or "
                    "authorization decision is enabled by this Pilot.",
                    "The target repository is treated as untrusted input; "
                    "AgentSec does not execute project code, hooks, skills, "
                    "commands, or MCP servers.",
                )
            )
            if not labels_complete:
                limitations.append(
                    "Independent human TP/FP/FN labels are incomplete; "
                    "acceptance remains evidence-pending."
                )
            if not metrics.scope_complete:
                limitations.append(
                    "The 20-scan, 10-pull-request, and three-drill scope is "
                    "incomplete; acceptance remains evidence-pending."
                )
        limitations.extend(
            (
                "False-positive and false-negative metrics use reviewed "
                "scenario-level unique Rule IDs, not runtime exploit labels.",
                "Performance is local wall-clock integration latency and "
                "varies by host and filesystem cache.",
                "Static findings do not prove runtime Tool, OAuth, identity, "
                "permission, or exploit reachability.",
            )
        )
        return PilotReport(
            status=status,
            pilot_id=loaded.plan.pilot_id,
            project_name=loaded.plan.project_name,
            owner=loaded.plan.owner,
            evidence_mode=loaded.plan.evidence_mode,
            plan_sha256=loaded.sha256,
            agentsec_executable=executable.name,
            metrics=metrics,
            cases=results,
            limitations=tuple(limitations),
            human_label_source=(
                "independent_reviewer"
                if human_labels is not None
                else "plan"
                if loaded.plan.evidence_mode == "internal_integration"
                else "none"
            ),
            human_reviewer_ids=(
                (human_labels.reviewer_id,) if human_labels is not None else ()
            ),
        )

    @staticmethod
    def _run_case(
        case: PilotCase,
        *,
        expected: PilotHumanLabelCase | None,
        root: Path,
        target_root: Path,
        trust_root: Path | None,
        runner: Path,
        executable: Path,
        output_root: Path,
        expect_policy_sha256: str | None,
    ) -> PilotCaseResult:
        case_output = output_root / case.case_id
        environment = os.environ.copy()
        environment["AGENTSEC_BIN"] = str(executable)
        if trust_root is not None:
            environment["AGENTSEC_TRUST_ROOT"] = str(trust_root)
        if expect_policy_sha256 is not None:
            environment["AGENTSEC_EXPECT_POLICY_SHA256"] = expect_policy_sha256
        project_path = (target_root / case.project_root).resolve(strict=True)
        policy_argument = (
            case.policy_path
            if trust_root is not None
            else str((root / case.policy_path).resolve(strict=True))
        )
        expected_exit = (
            expected.expected_exit if expected is not None else case.expected_exit
        )
        expected_coverage = (
            expected.expected_coverage
            if expected is not None
            else case.expected_coverage
        )
        expected_rule_ids = (
            expected.expected_rule_ids
            if expected is not None
            else case.expected_rule_ids
        )
        started = time.perf_counter_ns()
        completed = subprocess.run(
            [
                str(runner),
                str(project_path),
                policy_argument,
                str(case_output),
            ],
            cwd=root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        duration_ms = max(1, (time.perf_counter_ns() - started) // 1_000_000)
        json_path = case_output / "agentsec-assessment.json"
        sarif_path = case_output / "agentsec-results.sarif"
        observed_rules: tuple[str, ...] = ()
        observed_coverage: Literal["complete", "incomplete", "unavailable"] = (
            "unavailable"
        )
        if json_path.is_file() and json_path.stat().st_size:
            try:
                payload = json.loads(json_path.read_text(encoding="utf-8"))
                assessment = payload["assessment_report"]["assessment"]
                observed_rules = tuple(
                    sorted({item["rule_id"] for item in assessment["findings"]})
                )
                observed_coverage = (
                    "complete" if assessment["coverage"]["complete"] else "incomplete"
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                observed_rules = ()
                observed_coverage = "unavailable"
        expected_set = set(expected_rule_ids)
        observed = set(observed_rules)
        true_positive = tuple(sorted(expected_set & observed))
        false_positive = tuple(sorted(observed - expected_set))
        false_negative = tuple(sorted(expected_set - observed))
        decision_agreement = completed.returncode == expected_exit
        coverage_agreement = observed_coverage == expected_coverage
        detection_agreement = not false_positive and not false_negative
        performance_within_limit = duration_ms <= case.max_duration_ms
        sarif_valid = _sarif_is_valid(sarif_path)
        passed = (
            decision_agreement
            and coverage_agreement
            and detection_agreement
            and performance_within_limit
            and sarif_valid
        )
        return PilotCaseResult(
            case_id=case.case_id,
            title=case.title,
            expected_exit=expected_exit,
            observed_exit=completed.returncode,
            expected_coverage=expected_coverage,
            observed_coverage=observed_coverage,
            expected_rule_ids=expected_rule_ids,
            observed_rule_ids=observed_rules,
            true_positive_rule_ids=true_positive,
            false_positive_rule_ids=false_positive,
            false_negative_rule_ids=false_negative,
            duration_ms=duration_ms,
            max_duration_ms=case.max_duration_ms,
            json_bytes=json_path.stat().st_size if json_path.is_file() else 0,
            sarif_bytes=sarif_path.stat().st_size if sarif_path.is_file() else 0,
            sarif_valid=sarif_valid,
            decision_agreement=decision_agreement,
            coverage_agreement=coverage_agreement,
            detection_agreement=detection_agreement,
            performance_within_limit=performance_within_limit,
            passed=passed,
            scan_kind=case.scan_kind,
            drill=case.drill,
        )


def _sarif_is_valid(path: Path) -> bool:
    if not path.is_file() or not path.stat().st_size:
        return False
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return (
        isinstance(payload, dict)
        and payload.get("version") == "2.1.0"
        and isinstance(payload.get("runs"), list)
        and bool(payload["runs"])
    )


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _percentile(values: tuple[int, ...], percentile: float) -> int:
    ordered = tuple(sorted(values))
    index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * percentile + 0.5)))
    return ordered[index]


def _metrics(
    results: tuple[PilotCaseResult, ...],
    *,
    plan: PilotPlan | None = None,
    human_labels_complete: bool = False,
) -> PilotMetrics:
    durations = tuple(item.duration_ms for item in results)
    true_positives = sum(len(item.true_positive_rule_ids) for item in results)
    false_positives = sum(len(item.false_positive_rule_ids) for item in results)
    false_negatives = sum(len(item.false_negative_rule_ids) for item in results)
    precision_denominator = true_positives + false_positives
    recall_denominator = true_positives + false_negatives
    baseline_scans = sum(item.scan_kind == "baseline" for item in results)
    pull_request_scans = sum(item.scan_kind == "pull_request" for item in results)
    drill_counts: dict[str, int] = {}
    for item in results:
        if item.drill is not None:
            drill_counts[item.drill] = drill_counts.get(item.drill, 0) + 1
    scope_scans_target = plan.minimum_scans if plan is not None else None
    scope_pr_scans_target = plan.minimum_pr_scans if plan is not None else None
    scope_counts_ok = (
        scope_scans_target is None or len(results) >= scope_scans_target
    ) and (scope_pr_scans_target is None or pull_request_scans >= scope_pr_scans_target)
    required_drills = set(plan.required_drills) if plan is not None else set()
    drills_ok = required_drills <= set(drill_counts)
    scope_complete = scope_counts_ok and drills_ok
    acceptance_ready = (
        plan is None or plan.evidence_mode == "internal_integration"
    ) or (scope_complete and human_labels_complete)
    return PilotMetrics(
        cases=len(results),
        passed_cases=sum(item.passed for item in results),
        failed_cases=sum(not item.passed for item in results),
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision=(
            _ratio(true_positives, precision_denominator)
            if precision_denominator
            else None
        ),
        recall=(
            _ratio(true_positives, recall_denominator) if recall_denominator else None
        ),
        decision_accuracy=_ratio(
            sum(item.decision_agreement for item in results), len(results)
        ),
        coverage_accuracy=_ratio(
            sum(item.coverage_agreement for item in results), len(results)
        ),
        detection_accuracy=_ratio(
            sum(item.detection_agreement for item in results), len(results)
        ),
        total_duration_ms=sum(durations),
        mean_duration_ms=round(sum(durations) / len(durations), 2),
        p50_duration_ms=_percentile(durations, 0.5),
        p95_duration_ms=_percentile(durations, 0.95),
        max_duration_ms=max(durations),
        baseline_scans=baseline_scans,
        pull_request_scans=pull_request_scans,
        drill_counts=drill_counts,
        scope_scans_target=scope_scans_target,
        scope_pr_scans_target=scope_pr_scans_target,
        scope_complete=scope_complete,
        human_labels_complete=human_labels_complete,
        acceptance_ready=acceptance_ready,
    )


def encode_pilot_report_json(report: PilotReport) -> str:
    """Encode a stable key-sorted report without source excerpts."""

    return (
        json.dumps(
            report.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def render_pilot_report_markdown(report: PilotReport) -> str:
    """Render a compact pilot readout for developers and management."""

    metrics = report.metrics
    lines = [
        f"# AgentSec Pilot Report: {report.project_name}",
        "",
        f"- Pilot ID: `{report.pilot_id}`",
        f"- Status: **{report.status.upper()}**",
        f"- Evidence mode: `{report.evidence_mode}`",
        f"- Cases: {metrics.passed_cases}/{metrics.cases} passed",
        f"- Decision accuracy: {metrics.decision_accuracy:.2%}",
        f"- Detection accuracy: {metrics.detection_accuracy:.2%}",
        f"- Precision: {_metric_text(metrics.precision)}",
        f"- Recall: {_metric_text(metrics.recall)}",
        f"- FP/FN: {metrics.false_positives}/{metrics.false_negatives}",
        f"- Performance p50/p95/max: {metrics.p50_duration_ms}/"
        f"{metrics.p95_duration_ms}/{metrics.max_duration_ms} ms",
        f"- Baseline/PR scans: {metrics.baseline_scans}/{metrics.pull_request_scans}",
        f"- Scope: {'READY' if metrics.scope_complete else 'PENDING'}; "
        f"human labels: {'READY' if metrics.human_labels_complete else 'PENDING'}",
        "",
        "| Case | Exit E/O | Coverage E/O | Rules E/O | Duration | Result |",
        "|---|---:|---|---:|---:|---|",
    ]
    for item in report.cases:
        lines.append(
            f"| {item.case_id} | {item.expected_exit}/{item.observed_exit} | "
            f"{item.expected_coverage}/{item.observed_coverage} | "
            f"{len(item.expected_rule_ids)}/{len(item.observed_rule_ids)} | "
            f"{item.duration_ms} ms | {'PASS' if item.passed else 'FAIL'} |"
        )
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in report.limitations)
    return "\n".join(lines) + "\n"


def _metric_text(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.2%}"


def export_pilot_plan_schema() -> str:
    """Export the strict pilot plan JSON Schema."""

    return json.dumps(PilotPlan.model_json_schema(), indent=2, sort_keys=True) + "\n"


def export_pilot_report_schema() -> str:
    """Export the strict pilot report JSON Schema."""

    return json.dumps(PilotReport.model_json_schema(), indent=2, sort_keys=True) + "\n"


def export_pilot_human_labels_schema() -> str:
    """Export the strict independent human-label JSON Schema."""

    return (
        json.dumps(PilotHumanLabels.model_json_schema(), indent=2, sort_keys=True)
        + "\n"
    )


def export_pilot_json_schemas(output_dir: Path) -> tuple[Path, Path, Path]:
    """Write the public Pilot plan, report, and human-label Schemas."""

    output_dir.mkdir(parents=True, exist_ok=True)
    plan_path = output_dir / "pilot-plan.schema.json"
    report_path = output_dir / "pilot-report.schema.json"
    labels_path = output_dir / "pilot-human-labels.schema.json"
    plan_path.write_text(export_pilot_plan_schema(), encoding="utf-8")
    report_path.write_text(export_pilot_report_schema(), encoding="utf-8")
    labels_path.write_text(export_pilot_human_labels_schema(), encoding="utf-8")
    return plan_path, report_path, labels_path
