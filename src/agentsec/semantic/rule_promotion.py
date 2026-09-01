"""P3-10 controlled semantic Rule promotion and Rule Pack staging.

Staging is an immutable review artifact.  It does not mutate the installed Rule
Pack or grant CI, Policy, Hard-Gate, or release authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentsec.semantic.integration import RuleCandidateStatus, SemanticRuleCandidate
from agentsec.semantic.p3_07 import RuleImplementationReplayReport
from agentsec.versioning import parse_interface_version

SEMANTIC_RULE_PROMOTION_VERSION = "0.1.0"
SEMANTIC_RULE_PACK_STAGING_VERSION = "0.1.0"

_RULE_ID_PATTERN = r"^[A-Z][A-Z0-9]*-[A-Z][A-Z0-9]*-[0-9]{3}$"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class RulePromotionStatus(StrEnum):
    REJECTED = "rejected"
    ELIGIBLE_FOR_STAGING = "eligible_for_staging"
    STAGED = "staged"


class RulePromotionCheck(_Strict):
    check_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{1,63}$")]
    passed: bool


class RulePackDiff(_Strict):
    """Value-free deterministic before/after Rule ID inventory."""

    base_rule_pack_version: Annotated[str, Field(min_length=1, max_length=32)]
    before_rule_ids: tuple[Annotated[str, Field(pattern=_RULE_ID_PATTERN)], ...]
    after_rule_ids: tuple[Annotated[str, Field(pattern=_RULE_ID_PATTERN)], ...]
    added_rule_ids: tuple[Annotated[str, Field(pattern=_RULE_ID_PATTERN)], ...]
    removed_rule_ids: tuple[Annotated[str, Field(pattern=_RULE_ID_PATTERN)], ...]
    changed_rule_ids: tuple[Annotated[str, Field(pattern=_RULE_ID_PATTERN)], ...] = ()

    @model_validator(mode="after")
    def diff_must_be_coherent(self) -> RulePackDiff:
        parse_interface_version(self.base_rule_pack_version)
        before = set(self.before_rule_ids)
        after = set(self.after_rule_ids)
        if self.before_rule_ids != tuple(sorted(before)):
            raise ValueError("before Rule IDs must be sorted and unique")
        if self.after_rule_ids != tuple(sorted(after)):
            raise ValueError("after Rule IDs must be sorted and unique")
        if self.added_rule_ids != tuple(sorted(after - before)):
            raise ValueError("added Rule IDs do not match the Rule Pack diff")
        if self.removed_rule_ids != tuple(sorted(before - after)):
            raise ValueError("removed Rule IDs do not match the Rule Pack diff")
        if self.changed_rule_ids != tuple(sorted(set(self.changed_rule_ids))):
            raise ValueError("changed Rule IDs must be sorted and unique")
        return self


class SemanticRulePromotionReport(_Strict):
    """Owner-reviewed, report-only staging decision."""

    format: Literal["agentsec-semantic-rule-promotion-report"] = (
        "agentsec-semantic-rule-promotion-report"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    proposal_id: Annotated[
        str, Field(pattern=r"^semantic-rule-proposal-sha256:[0-9a-f]{64}$")
    ]
    replay_report_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    implementation_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    implemented_rule_id: Annotated[str, Field(pattern=_RULE_ID_PATTERN)]
    checks: tuple[RulePromotionCheck, ...]
    rule_pack_diff: RulePackDiff
    status: RulePromotionStatus
    owner_id: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    approval_id: Annotated[str, Field(min_length=1, max_length=160)] | None = None
    approval_reason: Annotated[str, Field(min_length=1, max_length=512)] | None = None
    automatic_publication: Literal[False] = False
    rule_pack_mutated: Literal[False] = False
    finding_authority: Literal[False] = False
    policy_authority: Literal[False] = False
    ci_authority: Literal[False] = False
    hard_gate_authority: Literal[False] = False
    release_authority: Literal[False] = False

    @model_validator(mode="after")
    def report_must_be_coherent(self) -> SemanticRulePromotionReport:
        checks = tuple(item.check_id for item in self.checks)
        if checks != tuple(sorted(set(checks))):
            raise ValueError("Rule promotion checks must be sorted and unique")
        passed = all(item.passed for item in self.checks)
        if self.status is RulePromotionStatus.ELIGIBLE_FOR_STAGING and not passed:
            raise ValueError("eligible staging report requires all checks to pass")
        if self.status is RulePromotionStatus.STAGED and (
            not passed
            or not self.owner_id
            or not self.approval_id
            or not self.approval_reason
        ):
            raise ValueError(
                "staged report requires passed checks and owner approval rationale"
            )
        if self.status is RulePromotionStatus.REJECTED and passed:
            raise ValueError("rejected report cannot have all checks passing")
        if self.status is not RulePromotionStatus.REJECTED and (
            self.implemented_rule_id not in self.rule_pack_diff.added_rule_ids
        ):
            raise ValueError("eligible/staged Rule must appear as an added Rule ID")
        return self


class SemanticRulePromotionController:
    """Assess and stage a deterministic Rule implementation after review."""

    def assess(
        self,
        proposal: SemanticRuleCandidate,
        replay: RuleImplementationReplayReport,
        *,
        implemented_rule_id: str,
        implementation_sha256: str,
        base_rule_pack_version: str,
        base_rule_ids: tuple[str, ...],
    ) -> SemanticRulePromotionReport:
        if not isinstance(proposal, SemanticRuleCandidate):
            raise TypeError("Rule Candidate proposal is required")
        if not isinstance(replay, RuleImplementationReplayReport):
            raise TypeError("Rule replay report is required")
        if not isinstance(base_rule_ids, tuple):
            raise TypeError("base_rule_ids must be a tuple")
        if proposal.status is not RuleCandidateStatus.ACCEPTED_FOR_IMPLEMENTATION:
            raise ValueError(
                "Rule promotion requires an accepted implementation proposal"
            )
        if replay.proposal_id != proposal.proposal_id:
            raise ValueError("Rule replay report does not match the proposal")
        if not re.fullmatch(_RULE_ID_PATTERN, implemented_rule_id):
            raise ValueError("implemented Rule ID is invalid")
        if not re.fullmatch(_SHA256_PATTERN, implementation_sha256):
            raise ValueError("implementation_sha256 must be a lowercase SHA-256 digest")
        parse_interface_version(base_rule_pack_version)
        before = tuple(sorted(set(base_rule_ids)))
        checks = tuple(
            sorted(
                (
                    RulePromotionCheck(
                        check_id="proposal_accepted",
                        passed=True,
                    ),
                    RulePromotionCheck(
                        check_id="replay_report_bound",
                        passed=replay.proposal_id == proposal.proposal_id,
                    ),
                    RulePromotionCheck(
                        check_id="replay_no_failures",
                        passed=replay.metrics.failure_count == 0,
                    ),
                    RulePromotionCheck(
                        check_id="replay_zero_false_positive",
                        passed=replay.metrics.false_positive == 0,
                    ),
                    RulePromotionCheck(
                        check_id="replay_zero_false_negative",
                        passed=replay.metrics.false_negative == 0,
                    ),
                    RulePromotionCheck(
                        check_id="replay_evidence_binding",
                        passed=replay.metrics.evidence_binding_accuracy == 1,
                    ),
                    RulePromotionCheck(
                        check_id="replay_finding_bounds",
                        passed=replay.metrics.finding_bound_accuracy == 1,
                    ),
                    RulePromotionCheck(
                        check_id="replay_perfect_metrics",
                        passed=(
                            replay.metrics.precision == 1
                            and replay.metrics.recall == 1
                            and replay.metrics.f1 == 1
                        ),
                    ),
                    RulePromotionCheck(
                        check_id="rule_family_bound",
                        passed=implemented_rule_id.startswith(
                            proposal.proposed_rule_family.replace("_", "") + "-"
                        ),
                    ),
                    RulePromotionCheck(
                        check_id="rule_id_is_new",
                        passed=implemented_rule_id not in before,
                    ),
                ),
                key=lambda item: item.check_id,
            )
        )
        after = tuple(sorted(set(before) | {implemented_rule_id}))
        diff = RulePackDiff(
            base_rule_pack_version=base_rule_pack_version,
            before_rule_ids=before,
            after_rule_ids=after,
            added_rule_ids=tuple(sorted(set(after) - set(before))),
            removed_rule_ids=(),
            changed_rule_ids=(),
        )
        status = (
            RulePromotionStatus.ELIGIBLE_FOR_STAGING
            if all(item.passed for item in checks)
            else RulePromotionStatus.REJECTED
        )
        return SemanticRulePromotionReport(
            proposal_id=proposal.proposal_id,
            replay_report_sha256=_report_digest(replay),
            implementation_sha256=implementation_sha256,
            implemented_rule_id=implemented_rule_id,
            checks=checks,
            rule_pack_diff=diff,
            status=status,
        )

    def stage(
        self,
        report: SemanticRulePromotionReport,
        *,
        owner_id: str,
        approval_id: str,
        approval_reason: str,
    ) -> SemanticRulePromotionReport:
        if not isinstance(report, SemanticRulePromotionReport):
            raise TypeError("Rule promotion report is required")
        if report.status is not RulePromotionStatus.ELIGIBLE_FOR_STAGING:
            raise ValueError("only eligible reports can be staged")
        if (
            not owner_id.strip()
            or not approval_id.strip()
            or not approval_reason.strip()
        ):
            raise ValueError("owner approval requires owner, approval ID, and reason")
        return SemanticRulePromotionReport.model_validate(
            {
                **report.model_dump(mode="python"),
                "status": RulePromotionStatus.STAGED,
                "owner_id": owner_id.strip(),
                "approval_id": approval_id.strip(),
                "approval_reason": approval_reason.strip(),
            }
        )

    def reject(
        self,
        report: SemanticRulePromotionReport,
        *,
        owner_id: str,
        approval_id: str,
        approval_reason: str,
    ) -> SemanticRulePromotionReport:
        if not isinstance(report, SemanticRulePromotionReport):
            raise TypeError("Rule promotion report is required")
        if report.status is not RulePromotionStatus.ELIGIBLE_FOR_STAGING:
            raise ValueError("only eligible reports can be explicitly rejected")
        if (
            not owner_id.strip()
            or not approval_id.strip()
            or not approval_reason.strip()
        ):
            raise ValueError("rejection requires owner, approval ID, and reason")
        # Rejection is only a review disposition; keep the Rule Pack unchanged.
        checks = tuple(
            sorted(
                (
                    *report.checks,
                    RulePromotionCheck(check_id="owner_rejected", passed=False),
                ),
                key=lambda item: item.check_id,
            )
        )
        return SemanticRulePromotionReport.model_validate(
            {
                **report.model_dump(mode="python"),
                "status": RulePromotionStatus.REJECTED,
                "checks": checks,
                "owner_id": owner_id.strip(),
                "approval_id": approval_id.strip(),
                "approval_reason": approval_reason.strip(),
            }
        )


def _report_digest(report: BaseModel) -> str:
    return hashlib.sha256(
        json.dumps(
            report.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()


__all__ = [
    "SEMANTIC_RULE_PACK_STAGING_VERSION",
    "SEMANTIC_RULE_PROMOTION_VERSION",
    "RulePackDiff",
    "RulePromotionCheck",
    "RulePromotionStatus",
    "SemanticRulePromotionController",
    "SemanticRulePromotionReport",
]
