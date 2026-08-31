"""Central version identifiers and interface compatibility rules."""

from __future__ import annotations

import re
from dataclasses import dataclass

PACKAGE_VERSION = "0.4.0"
CONFIG_SCHEMA_VERSION = "0.1.0"
DOMAIN_SCHEMA_VERSION = "0.8.0"
AGENT_MANIFEST_SCHEMA_VERSION = "0.3.0"
CAPABILITY_DIFF_SCHEMA_VERSION = "0.1.0"
CAPABILITY_RULE_PACK_VERSION = "0.2.0"
CAPABILITY_RISK_MODEL_VERSION = "0.1.0"
CAPABILITY_ASSESSMENT_OUTPUT_VERSION = "0.2.0"
CAPABILITY_SHADOW_GATE_VERSION = "0.1.0"
CAPABILITY_CHANGE_IMPACT_OUTPUT_VERSION = "0.1.0"
AGENTIC_FACTOR_MODEL_VERSION = "0.1.0"
THREAT_MITIGATION_MODEL_VERSION = "0.1.0"
TECHNICAL_SCORE_MODEL_VERSION = "0.1.0"
DRIFT_SCORE_MODEL_VERSION = "0.1.0"
GOVERNANCE_SCORE_MODEL_VERSION = "0.1.0"
OVERALL_SCORE_MODEL_VERSION = "0.1.0"
SCORING_REPLAY_MODEL_VERSION = "0.1.0"
AGENTIC_ASSESSMENT_OUTPUT_VERSION = "0.1.0"
SCORE_CONTEXT_SCHEMA_VERSION = "0.1.0"
RULE_SCORE_CALIBRATION_OUTPUT_VERSION = "0.1.0"
SARIF_REPORTER_VERSION = "0.4.0"
FAIL_ON_POLICY_VERSION = "0.1.0"
FAIL_ON_REPORT_OUTPUT_VERSION = "0.1.0"
ORGANIZATION_POLICY_SCHEMA_VERSION = "0.3.0"
ORGANIZATION_POLICY_REPORT_OUTPUT_VERSION = "0.3.0"
CAPABILITY_CI_POLICY_SCHEMA_VERSION = "0.2.0"
QUALIFICATION_REGISTRY_SCHEMA_VERSION = "0.1.0"
CAPABILITY_CI_REPORT_OUTPUT_VERSION = "0.5.0"
CALIBRATION_CASE_SCHEMA_VERSION = "0.1.0"
CALIBRATION_REPORT_OUTPUT_VERSION = "0.1.0"
CALIBRATION_CONFIDENCE_REVIEW_SCHEMA_VERSION = "0.1.0"
CALIBRATION_CONFIDENCE_REPORT_OUTPUT_VERSION = "0.1.0"
CALIBRATION_ADJUDICATION_REVIEW_SCHEMA_VERSION = "0.1.0"
CALIBRATION_ADJUDICATION_RESOLUTION_SCHEMA_VERSION = "0.1.0"
CALIBRATION_ADJUDICATION_REPORT_OUTPUT_VERSION = "0.3.0"
BASELINE_SCHEMA_VERSION = "0.1.0"
DIFF_OUTPUT_VERSION = "0.1.0"
ASSESSMENT_OUTPUT_VERSION = "0.7.0"
RULE_PACK_VERSION = "0.3.1"
RISK_MODEL_VERSION = "0.4.0"
CVSS_HARD_GATE_VERSION = "0.1.0"

_INTERFACE_VERSION_PATTERN = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)$"
)


@dataclass(frozen=True, slots=True)
class InterfaceVersion:
    """Parsed semantic version used by serialized AgentSec interfaces."""

    major: int
    minor: int
    patch: int


@dataclass(frozen=True, slots=True)
class VersionSet:
    """Version identifiers that must accompany reproducible assessments."""

    package: str
    config_schema: str
    domain_schema: str
    agent_manifest_schema: str
    capability_diff_schema: str
    capability_rule_pack: str
    capability_risk_model: str
    capability_assessment_output: str
    capability_change_impact_output: str
    baseline_schema: str
    diff_output: str
    assessment_output: str
    rule_pack: str
    risk_model: str
    cvss_hard_gate: str
    capability_shadow_gate: str


def current_versions() -> VersionSet:
    """Return the complete version vector for the running source tree."""

    return VersionSet(
        package=PACKAGE_VERSION,
        config_schema=CONFIG_SCHEMA_VERSION,
        domain_schema=DOMAIN_SCHEMA_VERSION,
        agent_manifest_schema=AGENT_MANIFEST_SCHEMA_VERSION,
        capability_diff_schema=CAPABILITY_DIFF_SCHEMA_VERSION,
        capability_rule_pack=CAPABILITY_RULE_PACK_VERSION,
        capability_risk_model=CAPABILITY_RISK_MODEL_VERSION,
        capability_assessment_output=CAPABILITY_ASSESSMENT_OUTPUT_VERSION,
        capability_change_impact_output=CAPABILITY_CHANGE_IMPACT_OUTPUT_VERSION,
        baseline_schema=BASELINE_SCHEMA_VERSION,
        diff_output=DIFF_OUTPUT_VERSION,
        assessment_output=ASSESSMENT_OUTPUT_VERSION,
        rule_pack=RULE_PACK_VERSION,
        risk_model=RISK_MODEL_VERSION,
        cvss_hard_gate=CVSS_HARD_GATE_VERSION,
        capability_shadow_gate=CAPABILITY_SHADOW_GATE_VERSION,
    )


def parse_interface_version(value: str) -> InterfaceVersion:
    """Parse an exact ``MAJOR.MINOR.PATCH`` interface version."""

    match = _INTERFACE_VERSION_PATTERN.fullmatch(value)
    if match is None:
        raise ValueError("interface version must use MAJOR.MINOR.PATCH")

    return InterfaceVersion(
        major=int(match.group("major")),
        minor=int(match.group("minor")),
        patch=int(match.group("patch")),
    )


def can_read_interface_version(*, produced: str, supported: str) -> bool:
    """Return whether a consumer can read a produced interface version.

    Before 1.0, a minor release may be breaking, so both major and minor must
    match. At 1.0 and later, a consumer may read the same major version up to
    its own supported minor version. Patch releases never change structure.
    """

    produced_version = parse_interface_version(produced)
    supported_version = parse_interface_version(supported)

    if produced_version.major != supported_version.major:
        return False
    if produced_version.major == 0:
        return produced_version.minor == supported_version.minor

    return produced_version.minor <= supported_version.minor
