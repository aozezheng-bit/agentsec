"""Tests for AgentSec version sources and compatibility policy."""

from __future__ import annotations

from importlib.metadata import version

import pytest

import agentsec
from agentsec.versioning import (
    AGENT_MANIFEST_SCHEMA_VERSION,
    ASSESSMENT_OUTPUT_VERSION,
    BASELINE_SCHEMA_VERSION,
    CALIBRATION_CASE_SCHEMA_VERSION,
    CAPABILITY_ASSESSMENT_OUTPUT_VERSION,
    CAPABILITY_CHANGE_IMPACT_OUTPUT_VERSION,
    CAPABILITY_CI_POLICY_SCHEMA_VERSION,
    CAPABILITY_CI_REPORT_OUTPUT_VERSION,
    CAPABILITY_DIFF_SCHEMA_VERSION,
    CAPABILITY_RISK_MODEL_VERSION,
    CAPABILITY_RULE_PACK_VERSION,
    CAPABILITY_SHADOW_GATE_VERSION,
    CONFIG_SCHEMA_VERSION,
    CVSS_HARD_GATE_VERSION,
    DIFF_OUTPUT_VERSION,
    DOMAIN_SCHEMA_VERSION,
    FAIL_ON_POLICY_VERSION,
    FAIL_ON_REPORT_OUTPUT_VERSION,
    ORGANIZATION_POLICY_REPORT_OUTPUT_VERSION,
    ORGANIZATION_POLICY_SCHEMA_VERSION,
    PACKAGE_VERSION,
    QUALIFICATION_REGISTRY_SCHEMA_VERSION,
    RISK_MODEL_VERSION,
    RULE_PACK_VERSION,
    SARIF_REPORTER_VERSION,
    InterfaceVersion,
    can_read_interface_version,
    current_versions,
    parse_interface_version,
)


def test_package_metadata_uses_the_central_version() -> None:
    """Source, import, and installed distribution versions do not drift."""

    assert agentsec.__version__ == PACKAGE_VERSION
    assert version("agentsec") == PACKAGE_VERSION


def test_current_versions_returns_the_complete_vector() -> None:
    """Reports can capture all independently evolving identifiers."""

    versions = current_versions()

    assert versions.package == PACKAGE_VERSION
    assert PACKAGE_VERSION == "0.4.0"
    assert versions.config_schema == CONFIG_SCHEMA_VERSION
    assert versions.domain_schema == DOMAIN_SCHEMA_VERSION
    assert versions.agent_manifest_schema == AGENT_MANIFEST_SCHEMA_VERSION
    assert AGENT_MANIFEST_SCHEMA_VERSION == "0.3.0"
    assert versions.capability_diff_schema == CAPABILITY_DIFF_SCHEMA_VERSION
    assert CAPABILITY_DIFF_SCHEMA_VERSION == "0.1.0"
    assert versions.capability_rule_pack == CAPABILITY_RULE_PACK_VERSION
    assert CAPABILITY_RULE_PACK_VERSION == "0.2.0"
    assert versions.capability_risk_model == CAPABILITY_RISK_MODEL_VERSION
    assert CAPABILITY_RISK_MODEL_VERSION == "0.1.0"
    assert versions.capability_assessment_output == CAPABILITY_ASSESSMENT_OUTPUT_VERSION
    assert CAPABILITY_ASSESSMENT_OUTPUT_VERSION == "0.2.0"
    assert (
        versions.capability_change_impact_output
        == CAPABILITY_CHANGE_IMPACT_OUTPUT_VERSION
    )
    assert CAPABILITY_CHANGE_IMPACT_OUTPUT_VERSION == "0.1.0"
    assert CALIBRATION_CASE_SCHEMA_VERSION == "0.1.0"
    assert versions.baseline_schema == BASELINE_SCHEMA_VERSION
    assert versions.diff_output == DIFF_OUTPUT_VERSION
    assert versions.assessment_output == ASSESSMENT_OUTPUT_VERSION
    assert ASSESSMENT_OUTPUT_VERSION == "0.7.0"
    assert versions.rule_pack == RULE_PACK_VERSION
    assert RULE_PACK_VERSION == "0.3.1"
    assert versions.risk_model == RISK_MODEL_VERSION
    assert RISK_MODEL_VERSION == "0.4.0"
    assert versions.cvss_hard_gate == CVSS_HARD_GATE_VERSION
    assert CVSS_HARD_GATE_VERSION == "0.1.0"
    assert versions.capability_shadow_gate == CAPABILITY_SHADOW_GATE_VERSION
    assert CAPABILITY_SHADOW_GATE_VERSION == "0.1.0"
    assert SARIF_REPORTER_VERSION == "0.4.0"
    assert ORGANIZATION_POLICY_SCHEMA_VERSION == "0.3.0"
    assert ORGANIZATION_POLICY_REPORT_OUTPUT_VERSION == "0.3.0"
    assert CAPABILITY_CI_POLICY_SCHEMA_VERSION == "0.2.0"
    assert QUALIFICATION_REGISTRY_SCHEMA_VERSION == "0.1.0"
    assert CAPABILITY_CI_REPORT_OUTPUT_VERSION == "0.5.0"
    assert FAIL_ON_POLICY_VERSION == "0.1.0"
    assert FAIL_ON_REPORT_OUTPUT_VERSION == "0.1.0"


def test_parse_interface_version_requires_exact_semver() -> None:
    """Serialized interfaces reject ambiguous or package-style versions."""

    assert parse_interface_version("1.2.3") == InterfaceVersion(1, 2, 3)

    for invalid in ("1", "1.2", "01.2.3", "1.2.3.dev0", "v1.2.3"):
        with pytest.raises(ValueError):
            parse_interface_version(invalid)


@pytest.mark.parametrize(
    ("produced", "supported", "expected"),
    [
        ("0.1.0", "0.1.5", True),
        ("0.1.9", "0.2.0", False),
        ("0.2.0", "0.1.9", False),
        ("1.1.0", "1.3.0", True),
        ("1.4.0", "1.3.9", False),
        ("1.0.0", "2.0.0", False),
    ],
)
def test_interface_compatibility_policy(
    produced: str, supported: str, expected: bool
) -> None:
    """Compatibility follows the documented pre-1.0 and stable rules."""

    assert (
        can_read_interface_version(produced=produced, supported=supported) is expected
    )
