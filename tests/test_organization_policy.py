"""P2-27 organization-level YAML Policy tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentsec.cli import ExitCode, app
from agentsec.organization_policy import (
    OrganizationPolicyError,
    load_organization_policy,
)
from agentsec.reporting import (
    OrganizationAssessmentValidationError,
    decode_organization_assessment_json,
    decode_sarif_json,
    export_organization_assessment_json_schema,
    export_organization_policy_json_schema,
)
from agentsec.versioning import (
    ORGANIZATION_POLICY_REPORT_OUTPUT_VERSION,
    ORGANIZATION_POLICY_SCHEMA_VERSION,
)

runner = CliRunner()
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RISKY_SCAN = REPOSITORY_ROOT / "demos" / "release-agent" / "risky-drift"
MALFORMED_SCAN = REPOSITORY_ROOT / "demos" / "release-agent" / "malformed"
RISKY_CAPABILITY = REPOSITORY_ROOT / "demos" / "capability-drift-agent" / "risky-drift"


def _policy_text(
    *,
    enabled: bool = True,
    mode: str = "enforce",
    threshold: str | None = "high",
    rule_ids: tuple[str, ...] = (),
    gates: tuple[str, ...] = (),
    qualification: bool = True,
) -> str:
    fail_on = "null" if threshold is None else threshold
    rules = "[]" if not rule_ids else "[" + ", ".join(rule_ids) + "]"
    qualified_gates = "[]" if not gates else "[" + ", ".join(gates) + "]"
    qualification_block = ""
    if gates and qualification:
        qualification_block = (
            "  qualification:\n"
            "    registry_path: evidence/qualified-gate-registry.yaml\n"
            f'    registry_sha256: "{"0" * 64}"\n'
        )
    return f"""format: agentsec-organization-policy
schema_version: "0.3.0"
policy_id: test-org-policy
policy_version: "2026.08.25"
enabled: {str(enabled).lower()}
enforcement_mode: {mode}
scan:
  fail_on: {fail_on}
  blocking_rule_ids: {rules}
capability:
  qualified_gates: {qualified_gates}
{qualification_block}coverage:
  require_complete: true
  require_unknown_free: true
safety:
  allow_llm_authority: false
  allow_runtime_unverified_authority: false
waivers: []
"""


def _write_policy(
    path: Path,
    *,
    enabled: bool = True,
    mode: str = "enforce",
    threshold: str | None = "high",
    rule_ids: tuple[str, ...] = (),
    gates: tuple[str, ...] = (),
    qualification: bool = True,
) -> Path:
    path.write_text(
        _policy_text(
            enabled=enabled,
            mode=mode,
            threshold=threshold,
            rule_ids=rule_ids,
            gates=gates,
            qualification=qualification,
        ),
        encoding="utf-8",
    )
    return path


def test_yaml_policy_loads_normalizes_and_records_provenance(tmp_path: Path) -> None:
    path = _write_policy(
        tmp_path / "organization-policy.yaml",
        rule_ids=("MD-SECRET-001", "MD-EXEC-001"),
        gates=("HG-CAPCHAIN-001",),
    )

    loaded = load_organization_policy(path)

    assert loaded.policy.schema_version == ORGANIZATION_POLICY_SCHEMA_VERSION
    assert loaded.policy.policy_id == "test-org-policy"
    assert loaded.policy.scan.fail_on == "high"
    assert loaded.policy.scan.blocking_rule_ids == (
        "MD-EXEC-001",
        "MD-SECRET-001",
    )
    assert loaded.policy.capability.qualified_gates == ("HG-CAPCHAIN-001",)
    assert loaded.path == path.resolve()
    assert len(loaded.sha256) == 64
    assert loaded.size_bytes == path.stat().st_size


@pytest.mark.parametrize(
    "content",
    [
        _policy_text().replace(
            "policy_id: test-org-policy",
            "policy_id: first\npolicy_id: second",
        ),
        _policy_text() + "unexpected: true\n",
        _policy_text(rule_ids=("MD-UNKNOWN-001",)),
        _policy_text(gates=("HG-UNKNOWN-001",)),
        _policy_text().replace(
            "scan:\n",
            "shared: &shared {fail_on: high}\nscan: *shared\nignored:\n",
        ),
        _policy_text().replace(
            "policy_id: test-org-policy",
            "policy_id: !!python/object:unsafe test-org-policy",
        ),
    ],
)
def test_yaml_policy_rejects_unsafe_or_unknown_content(
    tmp_path: Path,
    content: str,
) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(OrganizationPolicyError):
        load_organization_policy(path)


def test_yaml_policy_rejects_symlink_and_non_yaml_suffix(tmp_path: Path) -> None:
    policy = _write_policy(tmp_path / "policy.yaml")
    link = tmp_path / "link.yaml"
    link.symlink_to(policy)

    with pytest.raises(OrganizationPolicyError):
        load_organization_policy(link)

    json_path = tmp_path / "policy.json"
    json_path.write_text(_policy_text(), encoding="utf-8")
    with pytest.raises(OrganizationPolicyError):
        load_organization_policy(json_path)


def test_scan_organization_policy_blocks_only_configured_rules(tmp_path: Path) -> None:
    blocking = _write_policy(
        tmp_path / "blocking.yaml",
        rule_ids=("MD-EXEC-001",),
    )
    non_matching = _write_policy(
        tmp_path / "non-matching.yaml",
        rule_ids=("MD-NET-001",),
    )

    blocked = runner.invoke(
        app,
        [
            "scan",
            str(RISKY_SCAN),
            "--format",
            "json",
            "--policy",
            str(blocking),
        ],
    )
    allowed = runner.invoke(
        app,
        [
            "scan",
            str(RISKY_SCAN),
            "--format",
            "json",
            "--policy",
            str(non_matching),
        ],
    )

    assert blocked.exit_code == ExitCode.RISK_THRESHOLD_EXCEEDED
    blocked_report = decode_organization_assessment_json(blocked.stdout)
    assert blocked_report.decision.decision == "block"
    assert blocked_report.decision.matched_rule_ids == ("MD-EXEC-001",)
    assert len(blocked_report.decision.matched_finding_ids) == 1
    assert allowed.exit_code == ExitCode.SUCCESS
    allowed_report = decode_organization_assessment_json(allowed.stdout)
    assert allowed_report.decision.decision == "allow"
    assert allowed_report.decision.matched_finding_ids == ()


def test_scan_report_only_organization_policy_never_blocks_matches(
    tmp_path: Path,
) -> None:
    policy = _write_policy(
        tmp_path / "report-only.yaml",
        enabled=True,
        mode="report_only",
        rule_ids=("MD-EXEC-001",),
    )

    result = runner.invoke(
        app,
        ["scan", str(RISKY_SCAN), "--policy", str(policy)],
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert "AgentSec Organization Policy Decision" in result.stdout
    assert "Decision: ALLOW" in result.stdout
    assert "Matched findings: 1" in result.stdout
    assert "Mode: REPORT_ONLY" in result.stdout


def test_scan_policy_conflicts_with_cli_fail_on_before_analysis(tmp_path: Path) -> None:
    policy = _write_policy(tmp_path / "policy.yaml")

    result = runner.invoke(
        app,
        [
            "scan",
            str(RISKY_SCAN),
            "--policy",
            str(policy),
            "--fail-on",
            "high",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION_ERROR
    assert result.stdout == ""
    assert "mutually exclusive" in result.stderr


def test_scan_organization_policy_incomplete_coverage_returns_two(
    tmp_path: Path,
) -> None:
    policy = _write_policy(tmp_path / "policy.yaml")

    result = runner.invoke(
        app,
        [
            "scan",
            str(MALFORMED_SCAN),
            "--format",
            "json",
            "--policy",
            str(policy),
        ],
    )

    assert result.exit_code == ExitCode.SCAN_INCOMPLETE
    report = decode_organization_assessment_json(result.stdout)
    assert report.decision.decision == "incomplete"
    assert report.decision.blocks is False
    assert report.assessment_report.status == "incomplete"


def test_organization_policy_sarif_records_policy_rule_scope_and_decision(
    tmp_path: Path,
) -> None:
    policy = _write_policy(
        tmp_path / "policy.yaml",
        rule_ids=("MD-EXEC-001",),
    )

    result = runner.invoke(
        app,
        [
            "scan",
            str(RISKY_SCAN),
            "--format",
            "sarif",
            "--policy",
            str(policy),
        ],
    )

    assert result.exit_code == ExitCode.RISK_THRESHOLD_EXCEEDED
    run = decode_sarif_json(result.stdout).runs[0]
    assert run.properties["agentsecEnforcementMode"] == "organization_policy"
    assert run.properties["agentsecOrganizationPolicyId"] == "test-org-policy"
    assert run.properties["agentsecOrganizationPolicyVersion"] == "2026.08.25"
    assert run.properties["agentsecOrganizationPolicyRuleIds"] == ["MD-EXEC-001"]
    assert run.properties["agentsecOrganizationPolicyDecision"] == "block"
    assert (
        sum(
            item.properties.get("agentsecOrganizationPolicyMatched") is True
            for item in run.results
        )
        == 1
    )


def test_organization_json_rejects_tampered_decision(tmp_path: Path) -> None:
    policy = _write_policy(tmp_path / "policy.yaml", rule_ids=("MD-EXEC-001",))
    result = runner.invoke(
        app,
        [
            "scan",
            str(RISKY_SCAN),
            "--format",
            "json",
            "--policy",
            str(policy),
        ],
    )
    payload = json.loads(result.stdout)
    payload["decision"]["decision"] = "allow"
    payload["decision"]["blocks"] = False
    payload["decision"]["exit_code"] = 0

    with pytest.raises(OrganizationAssessmentValidationError):
        decode_organization_assessment_json(json.dumps(payload))


def test_capability_enforce_organization_yaml_gates_use_registry_binding() -> None:
    policy = REPOSITORY_ROOT / "policies" / "organization-policy-enforce-example.yaml"

    result = runner.invoke(
        app,
        [
            "capability",
            "enforce",
            str(RISKY_CAPABILITY),
            "--agent-id",
            "capability-drift-agent",
            "--policy",
            str(policy),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == ExitCode.SCAN_INCOMPLETE
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "0.5.0"
    assert payload["decision"] == "incomplete"
    assert payload["policy"]["source_format"] == "agentsec-organization-policy"
    assert payload["policy"]["source_schema_version"] == "0.3.0"
    assert len(payload["policy"]["source_sha256"]) == 64
    assert payload["qualification_registry"]["present"] is True
    assert payload["errors"] == ["policy requires unknown-free evidence"]


def test_capability_enforce_organization_gates_without_binding_fail_closed(
    tmp_path: Path,
) -> None:
    policy = _write_policy(
        tmp_path / "policy.yaml", gates=("HG-CAPCHAIN-001",), qualification=False
    )
    result = runner.invoke(
        app,
        [
            "capability",
            "enforce",
            str(RISKY_CAPABILITY),
            "--agent-id",
            "capability-drift-agent",
            "--policy",
            str(policy),
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION_ERROR
    assert "policy error" in result.stderr.lower()


def test_organization_policy_and_report_schemas_are_frozen(tmp_path: Path) -> None:
    generated_policy = export_organization_policy_json_schema(tmp_path / "policy")
    generated_report = export_organization_assessment_json_schema(tmp_path / "report")

    assert (
        generated_policy.read_bytes()
        == (
            REPOSITORY_ROOT / "schemas" / "policy" / "organization-policy.schema.json"
        ).read_bytes()
    )
    assert (
        generated_report.read_bytes()
        == (
            REPOSITORY_ROOT
            / "schemas"
            / "policy"
            / "organization-assessment-report.schema.json"
        ).read_bytes()
    )


def test_organization_policy_versions_are_independent() -> None:
    assert ORGANIZATION_POLICY_SCHEMA_VERSION == "0.3.0"
    assert ORGANIZATION_POLICY_REPORT_OUTPUT_VERSION == "0.3.0"


def test_active_rule_waiver_allows_without_hiding_matching_finding(
    tmp_path: Path,
) -> None:
    policy = _policy_text().replace(
        "waivers: []",
        """waivers:
  - waiver_id: waiver-exec-demo
    owner: security-team
    reason: Temporary reviewed demo exception
    expires_on: 2030-12-31
    rule_ids: [MD-EXEC-001]
""",
    )
    path = tmp_path / "waiver.yaml"
    path.write_text(policy, encoding="utf-8")
    result = runner.invoke(
        app,
        ["scan", str(RISKY_SCAN), "--format", "json", "--policy", str(path)],
    )
    assert result.exit_code == ExitCode.RISK_THRESHOLD_EXCEEDED
    report = decode_organization_assessment_json(result.stdout)
    assert "waiver-exec-demo" in report.decision.applied_waiver_ids
    assert len(report.decision.waived_finding_ids) == 1
    assert len(report.decision.blocking_finding_ids) == 3
    assert len(report.assessment_report.assessment.findings) == 10


def test_waiver_can_remove_only_block_and_expiry_reactivates_it(
    tmp_path: Path,
) -> None:
    base = _policy_text(rule_ids=("MD-EXEC-001",))
    active = base.replace(
        "waivers: []",
        """waivers:
  - waiver_id: waiver-active
    owner: security-team
    reason: Temporary reviewed exception
    expires_on: 2030-12-31
    rule_ids: [MD-EXEC-001]
""",
    )
    expired = active.replace("waiver-active", "waiver-expired").replace(
        "2030-12-31", "2026-08-24"
    )
    active_path = tmp_path / "active.yaml"
    expired_path = tmp_path / "expired.yaml"
    active_path.write_text(active, encoding="utf-8")
    expired_path.write_text(expired, encoding="utf-8")
    active_result = runner.invoke(
        app,
        ["scan", str(RISKY_SCAN), "--format", "json", "--policy", str(active_path)],
    )
    expired_result = runner.invoke(
        app,
        ["scan", str(RISKY_SCAN), "--format", "json", "--policy", str(expired_path)],
    )
    assert active_result.exit_code == ExitCode.SUCCESS
    active_report = decode_organization_assessment_json(active_result.stdout)
    assert active_report.decision.blocking_finding_ids == ()
    assert active_report.decision.waived_finding_ids
    assert expired_result.exit_code == ExitCode.RISK_THRESHOLD_EXCEEDED
    expired_report = decode_organization_assessment_json(expired_result.stdout)
    assert expired_report.decision.expired_waiver_ids == ("waiver-expired",)
    assert expired_report.decision.waived_finding_ids == ()


def test_waiver_requires_owner_reason_expiry_and_scope(tmp_path: Path) -> None:
    invalid = _policy_text().replace(
        "waivers: []",
        """waivers:
  - waiver_id: invalid-waiver
    owner: security-team
    reason: Temporary reviewed exception
    expires_on: 2030-12-31
""",
    )
    path = tmp_path / "invalid-waiver.yaml"
    path.write_text(invalid, encoding="utf-8")
    with pytest.raises(OrganizationPolicyError):
        load_organization_policy(path)
