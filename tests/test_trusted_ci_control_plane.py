"""P2-EXIT-02 Trusted CI Control Plane tests."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from agentsec.cli import ExitCode, app

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SAFE_PROJECT = REPOSITORY_ROOT / "testdata" / "safe" / "minimal-agent"
RISKY_SCAN = REPOSITORY_ROOT / "demos" / "release-agent" / "risky-drift"
BASELINE_CAPABILITY = REPOSITORY_ROOT / "demos" / "capability-drift-agent" / "baseline"
REGISTRY_PATH = (
    REPOSITORY_ROOT
    / "calibration"
    / "p2-15a-capchain-40"
    / "human-evidence"
    / "qualified-gate-registry.yaml"
)

runner = CliRunner()


REPORT_NAME = "hg-capchain-001-qualification-report-v2.json"
REPORT_PATH = REGISTRY_PATH.parent / REPORT_NAME


def _org_policy_text(
    *,
    gates: tuple[str, ...] = (),
    qualification: bool = True,
    registry_rel: str = "evidence/qualified-gate-registry.yaml",
    registry_sha256: str = "",
    unknown_free: bool = True,
    waivers: str = "[]",
    enabled: bool = True,
    mode: str = "report_only",
    threshold: str | None = None,
    rule_ids: tuple[str, ...] = (),
) -> str:
    rules = "[]" if not rule_ids else "[" + ", ".join(rule_ids) + "]"
    gate_lines = "\n".join(f"    - {gate}" for gate in gates)
    capability = f"""capability:
  qualified_gates:
{gate_lines}
"""
    if gates and qualification:
        capability += (
            "  qualification:\n"
            f"    registry_path: {registry_rel}\n"
            f'    registry_sha256: "{registry_sha256}"\n'
        )
    elif not gates:
        capability = "capability:\n  qualified_gates: []\n"
    fail_on = "null" if threshold is None else threshold
    return f"""format: agentsec-organization-policy
schema_version: "0.3.0"
policy_id: trusted-ci-test
policy_version: "2026.08.25"
enabled: {str(enabled).lower()}
enforcement_mode: {mode}
scan:
  fail_on: {fail_on}
  blocking_rule_ids: {rules}
{capability}coverage:
  require_complete: true
  require_unknown_free: {str(unknown_free).lower()}
safety:
  allow_llm_authority: false
  allow_runtime_unverified_authority: false
waivers: {waivers}
"""


def _write_policy(directory: Path, text: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "organization-policy.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _trust_setup(tmp_path: Path, **policy_options: Any) -> tuple[Path, Path]:
    """Create a Mode-A trust root carrying its policy and evidence bundle."""

    trust_root = tmp_path / "security-policy-repo"
    evidence_dir = trust_root / "evidence"
    evidence_dir.mkdir(parents=True)
    shutil.copy(REGISTRY_PATH, evidence_dir / REGISTRY_PATH.name)
    shutil.copy(REPORT_PATH, evidence_dir / REPORT_NAME)
    registry_digest = hashlib.sha256(
        (evidence_dir / REGISTRY_PATH.name).read_bytes()
    ).hexdigest()
    text = _org_policy_text(registry_sha256=registry_digest, **policy_options)
    policy = _write_policy(trust_root, text)
    return trust_root, policy


def _scan_args(project: Path, policy_argument: str, **options: str) -> list[str]:
    arguments = [
        "scan",
        str(project),
        "--policy",
        policy_argument,
        "--format",
        "json",
    ]
    for name, value in options.items():
        arguments.extend([f"--{name.replace('_', '-')}", value])
    return arguments


def test_trust_root_resolves_policy_from_separate_checkout(tmp_path: Path) -> None:
    trust_root, _ = _trust_setup(tmp_path)
    result = runner.invoke(
        app,
        _scan_args(
            SAFE_PROJECT, "organization-policy.yaml", trust_root=str(trust_root)
        ),
    )
    assert result.exit_code == ExitCode.SUCCESS, result.stderr
    payload = json.loads(result.stdout)
    assert payload["format_version"] == "0.3.0"
    assert payload["trust"]["trust_mode"] == "external_trust_root"
    assert payload["trust"]["policy_digest_pinned"] is False


def test_trust_root_rejects_absolute_and_escaping_policy_paths(
    tmp_path: Path,
) -> None:
    trust_root, policy = _trust_setup(tmp_path)

    absolute = runner.invoke(
        app, _scan_args(SAFE_PROJECT, str(policy), trust_root=str(trust_root))
    )
    assert absolute.exit_code == ExitCode.CONFIGURATION_ERROR

    escape = runner.invoke(
        app,
        _scan_args(SAFE_PROJECT, "../escape-policy.yaml", trust_root=str(trust_root)),
    )
    assert escape.exit_code == ExitCode.CONFIGURATION_ERROR


def test_trust_root_rejects_symlinked_file_and_missing_roots(
    tmp_path: Path,
) -> None:
    trust_root, _ = _trust_setup(tmp_path)

    link_root = tmp_path / "linked-root"
    os.symlink(trust_root, link_root)
    linked = runner.invoke(
        app,
        _scan_args(SAFE_PROJECT, "organization-policy.yaml", trust_root=str(link_root)),
    )
    assert linked.exit_code == ExitCode.CONFIGURATION_ERROR

    file_root = tmp_path / "file-root"
    file_root.write_text("not a directory", encoding="utf-8")
    file_based = runner.invoke(
        app,
        _scan_args(SAFE_PROJECT, "organization-policy.yaml", trust_root=str(file_root)),
    )
    assert file_based.exit_code == ExitCode.CONFIGURATION_ERROR

    missing = runner.invoke(
        app,
        _scan_args(
            SAFE_PROJECT,
            "organization-policy.yaml",
            trust_root=str(tmp_path / "absent"),
        ),
    )
    assert missing.exit_code == ExitCode.CONFIGURATION_ERROR


def test_trust_options_require_explicit_policy(tmp_path: Path) -> None:
    trust_root, _ = _trust_setup(tmp_path)

    root_only = runner.invoke(
        app, ["scan", str(SAFE_PROJECT), "--trust-root", str(trust_root)]
    )
    assert root_only.exit_code == ExitCode.CONFIGURATION_ERROR

    digest_only = runner.invoke(
        app,
        ["scan", str(SAFE_PROJECT), "--expect-policy-sha256", "0" * 64],
    )
    assert digest_only.exit_code == ExitCode.CONFIGURATION_ERROR


def test_policy_digest_pin_verified_and_reported(tmp_path: Path) -> None:
    trust_root, policy = _trust_setup(tmp_path)
    digest = hashlib.sha256(policy.read_bytes()).hexdigest()

    result = runner.invoke(
        app,
        _scan_args(
            SAFE_PROJECT,
            "organization-policy.yaml",
            trust_root=str(trust_root),
            expect_policy_sha256=digest,
        ),
    )
    assert result.exit_code == ExitCode.SUCCESS, result.stderr
    payload = json.loads(result.stdout)
    trust = payload["trust"]
    assert trust["policy_digest_pinned"] is True
    assert trust["policy_digest_verified"] is True
    assert trust["expected_policy_sha256"] == digest


def test_policy_digest_mismatch_fails_closed_before_decision(
    tmp_path: Path,
) -> None:
    trust_root, _ = _trust_setup(
        tmp_path, enabled=True, mode="enforce", threshold="high"
    )
    result = runner.invoke(
        app,
        _scan_args(
            RISKY_SCAN,
            "organization-policy.yaml",
            trust_root=str(trust_root),
            expect_policy_sha256="f" * 64,
        ),
    )
    assert result.exit_code == ExitCode.CONFIGURATION_ERROR
    assert "digest" in result.stderr.lower()


def test_invalid_digest_pin_syntax_fails_closed(tmp_path: Path) -> None:
    trust_root, _ = _trust_setup(tmp_path)
    result = runner.invoke(
        app,
        _scan_args(
            SAFE_PROJECT,
            "organization-policy.yaml",
            trust_root=str(trust_root),
            expect_policy_sha256="not-a-digest",
        ),
    )
    assert result.exit_code == ExitCode.CONFIGURATION_ERROR


def test_waiver_inherits_policy_digest_pin(tmp_path: Path) -> None:
    waiver = {
        "waiver_id": "waiver-trusted-exec",
        "owner": "security-team",
        "reason": "Reviewed trusted CI demonstration exception",
        "expires_on": "2026-12-31",
        "finding_ids": [],
        "rule_ids": ["MD-EXEC-001"],
        "gate_ids": [],
    }
    trust_root, policy = _trust_setup(
        tmp_path,
        enabled=True,
        mode="enforce",
        threshold="high",
        waivers=json.dumps([waiver]),
        rule_ids=("MD-EXEC-001",),
    )
    digest = hashlib.sha256(policy.read_bytes()).hexdigest()

    pinned = runner.invoke(
        app,
        _scan_args(
            RISKY_SCAN,
            "organization-policy.yaml",
            trust_root=str(trust_root),
            expect_policy_sha256=digest,
        ),
    )
    assert pinned.exit_code == ExitCode.SUCCESS, pinned.stderr
    payload = json.loads(pinned.stdout)
    assert payload["decision"]["applied_waiver_ids"] == ["waiver-trusted-exec"]
    assert payload["trust"]["policy_digest_verified"] is True

    unpinned_match = runner.invoke(
        app,
        _scan_args(
            RISKY_SCAN,
            "organization-policy.yaml",
            trust_root=str(trust_root),
            expect_policy_sha256="a" * 64,
        ),
    )
    assert unpinned_match.exit_code == ExitCode.CONFIGURATION_ERROR


def test_capability_enforce_accepts_organization_qualification_binding(
    tmp_path: Path,
) -> None:
    trust_root, policy = _trust_setup(
        tmp_path, gates=("HG-CAPCHAIN-001",), unknown_free=False
    )
    result = runner.invoke(
        app,
        [
            "capability",
            "enforce",
            str(BASELINE_CAPABILITY),
            "--agent-id",
            "capability-drift-agent",
            "--policy",
            "organization-policy.yaml",
            "--trust-root",
            str(trust_root),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == ExitCode.SUCCESS, result.stderr
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "0.5.0"
    assert payload["trust"]["trust_mode"] == "external_trust_root"
    gate = payload["matched_gates"][0]
    assert gate["gate_id"] == "HG-CAPCHAIN-001"
    assert gate["qualification"] == "accepted"
    assert gate["blocks"] is False


def test_capability_enforce_organization_gates_without_binding_fail_closed(
    tmp_path: Path,
) -> None:
    trust_root, _ = _trust_setup(
        tmp_path, gates=("HG-CAPCHAIN-001",), qualification=False
    )
    result = runner.invoke(
        app,
        [
            "capability",
            "enforce",
            str(BASELINE_CAPABILITY),
            "--agent-id",
            "capability-drift-agent",
            "--policy",
            "organization-policy.yaml",
            "--trust-root",
            str(trust_root),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == ExitCode.CONFIGURATION_ERROR
    assert "policy error" in result.stderr.lower()


def test_capability_enforce_digest_pins_fail_closed(tmp_path: Path) -> None:
    trust_root, policy = _trust_setup(
        tmp_path, gates=("HG-CAPCHAIN-001",), unknown_free=False
    )
    digest = hashlib.sha256(policy.read_bytes()).hexdigest()

    wrong_policy = runner.invoke(
        app,
        [
            "capability",
            "enforce",
            str(BASELINE_CAPABILITY),
            "--agent-id",
            "capability-drift-agent",
            "--policy",
            "organization-policy.yaml",
            "--trust-root",
            str(trust_root),
            "--expect-policy-sha256",
            "b" * 64,
            "--format",
            "json",
        ],
    )
    assert wrong_policy.exit_code == ExitCode.CONFIGURATION_ERROR

    wrong_registry = runner.invoke(
        app,
        [
            "capability",
            "enforce",
            str(BASELINE_CAPABILITY),
            "--agent-id",
            "capability-drift-agent",
            "--policy",
            "organization-policy.yaml",
            "--trust-root",
            str(trust_root),
            "--expect-policy-sha256",
            digest,
            "--expect-registry-sha256",
            "c" * 64,
            "--format",
            "json",
        ],
    )
    assert wrong_registry.exit_code == ExitCode.CONFIGURATION_ERROR
    assert "registry" in wrong_registry.stderr.lower()

    pinned = runner.invoke(
        app,
        [
            "capability",
            "enforce",
            str(BASELINE_CAPABILITY),
            "--agent-id",
            "capability-drift-agent",
            "--policy",
            "organization-policy.yaml",
            "--trust-root",
            str(trust_root),
            "--expect-policy-sha256",
            digest,
            "--expect-registry-sha256",
            hashlib.sha256(REGISTRY_PATH.read_bytes()).hexdigest(),
            "--format",
            "json",
        ],
    )
    assert pinned.exit_code == ExitCode.SUCCESS, pinned.stderr
    trust = json.loads(pinned.stdout)["trust"]
    assert trust["policy_digest_verified"] is True
    assert trust["registry_digest_pinned"] is True
    assert trust["registry_digest_verified"] is True


def test_repository_local_mode_is_labeled_in_reports(tmp_path: Path) -> None:
    policy = _write_policy(tmp_path, _org_policy_text())
    result = runner.invoke(app, _scan_args(SAFE_PROJECT, str(policy)))
    assert result.exit_code == ExitCode.SUCCESS
    payload = json.loads(result.stdout)
    assert payload["trust"]["trust_mode"] == "repository_local"
