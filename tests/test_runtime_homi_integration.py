"""RISK-06 Homi CLI and Bundle integration tests."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentsec.cli.app import create_app
from agentsec.risk import (
    OperationContextSet,
    RuntimeAttestationMethod,
    RuntimeSignatureAlgorithm,
    RuntimeVerificationStatus,
    TrustedRuntimeIssuer,
    build_runtime_attestation,
    build_runtime_observation,
    build_runtime_trust_registry,
    canonical_operation_context_sha256,
    encode_runtime_attestation_json,
    encode_runtime_trust_registry_json,
)

runner = CliRunner()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _workspace(path: Path) -> None:
    _write(
        path / "AGENTS.md",
        """# Workspace
Read files and update memory.md.
Search the web and check calendars.
""",
    )
    _write(path / "SOUL.md", "# Soul\nBe genuinely helpful.\n")
    _write(path / "IDENTITY.md", "Name: Demo\nCreature: AI assistant\n")
    _write(path / "USER.md", "# Human\nTimezone: Asia/Shanghai\n")
    _write(path / "TOOLS.md", "# Tools\nNo external tools configured.\n")
    _write(path / "HEARTBEAT.md", "# Heartbeat\n# disabled\n")


def _attestation_for_report(report_dir: Path) -> Path:
    now = datetime.now(UTC).replace(microsecond=0)
    issued_at = (now - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    expires_at = (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    pilot_path = report_dir / "homi-pilot-report.json"
    pilot_digest = hashlib.sha256(pilot_path.read_bytes()).hexdigest()
    context_payload = json.loads(
        (report_dir / "homi-operation-context.json").read_text(encoding="utf-8")
    )
    context_set = OperationContextSet.model_validate(context_payload["context_set"])
    observations = tuple(
        build_runtime_observation(
            operation_id=context.operation_id,
            action=context.action,
            target=context.target,
            observed=True,
            evidence_sha256=hashlib.sha256(
                context.operation_id.encode("utf-8")
            ).hexdigest(),
            source_ref="sandbox-event:summary",
            observed_at=issued_at,
        )
        for context in context_set.contexts
    )
    attestation = build_runtime_attestation(
        agent_snapshot_sha256=pilot_digest,
        context_sha256=canonical_operation_context_sha256(context_set),
        issuer="external-sandbox",
        key_id="test-key",
        signature_algorithm=RuntimeSignatureAlgorithm.HMAC_SHA256,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce="homi-test-nonce-01",
        method=RuntimeAttestationMethod.RUNTIME_VERIFICATION,
        verification_status=RuntimeVerificationStatus.VERIFIED,
        observations=observations,
        limitations=("Sanitized external sandbox evidence.",),
        signing_key=b"k" * 32,
    )
    path = report_dir.parent / "runtime-attestation.json"
    path.write_text(encode_runtime_attestation_json(attestation), encoding="utf-8")
    return path


def _trust_registry(path: Path) -> Path:
    registry = build_runtime_trust_registry(
        (
            TrustedRuntimeIssuer(
                issuer="external-sandbox",
                key_id="test-key",
                algorithm=RuntimeSignatureAlgorithm.HMAC_SHA256,
                secret_env_var="AGENTSEC_HOMI_RUNTIME_KEY",
            ),
        )
    )
    path.write_text(encode_runtime_trust_registry_json(registry), encoding="utf-8")
    return path


def test_reconcile_runtime_writes_bound_sidecar_and_bundle_displays_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "agent"
    report_dir = tmp_path / "reports"
    _workspace(workspace)
    generated = runner.invoke(
        create_app(),
        [
            "homi",
            "report",
            str(workspace),
            "--output-dir",
            str(report_dir),
            "--language",
            "zh",
            "--force",
        ],
    )
    assert generated.exit_code == 0, generated.output
    attestation_path = _attestation_for_report(report_dir)
    registry_path = _trust_registry(tmp_path / "runtime-trust-registry.json")
    monkeypatch.setenv("AGENTSEC_HOMI_RUNTIME_KEY", "k" * 32)

    reconciled = runner.invoke(
        create_app(),
        [
            "homi",
            "reconcile-runtime",
            "--report-dir",
            str(report_dir),
            "--attestation",
            str(attestation_path),
            "--trust-registry",
            str(registry_path),
            "--force",
        ],
    )
    assert reconciled.exit_code == 0, reconciled.output
    payload = json.loads(
        (report_dir / "homi-runtime-reconciliation.json").read_text(encoding="utf-8")
    )
    assert (
        payload["source_agent_snapshot_sha256"]
        == hashlib.sha256(
            (report_dir / "homi-pilot-report.json").read_bytes()
        ).hexdigest()
    )
    assert payload["report_only"] is True
    assert payload["policy_authority"] is False
    assert payload["ci_blocked"] is False
    assert payload["trust_verified"] is True
    assert payload["evidence_confidence"] == "B"
    trust = json.loads(
        (report_dir / "homi-runtime-trust-verification.json").read_text(
            encoding="utf-8"
        )
    )
    assert trust["trusted"] is True
    assert trust["signature_verified"] is True
    assert trust["replay_detected"] is False

    bundled = runner.invoke(
        create_app(),
        [
            "homi",
            "bundle",
            "--pilot",
            str(report_dir / "homi-pilot-report.json"),
            "--format",
            "html",
            "--language",
            "zh",
            "--output",
            str(tmp_path / "combined.html"),
            "--force",
        ],
    )
    assert bundled.exit_code == 0, bundled.output
    html = (tmp_path / "combined.html").read_text(encoding="utf-8")
    assert "运行时证据对账" in html
    assert "运行时信任验证" in html
    assert "signature_time_and_replay_valid" in html
    assert "Evidence Confidence" in html
    assert "不授予权限" in html


def test_reconcile_runtime_rejects_snapshot_mismatch(tmp_path: Path) -> None:
    workspace = tmp_path / "agent"
    report_dir = tmp_path / "reports"
    _workspace(workspace)
    generated = runner.invoke(
        create_app(),
        [
            "homi",
            "report",
            str(workspace),
            "--output-dir",
            str(report_dir),
            "--force",
        ],
    )
    assert generated.exit_code == 0, generated.output
    attestation_path = _attestation_for_report(report_dir)
    payload = json.loads(attestation_path.read_text(encoding="utf-8"))
    payload["agent_snapshot_sha256"] = "f" * 64
    # The altered artifact is intentionally not re-signed/re-hashed; the CLI
    # must reject the already inconsistent attestation before reconciliation.
    attestation_path.write_text(json.dumps(payload), encoding="utf-8")

    result = runner.invoke(
        create_app(),
        [
            "homi",
            "reconcile-runtime",
            "--report-dir",
            str(report_dir),
            "--attestation",
            str(attestation_path),
        ],
    )
    assert result.exit_code == 4
    assert not (report_dir / "homi-runtime-reconciliation.json").exists()


def test_reconcile_runtime_replay_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "agent"
    report_dir = tmp_path / "reports"
    _workspace(workspace)
    generated = runner.invoke(
        create_app(),
        ["homi", "report", str(workspace), "--output-dir", str(report_dir), "--force"],
    )
    assert generated.exit_code == 0, generated.output
    attestation_path = _attestation_for_report(report_dir)
    registry_path = _trust_registry(tmp_path / "runtime-trust-registry.json")
    monkeypatch.setenv("AGENTSEC_HOMI_RUNTIME_KEY", "k" * 32)
    args = [
        "homi",
        "reconcile-runtime",
        "--report-dir",
        str(report_dir),
        "--attestation",
        str(attestation_path),
        "--trust-registry",
        str(registry_path),
        "--force",
    ]
    first = runner.invoke(create_app(), args)
    assert first.exit_code == 0, first.output
    second = runner.invoke(create_app(), args)
    assert second.exit_code == 0, second.output
    trust = json.loads(
        (report_dir / "homi-runtime-trust-verification.json").read_text(
            encoding="utf-8"
        )
    )
    reconciliation = json.loads(
        (report_dir / "homi-runtime-reconciliation.json").read_text(encoding="utf-8")
    )
    assert trust["status"] == "replayed"
    assert trust["trusted"] is False
    assert reconciliation["status"] == "unverified"
    assert reconciliation["evidence_confidence"] == "D"
