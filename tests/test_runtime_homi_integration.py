"""RISK-06 Homi CLI and Bundle integration tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from typer.testing import CliRunner

from agentsec.cli.app import create_app
from agentsec.risk import (
    OperationContextSet,
    RuntimeAttestationMethod,
    RuntimeVerificationStatus,
    build_runtime_attestation,
    build_runtime_observation,
    canonical_operation_context_sha256,
    encode_runtime_attestation_json,
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
            observed_at="2026-09-04T00:00:00Z",
        )
        for context in context_set.contexts
    )
    attestation = build_runtime_attestation(
        agent_snapshot_sha256=pilot_digest,
        context_sha256=canonical_operation_context_sha256(context_set),
        issuer="external-sandbox",
        method=RuntimeAttestationMethod.RUNTIME_VERIFICATION,
        verification_status=RuntimeVerificationStatus.VERIFIED,
        observations=observations,
        limitations=("Sanitized external sandbox evidence.",),
    )
    path = report_dir.parent / "runtime-attestation.json"
    path.write_text(encode_runtime_attestation_json(attestation), encoding="utf-8")
    return path


def test_reconcile_runtime_writes_bound_sidecar_and_bundle_displays_it(
    tmp_path: Path,
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

    reconciled = runner.invoke(
        create_app(),
        [
            "homi",
            "reconcile-runtime",
            "--report-dir",
            str(report_dir),
            "--attestation",
            str(attestation_path),
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
