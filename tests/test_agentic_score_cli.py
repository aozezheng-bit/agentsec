"""P2-EXIT-03 Integrated Agentic Score CLI and Report tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from typer.testing import CliRunner

from agentsec.cli import ExitCode, app

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BASELINE_MANIFEST = (
    REPOSITORY_ROOT
    / "demos"
    / "capability-drift-agent"
    / "expected"
    / "baseline.manifest.json"
)
RISKY_PROJECT = REPOSITORY_ROOT / "demos" / "capability-drift-agent" / "risky-drift"
AGENT_ID = "release-agent"
FORMAT_NAME = "agentsec-agentic-assessment"
FORMAT_VERSION = "0.1.0"

runner = CliRunner()


def _score_args(
    *,
    output_format: str = "json",
    language: str | None = None,
    context: Path | None = None,
    before: Path = BASELINE_MANIFEST,
) -> list[str]:
    arguments = [
        "score",
        str(RISKY_PROJECT),
        "--agent-id",
        AGENT_ID,
        "--before",
        str(before),
        "--format",
        output_format,
    ]
    if context is not None:
        arguments.extend(["--context", str(context)])
    if language is not None:
        arguments.extend(["--language", language])
    return arguments


def _write_context(path: Path, payload: dict[str, object]) -> Path:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _minimal_context(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "format": "agentsec-score-context",
        "schema_version": "0.1.0",
    }
    payload.update(overrides)
    return payload


def test_score_reports_full_deterministic_chain_without_context() -> None:
    result = runner.invoke(app, _score_args())
    assert result.exit_code == ExitCode.SUCCESS, result.stderr
    payload = json.loads(result.stdout)

    assert payload["format"] == FORMAT_NAME
    assert payload["format_version"] == FORMAT_VERSION
    assert payload["agent_id"] == AGENT_ID
    assert len(payload["before_manifest_sha256"]) == 64
    assert len(payload["after_manifest_sha256"]) == 64
    assert payload["context"] == {"supplied": False, "sha256": None}
    assert isinstance(payload["coverage_complete"], bool)
    assert isinstance(payload["relevant_unknown_count"], int)

    for key in (
        "factor_vector",
        "threat_mitigation",
        "capability_diff",
        "technical",
        "drift",
        "governance",
        "overall",
    ):
        assert isinstance(payload[key], dict), key
    assert payload["cvss"] is None
    assert payload["gate_matches"] == []
    assert payload["policy"] == {
        "report_only": True,
        "ci_blocking_enabled": False,
        "score_ci_authority": False,
    }
    assert payload["boundary"]["llm_authority"] is False
    assert payload["boundary"]["runtime_verified"] is False
    assert isinstance(payload["versions"], dict)

    overall = payload["overall"]
    assert overall["overall_score"] >= overall["base_overall_score"] >= 0.0
    assert overall["technical_score"] == payload["technical"]["technical_score"]


def test_score_text_report_supports_bilingual_boundaries() -> None:
    english = runner.invoke(app, _score_args(output_format="text"))
    assert english.exit_code == ExitCode.SUCCESS, english.stderr
    assert "AgentSec Agentic Score" in english.stdout
    assert "report-only" in english.stdout.lower()

    chinese = runner.invoke(app, _score_args(output_format="text", language="zh"))
    assert chinese.exit_code == ExitCode.SUCCESS, chinese.stderr
    assert "Agentic" in chinese.stdout
    assert "阻断" not in chinese.stdout or "不阻断" in chinese.stdout


def test_reviewed_drift_context_is_explicit_and_changes_drift_score(
    tmp_path: Path,
) -> None:
    baseline = runner.invoke(app, _score_args())
    assert baseline.exit_code == ExitCode.SUCCESS
    unknown_drift = json.loads(baseline.stdout)["drift"]["drift_score"]

    context_path = _write_context(
        tmp_path / "score-context.json",
        _minimal_context(
            drift={
                "change_source": "reviewed_change",
                "approval_status": "approved",
                "approval_reference": "approval-2026-001",
                "deployment_scope": "development",
                "baseline_trust": "hash_only",
            },
            governance={
                "review_status": "reviewed",
                "policy_owner": "security-team",
                "approval_owner": "release-owner",
                "waiver_count": 1,
                "expired_waiver_count": 0,
            },
        ),
    )
    reviewed = runner.invoke(app, _score_args(context=context_path))
    assert reviewed.exit_code == ExitCode.SUCCESS, reviewed.stderr
    payload = json.loads(reviewed.stdout)

    assert payload["context"] == {
        "supplied": True,
        "sha256": hashlib.sha256(context_path.read_bytes()).hexdigest(),
    }
    assert payload["drift"]["drift_score"] <= unknown_drift
    assert payload["governance"]["governance_score"] >= 0.0


def test_score_context_rejects_unknown_fields_duplicate_keys_and_bad_digests(
    tmp_path: Path,
) -> None:
    unknown_field = _write_context(
        tmp_path / "unknown.json", _minimal_context(unexpected="reject me")
    )
    result = runner.invoke(app, _score_args(context=unknown_field))
    assert result.exit_code == ExitCode.CONFIGURATION_ERROR

    duplicate_path = tmp_path / "duplicate.json"
    duplicate_path.write_text(
        '{"format": "agentsec-score-context", "format": "agentsec-score-context",'
        ' "schema_version": "0.1.0"}',
        encoding="utf-8",
    )
    result = runner.invoke(app, _score_args(context=duplicate_path))
    assert result.exit_code == ExitCode.CONFIGURATION_ERROR

    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{not json", encoding="utf-8")
    result = runner.invoke(app, _score_args(context=invalid_json))
    assert result.exit_code == ExitCode.CONFIGURATION_ERROR


def test_context_cvss_vector_feeds_technical_high_water_mark(tmp_path: Path) -> None:
    context_path = _write_context(
        tmp_path / "cvss-context.json",
        _minimal_context(
            cvss={
                "vector": (
                    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
                )
            }
        ),
    )
    result = runner.invoke(app, _score_args(context=context_path))
    assert result.exit_code == ExitCode.SUCCESS, result.stderr
    payload = json.loads(result.stdout)

    assert payload["cvss"] is not None
    assert payload["cvss"]["base_score"] >= 9.0
    assert payload["technical"]["cvss_base_score"] == payload["cvss"]["base_score"]

    bad_cvss = _write_context(
        tmp_path / "bad-cvss.json", _minimal_context(cvss={"vector": "CVSS:4.0/AV:X"})
    )
    rejected = runner.invoke(app, _score_args(context=bad_cvss))
    assert rejected.exit_code == ExitCode.CONFIGURATION_ERROR


def test_accepted_gate_match_sets_qualified_floor_without_blocking(
    tmp_path: Path,
) -> None:
    context_path = _write_context(
        tmp_path / "gate-context.json",
        _minimal_context(
            gate_matches=[
                {
                    "gate_id": "HG-CAPCHAIN-001",
                    "floor": "critical",
                    "source": "capability",
                    "evidence_ids": ["capability-finding-sha256:" + "a1" * 32],
                    "confidence": "A",
                    "rationale": [
                        "Reviewed execute, secret-access, and external-network "
                        "chain evidence."
                    ],
                }
            ]
        ),
    )
    result = runner.invoke(app, _score_args(context=context_path))
    assert result.exit_code == ExitCode.SUCCESS, result.stderr
    payload = json.loads(result.stdout)

    overall = payload["overall"]
    assert overall["hard_gate"]["triggered"] is True
    assert overall["hard_gate"]["floor"] == "critical"
    assert overall["overall_score"] >= overall["base_overall_score"]
    assert payload["policy"]["ci_blocking_enabled"] is False
    assert result.exit_code != ExitCode.RISK_THRESHOLD_EXCEEDED

    d_confidence = _write_context(
        tmp_path / "d-confidence.json",
        _minimal_context(
            gate_matches=[
                {
                    "gate_id": "HG-CAPCHAIN-001",
                    "floor": "high",
                    "source": "capability",
                    "evidence_ids": ["capability-finding-sha256:" + "b2" * 32],
                    "confidence": "D",
                    "rationale": ["Low-confidence evidence cannot set a floor."],
                }
            ]
        ),
    )
    rejected = runner.invoke(app, _score_args(context=d_confidence))
    assert rejected.exit_code == ExitCode.CONFIGURATION_ERROR


def test_incompatible_before_manifest_fails_closed(tmp_path: Path) -> None:
    manifest = json.loads(BASELINE_MANIFEST.read_text(encoding="utf-8"))
    manifest["identity"]["agent_id"] = "different-agent"
    other_path = tmp_path / "other-agent.manifest.json"
    other_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = runner.invoke(app, _score_args(before=other_path))
    assert result.exit_code == ExitCode.ARTIFACT_ERROR


def test_missing_before_manifest_is_reported(tmp_path: Path) -> None:
    result = runner.invoke(app, _score_args(before=tmp_path / "missing.manifest.json"))
    assert result.exit_code == ExitCode.ARTIFACT_ERROR


def test_sarif_output_is_valid_and_report_only() -> None:
    result = runner.invoke(app, _score_args(output_format="sarif"))
    assert result.exit_code == ExitCode.SUCCESS, result.stderr
    payload = json.loads(result.stdout)

    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"]
    assert run["results"]
    assert run["properties"]["agentsecReportKind"] == "agentic_assessment"
    assert run["invocations"][0]["properties"]["agentsecReportOnly"] is True
    assert run["properties"]["agentsecCiBlockingEnabled"] is False


def test_json_output_is_deterministic() -> None:
    first = runner.invoke(app, _score_args())
    second = runner.invoke(app, _score_args())
    assert first.exit_code == ExitCode.SUCCESS
    assert first.stdout == second.stdout
