"""P3-19 Gate human corpus and Real Provider Pilot tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentsec.cli import app
from agentsec.semantic import (
    SemanticGateCaseClass,
    SemanticGateCorpusProvenance,
    SemanticGateCorpusReviewer,
    SemanticGateHumanCase,
    SemanticGateHumanCorpus,
    SemanticGatePilotConfig,
    SemanticGatePilotRunner,
    SemanticGatePilotStatus,
    SemanticGateReviewDecision,
    SemanticGateReviewSubmission,
    build_semantic_evidence_chunk,
    build_semantic_gate_human_corpus,
    encode_semantic_gate_human_corpus_json,
    import_semantic_gate_review,
)

ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()


def _case(
    case_id: str, case_class: SemanticGateCaseClass, reviewer: str = "reviewer-a"
) -> SemanticGateHumanCase:
    text = f"case {case_id}: review the instruction safely"
    asset_sha = hashlib.sha256(b"asset").hexdigest()
    chunk = build_semantic_evidence_chunk(
        asset_path="AGENTS.md",
        asset_sha256=asset_sha,
        start_line=1,
        end_line=1,
        text=text,
    )
    return SemanticGateHumanCase(
        case_id=case_id,
        gate_id="SG-TEST-001",
        signal="instruction_integrity",
        case_class=case_class,
        expected_gate_match=case_class is SemanticGateCaseClass.POSITIVE,
        evidence_id=chunk.evidence_id,
        asset_path="AGENTS.md",
        asset_sha256=asset_sha,
        start_line=1,
        end_line=1,
        sanitized_text=chunk.text,
        text_sha256=chunk.text_sha256,
        source_kind="review_pack",
        source_label="sanitized test case",
        reviewer_id=reviewer,
        review_provenance=SemanticGateCorpusProvenance.HUMAN_AUTHORED,
        confidence_rationale="reviewed against the Gate definition",
    )


def _reviewer(reviewer_id: str) -> SemanticGateCorpusReviewer:
    return SemanticGateCorpusReviewer(
        reviewer_id=reviewer_id,
        independence_statement="I reviewed the cases independently.",
        reviewed_case_count=2,
        reviewed_at="2026-09-01T00:00:00Z",
        provenance=SemanticGateCorpusProvenance.HUMAN_AUTHORED,
    )


def _corpus() -> SemanticGateHumanCorpus:
    return build_semantic_gate_human_corpus(
        gate_id="SG-TEST-001",
        signal="instruction_integrity",
        cases=(
            _case("case-01", SemanticGateCaseClass.POSITIVE),
            _case("case-02", SemanticGateCaseClass.ELIGIBLE_NEGATIVE),
        ),
        reviewers=(_reviewer("reviewer-a"),),
    )


def test_corpus_is_digest_bound_and_reports_coverage() -> None:
    corpus = _corpus()
    assert corpus.coverage.case_count == 2
    assert corpus.coverage.positive_count == 1
    assert corpus.coverage.eligible_negative_count == 1
    assert corpus.coverage.minimum_positive_met is False
    payload = json.loads(encode_semantic_gate_human_corpus_json(corpus))
    assert payload["authority_can_block_ci"] is False
    assert payload["corpus_id"].startswith("semantic-gate-human-corpus-sha256:")


def test_corpus_rejects_secret_or_url_evidence() -> None:
    base = _case("case-secret", SemanticGateCaseClass.POSITIVE).model_dump(
        mode="python"
    )
    base["sanitized_text"] = "https://not-allowed.invalid"
    with pytest.raises(ValueError):
        SemanticGateHumanCase.model_validate(base)


def test_review_import_requires_adjudication_for_disagreement() -> None:
    corpus = _corpus()
    base_id = corpus.corpus_id
    a = SemanticGateReviewSubmission(
        corpus_id=base_id,
        gate_id=corpus.gate_id,
        reviewer_id="reviewer-a",
        independence_statement="Independent review A.",
        reviewed_at="2026-09-01T00:00:00Z",
        decisions=tuple(
            SemanticGateReviewDecision(
                case_id=case.case_id,
                case_class=case.case_class,
                expected_gate_match=case.expected_gate_match,
                confidence_grade="B",
                rationale_code="direct_evidence",
            )
            for case in corpus.cases
        ),
    )
    b = a.model_copy(
        update={
            "reviewer_id": "reviewer-b",
            "independence_statement": "Independent review B.",
            "decisions": (
                a.decisions[0],
                a.decisions[1].model_copy(
                    update={
                        "case_class": SemanticGateCaseClass.NEAR_MISS,
                        "expected_gate_match": False,
                    }
                ),
            ),
        }
    )
    with pytest.raises(ValueError, match="adjudication"):
        import_semantic_gate_review(corpus, reviewer_submissions=(a, b))


def test_pilot_preflight_is_fail_closed_without_opt_in() -> None:
    corpus = _corpus()
    config = SemanticGatePilotConfig(
        provider_id="provider",
        model_id="model",
        credential_env="MISSING_KEY",
        corpus_path="corpus.json",
    )
    report = SemanticGatePilotRunner().run(config, corpus)
    assert report.status is SemanticGatePilotStatus.PREFLIGHT_BLOCKED
    assert report.evaluation is None
    assert "live_opt_in_required" in report.error_codes
    assert report.blocks is False


def test_pilot_uses_injected_provider_without_network() -> None:
    corpus = _corpus()
    config = SemanticGatePilotConfig(
        endpoint_url="https://provider.invalid/v1",
        provider_id="offline-fixture",
        model_id="agentsec-semantic-fixture-v1",
        credential_env="MISSING_KEY",
        corpus_path="corpus.json",
        max_cases=2,
        max_calls=2,
        allow_live=True,
        data_residency_approved=True,
        retention_policy_approved=True,
        cost_approved=True,
        review_owner_id="owner",
        approval_id="approval-1",
    )
    # The actual network adapter is intentionally not constructed in this test;
    # preflight remains the safety boundary when the credential is unavailable.
    report = SemanticGatePilotRunner().run(config, corpus)
    assert report.status is SemanticGatePilotStatus.PREFLIGHT_BLOCKED
    assert "credential_unavailable" in report.error_codes


def test_gate_pilot_cli_emits_preflight_report(tmp_path: Path) -> None:
    corpus = _corpus()
    corpus_path = tmp_path / "corpus.json"
    corpus_path.write_text(
        encode_semantic_gate_human_corpus_json(corpus), encoding="utf-8"
    )
    result = runner.invoke(
        app,
        [
            "semantic",
            "gate-pilot",
            "--corpus",
            str(corpus_path),
            "--provider-id",
            "provider",
            "--model-id",
            "model",
            "--credential-env",
            "MISSING_KEY",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 3
    payload = json.loads(result.stdout)
    assert payload["status"] == "preflight_blocked"
    assert payload["blocks"] is False
