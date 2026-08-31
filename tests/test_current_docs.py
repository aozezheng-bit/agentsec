"""P2-EXIT-05 current-state documentation consistency tests."""

from __future__ import annotations

from pathlib import Path

from agentsec.semantic import (
    SEMANTIC_ANALYZER_VERSION,
    SEMANTIC_EVALUATION_OUTPUT_VERSION,
    SEMANTIC_EVALUATION_SCHEMA_VERSION,
    SEMANTIC_INPUT_SCHEMA_VERSION,
    SEMANTIC_LIVE_PROVIDER_CONFIG_VERSION,
    SEMANTIC_LIVE_PROVIDER_TRANSPORT_VERSION,
    SEMANTIC_MODEL_OUTPUT_SCHEMA_VERSION,
    SEMANTIC_OUTPUT_SCHEMA_VERSION,
    SEMANTIC_PROMPT_SCHEMA_VERSION,
    SEMANTIC_PROMPT_VERSION,
    SEMANTIC_PROVIDER_CONTRACT_VERSION,
    SEMANTIC_PROVIDER_REQUEST_SCHEMA_VERSION,
    SEMANTIC_PROVIDER_RESPONSE_SCHEMA_VERSION,
    SEMANTIC_SHADOW_INVOCATION_ADAPTER_VERSION,
    SEMANTIC_SHADOW_INVOCATION_OUTPUT_VERSION,
)
from agentsec.versioning import (
    AGENTIC_ASSESSMENT_OUTPUT_VERSION,
    ORGANIZATION_POLICY_SCHEMA_VERSION,
    PACKAGE_VERSION,
    QUALIFICATION_REGISTRY_SCHEMA_VERSION,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
README = REPOSITORY_ROOT / "README.md"
CURRENT_ARCHITECTURE = REPOSITORY_ROOT / "docs" / "current-architecture.md"
CURRENT_RELEASE_STATUS = REPOSITORY_ROOT / "docs" / "current-release-status.md"
SEMANTIC_CONTRACT = REPOSITORY_ROOT / "docs" / "semantic-analysis-contract.md"
P3_01_TASK = (
    REPOSITORY_ROOT
    / "docs"
    / "tasks"
    / "P3-01-llm-semantic-analysis-contract-authority-boundary.md"
)
SEMANTIC_INVOCATION = REPOSITORY_ROOT / "docs" / "semantic-shadow-invocation.md"
P3_02_TASK = (
    REPOSITORY_ROOT
    / "docs"
    / "tasks"
    / "P3-02-model-provider-prompt-shadow-invocation-adapter.md"
)
SEMANTIC_EVALUATION = REPOSITORY_ROOT / "docs" / "semantic-evaluation.md"
P3_03_TASK = (
    REPOSITORY_ROOT
    / "docs"
    / "tasks"
    / "P3-03-live-provider-shadow-trial-semantic-evaluation-harness.md"
)
QUAL_V1_TASK = (
    REPOSITORY_ROOT
    / "docs"
    / "tasks"
    / "P2-15A-QUAL-01-capchain-gate-qualification-report.md"
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_readme_points_at_authoritative_current_pages() -> None:
    text = _read(README)
    assert "docs/current-architecture.md" in text
    assert "docs/current-release-status.md" in text
    assert PACKAGE_VERSION in text


def test_current_architecture_is_the_single_authority() -> None:
    text = _read(CURRENT_ARCHITECTURE)
    assert "single authoritative architecture page" in text
    assert "agentsec.provenance.interface_provenance_registry()" in text
    assert "agentsec.provenance.schema_file_ownership()" in text
    assert "agentsec score PROJECT" in text
    assert "HG-CAPCHAIN-001" in text
    assert "SemanticAnalysisContract" in text
    assert "SemanticShadowInvocationAdapter" in text
    assert "offline fixture" in text
    assert "No SDK" in text
    assert "credential" in text
    assert "network" in text
    assert "LLM output is never part of a" in text


def test_current_release_status_records_releases_and_remediation() -> None:
    text = _read(CURRENT_RELEASE_STATUS)
    assert "single authoritative release/status page" in text
    assert "docs/current-architecture.md" in text
    assert PACKAGE_VERSION in text
    for release in ("agentsec-0.1.0", "agentsec-0.2.0", "agentsec-0.3.0"):
        assert release in text
    for task in (
        "P2-EXIT-01",
        "P2-EXIT-02",
        "P2-EXIT-03",
        "P2-EXIT-04",
        "P2-EXIT-05",
        "P2-EXIT-06",
        "P2-EXIT-07",
        "P2-EXIT-08",
    ):
        assert task in text
    assert ORGANIZATION_POLICY_SCHEMA_VERSION in text
    assert QUALIFICATION_REGISTRY_SCHEMA_VERSION in text
    assert AGENTIC_ASSESSMENT_OUTPUT_VERSION in text
    assert "P3-01～P3-10 complete" in text
    assert "P3-11A/P3-11B/P3-11C complete" in text
    assert "P3-12/P3-13/P3-14 scenario metrics track complete" in text
    assert "Shadow-only started" in text
    assert "offline fixture" in text
    for version in (
        SEMANTIC_ANALYZER_VERSION,
        SEMANTIC_INPUT_SCHEMA_VERSION,
        SEMANTIC_MODEL_OUTPUT_SCHEMA_VERSION,
        SEMANTIC_OUTPUT_SCHEMA_VERSION,
        SEMANTIC_EVALUATION_SCHEMA_VERSION,
        SEMANTIC_EVALUATION_OUTPUT_VERSION,
        SEMANTIC_LIVE_PROVIDER_CONFIG_VERSION,
        SEMANTIC_LIVE_PROVIDER_TRANSPORT_VERSION,
        SEMANTIC_PROVIDER_CONTRACT_VERSION,
        SEMANTIC_PROMPT_VERSION,
        SEMANTIC_PROMPT_SCHEMA_VERSION,
        SEMANTIC_PROVIDER_REQUEST_SCHEMA_VERSION,
        SEMANTIC_PROVIDER_RESPONSE_SCHEMA_VERSION,
        SEMANTIC_SHADOW_INVOCATION_ADAPTER_VERSION,
        SEMANTIC_SHADOW_INVOCATION_OUTPUT_VERSION,
    ):
        assert version in text


def test_p3_01_contract_documents_the_authority_boundary() -> None:
    contract = _read(SEMANTIC_CONTRACT)
    task = _read(P3_01_TASK)
    for text in (contract, task):
        assert "P3-01" in text
        assert "Shadow-only" in text or "shadow_only" in text
        assert "candidate evidence only" in text
        assert "no model invocation" in text or "no real model invocation" in text
    assert "SemanticAnalysisContract" in contract
    assert "Provider, Model, Prompt" in contract
    assert "blocks=false" in contract


def test_p3_02_documents_offline_shadow_invocation_without_live_authority() -> None:
    invocation = _read(SEMANTIC_INVOCATION)
    task = _read(P3_02_TASK)
    for text in (invocation, task):
        assert "P3-02" in text
        assert "offline" in text
        assert "shadow_only" in text or "Shadow-only" in text
        assert "candidate evidence only" in text or "candidate Evidence only" in text
        assert "live Provider" in text
    assert "SemanticShadowInvocationAdapter" in invocation
    assert "OfflineFixtureSemanticProvider" in invocation
    assert "policy_authority" in invocation
    assert "network transport" in invocation


def test_p3_03_documents_live_shadow_trial_and_evaluation_boundary() -> None:
    evaluation = _read(SEMANTIC_EVALUATION)
    task = _read(P3_03_TASK)
    for text in (evaluation, task):
        assert "P3-03" in text
        assert "Shadow-only" in text or "shadow_only" in text
        assert "Precision" in text
        assert "Recall" in text
        assert "Evidence" in text
        assert "policy_authority" in text
        assert "runtime_verified" in text
        assert "credential" in text
        assert "raw" in text
    assert "LiveSemanticProvider" in evaluation
    assert "LiveSemanticProviderConfig" in evaluation
    assert "semantic-evaluation-report.schema.json" in evaluation


def test_qualification_v1_is_marked_superseded() -> None:
    text = _read(QUAL_V1_TASK)
    assert "Superseded (P2-EXIT-05)" in text
    assert "hg-capchain-001-qualification-report-v2.json" in text
    assert "grants no Gate authority" in text


def test_no_current_page_claims_phase3_authority_or_blocking() -> None:
    for page in (CURRENT_ARCHITECTURE, CURRENT_RELEASE_STATUS):
        text = _read(page)
        assert "candidate evidence only" in text or "candidate evidence" in text
        assert "offline fixture" in text or "OfflineFixtureSemanticProvider" in text
        assert "only decision authority" in text or "never part of a decision" in text
