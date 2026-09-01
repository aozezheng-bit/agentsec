"""P2-EXIT-05 interface provenance registry consistency tests."""

from __future__ import annotations

from pathlib import Path

from agentsec import versioning
from agentsec.calibration.pilot_review import (
    FULL_PACK_SCHEMA_VERSION,
    JOINT_EVIDENCE_SCHEMA_VERSION,
    PILOT_SCHEMA_VERSION,
)
from agentsec.external_pilot import EXTERNAL_HOMI_REVIEW_SCHEMA_VERSION
from agentsec.pilot import (
    PILOT_HUMAN_LABELS_SCHEMA_VERSION,
    PILOT_PLAN_SCHEMA_VERSION,
    PILOT_REPORT_OUTPUT_VERSION,
)
from agentsec.provenance import (
    PHASE3_RESERVED_INTERFACE_NAMES,
    InterfaceClassification,
    interface_provenance_registry,
    render_interface_provenance_markdown,
)
from agentsec.risk.cvss import CVSS_ADAPTER_VERSION
from agentsec.semantic import (
    SEMANTIC_ANALYZER_VERSION,
    SEMANTIC_EVALUATION_OUTPUT_VERSION,
    SEMANTIC_EVALUATION_SCHEMA_VERSION,
    SEMANTIC_INPUT_SCHEMA_VERSION,
    SEMANTIC_LIVE_PROVIDER_CONFIG_VERSION,
    SEMANTIC_LIVE_PROVIDER_TRANSPORT_VERSION,
    SEMANTIC_MODEL_ID,
    SEMANTIC_MODEL_OUTPUT_SCHEMA_VERSION,
    SEMANTIC_MODEL_PROVIDER_ID,
    SEMANTIC_OUTPUT_SCHEMA_VERSION,
    SEMANTIC_PROMPT_SCHEMA_VERSION,
    SEMANTIC_PROMPT_VERSION,
    SEMANTIC_PROVIDER_CONTRACT_VERSION,
    SEMANTIC_PROVIDER_REQUEST_SCHEMA_VERSION,
    SEMANTIC_PROVIDER_RESPONSE_SCHEMA_VERSION,
    SEMANTIC_PROVIDER_SPECIFIC_ADAPTER_VERSION,
    SEMANTIC_SHADOW_INVOCATION_ADAPTER_VERSION,
    SEMANTIC_SHADOW_INVOCATION_OUTPUT_VERSION,
    SEMANTIC_TRIAL_CASE_SET_VERSION,
    SEMANTIC_TRIAL_CONFIG_VERSION,
)
from agentsec.vulnerabilities.input import VULNERABILITY_INPUT_VERSION
from agentsec.vulnerabilities.sources import VULNERABILITY_CATALOG_VERSION

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

VERSION_SET_FIELDS = (
    "PACKAGE_VERSION",
    "CONFIG_SCHEMA_VERSION",
    "DOMAIN_SCHEMA_VERSION",
    "AGENT_MANIFEST_SCHEMA_VERSION",
    "CAPABILITY_DIFF_SCHEMA_VERSION",
    "CAPABILITY_RULE_PACK_VERSION",
    "CAPABILITY_RISK_MODEL_VERSION",
    "CAPABILITY_ASSESSMENT_OUTPUT_VERSION",
    "CAPABILITY_CHANGE_IMPACT_OUTPUT_VERSION",
    "BASELINE_SCHEMA_VERSION",
    "DIFF_OUTPUT_VERSION",
    "ASSESSMENT_OUTPUT_VERSION",
    "RULE_PACK_VERSION",
    "RISK_MODEL_VERSION",
    "CVSS_HARD_GATE_VERSION",
    "CAPABILITY_SHADOW_GATE_VERSION",
)


def test_registry_classifies_every_central_version_constant_exactly_once() -> None:
    records = interface_provenance_registry()
    names = [record.name for record in records]
    assert len(names) == len(set(names))

    versioning_constants = {
        name for name in dir(versioning) if name.endswith("_VERSION")
    }
    assert versioning_constants <= set(names)
    for constant in versioning_constants:
        assert names.count(constant) == 1


def test_registry_classifies_module_scoped_version_constants() -> None:
    module_constants = {
        "PILOT_PLAN_SCHEMA_VERSION": PILOT_PLAN_SCHEMA_VERSION,
        "PILOT_HUMAN_LABELS_SCHEMA_VERSION": PILOT_HUMAN_LABELS_SCHEMA_VERSION,
        "PILOT_REPORT_OUTPUT_VERSION": PILOT_REPORT_OUTPUT_VERSION,
        "CVSS_ADAPTER_VERSION": CVSS_ADAPTER_VERSION,
        "VULNERABILITY_INPUT_VERSION": VULNERABILITY_INPUT_VERSION,
        "VULNERABILITY_CATALOG_VERSION": VULNERABILITY_CATALOG_VERSION,
        "PILOT_SCHEMA_VERSION": PILOT_SCHEMA_VERSION,
        "FULL_PACK_SCHEMA_VERSION": FULL_PACK_SCHEMA_VERSION,
        "JOINT_EVIDENCE_SCHEMA_VERSION": JOINT_EVIDENCE_SCHEMA_VERSION,
        "EXTERNAL_HOMI_REVIEW_SCHEMA_VERSION": EXTERNAL_HOMI_REVIEW_SCHEMA_VERSION,
        "SEMANTIC_ANALYZER_VERSION": SEMANTIC_ANALYZER_VERSION,
        "SEMANTIC_EVALUATION_SCHEMA_VERSION": SEMANTIC_EVALUATION_SCHEMA_VERSION,
        "SEMANTIC_EVALUATION_OUTPUT_VERSION": SEMANTIC_EVALUATION_OUTPUT_VERSION,
        "SEMANTIC_LIVE_PROVIDER_CONFIG_VERSION": SEMANTIC_LIVE_PROVIDER_CONFIG_VERSION,
        "SEMANTIC_LIVE_PROVIDER_TRANSPORT_VERSION": (
            SEMANTIC_LIVE_PROVIDER_TRANSPORT_VERSION
        ),
        "SEMANTIC_PROVIDER_SPECIFIC_ADAPTER_VERSION": (
            SEMANTIC_PROVIDER_SPECIFIC_ADAPTER_VERSION
        ),
        "SEMANTIC_TRIAL_CASE_SET_VERSION": SEMANTIC_TRIAL_CASE_SET_VERSION,
        "SEMANTIC_TRIAL_CONFIG_VERSION": SEMANTIC_TRIAL_CONFIG_VERSION,
        "SEMANTIC_TRIAL_RESPONSE_SET_VERSION": SEMANTIC_TRIAL_CASE_SET_VERSION,
        "SEMANTIC_PARITY_REPORT_VERSION": "0.1.0",
        "SEMANTIC_INPUT_SCHEMA_VERSION": SEMANTIC_INPUT_SCHEMA_VERSION,
        "SEMANTIC_MODEL_OUTPUT_SCHEMA_VERSION": SEMANTIC_MODEL_OUTPUT_SCHEMA_VERSION,
        "SEMANTIC_OUTPUT_SCHEMA_VERSION": SEMANTIC_OUTPUT_SCHEMA_VERSION,
        "SEMANTIC_MODEL_PROVIDER_ID": SEMANTIC_MODEL_PROVIDER_ID,
        "SEMANTIC_MODEL_ID": SEMANTIC_MODEL_ID,
        "SEMANTIC_PROVIDER_CONTRACT_VERSION": SEMANTIC_PROVIDER_CONTRACT_VERSION,
        "SEMANTIC_PROMPT_VERSION": SEMANTIC_PROMPT_VERSION,
        "SEMANTIC_PROMPT_SCHEMA_VERSION": SEMANTIC_PROMPT_SCHEMA_VERSION,
        "SEMANTIC_PROVIDER_REQUEST_SCHEMA_VERSION": (
            SEMANTIC_PROVIDER_REQUEST_SCHEMA_VERSION
        ),
        "SEMANTIC_PROVIDER_RESPONSE_SCHEMA_VERSION": (
            SEMANTIC_PROVIDER_RESPONSE_SCHEMA_VERSION
        ),
        "SEMANTIC_SHADOW_INVOCATION_ADAPTER_VERSION": (
            SEMANTIC_SHADOW_INVOCATION_ADAPTER_VERSION
        ),
        "SEMANTIC_SHADOW_INVOCATION_OUTPUT_VERSION": (
            SEMANTIC_SHADOW_INVOCATION_OUTPUT_VERSION
        ),
    }
    for name, value in module_constants.items():
        matches = [
            record for record in interface_provenance_registry() if record.name == name
        ]
        assert len(matches) == 1, name
        assert matches[0].version == value, name


def test_product_version_vector_fields_keep_the_frozen_classification() -> None:
    records = {record.name: record for record in interface_provenance_registry()}
    for name in VERSION_SET_FIELDS:
        assert records[name].classification is (
            InterfaceClassification.PRODUCT_VECTOR
        ), name


def test_phase3_interfaces_are_reserved_without_authority() -> None:
    records = {record.name: record for record in interface_provenance_registry()}
    assert len(PHASE3_RESERVED_INTERFACE_NAMES) == 3
    for name in PHASE3_RESERVED_INTERFACE_NAMES:
        assert name in records
        assert records[name].version is None
        assert records[name].classification is (InterfaceClassification.RESERVED_PHASE3)


def test_no_interface_version_grants_authority() -> None:
    for record in interface_provenance_registry():
        assert record.grants_authority is False, record.name


def test_schema_files_are_owned_by_the_registry() -> None:
    from agentsec.provenance import schema_file_ownership

    disk = {
        str(path.relative_to(REPOSITORY_ROOT))
        for path in (REPOSITORY_ROOT / "schemas").rglob("*.schema.json")
    }
    owned = set(schema_file_ownership())
    assert disk == owned, (sorted(disk - owned), sorted(owned - disk))


def test_provenance_markdown_is_deterministic_and_records_limits() -> None:
    first = render_interface_provenance_markdown()
    second = render_interface_provenance_markdown()
    assert first == second
    assert versioning.PACKAGE_VERSION in first
    assert "no interface version grants authorization authority".lower() in (
        first.lower()
    )
