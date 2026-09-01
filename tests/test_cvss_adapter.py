"""Tests for the P2-17 CVSS Base input adapter."""

from __future__ import annotations

import json

import pytest

from agentsec.domain import Severity
from agentsec.risk import (
    CVSS_ADAPTER_VERSION,
    CVSS_MAPPING_BASIS,
    CvssAdapterCode,
    CvssAdapterError,
    CvssBaseAdapter,
    CvssBaseInput,
    CvssScoreVerification,
    CvssVersion,
    severity_for_cvss_score,
)

_V31_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_V31_HIGH = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
_V40_BASE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"


@pytest.fixture
def adapter() -> CvssBaseAdapter:
    """Return one stateless adapter instance."""

    return CvssBaseAdapter()


def test_v31_vector_is_calculated_and_report_ready(adapter: CvssBaseAdapter) -> None:
    """A conventional CVSS v3.1 vector can be reused without a second calculator."""

    result = adapter.adapt({"vector": _V31_CRITICAL})

    assert result.adapter_version == CVSS_ADAPTER_VERSION
    assert result.version is CvssVersion.V3_1
    assert result.base_score == 9.8
    assert result.severity is Severity.CRITICAL
    assert result.score_verification is CvssScoreVerification.CALCULATED
    assert result.metric_values == {
        "AV": "N",
        "AC": "L",
        "PR": "N",
        "UI": "N",
        "S": "U",
        "C": "H",
        "I": "H",
        "A": "H",
    }
    assert result.mapping_basis == CVSS_MAPPING_BASIS
    assert result.to_dict()["cvss_version"] == "3.1"


def test_v31_provided_score_and_severity_are_verified(
    adapter: CvssBaseAdapter,
) -> None:
    """Imported CVSS values must agree with the canonical Base vector."""

    result = adapter.adapt(
        CvssBaseInput(
            vector=_V31_HIGH,
            version="3.1",
            base_score=8.8,
            base_severity="HIGH",
        )
    )

    assert result.base_score == 8.8
    assert result.severity is Severity.HIGH
    assert result.score_verification is CvssScoreVerification.CALCULATED


def test_json_input_is_strict_and_deterministic(adapter: CvssBaseAdapter) -> None:
    """JSON input produces the same normalized assessment as mapping input."""

    payload = json.dumps(
        {
            "vector": _V31_CRITICAL,
            "base_score": 9.8,
            "base_severity": "critical",
        }
    )

    first = adapter.adapt_json(payload).to_dict()
    second = adapter.adapt_json(payload).to_dict()

    assert first == second
    assert json.dumps(first, ensure_ascii=False, sort_keys=True) == json.dumps(
        second,
        ensure_ascii=False,
        sort_keys=True,
    )


def test_v40_base_vector_is_calculated_locally_and_verifiable(
    adapter: CvssBaseAdapter,
) -> None:
    """v4 input is locally calculated and a supplied score is checked."""

    result = adapter.adapt(
        {
            "vector": _V40_BASE,
            "base_score": 10.0,
            "base_severity": "critical",
        }
    )

    assert result.version is CvssVersion.V4_0
    assert result.base_score == 10.0
    assert result.score_verification is CvssScoreVerification.CALCULATED
    assert len(result.metrics) == 11


def test_v40_known_base_vectors_match_reference_scores(
    adapter: CvssBaseAdapter,
) -> None:
    """Representative v4.0 Base vectors cover critical, none, and interpolation."""

    critical_subsequent = adapter.adapt(
        {"vector": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")}
    )
    all_impact = adapter.adapt(
        {"vector": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")}
    )
    no_impact = adapter.adapt(
        {"vector": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")}
    )

    assert critical_subsequent.base_score == 9.3
    assert all_impact.base_score == 10.0
    assert no_impact.base_score == 0.0
    assert no_impact.severity is Severity.NONE


def test_v40_provided_score_must_match_local_calculation(
    adapter: CvssBaseAdapter,
) -> None:
    """An imported v4.0 score cannot silently downgrade a local result."""

    with pytest.raises(CvssAdapterError) as captured:
        adapter.adapt(
            {
                "vector": (
                    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                ),
                "base_score": 9.2,
            }
        )

    assert captured.value.code is CvssAdapterCode.SCORE_MISMATCH


def test_severity_mapping_matches_cvss_qualitative_boundaries() -> None:
    """The 0–10 qualitative ranges remain separate from AgentSec base scores."""

    assert severity_for_cvss_score(0.0) is Severity.NONE
    assert severity_for_cvss_score(3.9) is Severity.LOW
    assert severity_for_cvss_score(4.0) is Severity.MEDIUM
    assert severity_for_cvss_score(6.9) is Severity.MEDIUM
    assert severity_for_cvss_score(7.0) is Severity.HIGH
    assert severity_for_cvss_score(8.9) is Severity.HIGH
    assert severity_for_cvss_score(9.0) is Severity.CRITICAL


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        ({"vector": _V31_CRITICAL, "base_score": 9.7}, CvssAdapterCode.SCORE_MISMATCH),
        (
            {"vector": _V31_CRITICAL, "base_severity": "high"},
            CvssAdapterCode.SEVERITY_MISMATCH,
        ),
        (
            {"vector": _V31_CRITICAL, "unexpected": "value"},
            CvssAdapterCode.UNKNOWN_INPUT_FIELD,
        ),
        (
            {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A"},
            CvssAdapterCode.INVALID_METRIC,
        ),
        (
            {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"},
            CvssAdapterCode.MISSING_METRIC,
        ),
        (
            {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "base_score": 10.01,
            },
            CvssAdapterCode.INVALID_SCORE,
        ),
    ],
)
def test_invalid_input_fails_closed_without_source_payload(
    adapter: CvssBaseAdapter,
    payload: dict[str, object],
    code: CvssAdapterCode,
) -> None:
    """Malformed external values return stable safe errors without echoing input."""

    with pytest.raises(CvssAdapterError) as captured:
        adapter.adapt(payload)

    assert captured.value.code is code
    assert "CVSS:" not in str(captured.value)


def test_version_must_match_vector_prefix(adapter: CvssBaseAdapter) -> None:
    """A caller cannot relabel one version's vector as another version."""

    with pytest.raises(CvssAdapterError) as captured:
        adapter.adapt({"vector": _V31_CRITICAL, "version": "4.0"})

    assert captured.value.code is CvssAdapterCode.UNSUPPORTED_VERSION


def test_unsupported_prefix_and_non_object_json_fail_safely(
    adapter: CvssBaseAdapter,
) -> None:
    """Unknown formats and JSON arrays do not reach scoring logic."""

    with pytest.raises(CvssAdapterError) as unsupported:
        adapter.adapt({"vector": "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"})
    assert unsupported.value.code is CvssAdapterCode.UNSUPPORTED_VERSION

    with pytest.raises(CvssAdapterError) as invalid_json:
        adapter.adapt_json("[]")
    assert invalid_json.value.code is CvssAdapterCode.INVALID_JSON
