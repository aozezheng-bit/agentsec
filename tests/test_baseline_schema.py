"""Validation, compatibility, and serialization tests for Baseline Schema."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from agentsec.baselines import (
    Baseline,
    BaselineAsset,
    BaselineMetadata,
    BaselineValidationCode,
    BaselineValidationError,
    decode_baseline_json,
    encode_baseline_json,
    export_baseline_json_schema,
    validate_baseline_payload,
)
from agentsec.domain import AssetSource, AssetType
from agentsec.versioning import BASELINE_SCHEMA_VERSION, current_versions

CONTENT_A = "# Agent instructions\n\nRequire human approval.\n"
CONTENT_B = "# Review skill\n\nReview changes without executing them.\n"
HASH_A = hashlib.sha256(CONTENT_A.encode()).hexdigest()
HASH_B = hashlib.sha256(CONTENT_B.encode()).hexdigest()
CONFIG_HASH = "c" * 64
GIT_COMMIT = "d" * 40
SECRET_MARKER = "token-never-copy-into-errors"


def make_asset(
    *,
    path: str = "AGENTS.md",
    content: str = CONTENT_A,
    asset_type: AssetType = AssetType.AGENTS,
) -> BaselineAsset:
    """Create an internally consistent baseline asset."""

    content_bytes = content.encode("utf-8")
    return BaselineAsset(
        path=path,
        asset_type=asset_type,
        source=AssetSource.DISCOVERED,
        sha256=hashlib.sha256(content_bytes).hexdigest(),
        size_bytes=len(content_bytes),
        line_count=len(content.splitlines()),
        content=content,
    )


def make_metadata() -> BaselineMetadata:
    """Create deterministic provenance using the current version vector."""

    versions = current_versions()
    return BaselineMetadata(
        scanner_version=versions.package,
        config_schema_version=versions.config_schema,
        domain_schema_version=versions.domain_schema,
        rule_pack_version=versions.rule_pack,
        risk_model_version=versions.risk_model,
        collection_config_sha256=CONFIG_HASH,
        generated_at=datetime(2026, 8, 18, 12, 0, tzinfo=UTC),
        git_commit=GIT_COMMIT,
        git_dirty=False,
    )


def make_baseline() -> Baseline:
    """Create a valid, canonically sorted baseline."""

    return Baseline(
        schema_version=BASELINE_SCHEMA_VERSION,
        metadata=make_metadata(),
        assets=(
            make_asset(),
            make_asset(
                path="skills/review/SKILL.md",
                content=CONTENT_B,
                asset_type=AssetType.SKILL,
            ),
        ),
    )


def test_baseline_round_trip_is_deterministic_and_preserves_content() -> None:
    """Repeated JSON encoding produces identical bytes and exact source text."""

    baseline = make_baseline()

    first = encode_baseline_json(baseline)
    decoded = decode_baseline_json(first)
    second = encode_baseline_json(decoded)

    assert first == second
    assert decoded == baseline
    assert decoded.assets[0].content == CONTENT_A
    assert json.loads(first)["schema_version"] == BASELINE_SCHEMA_VERSION


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sha256", "f" * 64),
        ("size_bytes", len(CONTENT_A.encode("utf-8")) + 1),
        ("line_count", len(CONTENT_A.splitlines()) + 1),
    ],
)
def test_baseline_asset_metadata_must_match_content(
    field: str,
    value: str | int,
) -> None:
    """A modified body cannot retain stale integrity metadata."""

    payload = make_asset().model_dump()
    payload[field] = value

    with pytest.raises(ValidationError):
        BaselineAsset.model_validate(payload)


def test_baseline_asset_rejects_unsafe_paths_and_invalid_unicode() -> None:
    """Baseline content stays project-relative and exactly UTF-8 encodable."""

    payload = make_asset().model_dump()
    payload["path"] = "../AGENTS.md"
    with pytest.raises(ValidationError):
        BaselineAsset.model_validate(payload)

    invalid_content = "\ud800"
    payload = make_asset().model_dump()
    payload.update(
        content=invalid_content,
        size_bytes=1,
        line_count=1,
        sha256="0" * 64,
    )
    with pytest.raises(ValidationError):
        BaselineAsset.model_validate(payload)


def test_baseline_metadata_requires_time_and_git_provenance_coherence() -> None:
    """Ambiguous timestamps and partial Git identity are not accepted."""

    payload = make_metadata().model_dump()
    payload["generated_at"] = datetime(2026, 8, 18, 12, 0)
    with pytest.raises(ValidationError):
        BaselineMetadata.model_validate(payload)

    payload = make_metadata().model_dump()
    payload["git_dirty"] = None
    with pytest.raises(ValidationError):
        BaselineMetadata.model_validate(payload)

    payload = make_metadata().model_dump()
    payload["git_commit"] = None
    payload["git_dirty"] = None
    metadata = BaselineMetadata.model_validate(payload)
    assert metadata.git_commit is None
    assert metadata.git_dirty is None


def test_baseline_assets_must_be_unique_and_sorted() -> None:
    """Canonical path order and identity are enforced by the schema model."""

    metadata = make_metadata()
    root_asset = make_asset()
    skill_asset = make_asset(
        path="skills/review/SKILL.md",
        content=CONTENT_B,
        asset_type=AssetType.SKILL,
    )

    with pytest.raises(ValidationError):
        Baseline(
            schema_version=BASELINE_SCHEMA_VERSION,
            metadata=metadata,
            assets=(skill_asset, root_asset),
        )

    with pytest.raises(ValidationError):
        Baseline(
            schema_version=BASELINE_SCHEMA_VERSION,
            metadata=metadata,
            assets=(root_asset, root_asset),
        )


def test_compatibility_is_checked_before_payload_shape() -> None:
    """An unsupported version wins over unrelated untrusted payload defects."""

    payload = {
        "schema_version": "0.2.0",
        "metadata": SECRET_MARKER,
        "assets": SECRET_MARKER,
    }

    with pytest.raises(BaselineValidationError) as captured:
        validate_baseline_payload(payload)

    assert captured.value.code is BaselineValidationCode.UNSUPPORTED_SCHEMA_VERSION
    assert SECRET_MARKER not in str(captured.value)


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        ([], BaselineValidationCode.INVALID_ROOT),
        ({}, BaselineValidationCode.MISSING_SCHEMA_VERSION),
        (
            {"schema_version": 1},
            BaselineValidationCode.INVALID_SCHEMA_VERSION,
        ),
        (
            {"schema_version": "v0.1"},
            BaselineValidationCode.INVALID_SCHEMA_VERSION,
        ),
    ],
)
def test_baseline_version_failures_have_stable_codes(
    payload: object,
    code: BaselineValidationCode,
) -> None:
    """Future CLI behavior can map each compatibility failure deterministically."""

    with pytest.raises(BaselineValidationError) as captured:
        validate_baseline_payload(payload)

    assert captured.value.code is code


def test_same_pre_one_minor_patch_is_compatible() -> None:
    """Patch releases preserve the 0.1 baseline structure and meaning."""

    payload = make_baseline().model_dump(mode="json")
    payload["schema_version"] = "0.1.99"

    baseline = validate_baseline_payload(payload)

    assert baseline.schema_version == "0.1.99"


def test_invalid_payload_error_exposes_only_field_paths() -> None:
    """Validation diagnostics never include rejected asset content."""

    payload = make_baseline().model_dump(mode="json")
    payload["assets"][0]["content"] = SECRET_MARKER
    payload["unexpected"] = SECRET_MARKER

    with pytest.raises(BaselineValidationError) as captured:
        validate_baseline_payload(payload)

    error = captured.value
    assert error.code is BaselineValidationCode.INVALID_PAYLOAD
    assert SECRET_MARKER not in str(error)
    assert "assets.0" in " ".join(error.field_paths)
    assert "unexpected" in error.field_paths


def test_invalid_json_has_a_safe_error() -> None:
    """Malformed JSON never leaks parser excerpts into the user-facing error."""

    with pytest.raises(BaselineValidationError) as captured:
        decode_baseline_json('{"schema_version": "0.1.0", "secret": invalid}')

    assert captured.value.code is BaselineValidationCode.INVALID_JSON
    assert "secret" not in str(captured.value)


def test_baseline_schema_export_is_deterministic_and_strict(tmp_path: Path) -> None:
    """The generated standalone schema is stable and rejects unknown fields."""

    first_path = export_baseline_json_schema(tmp_path / "first")
    second_path = export_baseline_json_schema(tmp_path / "second")

    assert first_path.read_bytes() == second_path.read_bytes()
    schema: dict[str, Any] = json.loads(first_path.read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["x-agentsec-baseline-schema-version"] == "0.1.0"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {"schema_version", "metadata", "assets"}
    assert "BaselineAsset" in schema["$defs"]
    assert schema["$defs"]["BaselineAsset"]["additionalProperties"] is False
    assert "content" in schema["$defs"]["BaselineAsset"]["required"]
