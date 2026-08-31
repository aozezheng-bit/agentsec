"""Build, validate, and import the P2-CAL-04A independent Reviewer Pack.

The build operation reads bounded inert calibration data, validates any supplied
Source View against a strict schema, and regenerates a canonical Reviewer View.
It never copies untrusted source text verbatim and never executes fixture data.

Operations:
  build     Create a new deterministic Reviewer Pack (default).
  validate  Validate completed Reviewer A/B submissions and optional adjudication.
  import    Validate submissions and convert them into the formal P2-CAL-04
            AdjudicationReviewSet consumed by the existing Runner.

Exit codes:
  0 = operation completed
  4 = input or output path/format is invalid
  5 = unexpected failure
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from agentsec.calibration import (
    AdjudicationCategory,
    AdjudicationResolution,
    AdjudicationResolutionSet,
    AdjudicationReviewLabel,
    AdjudicationReviewSet,
    AdjudicationStatus,
    CalibrationClassification,
    CalibrationCorpusError,
    CalibrationRuleOutcome,
    ConfidenceReviewLabel,
    ConfidenceReviewSet,
    ConfidenceReviewStatus,
    DeterministicFactBundleEvaluator,
    RuleDisposition,
    encode_adjudication_resolution_set_json,
    encode_adjudication_review_set_json,
    encode_confidence_review_set_json,
    load_calibration_corpus,
)
from agentsec.calibration.corpus import LoadedCalibrationCorpus
from agentsec.calibration.models import CalibrationCase
from agentsec.capability_rules import (
    CapabilityCorrelation,
    CapabilityRuleLanguage,
    builtin_capability_rules,
)
from agentsec.domain import EvidenceConfidence

EXIT_OK = 0
EXIT_INVALID = 4
EXIT_FAILED = 5

_PACK_SCHEMA_VERSION = "0.3.0"
_PACK_MANIFEST_FORMAT = "agentsec-independent-reviewer-pack-manifest"
_REVIEW_CASE_FORMAT = "agentsec-independent-review-case"
_REVIEW_MATRIX_FORMAT = "agentsec-independent-review-case-matrix"
_REVIEW_LABEL_FORMAT = "agentsec-independent-review-label-template"
_ADJUDICATION_LABEL_FORMAT = "agentsec-independent-adjudication-template"
_BLINDING_SALT = "agentsec-p2-cal-04a-reviewer-pack-v2"

_MAX_INDEX_BYTES = 256 * 1024
_MAX_CASE_BYTES = 512 * 1024
_MAX_SOURCE_BYTES = 512 * 1024
_MAX_LABEL_BYTES = 8 * 1024 * 1024
_MAX_CASES = 10_000
_MAX_REVIEWS = 20_000
_MAX_EVIDENCE_LOCATIONS = 16
_MAX_NOTES_LENGTH = 2_000
_MAX_SUMMARY_LENGTH = 512

_SOURCE_FILENAMES = {
    "json": "source.json",
    "manifest": "source.manifest.json",
    "markdown": "source.md",
    "toml": "source.toml",
    "yaml": "source.yaml",
}
_SOURCE_FORMATS = frozenset(_SOURCE_FILENAMES)
_FACT_DIMENSIONS = frozenset(
    {
        "tool",
        "permission",
        "control",
        "runtime_identity",
        "relationship",
        "unknown",
        "coverage",
    }
)
_FACT_STATES = frozenset({"present", "absent", "unknown"})
_HUMAN_CONDITION_LABELS = ("match", "no_match", "uncertain")
_OBSERVED_FINDINGS = ("present", "absent", "uncertain")
_REVIEW_CATEGORIES = (
    "standard",
    "policy_accepted_risk",
    "out_of_scope",
    "runtime_uncertainty",
    "unresolved",
)
_CONFIDENCES = ("A", "B", "C", "D")
_CORRELATIONS = (
    "same_target",
    "parent_child",
    "same_source",
    "explicit_relation",
    "agent_wide",
    "incomplete_coverage",
)
_DISPOSITIONS = ("keep", "tune", "shadow", "retire", "more_data")

_STABLE_ID_PATTERN = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")
_RULE_ID_PATTERN = re.compile(r"^CAP-[A-Z0-9]+-[0-9]{3}$")
_REVIEW_CASE_ID_PATTERN = re.compile(r"^review-case-[0-9a-f]{20}$")
_HASH_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_PACK_ID_PATTERN = re.compile(r"^reviewer-pack-sha256:[0-9a-f]{64}$")
_SAFE_PATH_PATTERN = re.compile(r"^[A-Za-z0-9._/-]{1,256}$")
_MARKDOWN_FACT_PATTERN = re.compile(
    r"^- `(?P<dimension>[a-z_]+)` / `(?P<key>[a-z0-9._:-]+)` / "
    r"`(?P<state>present|absent|unknown)` / `(?P<target>[a-z0-9._:-]+|none)`$"
)
_SENSITIVE_SOURCE_PATTERNS = (
    re.compile(r"authorization\s*:", re.IGNORECASE),
    re.compile(r"bearer\s+", re.IGNORECASE),
    re.compile(r"(?:api[_-]?key|password|access[_-]?token)\s*[:=]", re.IGNORECASE),
)


class _InputError(RuntimeError):
    """Safe invalid-input failure without untrusted values."""


class _OutputError(RuntimeError):
    """Safe output-creation failure."""


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        raise SystemExit(EXIT_INVALID) from None


@dataclass(frozen=True, slots=True)
class _ReviewFact:
    dimension: str
    key: str
    state: str
    target_id: str | None

    def as_json(self) -> dict[str, object]:
        return {
            "dimension": self.dimension,
            "key": self.key,
            "state": self.state,
            "target_id": self.target_id,
        }


@dataclass(frozen=True, slots=True)
class _ReviewQuestion:
    question_id: str
    rule_id: str
    title: dict[str, str]
    condition: dict[str, str]
    prompt: dict[str, str]

    def as_json(self) -> dict[str, object]:
        return {
            "condition": self.condition,
            "prompt": self.prompt,
            "question_id": self.question_id,
            "rule_id": self.rule_id,
            "title": self.title,
        }


@dataclass(frozen=True, slots=True)
class _ReviewCase:
    original_case_id: str
    review_case_id: str
    language: str
    input_format: str
    source_filename: str
    source_text: str
    source_sha256: str
    question_set_sha256: str
    review_case_fingerprint: str
    questions: tuple[_ReviewQuestion, ...]

    @property
    def line_count(self) -> int:
        return max(1, len(self.source_text.splitlines()))

    @property
    def reviewer_evidence_path(self) -> str:
        return f"cases/{self.review_case_id}/{self.source_filename}"


@dataclass(frozen=True, slots=True)
class _PackData:
    corpus: LoadedCalibrationCorpus
    corpus_binding_hash: str
    pack_id: str
    cases: tuple[_ReviewCase, ...]

    @property
    def question_count(self) -> int:
        return sum(len(case.questions) for case in self.cases)


@dataclass(frozen=True, slots=True)
class _PackSummary:
    case_count: int
    question_count: int
    pack_id: str


def _fail_input(message: str) -> None:
    raise _InputError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail_input(message)


def _safe_relative_parts(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value:
        _fail_input(f"{label} must be a non-empty relative path")
    if value.startswith("/") or "\\" in value:
        _fail_input(f"{label} must be a safe relative path")
    parts = tuple(value.split("/"))
    if any(part in {"", ".", ".."} for part in parts):
        _fail_input(f"{label} must be a safe relative path")
    return parts


def _reject_symlink_components(root: Path, parts: tuple[str, ...]) -> None:
    current = root
    for part in parts:
        current = current / part
        if current.is_symlink():
            _fail_input("input path contains a symlink")


def _safe_child(
    root: Path,
    relative: object,
    *,
    label: str,
    kind: str,
) -> Path:
    parts = _safe_relative_parts(relative, label)
    _reject_symlink_components(root, parts)
    candidate = root.joinpath(*parts)
    try:
        resolved = candidate.resolve()
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise _InputError(f"{label} escapes its root") from error
    if resolved == root:
        _fail_input(f"{label} cannot be the root")
    if kind == "file" and not resolved.is_file():
        _fail_input(f"{label} is missing")
    if kind == "directory" and not resolved.is_dir():
        _fail_input(f"{label} is missing")
    return resolved


def _resolve_directory(raw_path: Path, label: str) -> Path:
    lexical = Path(os.path.abspath(raw_path))
    if lexical.is_symlink() or not lexical.is_dir():
        _fail_input(f"{label} is not a directory or is a symlink")
    try:
        resolved = lexical.resolve()
    except OSError as error:
        raise _InputError(f"{label} cannot be resolved") from error
    if not resolved.is_dir():
        _fail_input(f"{label} is not a directory")
    return resolved


def _read_bounded_text(path: Path, limit: int, label: str) -> str:
    if path.is_symlink() or not path.is_file():
        _fail_input(f"{label} is missing or unsafe")
    try:
        data = path.read_bytes()
    except OSError as error:
        raise _InputError(f"{label} cannot be read") from error
    if len(data) > limit:
        _fail_input(f"{label} exceeds the bounded size")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise _InputError(f"{label} must be UTF-8") from error


def _read_json_object(path: Path, limit: int, label: str) -> dict[str, Any]:
    text = _read_bounded_text(path, limit, label)
    try:
        payload: object = json.loads(text)
    except (ValueError, RecursionError) as error:
        raise _InputError(f"{label} must contain valid JSON") from error
    if not isinstance(payload, dict):
        _fail_input(f"{label} must contain a JSON object")
    return payload


def _read_explicit_json(path: Path, label: str) -> dict[str, Any]:
    lexical = Path(os.path.abspath(path))
    if lexical.is_symlink() or not lexical.is_file():
        _fail_input(f"{label} is missing or is a symlink")
    return _read_json_object(lexical.resolve(), _MAX_LABEL_BYTES, label)


def _exact_keys(value: dict[str, Any], keys: set[str], label: str) -> None:
    if set(value) != keys:
        _fail_input(f"{label} contains unsupported or missing fields")


def _json_text(payload: object) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _canonical_json_bytes(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _sha256_json(payload: object) -> str:
    return _sha256_bytes(_canonical_json_bytes(payload))


def _review_case_id(corpus_id: str, case_id: str) -> str:
    material = f"{_BLINDING_SALT}:{corpus_id}:{case_id}".encode()
    return "review-case-" + hashlib.sha256(material).hexdigest()[:20]


def _preflight_corpus_paths(root: Path) -> None:
    """Reject unsafe paths before the standard Loader opens fixture assets."""

    index_path = _safe_child(root, "corpus.json", label="corpus index", kind="file")
    index = _read_json_object(index_path, _MAX_INDEX_BYTES, "corpus index")
    raw_case_paths = index.get("case_paths")
    if not isinstance(raw_case_paths, list) or not raw_case_paths:
        _fail_input("corpus index case_paths must be a non-empty list")
    if len(raw_case_paths) > _MAX_CASES:
        _fail_input("corpus index contains too many Cases")

    for raw_case_path in raw_case_paths:
        case_path = _safe_child(
            root, raw_case_path, label="calibration Case", kind="file"
        )
        case = _read_json_object(case_path, _MAX_CASE_BYTES, "calibration Case")
        fixture = case.get("fixture")
        if not isinstance(fixture, dict):
            _fail_input("calibration Case fixture must be an object")
        fixture_path_value = fixture.get("path")
        fixture_kind = fixture.get("kind")
        if fixture_kind == "project":
            fixture_path = _safe_child(
                root,
                fixture_path_value,
                label="project fixture",
                kind="directory",
            )
            assets = fixture.get("assets", [])
            if not isinstance(assets, list):
                _fail_input("project fixture assets must be a list")
            for asset in assets:
                _safe_child(
                    fixture_path,
                    asset,
                    label="project fixture asset",
                    kind="file",
                )
        else:
            fixture_path = _safe_child(
                root, fixture_path_value, label="calibration fixture", kind="file"
            )

        labels = case.get("ground_truth")
        if not isinstance(labels, dict):
            _fail_input("calibration Case labels must be an object")
        facts = labels.get("facts")
        if not isinstance(facts, list):
            _fail_input("calibration Case facts must be a list")
        evidence_root = (
            fixture_path if fixture_kind == "project" else fixture_path.parent
        )
        for fact in facts:
            if not isinstance(fact, dict):
                _fail_input("calibration fact must be an object")
            evidence = fact.get("evidence")
            if not isinstance(evidence, list):
                _fail_input("calibration fact evidence must be a list")
            for reference in evidence:
                if not isinstance(reference, dict):
                    _fail_input("calibration evidence reference must be an object")
                _safe_child(
                    evidence_root,
                    reference.get("asset_path"),
                    label="calibration evidence asset",
                    kind="file",
                )


def _validate_stable_id(value: object, label: str) -> str:
    if not isinstance(value, str) or _STABLE_ID_PATTERN.fullmatch(value) is None:
        _fail_input(f"{label} must use the stable identifier form")
    return value


def _validate_review_fact(value: object, label: str) -> _ReviewFact:
    if not isinstance(value, dict):
        _fail_input(f"{label} must be an object")
    _exact_keys(value, {"dimension", "key", "state", "target_id"}, label)
    dimension = value["dimension"]
    state = value["state"]
    if not isinstance(dimension, str) or dimension not in _FACT_DIMENSIONS:
        _fail_input(f"{label} dimension is unsupported")
    key = _validate_stable_id(value["key"], f"{label} key")
    if not isinstance(state, str) or state not in _FACT_STATES:
        _fail_input(f"{label} state is unsupported")
    raw_target = value["target_id"]
    target_id = (
        None
        if raw_target is None
        else _validate_stable_id(raw_target, f"{label} target_id")
    )
    return _ReviewFact(
        dimension=dimension,
        key=key,
        state=state,
        target_id=target_id,
    )


def _strip_none(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: _strip_none(item) for key, item in value.items() if item is not None
        }
    if isinstance(value, list):
        return [_strip_none(item) for item in value]
    return value


def _load_fixture_facts(root: Path, case: CalibrationCase) -> tuple[_ReviewFact, ...]:
    if case.fixture.kind.value != "fact_bundle":
        _fail_input("Reviewer Pack requires inert fact-bundle Fixtures")
    path = _safe_child(
        root, case.fixture.path, label="calibration fact bundle", kind="file"
    )
    payload = _read_json_object(path, _MAX_CASE_BYTES, "calibration fact bundle")
    _exact_keys(payload, {"case_id", "facts", "fixture_version"}, "fact bundle")
    if payload["case_id"] != case.case_id or payload["fixture_version"] != "0.1.0":
        _fail_input("calibration fact bundle identity is invalid")
    raw_facts = payload["facts"]
    if not isinstance(raw_facts, list):
        _fail_input("calibration fact bundle facts must be a list")
    for raw_fact in raw_facts:
        if not isinstance(raw_fact, dict):
            _fail_input("calibration fact bundle fact must be an object")
        _exact_keys(
            raw_fact,
            {"dimension", "evidence", "fact_id", "key", "state", "target_id"},
            "calibration fact bundle fact",
        )
        evidence = raw_fact["evidence"]
        if not isinstance(evidence, list):
            _fail_input("calibration fact bundle evidence must be a list")
        for reference in evidence:
            if not isinstance(reference, dict):
                _fail_input("calibration fact bundle evidence must be an object")
            if (
                not {"asset_path"}
                <= set(reference)
                <= {
                    "asset_path",
                    "field_path",
                    "start_line",
                    "end_line",
                }
            ):
                _fail_input("calibration fact bundle evidence fields are invalid")
    expected_payload = [
        fact.model_dump(mode="json") for fact in case.ground_truth.facts
    ]
    if _strip_none(raw_facts) != _strip_none(expected_payload):
        _fail_input("calibration fact bundle does not match the validated Case")
    return tuple(
        _ReviewFact(
            dimension=fact.dimension.value,
            key=fact.key,
            state=fact.state.value,
            target_id=fact.target_id,
        )
        for fact in case.ground_truth.facts
    )


def _reject_sensitive_source(text: str) -> None:
    if any(pattern.search(text) for pattern in _SENSITIVE_SOURCE_PATTERNS):
        _fail_input("synthetic review source contains secret-like material")


def _facts_from_structured_source(
    payload: object,
    *,
    case_id: str,
    input_format: str,
) -> tuple[_ReviewFact, ...]:
    if not isinstance(payload, dict):
        _fail_input("synthetic review source root must be an object")
    if input_format in {"json", "manifest"}:
        _exact_keys(
            payload,
            {"case_id", "facts", "format", "synthetic"},
            "synthetic review source",
        )
        if not isinstance(payload["format"], str):
            _fail_input("synthetic review source format is invalid")
    else:
        _exact_keys(
            payload,
            {"case_id", "facts", "synthetic", "title"},
            "synthetic review source",
        )
        if not isinstance(payload["title"], str) or not payload["title"].strip():
            _fail_input("synthetic review source title is invalid")
    if payload["case_id"] != case_id or payload["synthetic"] is not True:
        _fail_input("synthetic review source identity is invalid")
    raw_facts = payload["facts"]
    if not isinstance(raw_facts, list):
        _fail_input("synthetic review source facts must be a list")
    facts = []
    for index, raw_fact in enumerate(raw_facts):
        facts.append(_validate_review_fact(raw_fact, f"source fact {index}"))
    return tuple(facts)


def _facts_from_markdown_source(
    text: str,
    *,
    case_id: str,
) -> tuple[_ReviewFact, ...]:
    lines = text.splitlines()
    non_empty = [line for line in lines if line]
    if len(non_empty) < 4:
        _fail_input("synthetic Markdown source is incomplete")
    if non_empty[0] not in {
        "# Synthetic static capability review input",
        "# 合成静态能力评审输入",
    }:
        _fail_input("synthetic Markdown source heading is invalid")
    if non_empty[1] != f"- Case: `{case_id}`":
        _fail_input("synthetic Markdown source identity is invalid")
    if non_empty[2] != "- Synthetic: `true`":
        _fail_input("synthetic Markdown source marker is invalid")
    if non_empty[3] != "## Declared facts":
        _fail_input("synthetic Markdown source structure is invalid")
    facts = []
    for index, line in enumerate(non_empty[4:]):
        match = _MARKDOWN_FACT_PATTERN.fullmatch(line)
        if match is None:
            _fail_input("synthetic Markdown source contains unsupported content")
        target = match.group("target")
        facts.append(
            _validate_review_fact(
                {
                    "dimension": match.group("dimension"),
                    "key": match.group("key"),
                    "state": match.group("state"),
                    "target_id": None if target == "none" else target,
                },
                f"Markdown source fact {index}",
            )
        )
    return tuple(facts)


def _validate_existing_source(
    path: Path,
    *,
    case_id: str,
    input_format: str,
    expected_facts: tuple[_ReviewFact, ...],
) -> None:
    text = _read_bounded_text(path, _MAX_SOURCE_BYTES, "synthetic review source")
    _reject_sensitive_source(text)
    try:
        if input_format in {"json", "manifest"}:
            payload: object = json.loads(text)
            observed = _facts_from_structured_source(
                payload, case_id=case_id, input_format=input_format
            )
        elif input_format == "yaml":
            payload = yaml.safe_load(text)
            observed = _facts_from_structured_source(
                payload, case_id=case_id, input_format=input_format
            )
        elif input_format == "toml":
            payload = tomllib.loads(text)
            observed = _facts_from_structured_source(
                payload, case_id=case_id, input_format=input_format
            )
        elif input_format == "markdown":
            observed = _facts_from_markdown_source(text, case_id=case_id)
        else:
            _fail_input("synthetic review source format is unsupported")
    except (ValueError, yaml.YAMLError, tomllib.TOMLDecodeError) as error:
        raise _InputError("synthetic review source is invalid") from error
    if observed != expected_facts:
        _fail_input("synthetic review source does not match the validated Fixture")


def _json_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _render_source(
    *,
    review_case_id: str,
    input_format: str,
    language: str,
    facts: tuple[_ReviewFact, ...],
) -> str:
    fact_payload = [fact.as_json() for fact in facts]
    if input_format in {"json", "manifest"}:
        view_format = (
            "synthetic-agent-manifest-review-view"
            if input_format == "manifest"
            else "synthetic-static-review-view"
        )
        return _json_text(
            {
                "facts": fact_payload,
                "format": view_format,
                "review_case_id": review_case_id,
                "synthetic": True,
            }
        )
    title = (
        "Synthetic static capability review input / 合成静态能力评审输入"
        if language == "bilingual"
        else "合成静态能力评审输入"
        if language == "zh"
        else "Synthetic static capability review input"
    )
    if input_format == "yaml":
        lines = [
            f"title: {_json_string(title)}",
            "synthetic: true",
            f"review_case_id: {review_case_id}",
            "facts:",
        ]
        for fact in facts:
            lines.extend(
                (
                    f"  - dimension: {fact.dimension}",
                    f"    key: {fact.key}",
                    f"    state: {fact.state}",
                    "    target_id: "
                    + (fact.target_id if fact.target_id is not None else "null"),
                )
            )
        return "\n".join(lines) + "\n"
    if input_format == "toml":
        lines = [
            f"title = {_json_string(title)}",
            "synthetic = true",
            f"review_case_id = {_json_string(review_case_id)}",
            "",
        ]
        for fact in facts:
            if fact.target_id is None:
                _fail_input("TOML Reviewer View cannot represent a null target")
            lines.extend(
                (
                    "[[facts]]",
                    f"dimension = {_json_string(fact.dimension)}",
                    f"key = {_json_string(fact.key)}",
                    f"state = {_json_string(fact.state)}",
                    f"target_id = {_json_string(fact.target_id)}",
                    "",
                )
            )
        return "\n".join(lines)
    if input_format == "markdown":
        lines = [
            f"# {title}",
            "",
            f"- Review Case: `{review_case_id}`",
            "- Synthetic: `true`",
            "",
            "## Declared facts",
        ]
        for fact in facts:
            target = fact.target_id if fact.target_id is not None else "none"
            lines.append(
                f"- `{fact.dimension}` / `{fact.key}` / `{fact.state}` / `{target}`"
            )
        return "\n".join(lines) + "\n"
    _fail_input("Reviewer View output format is unsupported")


def _localized_rule_texts(
    case_language: str,
    rule_id: str,
    review_case_id: str,
    rules_by_id: dict[str, Any],
) -> _ReviewQuestion:
    metadata = rules_by_id.get(rule_id)
    if metadata is None:
        _fail_input("review Case references an unknown Capability Rule")
    languages = (
        (CapabilityRuleLanguage.EN,)
        if case_language == "en"
        else (CapabilityRuleLanguage.ZH,)
        if case_language == "zh"
        else (CapabilityRuleLanguage.EN, CapabilityRuleLanguage.ZH)
    )
    titles: dict[str, str] = {}
    conditions: dict[str, str] = {}
    prompts: dict[str, str] = {}
    for language in languages:
        text = metadata.text_for(language)
        titles[language.value] = text.title
        conditions[language.value] = text.description
        prompts[language.value] = (
            "Independently label the human Rule condition as match, no_match, or "
            "uncertain; record your direct finding observation, policy/scope "
            "category, evidence location, Confidence, Correlation, disposition, "
            "rationale code, and notes. Do not calculate TP/FP/FN/TN."
            if language is CapabilityRuleLanguage.EN
            else "请独立将人工规则条件标记为 match、no_match 或 uncertain，并填写"
            "直接观察、策略或范围类别、证据位置、置信度、关联方式、处置意见、理由"
            "代码和备注。不要自行计算 TP/FP/FN/TN。"
        )
    return _ReviewQuestion(
        question_id=f"question:{review_case_id}:{rule_id}",
        rule_id=rule_id,
        title=titles,
        condition=conditions,
        prompt=prompts,
    )


def _corpus_binding_hash(corpus: LoadedCalibrationCorpus) -> str:
    payload = {
        "index": corpus.index.model_dump(mode="json"),
        "cases": [case.model_dump(mode="json") for case in corpus.cases],
    }
    return _sha256_json(payload)


def _load_pack_data(root: Path) -> _PackData:
    _preflight_corpus_paths(root)
    try:
        corpus = load_calibration_corpus(root)
    except CalibrationCorpusError as error:
        raise _InputError("calibration corpus failed validation") from error
    if len(corpus.cases) > _MAX_CASES:
        _fail_input("calibration corpus contains too many Cases")

    binding_hash = _corpus_binding_hash(corpus)
    rules_by_id = {
        rule.metadata.rule_id: rule.metadata for rule in builtin_capability_rules()
    }
    review_cases = []
    seen_review_ids: set[str] = set()
    for case in corpus.cases:
        review_case_id = _review_case_id(corpus.index.corpus_id, case.case_id)
        if review_case_id in seen_review_ids:
            _fail_input("opaque review Case identity collision")
        seen_review_ids.add(review_case_id)
        input_format = case.source_formats[0].value
        if input_format not in _SOURCE_FORMATS:
            _fail_input("review Case source format is unsupported")
        source_filename = _SOURCE_FILENAMES[input_format]
        facts = _load_fixture_facts(root, case)
        source_relative = (Path(case.fixture.path).parent / source_filename).as_posix()
        source_candidate = root / source_relative
        if source_candidate.is_symlink():
            _fail_input("synthetic review source is a symlink")
        if source_candidate.exists():
            source_path = _safe_child(
                root,
                source_relative,
                label="synthetic review source",
                kind="file",
            )
            _validate_existing_source(
                source_path,
                case_id=case.case_id,
                input_format=input_format,
                expected_facts=facts,
            )
        source_text = _render_source(
            review_case_id=review_case_id,
            input_format=input_format,
            language=case.language.value,
            facts=facts,
        )
        _reject_sensitive_source(source_text)
        source_sha256 = _sha256_bytes(source_text.encode("utf-8"))
        questions = tuple(
            _localized_rule_texts(
                case.language.value,
                rule_id,
                review_case_id,
                rules_by_id,
            )
            for rule_id in sorted(
                expectation.rule_id
                for expectation in case.ground_truth.rule_expectations
            )
        )
        question_hash = _sha256_json([question.as_json() for question in questions])
        fingerprint = _sha256_json(
            {
                "input_format": input_format,
                "language": case.language.value,
                "question_set_sha256": question_hash,
                "review_case_id": review_case_id,
                "source_sha256": source_sha256,
            }
        )
        review_cases.append(
            _ReviewCase(
                original_case_id=case.case_id,
                review_case_id=review_case_id,
                language=case.language.value,
                input_format=input_format,
                source_filename=source_filename,
                source_text=source_text,
                source_sha256=source_sha256,
                question_set_sha256=question_hash,
                review_case_fingerprint=fingerprint,
                questions=questions,
            )
        )
    ordered = tuple(sorted(review_cases, key=lambda item: item.review_case_id))
    pack_digest = hashlib.sha256(
        _canonical_json_bytes(
            {
                "corpus_binding_hash": binding_hash,
                "pack_schema_version": _PACK_SCHEMA_VERSION,
                "review_cases": [
                    {
                        "review_case_fingerprint": case.review_case_fingerprint,
                        "review_case_id": case.review_case_id,
                    }
                    for case in ordered
                ],
            }
        )
    ).hexdigest()
    return _PackData(
        corpus=corpus,
        corpus_binding_hash=binding_hash,
        pack_id="reviewer-pack-sha256:" + pack_digest,
        cases=ordered,
    )


def _binding_fields(pack: _PackData, case: _ReviewCase) -> dict[str, str]:
    return {
        "corpus_binding_hash": pack.corpus_binding_hash,
        "pack_id": pack.pack_id,
        "question_set_sha256": case.question_set_sha256,
        "review_case_fingerprint": case.review_case_fingerprint,
        "source_sha256": case.source_sha256,
    }


def _review_case_payload(pack: _PackData, case: _ReviewCase) -> dict[str, object]:
    return {
        **_binding_fields(pack, case),
        "format": _REVIEW_CASE_FORMAT,
        "input_format": case.input_format,
        "language": case.language,
        "review_case_id": case.review_case_id,
        "review_questions": [question.as_json() for question in case.questions],
        "schema_version": _PACK_SCHEMA_VERSION,
        "source_location": {
            "end_line": case.line_count,
            "path": case.source_filename,
            "start_line": 1,
        },
        "synthetic_fixture": True,
    }


def _review_record(
    reviewer_id: str,
    pack: _PackData,
    case: _ReviewCase,
    question: _ReviewQuestion,
) -> dict[str, object]:
    return {
        **_binding_fields(pack, case),
        "category": None,
        "classification": None,
        "confidence": None,
        "correlation": None,
        "disposition": None,
        "evidence_locations": [],
        "finding_summary": None,
        "human_condition_label": None,
        "observed_finding": None,
        "rationale_code": None,
        "review_case_id": case.review_case_id,
        "review_id": (f"review:{reviewer_id}:{case.review_case_id}:{question.rule_id}"),
        "review_notes": "",
        "reviewer_id": reviewer_id,
        "rule_id": question.rule_id,
        "status": None,
    }


def _review_template_payload(reviewer_id: str, pack: _PackData) -> dict[str, object]:
    return {
        "corpus_binding_hash": pack.corpus_binding_hash,
        "format": _REVIEW_LABEL_FORMAT,
        "pack_id": pack.pack_id,
        "reviewer_id": reviewer_id,
        "reviews": [
            _review_record(reviewer_id, pack, case, question)
            for case in pack.cases
            for question in case.questions
        ],
        "schema_version": _PACK_SCHEMA_VERSION,
    }


def _adjudication_record(
    pack: _PackData,
    case: _ReviewCase,
    question: _ReviewQuestion,
) -> dict[str, object]:
    return {
        **_binding_fields(pack, case),
        "adjudication_id": f"adjudication:{case.review_case_id}:{question.rule_id}",
        "adjudication_notes": "",
        "category": None,
        "classification": None,
        "confidence": None,
        "correlation": None,
        "disposition": None,
        "evidence_locations": [],
        "finding_summary": None,
        "human_condition_label": None,
        "observed_finding": None,
        "rationale_code": None,
        "review_case_id": case.review_case_id,
        "review_ids": [
            f"review:reviewer-a:{case.review_case_id}:{question.rule_id}",
            f"review:reviewer-b:{case.review_case_id}:{question.rule_id}",
        ],
        "rule_id": question.rule_id,
        "status": None,
    }


def _adjudication_template_payload(pack: _PackData) -> dict[str, object]:
    return {
        "adjudications": [
            _adjudication_record(pack, case, question)
            for case in pack.cases
            for question in case.questions
        ],
        "corpus_binding_hash": pack.corpus_binding_hash,
        "format": _ADJUDICATION_LABEL_FORMAT,
        "pack_id": pack.pack_id,
        "schema_version": _PACK_SCHEMA_VERSION,
    }


def _pack_file_role_scope(relative: str) -> tuple[str, str]:
    if relative.startswith("reviewer-a/cases/"):
        role = "review_case" if relative.endswith("/case.json") else "review_source"
        return role, "reviewer-a"
    if relative.startswith("reviewer-b/cases/"):
        role = "review_case" if relative.endswith("/case.json") else "review_source"
        return role, "reviewer-b"
    if relative == "reviewer-a/labels.template.json":
        return "review_label_template", "reviewer-a"
    if relative == "reviewer-b/labels.template.json":
        return "review_label_template", "reviewer-b"
    if relative.startswith("adjudicator/"):
        return "adjudication_material", "adjudicator"
    return "pack_metadata", "coordinator"


def _pack_manifest(
    pack: _PackData, payloads_without_manifest: dict[str, bytes]
) -> dict[str, object]:
    files = []
    for relative, data in sorted(payloads_without_manifest.items()):
        role, scope = _pack_file_role_scope(relative)
        files.append(
            {
                "mode": "0600",
                "path": relative,
                "reviewer_scope": scope,
                "role": role,
                "sha256": _sha256_bytes(data),
                "size": len(data),
            }
        )
    return {
        "case_count": len(pack.cases),
        "cases": [
            {
                **_binding_fields(pack, case),
                "review_case_id": case.review_case_id,
            }
            for case in pack.cases
        ],
        "corpus_binding_hash": pack.corpus_binding_hash,
        "files": files,
        "format": _PACK_MANIFEST_FORMAT,
        "manifest_self_excluded": True,
        "pack_id": pack.pack_id,
        "question_count": pack.question_count,
        "schema_version": _PACK_SCHEMA_VERSION,
    }


def _matrix_rows(pack: _PackData) -> list[dict[str, object]]:
    return [
        {
            **_binding_fields(pack, case),
            "input_format": case.input_format,
            "language": case.language,
            "question_count": len(case.questions),
            "review_case_id": case.review_case_id,
            "reviewer_a_case_path": (
                f"reviewer-a/cases/{case.review_case_id}/case.json"
            ),
            "reviewer_b_case_path": (
                f"reviewer-b/cases/{case.review_case_id}/case.json"
            ),
            "synthetic_fixture": True,
        }
        for case in pack.cases
    ]


def _case_matrix_json(pack: _PackData) -> dict[str, object]:
    rows = _matrix_rows(pack)
    return {
        "case_count": len(rows),
        "cases": rows,
        "corpus_binding_hash": pack.corpus_binding_hash,
        "format": _REVIEW_MATRIX_FORMAT,
        "pack_id": pack.pack_id,
        "schema_version": _PACK_SCHEMA_VERSION,
    }


def _case_matrix_csv(pack: _PackData) -> str:
    fieldnames = [
        "review_case_id",
        "language",
        "input_format",
        "synthetic_fixture",
        "question_count",
        "source_sha256",
        "question_set_sha256",
        "review_case_fingerprint",
        "pack_id",
        "corpus_binding_hash",
        "reviewer_a_case_path",
        "reviewer_b_case_path",
    ]
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    writer.writerows(_matrix_rows(pack))
    return output.getvalue()


def _nullable_enum(values: tuple[str, ...]) -> dict[str, object]:
    return {"enum": [None, *values]}


def _evidence_schema() -> dict[str, object]:
    return {
        "items": {
            "additionalProperties": False,
            "description": "The importer also enforces end_line >= start_line.",
            "properties": {
                "end_line": {"maximum": 1_000_000, "minimum": 1, "type": "integer"},
                "path": {
                    "maxLength": 256,
                    "minLength": 1,
                    "pattern": r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9._/-]+$",
                    "type": "string",
                },
                "start_line": {
                    "maximum": 1_000_000,
                    "minimum": 1,
                    "type": "integer",
                },
            },
            "required": ["path", "start_line", "end_line"],
            "type": "object",
        },
        "maxItems": _MAX_EVIDENCE_LOCATIONS,
        "type": "array",
    }


def _binding_schema_properties() -> dict[str, object]:
    hash_schema = {
        "pattern": r"^sha256:[0-9a-f]{64}$",
        "type": "string",
    }
    return {
        "corpus_binding_hash": hash_schema,
        "pack_id": {
            "pattern": r"^reviewer-pack-sha256:[0-9a-f]{64}$",
            "type": "string",
        },
        "question_set_sha256": hash_schema,
        "review_case_fingerprint": hash_schema,
        "source_sha256": hash_schema,
    }


def _review_label_schema() -> dict[str, object]:
    record_properties: dict[str, object] = {
        **_binding_schema_properties(),
        "category": _nullable_enum(_REVIEW_CATEGORIES),
        "classification": {"const": None},
        "confidence": _nullable_enum(_CONFIDENCES),
        "correlation": _nullable_enum(_CORRELATIONS),
        "disposition": _nullable_enum(_DISPOSITIONS),
        "evidence_locations": _evidence_schema(),
        "finding_summary": {
            "maxLength": _MAX_SUMMARY_LENGTH,
            "type": ["string", "null"],
        },
        "human_condition_label": _nullable_enum(_HUMAN_CONDITION_LABELS),
        "observed_finding": _nullable_enum(_OBSERVED_FINDINGS),
        "rationale_code": {
            "maxLength": 128,
            "pattern": r"^[a-z][a-z0-9._:-]{0,127}$",
            "type": ["string", "null"],
        },
        "review_case_id": {
            "pattern": r"^review-case-[0-9a-f]{20}$",
            "type": "string",
        },
        "review_id": {
            "maxLength": 256,
            "pattern": (
                r"^review:reviewer-[ab]:review-case-[0-9a-f]{20}:"
                r"CAP-[A-Z0-9]+-[0-9]{3}$"
            ),
            "type": "string",
        },
        "review_notes": {"maxLength": _MAX_NOTES_LENGTH, "type": "string"},
        "reviewer_id": {"enum": ["reviewer-a", "reviewer-b"]},
        "rule_id": {
            "pattern": r"^CAP-[A-Z0-9]+-[0-9]{3}$",
            "type": "string",
        },
        "status": {"enum": [None, "reviewed"]},
    }
    required = list(record_properties)
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": {
            "corpus_binding_hash": _binding_schema_properties()["corpus_binding_hash"],
            "format": {"const": _REVIEW_LABEL_FORMAT},
            "pack_id": _binding_schema_properties()["pack_id"],
            "reviewer_id": {"enum": ["reviewer-a", "reviewer-b"]},
            "reviews": {
                "items": {
                    "additionalProperties": False,
                    "allOf": [
                        {
                            "if": {
                                "properties": {"status": {"const": "reviewed"}},
                                "required": ["status"],
                            },
                            "then": {
                                "properties": {
                                    "category": {"enum": list(_REVIEW_CATEGORIES)},
                                    "confidence": {"enum": list(_CONFIDENCES)},
                                    "correlation": {"enum": list(_CORRELATIONS)},
                                    "disposition": {"enum": list(_DISPOSITIONS)},
                                    "evidence_locations": {
                                        **_evidence_schema(),
                                        "minItems": 1,
                                    },
                                    "finding_summary": {
                                        "maxLength": _MAX_SUMMARY_LENGTH,
                                        "minLength": 1,
                                        "type": "string",
                                    },
                                    "human_condition_label": {
                                        "enum": list(_HUMAN_CONDITION_LABELS)
                                    },
                                    "observed_finding": {
                                        "enum": list(_OBSERVED_FINDINGS)
                                    },
                                    "rationale_code": {
                                        "maxLength": 128,
                                        "pattern": r"^[a-z][a-z0-9._:-]{0,127}$",
                                        "type": "string",
                                    },
                                }
                            },
                        }
                    ],
                    "properties": record_properties,
                    "required": required,
                    "type": "object",
                },
                "maxItems": _MAX_REVIEWS,
                "type": "array",
            },
            "schema_version": {"const": _PACK_SCHEMA_VERSION},
        },
        "required": [
            "format",
            "schema_version",
            "pack_id",
            "corpus_binding_hash",
            "reviewer_id",
            "reviews",
        ],
        "title": "IndependentReviewerLabelTemplate",
        "type": "object",
    }


def _adjudication_label_schema() -> dict[str, object]:
    record_properties: dict[str, object] = {
        **_binding_schema_properties(),
        "adjudication_id": {
            "maxLength": 256,
            "pattern": (
                r"^adjudication:review-case-[0-9a-f]{20}:"
                r"CAP-[A-Z0-9]+-[0-9]{3}$"
            ),
            "type": "string",
        },
        "adjudication_notes": {
            "maxLength": _MAX_NOTES_LENGTH,
            "type": "string",
        },
        "category": _nullable_enum(_REVIEW_CATEGORIES),
        "classification": {"const": None},
        "confidence": _nullable_enum(_CONFIDENCES),
        "correlation": _nullable_enum(_CORRELATIONS),
        "disposition": _nullable_enum(_DISPOSITIONS),
        "evidence_locations": _evidence_schema(),
        "finding_summary": {
            "maxLength": _MAX_SUMMARY_LENGTH,
            "type": ["string", "null"],
        },
        "human_condition_label": _nullable_enum(_HUMAN_CONDITION_LABELS),
        "observed_finding": _nullable_enum(_OBSERVED_FINDINGS),
        "rationale_code": {
            "maxLength": 128,
            "pattern": r"^[a-z][a-z0-9._:-]{0,127}$",
            "type": ["string", "null"],
        },
        "review_case_id": {
            "pattern": r"^review-case-[0-9a-f]{20}$",
            "type": "string",
        },
        "review_ids": {
            "items": {
                "pattern": (
                    r"^review:reviewer-[ab]:review-case-[0-9a-f]{20}:"
                    r"CAP-[A-Z0-9]+-[0-9]{3}$"
                ),
                "type": "string",
            },
            "maxItems": 2,
            "minItems": 2,
            "type": "array",
            "uniqueItems": True,
        },
        "rule_id": {
            "pattern": r"^CAP-[A-Z0-9]+-[0-9]{3}$",
            "type": "string",
        },
        "status": {"enum": [None, "adjudicated"]},
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": {
            "adjudications": {
                "items": {
                    "additionalProperties": False,
                    "allOf": [
                        {
                            "if": {
                                "properties": {"status": {"const": "adjudicated"}},
                                "required": ["status"],
                            },
                            "then": {
                                "properties": {
                                    "category": {"enum": list(_REVIEW_CATEGORIES)},
                                    "confidence": {"enum": list(_CONFIDENCES)},
                                    "correlation": {"enum": list(_CORRELATIONS)},
                                    "disposition": {"enum": list(_DISPOSITIONS)},
                                    "evidence_locations": {
                                        **_evidence_schema(),
                                        "minItems": 1,
                                    },
                                    "finding_summary": {
                                        "maxLength": _MAX_SUMMARY_LENGTH,
                                        "minLength": 1,
                                        "type": "string",
                                    },
                                    "human_condition_label": {
                                        "enum": ["match", "no_match"]
                                    },
                                    "observed_finding": {
                                        "enum": list(_OBSERVED_FINDINGS)
                                    },
                                    "rationale_code": {
                                        "maxLength": 128,
                                        "pattern": r"^[a-z][a-z0-9._:-]{0,127}$",
                                        "type": "string",
                                    },
                                }
                            },
                        }
                    ],
                    "properties": record_properties,
                    "required": list(record_properties),
                    "type": "object",
                },
                "maxItems": _MAX_REVIEWS,
                "type": "array",
            },
            "corpus_binding_hash": _binding_schema_properties()["corpus_binding_hash"],
            "format": {"const": _ADJUDICATION_LABEL_FORMAT},
            "pack_id": _binding_schema_properties()["pack_id"],
            "schema_version": {"const": _PACK_SCHEMA_VERSION},
        },
        "required": [
            "format",
            "schema_version",
            "pack_id",
            "corpus_binding_hash",
            "adjudications",
        ],
        "title": "IndependentAdjudicationTemplate",
        "type": "object",
    }


def _pack_payloads_without_manifest(pack: _PackData) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {
        "README.md": _readme(pack).encode("utf-8"),
        "reviewer-instructions.md": _reviewer_instructions().encode("utf-8"),
        "case-matrix.json": _json_text(_case_matrix_json(pack)).encode("utf-8"),
        "case-matrix.csv": _case_matrix_csv(pack).encode("utf-8"),
        "reviewer-label-schema.json": _json_text(_review_label_schema()).encode(
            "utf-8"
        ),
        "adjudication-label-schema.json": _json_text(
            _adjudication_label_schema()
        ).encode("utf-8"),
        "adjudicator/adjudication-instructions.md": (
            _adjudication_instructions().encode("utf-8")
        ),
        "adjudicator/adjudication.template.json": _json_text(
            _adjudication_template_payload(pack)
        ).encode("utf-8"),
    }
    for reviewer_id in ("reviewer-a", "reviewer-b"):
        payloads[f"{reviewer_id}/labels.template.json"] = _json_text(
            _review_template_payload(reviewer_id, pack)
        ).encode("utf-8")
        for case in pack.cases:
            root = f"{reviewer_id}/cases/{case.review_case_id}"
            payloads[f"{root}/case.json"] = _json_text(
                _review_case_payload(pack, case)
            ).encode("utf-8")
            payloads[f"{root}/{case.source_filename}"] = case.source_text.encode(
                "utf-8"
            )
    return payloads


def _expected_pack_payloads(pack: _PackData) -> dict[str, bytes]:
    payloads = _pack_payloads_without_manifest(pack)
    manifest = _json_text(_pack_manifest(pack, payloads)).encode("utf-8")
    return {"pack-manifest.json": manifest, **payloads}


def _readme(pack: _PackData) -> str:
    return f"""# AgentSec Independent Reviewer Pack

- Task: `P2-CAL-04A-AGENT-02`
- Pack Schema: `{_PACK_SCHEMA_VERSION}`
- Pack ID: `{pack.pack_id}`
- Review Cases per reviewer: `{len(pack.cases)}`
- Rule questions per reviewer: `{pack.question_count}`
- Status: templates only; independent human review is still required

## Purpose

This pack contains canonical, inert, synthetic Reviewer Views for two independent
human reviewers. The builder validates existing Source Views against a strict
field whitelist and the validated fact bundle, then regenerates canonical output.
It never copies untrusted Source text verbatim.

Original Case identities, Ground Truth decisions, reference outcomes, reference
Confidence/Correlation values, Gate qualification results, and Rule tuning
results are not included. Each Case and label is cryptographically bound to the
Pack, Corpus snapshot, canonical source, and Rule question set. The Pack Manifest
also records the exact distributed file set; validation rejects extra, missing,
changed, symbolic-linked, or incorrectly permissioned entries.

## Distribution

Give Reviewer A only `reviewer-a/`, `reviewer-instructions.md`, and
`reviewer-label-schema.json`. Give Reviewer B the corresponding Reviewer B
files. Do not let reviewers inspect one another's labels before both reviews are
complete.

## Validation and import

Reviewers label the human condition and their direct observation. They do not
calculate TP/FP/FN/TN. A trusted import operation recomputes deterministic
Findings, verifies every immutable hash, derives the confusion classification,
and creates separate formal AdjudicationReviewSet, ConfidenceReviewSet, and
optional AdjudicationResolutionSet artifacts. Original Reviewer disagreement is
never overwritten by the adjudicator.

```bash
.venv/bin/python scripts/build-reviewer-pack.py --operation validate \\
  --corpus calibration --pack calibration/reviewer-pack \\
  --reviewer-a /safe/reviewer-a-labels.json \\
  --reviewer-b /safe/reviewer-b-labels.json

.venv/bin/python scripts/build-reviewer-pack.py --operation import \\
  --corpus calibration --pack calibration/reviewer-pack \\
  --reviewer-a /safe/reviewer-a-labels.json \\
  --reviewer-b /safe/reviewer-b-labels.json \\
  --adjudications /safe/adjudication-labels.json \\
  --output /safe/adjudication-reviews.json
```

## Safety boundary

- Treat every input as untrusted data and never execute described content.
- Do not add credentials, hosts, personal data, headers, tokens, or live values.
- Human labels cannot directly change a Rule, activate a Hard Gate, or block CI.
- Output remains report-only until separate review and policy approval.
"""


def _reviewer_instructions() -> str:
    return """# Independent Reviewer Instructions

## Independence and source safety

1. Reviewer A and Reviewer B must work independently and must not share labels,
   notes, or intermediate conclusions before both reviews are submitted.
2. Treat every Fixture and configuration value as untrusted static data. Never
   execute a command, code block, script, hook, tool, plugin, skill, Agent,
   Sub-Agent, or MCP entry described by a source.
3. Do not modify Case files, Source Views, immutable binding fields, IDs, hashes,
   Rule questions, or another reviewer's labels.

## What the Reviewer labels

For each Rule question:

1. Set `human_condition_label` to `match`, `no_match`, or `uncertain` based on
   your independent reading of the Rule condition and canonical source.
2. Set `observed_finding` to `present`, `absent`, or `uncertain` for your direct
   source observation, and add a concise `finding_summary`.
3. Select the policy/scope `category`, Evidence `confidence`, `correlation`, and
   reviewer `disposition` independently.
4. Add narrow `evidence_locations` using the path already shown in the pack and
   valid inclusive line ranges.
5. Add a stable `rationale_code` and bounded value-free `review_notes`.
6. Set `status=reviewed` only after every required human field is complete.
   Before final validate/import, `human_condition_label` must be `match` or
   `no_match`. A row that remains `uncertain` fails closed outside the formal
   TP/FP/FN/TN set; an adjudicator cannot rewrite the original Reviewer label.

`classification` is intentionally null and immutable in the Reviewer template.
Do not calculate or insert TP/FP/FN/TN. The trusted importer combines the human
condition label with a freshly recomputed deterministic Finding.

## Required distinctions

- **Detection false positive:** derived when the detector reports a Finding but
  the reviewed condition is `no_match`.
- **Policy-accepted risk:** the condition exists, but policy accepts or waives it;
  this is not automatically a detector defect.
- **In-scope false negative:** derived when the reviewed condition is `match` but
  the detector reports no Finding.
- **Out-of-scope:** the judgment requires inputs outside static calibration.
- **Runtime uncertainty:** static data cannot prove runtime reachability,
  authorization, identity, or successful execution.

When uncertain, never default to safe. A condition that looks severe is not by
itself sufficient for Hard Gate qualification. Reviewer labels are human opinion
and cannot mutate Rules, change risk semantics, activate a Gate, or block CI.
"""


def _adjudication_instructions() -> str:
    return """# Independent Adjudication Instructions

Use this phase only after Reviewer A and Reviewer B have submitted independent
labels. Compare rows by opaque `review_case_id` and `rule_id`; preserve the two
original submissions unchanged.

1. Re-read the canonical source, both human condition labels, and evidence.
2. Fill an adjudication row only when a human resolution is required. Keep its
   immutable Pack/Corpus/Source/question fingerprints unchanged.
3. Resolve `human_condition_label`, direct observation, policy/scope category,
   Confidence, Correlation, disposition, rationale, and evidence separately.
4. Do not calculate TP/FP/FN/TN. The trusted importer derives classification
   from the final human condition and a freshly recomputed detector result.
5. Preserve policy-accepted risk, out-of-scope, runtime uncertainty, and
   unresolved evidence as distinct concepts. Never authorize by majority vote.
6. Set `status=adjudicated` only after all required fields are complete and the
   row references exactly the Reviewer A and Reviewer B labels.

Adjudication cannot directly change or retire a Rule, activate a Hard Gate, or
enable CI blocking.
"""


def _private_mkdir(path: Path) -> None:
    path.mkdir(mode=0o700)
    path.chmod(0o700)


def _write_private_bytes(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    path.chmod(0o600)


def _write_private_text(path: Path, text: str) -> None:
    _write_private_bytes(path, text.encode("utf-8"))


def _ensure_private_parent_directories(root: Path, relative: Path) -> None:
    current = root
    for part in relative.parts:
        current = current / part
        if current.exists():
            if current.is_symlink() or not current.is_dir():
                raise _OutputError("output parent path is unsafe")
            current.chmod(0o700)
        else:
            _private_mkdir(current)


def _build_pack(output: Path, pack: _PackData) -> _PackSummary:
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise _OutputError("output parent cannot be created") from error
    try:
        _private_mkdir(output)
    except FileExistsError as error:
        raise _OutputError("output directory already exists") from error
    except OSError as error:
        raise _OutputError("output directory cannot be created") from error

    try:
        for relative, data in sorted(_expected_pack_payloads(pack).items()):
            relative_path = Path(relative)
            _ensure_private_parent_directories(output, relative_path.parent)
            _write_private_bytes(output / relative_path, data)
    except Exception:
        shutil.rmtree(output, ignore_errors=True)
        raise

    return _PackSummary(
        case_count=len(pack.cases),
        question_count=pack.question_count,
        pack_id=pack.pack_id,
    )


def _pack_tree(root: Path) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            _fail_input("Reviewer Pack contains a symlink")
        if path.is_dir():
            directories.add(relative)
        elif path.is_file():
            files.add(relative)
        else:
            _fail_input("Reviewer Pack contains an unsupported filesystem entry")
    return files, directories


def _expected_directories(files: set[str]) -> set[str]:
    directories: set[str] = set()
    for relative in files:
        parent = Path(relative).parent
        while parent != Path("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    return directories


def _validate_pack_directory(pack_root: Path, pack: _PackData) -> None:
    expected = _expected_pack_payloads(pack)
    expected_files = set(expected)
    actual_files, actual_directories = _pack_tree(pack_root)
    if actual_files != expected_files:
        _fail_input("Reviewer Pack file set is incomplete or contains extra files")
    expected_directories = _expected_directories(expected_files)
    if actual_directories != expected_directories:
        _fail_input("Reviewer Pack directory set is incomplete or contains extras")
    if (pack_root.stat().st_mode & 0o777) != 0o700:
        _fail_input("Reviewer Pack root permissions are invalid")
    for relative in sorted(expected_directories):
        directory = _safe_child(
            pack_root, relative, label="Reviewer Pack directory", kind="directory"
        )
        if (directory.stat().st_mode & 0o777) != 0o700:
            _fail_input("Reviewer Pack directory permissions are invalid")
    for relative, expected_bytes in sorted(expected.items()):
        path = _safe_child(pack_root, relative, label="Reviewer Pack file", kind="file")
        if (path.stat().st_mode & 0o777) != 0o600:
            _fail_input("Reviewer Pack file permissions are invalid")
        try:
            observed = path.read_bytes()
        except OSError as error:
            raise _InputError("Reviewer Pack file cannot be read") from error
        if observed != expected_bytes:
            _fail_input("Reviewer Pack file content does not match its manifest")


def _safe_evidence_path(value: object, expected: str) -> str:
    if not isinstance(value, str):
        _fail_input("evidence path must be text")
    if (
        _SAFE_PATH_PATTERN.fullmatch(value) is None
        or value.startswith("/")
        or "\\" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        _fail_input("evidence path must be a safe relative path")
    if value != expected:
        _fail_input("evidence path does not match the bound Reviewer source")
    return value


def _validate_evidence_locations(
    value: object,
    *,
    expected_path: str,
    max_line: int,
    require_non_empty: bool,
) -> list[dict[str, object]]:
    if not isinstance(value, list):
        _fail_input("evidence_locations must be a list")
    if len(value) > _MAX_EVIDENCE_LOCATIONS:
        _fail_input("evidence_locations exceed the bounded count")
    if require_non_empty and not value:
        _fail_input("completed review requires evidence_locations")
    validated = []
    for item in value:
        if not isinstance(item, dict):
            _fail_input("evidence location must be an object")
        _exact_keys(item, {"path", "start_line", "end_line"}, "evidence location")
        path = _safe_evidence_path(item["path"], expected_path)
        start = item["start_line"]
        end = item["end_line"]
        if (
            not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(end, int)
            or isinstance(end, bool)
            or start < 1
            or end < start
            or end > max_line
        ):
            _fail_input("evidence line range is invalid")
        validated.append({"path": path, "start_line": start, "end_line": end})
    return validated


def _validate_optional_choice(
    value: object,
    choices: tuple[str, ...],
    label: str,
    *,
    required: bool,
) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or value not in choices:
        _fail_input(f"{label} is invalid")
    return value


def _validate_optional_text(
    value: object,
    label: str,
    *,
    maximum: int,
    required: bool,
) -> str | None:
    if value is None and not required:
        return None
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or (required and not value.strip())
    ):
        _fail_input(f"{label} is invalid")
    return value


def _review_record_keys() -> set[str]:
    return {
        *set(_binding_fields_placeholder()),
        "category",
        "classification",
        "confidence",
        "correlation",
        "disposition",
        "evidence_locations",
        "finding_summary",
        "human_condition_label",
        "observed_finding",
        "rationale_code",
        "review_case_id",
        "review_id",
        "review_notes",
        "reviewer_id",
        "rule_id",
        "status",
    }


def _binding_fields_placeholder() -> tuple[str, ...]:
    return (
        "corpus_binding_hash",
        "pack_id",
        "question_set_sha256",
        "review_case_fingerprint",
        "source_sha256",
    )


def _expected_question_rows(
    pack: _PackData,
) -> list[tuple[_ReviewCase, _ReviewQuestion]]:
    return [(case, question) for case in pack.cases for question in case.questions]


def _validate_review_submission(
    payload: dict[str, Any],
    *,
    reviewer_id: str,
    pack: _PackData,
    require_complete: bool,
) -> dict[tuple[str, str], dict[str, Any]]:
    _exact_keys(
        payload,
        {
            "corpus_binding_hash",
            "format",
            "pack_id",
            "reviewer_id",
            "reviews",
            "schema_version",
        },
        "review submission",
    )
    if (
        payload["format"] != _REVIEW_LABEL_FORMAT
        or payload["schema_version"] != _PACK_SCHEMA_VERSION
        or payload["pack_id"] != pack.pack_id
        or payload["corpus_binding_hash"] != pack.corpus_binding_hash
        or payload["reviewer_id"] != reviewer_id
    ):
        _fail_input("review submission top-level binding is invalid")
    raw_reviews = payload["reviews"]
    expected_rows = _expected_question_rows(pack)
    if not isinstance(raw_reviews, list) or len(raw_reviews) != len(expected_rows):
        _fail_input("review submission must contain every bound Rule question")
    if len(raw_reviews) > _MAX_REVIEWS:
        _fail_input("review submission exceeds the bounded count")

    validated: dict[tuple[str, str], dict[str, Any]] = {}
    for raw, (case, question) in zip(raw_reviews, expected_rows, strict=True):
        if not isinstance(raw, dict):
            _fail_input("review record must be an object")
        _exact_keys(raw, _review_record_keys(), "review record")
        expected_immutable = _review_record(reviewer_id, pack, case, question)
        immutable_keys = {
            *_binding_fields_placeholder(),
            "classification",
            "review_case_id",
            "review_id",
            "reviewer_id",
            "rule_id",
        }
        if any(raw[key] != expected_immutable[key] for key in immutable_keys):
            _fail_input("review record immutable binding is invalid")
        if raw["classification"] is not None:
            _fail_input("Reviewer must not provide TP/FP/FN/TN classification")
        status = raw["status"]
        if status not in {None, "reviewed"}:
            _fail_input("review status is invalid")
        complete = status == "reviewed"
        if require_complete and not complete:
            _fail_input("review submission contains incomplete records")
        human_label = _validate_optional_choice(
            raw["human_condition_label"],
            _HUMAN_CONDITION_LABELS,
            "human_condition_label",
            required=complete,
        )
        observed = _validate_optional_choice(
            raw["observed_finding"],
            _OBSERVED_FINDINGS,
            "observed_finding",
            required=complete,
        )
        category = _validate_optional_choice(
            raw["category"],
            _REVIEW_CATEGORIES,
            "review category",
            required=complete,
        )
        confidence = _validate_optional_choice(
            raw["confidence"],
            _CONFIDENCES,
            "review confidence",
            required=complete,
        )
        correlation = _validate_optional_choice(
            raw["correlation"],
            _CORRELATIONS,
            "review correlation",
            required=complete,
        )
        disposition = _validate_optional_choice(
            raw["disposition"],
            _DISPOSITIONS,
            "review disposition",
            required=complete,
        )
        finding_summary = _validate_optional_text(
            raw["finding_summary"],
            "finding_summary",
            maximum=_MAX_SUMMARY_LENGTH,
            required=complete,
        )
        rationale = _validate_optional_text(
            raw["rationale_code"],
            "rationale_code",
            maximum=128,
            required=complete,
        )
        if rationale is not None and _STABLE_ID_PATTERN.fullmatch(rationale) is None:
            _fail_input("rationale_code must use the stable identifier form")
        notes = _validate_optional_text(
            raw["review_notes"],
            "review_notes",
            maximum=_MAX_NOTES_LENGTH,
            required=False,
        )
        evidence = _validate_evidence_locations(
            raw["evidence_locations"],
            expected_path=case.reviewer_evidence_path,
            max_line=case.line_count,
            require_non_empty=complete,
        )
        if human_label == "uncertain" and category not in {
            "out_of_scope",
            "runtime_uncertainty",
            "unresolved",
        }:
            _fail_input("uncertain human condition requires an uncertainty category")
        normalized = dict(raw)
        normalized.update(
            {
                "category": category,
                "confidence": confidence,
                "correlation": correlation,
                "disposition": disposition,
                "evidence_locations": evidence,
                "finding_summary": finding_summary,
                "human_condition_label": human_label,
                "observed_finding": observed,
                "rationale_code": rationale,
                "review_notes": notes or "",
            }
        )
        key = (case.review_case_id, question.rule_id)
        if key in validated:
            _fail_input("duplicate review record")
        validated[key] = normalized
    return validated


def _adjudication_record_keys() -> set[str]:
    return {
        *set(_binding_fields_placeholder()),
        "adjudication_id",
        "adjudication_notes",
        "category",
        "classification",
        "confidence",
        "correlation",
        "disposition",
        "evidence_locations",
        "finding_summary",
        "human_condition_label",
        "observed_finding",
        "rationale_code",
        "review_case_id",
        "review_ids",
        "rule_id",
        "status",
    }


def _validate_adjudication_submission(
    payload: dict[str, Any],
    *,
    pack: _PackData,
) -> dict[tuple[str, str], dict[str, Any]]:
    _exact_keys(
        payload,
        {
            "adjudications",
            "corpus_binding_hash",
            "format",
            "pack_id",
            "schema_version",
        },
        "adjudication submission",
    )
    if (
        payload["format"] != _ADJUDICATION_LABEL_FORMAT
        or payload["schema_version"] != _PACK_SCHEMA_VERSION
        or payload["pack_id"] != pack.pack_id
        or payload["corpus_binding_hash"] != pack.corpus_binding_hash
    ):
        _fail_input("adjudication submission top-level binding is invalid")
    raw_entries = payload["adjudications"]
    expected_rows = _expected_question_rows(pack)
    if not isinstance(raw_entries, list) or len(raw_entries) != len(expected_rows):
        _fail_input("adjudication submission must retain every bound Rule question")
    if len(raw_entries) > _MAX_REVIEWS:
        _fail_input("adjudication submission exceeds the bounded count")

    completed: dict[tuple[str, str], dict[str, Any]] = {}
    for raw, (case, question) in zip(raw_entries, expected_rows, strict=True):
        if not isinstance(raw, dict):
            _fail_input("adjudication record must be an object")
        _exact_keys(raw, _adjudication_record_keys(), "adjudication record")
        expected = _adjudication_record(pack, case, question)
        immutable_keys = {
            *_binding_fields_placeholder(),
            "adjudication_id",
            "classification",
            "review_case_id",
            "review_ids",
            "rule_id",
        }
        if any(raw[key] != expected[key] for key in immutable_keys):
            _fail_input("adjudication record immutable binding is invalid")
        if raw["classification"] is not None:
            _fail_input("Adjudicator must not provide TP/FP/FN/TN classification")
        status = raw["status"]
        if status not in {None, "adjudicated"}:
            _fail_input("adjudication status is invalid")
        if status is None:
            continue
        human_label = _validate_optional_choice(
            raw["human_condition_label"],
            ("match", "no_match"),
            "adjudicated human_condition_label",
            required=True,
        )
        normalized = dict(raw)
        normalized["human_condition_label"] = human_label
        for field, choices in (
            ("observed_finding", _OBSERVED_FINDINGS),
            ("category", _REVIEW_CATEGORIES),
            ("confidence", _CONFIDENCES),
            ("correlation", _CORRELATIONS),
            ("disposition", _DISPOSITIONS),
        ):
            normalized[field] = _validate_optional_choice(
                raw[field], choices, f"adjudication {field}", required=True
            )
        normalized["finding_summary"] = _validate_optional_text(
            raw["finding_summary"],
            "adjudication finding_summary",
            maximum=_MAX_SUMMARY_LENGTH,
            required=True,
        )
        rationale = _validate_optional_text(
            raw["rationale_code"],
            "adjudication rationale_code",
            maximum=128,
            required=True,
        )
        if rationale is None or _STABLE_ID_PATTERN.fullmatch(rationale) is None:
            _fail_input("adjudication rationale_code is invalid")
        normalized["rationale_code"] = rationale
        normalized["adjudication_notes"] = (
            _validate_optional_text(
                raw["adjudication_notes"],
                "adjudication_notes",
                maximum=_MAX_NOTES_LENGTH,
                required=False,
            )
            or ""
        )
        expected_evidence = (
            f"reviewer-a/cases/{case.review_case_id}/{case.source_filename}"
        )
        normalized["evidence_locations"] = _validate_evidence_locations(
            raw["evidence_locations"],
            expected_path=expected_evidence,
            max_line=case.line_count,
            require_non_empty=True,
        )
        key = (case.review_case_id, question.rule_id)
        completed[key] = normalized
    return completed


def _classification(
    human_condition_label: str,
    observed_outcome: CalibrationRuleOutcome,
) -> CalibrationClassification:
    if human_condition_label == "match":
        return (
            CalibrationClassification.TRUE_POSITIVE
            if observed_outcome is CalibrationRuleOutcome.MATCH
            else CalibrationClassification.FALSE_NEGATIVE
        )
    if human_condition_label == "no_match":
        return (
            CalibrationClassification.FALSE_POSITIVE
            if observed_outcome is CalibrationRuleOutcome.MATCH
            else CalibrationClassification.TRUE_NEGATIVE
        )
    _fail_input("uncertain human condition requires completed adjudication")


def _formal_category(
    classification: CalibrationClassification,
    review_category: str,
) -> AdjudicationCategory:
    explicit = {
        "policy_accepted_risk": AdjudicationCategory.POLICY_ACCEPTED_RISK,
        "out_of_scope": AdjudicationCategory.OUT_OF_SCOPE,
        "runtime_uncertainty": AdjudicationCategory.RUNTIME_UNCERTAINTY,
        "unresolved": AdjudicationCategory.UNRESOLVED,
    }
    if review_category in explicit:
        return explicit[review_category]
    return {
        CalibrationClassification.TRUE_POSITIVE: (
            AdjudicationCategory.CONFIRMED_TRUE_POSITIVE
        ),
        CalibrationClassification.FALSE_POSITIVE: (
            AdjudicationCategory.DETECTION_FALSE_POSITIVE
        ),
        CalibrationClassification.FALSE_NEGATIVE: (
            AdjudicationCategory.IN_SCOPE_FALSE_NEGATIVE
        ),
        CalibrationClassification.TRUE_NEGATIVE: (
            AdjudicationCategory.CONFIRMED_TRUE_NEGATIVE
        ),
    }[classification]


def _load_submissions(
    *,
    pack: _PackData,
    reviewer_a_path: Path,
    reviewer_b_path: Path,
    adjudications_path: Path | None,
    require_complete: bool,
) -> tuple[
    dict[tuple[str, str], dict[str, Any]],
    dict[tuple[str, str], dict[str, Any]],
    dict[tuple[str, str], dict[str, Any]],
]:
    reviewer_a = _validate_review_submission(
        _read_explicit_json(reviewer_a_path, "Reviewer A labels"),
        reviewer_id="reviewer-a",
        pack=pack,
        require_complete=require_complete,
    )
    reviewer_b = _validate_review_submission(
        _read_explicit_json(reviewer_b_path, "Reviewer B labels"),
        reviewer_id="reviewer-b",
        pack=pack,
        require_complete=require_complete,
    )
    adjudications = (
        {}
        if adjudications_path is None
        else _validate_adjudication_submission(
            _read_explicit_json(adjudications_path, "adjudication labels"),
            pack=pack,
        )
    )
    return reviewer_a, reviewer_b, adjudications


def _formal_review_set(
    pack: _PackData,
    reviewer_a: dict[tuple[str, str], dict[str, Any]],
    reviewer_b: dict[tuple[str, str], dict[str, Any]],
) -> AdjudicationReviewSet:
    cases_by_id = {case.case_id: case for case in pack.corpus.cases}
    evaluator = DeterministicFactBundleEvaluator()
    formal_labels = []
    for review_case in pack.cases:
        original_case = cases_by_id[review_case.original_case_id]
        expectations = {
            expectation.rule_id: expectation
            for expectation in original_case.ground_truth.rule_expectations
        }
        for question in review_case.questions:
            expectation = expectations[question.rule_id]
            try:
                observation = evaluator.evaluate(
                    corpus_root=pack.corpus.root,
                    case=original_case,
                    expectation=expectation,
                )
            except Exception as error:
                raise _InputError(
                    "deterministic review import evaluation failed"
                ) from error
            key = (review_case.review_case_id, question.rule_id)
            for reviewer_id, submission in (
                ("reviewer-a", reviewer_a),
                ("reviewer-b", reviewer_b),
            ):
                source = submission[key]
                human_label = source["human_condition_label"]
                if human_label == "uncertain":
                    _fail_input(
                        "uncertain Reviewer labels remain unresolved and cannot be "
                        "imported as TP/FP/FN/TN"
                    )
                if not isinstance(human_label, str):
                    _fail_input("completed review is missing human condition label")
                classification = _classification(human_label, observation.outcome)
                review_category = source["category"]
                disposition = source["disposition"]
                rationale = source["rationale_code"]
                if (
                    not isinstance(review_category, str)
                    or not isinstance(disposition, str)
                    or not isinstance(rationale, str)
                ):
                    _fail_input("completed review is missing formal import fields")
                formal_labels.append(
                    AdjudicationReviewLabel(
                        adjudication_id=(
                            f"adjudication:{reviewer_id}:"
                            f"{review_case.original_case_id}:{question.rule_id}"
                        ),
                        case_id=review_case.original_case_id,
                        rule_id=question.rule_id,
                        reviewer_id=reviewer_id,
                        classification=classification,
                        category=_formal_category(classification, review_category),
                        disposition=RuleDisposition(disposition),
                        status=AdjudicationStatus.REVIEWED,
                        rationale_code=rationale,
                    )
                )
    ordered = tuple(
        sorted(
            formal_labels,
            key=lambda item: (item.case_id, item.rule_id, item.reviewer_id),
        )
    )
    return AdjudicationReviewSet(
        corpus_id=pack.corpus.index.corpus_id,
        labels_version=pack.corpus.index.labels_version,
        reviewer_ids=("reviewer-a", "reviewer-b"),
        reviews=ordered,
    )


def _formal_confidence_set(
    pack: _PackData,
    reviewer_a: dict[tuple[str, str], dict[str, Any]],
    reviewer_b: dict[tuple[str, str], dict[str, Any]],
) -> ConfidenceReviewSet:
    cases_by_id = {case.case_id: case for case in pack.corpus.cases}
    labels = []
    for review_case in pack.cases:
        original_case = cases_by_id[review_case.original_case_id]
        expected_matches = {
            expectation.rule_id
            for expectation in original_case.ground_truth.rule_expectations
            if expectation.outcome is CalibrationRuleOutcome.MATCH
        }
        for question in review_case.questions:
            if question.rule_id not in expected_matches:
                continue
            key = (review_case.review_case_id, question.rule_id)
            for reviewer_id, submission in (
                ("reviewer-a", reviewer_a),
                ("reviewer-b", reviewer_b),
            ):
                source = submission[key]
                confidence = source["confidence"]
                correlation = source["correlation"]
                rationale = source["rationale_code"]
                if not all(
                    isinstance(item, str)
                    for item in (confidence, correlation, rationale)
                ):
                    _fail_input("completed review is missing Confidence import fields")
                labels.append(
                    ConfidenceReviewLabel(
                        review_id=(
                            f"review:{reviewer_id}:"
                            f"{review_case.original_case_id}:{question.rule_id}"
                        ),
                        case_id=review_case.original_case_id,
                        rule_id=question.rule_id,
                        reviewer_id=reviewer_id,
                        confidence=EvidenceConfidence(confidence),
                        correlation=CapabilityCorrelation(correlation),
                        status=ConfidenceReviewStatus.REVIEWED,
                        rationale_code=rationale,
                    )
                )
    ordered = tuple(
        sorted(labels, key=lambda item: (item.case_id, item.rule_id, item.reviewer_id))
    )
    return ConfidenceReviewSet(
        corpus_id=pack.corpus.index.corpus_id,
        labels_version=pack.corpus.index.labels_version,
        reviewer_ids=("reviewer-a", "reviewer-b"),
        reviews=ordered,
    )


def _formal_resolution_set(
    pack: _PackData,
    reviewer_a: dict[tuple[str, str], dict[str, Any]],
    reviewer_b: dict[tuple[str, str], dict[str, Any]],
    adjudications: dict[tuple[str, str], dict[str, Any]],
) -> AdjudicationResolutionSet:
    cases_by_id = {case.case_id: case for case in pack.corpus.cases}
    evaluator = DeterministicFactBundleEvaluator()
    resolutions = []
    for review_case in pack.cases:
        original_case = cases_by_id[review_case.original_case_id]
        expectations = {
            expectation.rule_id: expectation
            for expectation in original_case.ground_truth.rule_expectations
        }
        for question in review_case.questions:
            key = (review_case.review_case_id, question.rule_id)
            adjudicated = adjudications.get(key)
            if adjudicated is None:
                continue
            expectation = expectations[question.rule_id]
            observation = evaluator.evaluate(
                corpus_root=pack.corpus.root,
                case=original_case,
                expectation=expectation,
            )
            independent_values = []
            for submission in (reviewer_a, reviewer_b):
                label = submission[key]["human_condition_label"]
                if label == "uncertain":
                    independent_values.append(("uncertain", "unresolved", "more_data"))
                    continue
                if not isinstance(label, str):
                    _fail_input("completed review is missing human condition label")
                classification = _classification(label, observation.outcome)
                category = submission[key]["category"]
                disposition = submission[key]["disposition"]
                if not isinstance(category, str) or not isinstance(disposition, str):
                    _fail_input(
                        "completed review is missing adjudication comparison fields"
                    )
                independent_values.append(
                    (
                        classification.value,
                        _formal_category(classification, category).value,
                        disposition,
                    )
                )
            if len(set(independent_values)) == 1:
                _fail_input("adjudication is not allowed for an agreed review")
            final_label = adjudicated["human_condition_label"]
            review_category = adjudicated["category"]
            disposition = adjudicated["disposition"]
            rationale = adjudicated["rationale_code"]
            if not all(
                isinstance(item, str)
                for item in (final_label, review_category, disposition, rationale)
            ):
                _fail_input("completed adjudication is missing formal fields")
            classification = _classification(final_label, observation.outcome)
            resolutions.append(
                AdjudicationResolution(
                    resolution_id=(
                        f"resolution:{review_case.original_case_id}:{question.rule_id}"
                    ),
                    case_id=review_case.original_case_id,
                    rule_id=question.rule_id,
                    reviewer_ids=("reviewer-a", "reviewer-b"),
                    final_classification=classification,
                    final_category=_formal_category(classification, review_category),
                    final_disposition=RuleDisposition(disposition),
                    rationale_code=rationale,
                )
            )
    ordered = tuple(sorted(resolutions, key=lambda item: (item.case_id, item.rule_id)))
    return AdjudicationResolutionSet(
        corpus_id=pack.corpus.index.corpus_id,
        labels_version=pack.corpus.index.labels_version,
        reviewer_ids=("reviewer-a", "reviewer-b"),
        resolutions=ordered,
    )


def _run_build(corpus_path: Path, output: Path) -> _PackSummary:
    corpus_root = _resolve_directory(corpus_path, "corpus root")
    pack = _load_pack_data(corpus_root)
    return _build_pack(Path(os.path.abspath(output)), pack)


def _prepare_review_operation(
    *,
    corpus_path: Path,
    pack_path: Path,
    reviewer_a_path: Path,
    reviewer_b_path: Path,
    adjudications_path: Path | None,
) -> tuple[
    _PackData,
    dict[tuple[str, str], dict[str, Any]],
    dict[tuple[str, str], dict[str, Any]],
    dict[tuple[str, str], dict[str, Any]],
]:
    corpus_root = _resolve_directory(corpus_path, "corpus root")
    pack_root = _resolve_directory(pack_path, "Reviewer Pack root")
    pack = _load_pack_data(corpus_root)
    _validate_pack_directory(pack_root, pack)
    reviewer_a, reviewer_b, adjudications = _load_submissions(
        pack=pack,
        reviewer_a_path=reviewer_a_path,
        reviewer_b_path=reviewer_b_path,
        adjudications_path=adjudications_path,
        require_complete=True,
    )
    return pack, reviewer_a, reviewer_b, adjudications


def _run_validate(
    *,
    corpus_path: Path,
    pack_path: Path,
    reviewer_a_path: Path,
    reviewer_b_path: Path,
    adjudications_path: Path | None,
) -> _PackSummary:
    pack, reviewer_a, reviewer_b, adjudications = _prepare_review_operation(
        corpus_path=corpus_path,
        pack_path=pack_path,
        reviewer_a_path=reviewer_a_path,
        reviewer_b_path=reviewer_b_path,
        adjudications_path=adjudications_path,
    )
    _formal_review_set(pack, reviewer_a, reviewer_b)
    _formal_confidence_set(pack, reviewer_a, reviewer_b)
    _formal_resolution_set(pack, reviewer_a, reviewer_b, adjudications)
    return _PackSummary(
        case_count=len(pack.cases),
        question_count=pack.question_count,
        pack_id=pack.pack_id,
    )


def _run_import(
    *,
    corpus_path: Path,
    pack_path: Path,
    reviewer_a_path: Path,
    reviewer_b_path: Path,
    adjudications_path: Path | None,
    output: Path,
    confidence_output: Path | None,
    resolution_output: Path | None,
) -> _PackSummary:
    if confidence_output is None:
        raise _OutputError("import requires --confidence-output")
    if adjudications_path is not None and resolution_output is None:
        raise _OutputError("import with adjudications requires --resolution-output")
    pack, reviewer_a, reviewer_b, adjudications = _prepare_review_operation(
        corpus_path=corpus_path,
        pack_path=pack_path,
        reviewer_a_path=reviewer_a_path,
        reviewer_b_path=reviewer_b_path,
        adjudications_path=adjudications_path,
    )
    review_set = _formal_review_set(pack, reviewer_a, reviewer_b)
    confidence_set = _formal_confidence_set(pack, reviewer_a, reviewer_b)
    resolution_set = _formal_resolution_set(pack, reviewer_a, reviewer_b, adjudications)
    outputs: list[tuple[Path, str]] = [
        (
            Path(os.path.abspath(output)),
            encode_adjudication_review_set_json(review_set),
        ),
        (
            Path(os.path.abspath(confidence_output)),
            encode_confidence_review_set_json(confidence_set),
        ),
    ]
    if resolution_output is not None:
        outputs.append(
            (
                Path(os.path.abspath(resolution_output)),
                encode_adjudication_resolution_set_json(resolution_set),
            )
        )
    paths = [path for path, _ in outputs]
    if len(paths) != len(set(paths)):
        raise _OutputError("import output paths must be distinct")
    if any(path.exists() or path.is_symlink() for path in paths):
        raise _OutputError("import output file already exists")
    created: list[Path] = []
    try:
        for output_path, text in outputs:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            _write_private_text(output_path, text)
            created.append(output_path)
    except OSError as error:
        for path in created:
            path.unlink(missing_ok=True)
        raise _OutputError("formal review outputs cannot be created") from error
    return _PackSummary(
        case_count=len(pack.cases),
        question_count=pack.question_count,
        pack_id=pack.pack_id,
    )


def main() -> None:
    parser = _ArgumentParser(description=__doc__)
    parser.add_argument(
        "--operation", choices=("build", "validate", "import"), default="build"
    )
    parser.add_argument("--corpus", type=Path, default=Path("calibration"))
    parser.add_argument("--pack", type=Path, default=Path("calibration/reviewer-pack"))
    parser.add_argument(
        "--reviewer-a",
        type=Path,
        default=Path("calibration/reviewer-pack/reviewer-a/labels.template.json"),
    )
    parser.add_argument(
        "--reviewer-b",
        type=Path,
        default=Path("calibration/reviewer-pack/reviewer-b/labels.template.json"),
    )
    parser.add_argument("--adjudications", type=Path, default=None)
    parser.add_argument(
        "--output", type=Path, default=Path("calibration/reviewer-pack")
    )
    parser.add_argument("--confidence-output", type=Path, default=None)
    parser.add_argument("--resolution-output", type=Path, default=None)
    args = parser.parse_args()
    try:
        if args.operation == "build":
            summary = _run_build(args.corpus, args.output)
        elif args.operation == "validate":
            summary = _run_validate(
                corpus_path=args.corpus,
                pack_path=args.pack,
                reviewer_a_path=args.reviewer_a,
                reviewer_b_path=args.reviewer_b,
                adjudications_path=args.adjudications,
            )
        else:
            summary = _run_import(
                corpus_path=args.corpus,
                pack_path=args.pack,
                reviewer_a_path=args.reviewer_a,
                reviewer_b_path=args.reviewer_b,
                adjudications_path=args.adjudications,
                output=args.output,
                confidence_output=args.confidence_output,
                resolution_output=args.resolution_output,
            )
    except (_InputError, _OutputError) as error:
        print(f"reviewer pack operation failed: {error}", file=sys.stderr)
        code = EXIT_INVALID
    except Exception as error:  # noqa: BLE001 - fail closed without input values
        print(
            f"reviewer pack operation failed: {type(error).__name__}", file=sys.stderr
        )
        code = EXIT_FAILED
    else:
        print(f"Reviewer Cases per reviewer: {summary.case_count}")
        print(f"Rule questions per reviewer: {summary.question_count}")
        print(f"Pack ID: {summary.pack_id}")
        code = EXIT_OK
    raise SystemExit(code)


if __name__ == "__main__":
    main()
