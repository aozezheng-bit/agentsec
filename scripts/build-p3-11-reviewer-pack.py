#!/usr/bin/env python3
"""Build the P3-11A blinded semantic reviewer pack from real corpus text.

The pack contains only bounded, sanitized, content-addressed Evidence derived
from repository test data, Homi Pilot snapshots, and demonstration
workspaces. Corpus assets are read strictly as untrusted text and are never
executed. No expected labels, no secrets, and no raw Provider payloads are
included.
"""

from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentsec.semantic import build_semantic_evidence_chunk

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_ROOT = REPOSITORY_ROOT / "pilots" / "semantic-quality-p3-11" / "reviewer-pack"

# 占位 asset SHA-256：盲评包不需要绑定源文件哈希（标注工作不需要），
# 真正的绑定发生在 P3-11B 复放阶段。
_ASSET_SHA_PLACEHOLDER = "00" * 32


@dataclass(frozen=True, slots=True)
class CorpusSegment:
    """One selected text segment treated strictly as untrusted data."""

    case_id: str
    source_kind: str
    source_label: str
    start_line: int
    content: str


def _read_lines(path: Path, *, inner: str | None = None) -> list[str]:
    if inner is not None:
        with zipfile.ZipFile(path) as archive:
            data = archive.read(inner)
    else:
        data = path.read_bytes()
    return data.decode("utf-8", errors="strict").splitlines()


def _segment(
    path: Path,
    case_id: str,
    kind: str,
    start: int,
    end: int,
    *,
    inner: str | None = None,
) -> CorpusSegment | None:
    try:
        lines = _read_lines(path, inner=inner)
    except (OSError, zipfile.BadZipFile, UnicodeDecodeError):
        return None
    if not lines:
        return None
    end = min(end, len(lines))
    content = "\n".join(lines[start:end])
    if not content.strip():
        return None
    return CorpusSegment(
        case_id=case_id,
        source_kind=kind,
        source_label=path.relative_to(REPOSITORY_ROOT).as_posix()
        + ("::AGENTS.md" if inner else ""),
        start_line=start + 1,
        content=content,
    )


def _risky_segments() -> list[CorpusSegment]:
    selections = [
        ("approval-bypass", 0, 6),
        ("approval-chinese", 0, 0 - 6),
        ("credential-read", 0, 6),
        ("database-drop", 0, 6),
        ("root-access", 0, 6),
        ("safety-check-disable-only", 0, 6),
        ("dynamic-eval", 0, 8),
        ("external-api", 0, 6),
        ("external-tool-text", 0, 6),
        ("instruction-override-only", 0, 6),
        ("obfuscated-instructions", 0, 8),
        ("production-write", 0, 6),
        ("shell-fenced", 0, 8),
        ("chinese-admin-destructive-dynamic", 0, 8),
        ("chinese-capability-chain", 0, 8),
        ("chinese-governance-memory", 0, 8),
    ]
    segments: list[CorpusSegment] = []
    for slug, start, end in selections:
        if end < 0:
            risky_path = REPOSITORY_ROOT / "testdata" / "risky" / slug / "AGENTS.md"
            module = _read_lines(risky_path)
            end = max(0, len(module) + end)
        seg = _segment(
            REPOSITORY_ROOT / "testdata" / "risky" / slug / "AGENTS.md",
            f"risky-{slug}",
            "testdata",
            start,
            end,
        )
        if seg:
            segments.append(seg)
    return segments


def _injection_segments() -> list[CorpusSegment]:
    segments: list[CorpusSegment] = []
    for slug in (
        "auto-approve",
        "chinese-scanner-control",
        "disregard-prior",
        "execute-command",
        "hide-instruction",
        "ignore-scanner",
        "suppress-findings",
    ):
        seg = _segment(
            REPOSITORY_ROOT / "testdata" / "prompt-injection" / slug / "AGENTS.md",
            f"inj-{slug}",
            "testdata",
            0,
            8,
        )
        if seg:
            segments.append(seg)
    return segments


def _safe_segments() -> list[CorpusSegment]:
    segments: list[CorpusSegment] = []
    for slug in (
        "chinese-local-review",
        "shell-explanation",
        "local-only-network",
        "read-only-control-assets",
        "document-reference",
        "minimal-agent",
    ):
        seg = _segment(
            REPOSITORY_ROOT / "testdata" / "safe" / slug / "AGENTS.md",
            f"safe-{slug}",
            "testdata",
            0,
            8,
        )
        if seg:
            segments.append(seg)
    return segments


def _homi_segments() -> list[CorpusSegment]:
    selections = [
        ("baseline-01", 44, 56),
        ("baseline-02", 0, 5),
        ("baseline-03", 0, 5),
        ("baseline-08", 0, 5),
        ("baseline-09", 0, 5),
        ("pr-01", 0, 5),
        ("pr-02", 0, 5),
        ("pr-04", 0, 5),
        ("pr-07", 0, 5),
        ("pr-09", 0, 5),
    ]
    pack_root = (
        REPOSITORY_ROOT
        / "pilots"
        / "external-homi-demo"
        / "final-pilot"
        / "reviewer-pack"
        / "snapshots"
    )
    segments: list[CorpusSegment] = []
    for slug, start, end in selections:
        path = pack_root / f"{slug}.zip"
        if not path.exists():
            continue
        seg = _segment(
            path,
            f"homi-{slug}",
            "homi_snapshot",
            start,
            end,
            inner="AGENTS.md",
        )
        if seg:
            segments.append(seg)
    return segments


def _demo_segments() -> list[CorpusSegment]:
    sources = [
        ("demo-release-baseline", "demos/release-agent/baseline/AGENTS.md"),
        ("demo-release-risky", "demos/release-agent/risky-drift/AGENTS.md"),
        ("demo-release-remediated", "demos/release-agent/remediated/AGENTS.md"),
        ("demo-release-injection", "demos/release-agent/prompt-injection/AGENTS.md"),
        ("demo-release-zh-risky", "demos/release-agent-zh/risky-drift/AGENTS.md"),
        ("demo-release-zh-baseline", "demos/release-agent-zh/baseline/AGENTS.md"),
        ("demo-capchain-risky", "demos/capability-drift-agent/risky-drift/AGENTS.md"),
    ]
    segments: list[CorpusSegment] = []
    for case_id, relative in sources:
        path = REPOSITORY_ROOT / relative
        if not path.exists():
            continue
        seg = _segment(path, case_id, "demo", 0, 10)
        if seg:
            segments.append(seg)
    return segments


def collect_segments() -> list[CorpusSegment]:
    """Collect every corpus segment, deduplicated and sorted by case id."""

    segments = (
        _risky_segments()
        + _injection_segments()
        + _safe_segments()
        + _homi_segments()
        + _demo_segments()
    )
    unique: dict[str, CorpusSegment] = {}
    for segment in segments:
        unique.setdefault(segment.case_id, segment)
    return [unique[key] for key in sorted(unique)]


def build_pack() -> int:
    segments = collect_segments()
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)

    cases: list[dict[str, Any]] = []
    for segment in segments:
        chunk = build_semantic_evidence_chunk(
            asset_path=segment.source_label,
            asset_sha256=_ASSET_SHA_PLACEHOLDER,
            start_line=segment.start_line,
            end_line=segment.start_line + segment.content.count("\n"),
            text=segment.content,
        )
        cases.append(
            {
                "case_id": segment.case_id,
                "source_kind": segment.source_kind,
                "source_label": segment.source_label,
                "start_line": segment.start_line,
                "end_line": segment.start_line + segment.content.count("\n"),
                "evidence_id": chunk.evidence_id,
                "sanitized_text": chunk.text,
            }
        )

    manifest = {
        "format": "agentsec-p3-11-semantic-reviewer-pack",
        "format_version": "0.1.0",
        "pilot_task": "P3-11A",
        "case_count": len(cases),
        "case_ids": [case["case_id"] for case in cases],
        "authority": {
            "report_only": True,
            "blocks": False,
            "policy_authority": False,
        },
        "note": (
            "Cases carry sanitized bounded text only. No expected labels are "
            "included; human reviewers must not read scanner outputs while "
            "labeling."
        ),
    }

    template = {
        "format": "agentsec-p3-11-semantic-review-submission",
        "format_version": "0.1.0",
        "reviewer_id": None,
        "cases": [
            {
                "case_id": case["case_id"],
                "evidence_id": case["evidence_id"],
                "expected": [
                    {
                        "judgment_id": "j-01",
                        "kind": None,
                        "category": None,
                        "disposition": None,
                        "evidence_ids": None,
                    }
                ],
            }
            for case in cases
        ],
    }

    (OUTPUT_ROOT / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (OUTPUT_ROOT / "cases.json").write_text(
        json.dumps(
            {"format": manifest["format"], "cases": cases},
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    (OUTPUT_ROOT / "submission.template.json").write_text(
        json.dumps(template, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    kinds: dict[str, int] = {}
    for case in cases:
        kinds[case["source_kind"]] = kinds.get(case["source_kind"], 0) + 1
    print(f"built {len(cases)} cases -> {OUTPUT_ROOT}")
    print(f"kinds: {kinds}")
    return 0


if __name__ == "__main__":
    raise SystemExit(build_pack())
