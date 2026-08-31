"""Regenerate deterministic offline fallback artifacts for the Release Agent Demo."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from agentsec.application import (
    AssessmentRequest,
    BaselineCreationRequest,
    CollectionAssessmentEngine,
    CollectionBaselineCreator,
    CollectionProjectDiffEngine,
    ProjectDiffRequest,
)
from agentsec.baselines import (
    BaselineFileWriter,
    BaselineReadResult,
    GitProvenance,
)
from agentsec.collectors import MarkdownAssetCollector
from agentsec.config import default_project_config
from agentsec.reporting import (
    AssessmentJsonRenderer,
    DiffJsonRenderer,
)

FIXED_TIME = datetime(2026, 8, 19, 5, 30, tzinfo=UTC)


class _NoGitProvenance:
    def inspect(
        self,
        project_root: Path,
        *,
        excluded_paths: tuple[Path, ...] = (),
    ) -> GitProvenance:
        del project_root, excluded_paths
        return GitProvenance(commit=None, dirty=None)


def _assessment_json(project_root: Path) -> str:
    engine = CollectionAssessmentEngine(
        MarkdownAssetCollector(),
        clock=lambda: FIXED_TIME,
    )
    assessment = engine.assess(
        AssessmentRequest(
            project_root=project_root,
            config=default_project_config(),
            config_path=None,
        )
    )
    return AssessmentJsonRenderer().render(assessment)


def _write_checksums(expected_dir: Path) -> None:
    lines = []
    for path in sorted(expected_dir.iterdir(), key=lambda item: item.name):
        if not path.is_file() or path.name == "checksums.sha256":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}")
    (expected_dir / "checksums.sha256").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    os.chdir(repository_root)
    demo_root = Path("demos/release-agent")
    expected_dir = demo_root / "expected"
    expected_dir.mkdir(parents=True, exist_ok=True)
    config = default_project_config()

    baseline_path = expected_dir / "baseline.json"
    creator = CollectionBaselineCreator(
        MarkdownAssetCollector(),
        provenance_provider=_NoGitProvenance(),
        clock=lambda: FIXED_TIME,
    )
    baseline = creator.create(
        BaselineCreationRequest(
            project_root=demo_root / "baseline",
            config=config,
            config_path=None,
            output_path=baseline_path,
        )
    )
    BaselineFileWriter().write(
        baseline,
        baseline_path,
        project_root=demo_root / "baseline",
        config_path=None,
        force=baseline_path.exists(),
    )

    reports = {
        "baseline-scan.json": demo_root / "baseline",
        "risky-findings.json": demo_root / "risky-drift",
        "injection-findings.json": demo_root / "prompt-injection",
        "malformed-scan.json": demo_root / "malformed",
        "remediated-scan.json": demo_root / "remediated",
    }
    for filename, project_root in reports.items():
        (expected_dir / filename).write_text(
            _assessment_json(project_root),
            encoding="utf-8",
        )

    diff_result = CollectionProjectDiffEngine(MarkdownAssetCollector()).compare(
        ProjectDiffRequest(
            project_root=demo_root / "risky-drift",
            config=config,
            config_path=None,
            baseline_path=baseline_path,
        )
    )
    portable_baseline = BaselineReadResult(
        baseline=diff_result.baseline.baseline,
        path=baseline_path,
        size_bytes=diff_result.baseline.size_bytes,
    )
    portable_result = replace(diff_result, baseline=portable_baseline)
    (expected_dir / "risky-diff.json").write_text(
        DiffJsonRenderer().render(portable_result),
        encoding="utf-8",
    )

    management_summary = {
        "agent": "Release Agent",
        "assessment_status": "complete",
        "highest_severity": "high",
        "findings": 10,
        "unique_rule_ids": 9,
        "modified_assets": 2,
        "human_recommendation": "hold release until the risky drift is remediated",
        "agentsec_enforcement": "report_only",
        "ci_blocking_enabled": False,
        "global_safety_claimed": False,
    }
    (expected_dir / "management-summary.json").write_text(
        json.dumps(management_summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_checksums(expected_dir)


if __name__ == "__main__":
    main()
