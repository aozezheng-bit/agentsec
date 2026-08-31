"""Generate deterministic P2I-05 Capability Drift offline artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agentsec.application import (
    AgentAnalysisPipeline,
    AgentAnalysisRequest,
    AgentAnalysisResult,
    CapabilityAssessmentEngine,
    CapabilityAssessmentResult,
    DeterministicManifestCapabilityChangeImpactEngine,
)
from agentsec.capability_rules import CapabilityRuleLanguage
from agentsec.change_impact import CapabilityChangeImpactReport
from agentsec.manifests import CapabilityDiffer, CapabilityDiffResult
from agentsec.reporting import (
    CapabilityAssessmentJsonRenderer,
    CapabilityAssessmentTextRenderer,
    CapabilityChangeImpactJsonRenderer,
    CapabilityChangeImpactTextRenderer,
    CapabilityDiffJsonRenderer,
    CapabilityDiffTextRenderer,
    ManifestJsonRenderer,
    ManifestTextRenderer,
)

AGENT_ID = "release-agent"
DEMO_ROOTS = (
    (Path("demos/capability-drift-agent"), CapabilityRuleLanguage.EN),
    (Path("demos/capability-drift-agent-zh"), CapabilityRuleLanguage.ZH),
)
CASES = ("baseline", "risky-drift", "incomplete", "remediated")


def _write_checksums(expected: Path) -> None:
    lines = []
    for path in sorted(expected.iterdir(), key=lambda item: item.name):
        if not path.is_file() or path.name == "checksums.sha256":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}")
    (expected / "checksums.sha256").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def _management_summary(
    assessments: dict[str, CapabilityAssessmentResult],
    risky_diff: CapabilityDiffResult,
    remediation_diff: CapabilityDiffResult,
    risky_impact: CapabilityChangeImpactReport,
    remediation_impact: CapabilityChangeImpactReport,
) -> dict[str, object]:
    risky = assessments["risky-drift"]
    return {
        "agent": "Release Agent",
        "baseline_findings": len(assessments["baseline"].rules.findings),
        "risky_findings": len(risky.rules.findings),
        "risky_rule_ids": sorted({item.rule_id for item in risky.rules.findings}),
        "risky_highest_severity": max(
            (item.severity.value for item in risky.rules.findings),
            key=("none", "low", "medium", "high", "critical").index,
        ),
        "risky_capability_changes": len(risky_diff.changes),
        "risky_added": risky_diff.added_count,
        "risky_modified": risky_diff.modified_count,
        "risky_removed": risky_diff.removed_count,
        "incomplete_status": "incomplete",
        "remediated_findings": len(assessments["remediated"].rules.findings),
        "remediation_capability_changes": len(remediation_diff.changes),
        "risky_impact_added_findings": risky_impact.summary.added_findings,
        "remediation_impact_resolved_findings": (
            remediation_impact.summary.resolved_findings
        ),
        "human_recommendation": (
            "hold release until approval, credential, external MCP, delegation, "
            "and persistence drift is remediated"
        ),
        "enforcement_mode": "report_only",
        "ci_blocking_enabled": False,
        "runtime_capability_verified": False,
        "global_safety_claimed": False,
    }


def _freeze_one(root: Path, language: CapabilityRuleLanguage) -> None:
    expected = root / "expected"
    expected.mkdir(parents=True, exist_ok=True)
    pipeline = AgentAnalysisPipeline()
    assessment_engine = CapabilityAssessmentEngine()
    analyses: dict[str, AgentAnalysisResult] = {}
    assessments: dict[str, CapabilityAssessmentResult] = {}

    for case in CASES:
        request = AgentAnalysisRequest(
            project_root=root / case,
            agent_id=AGENT_ID,
        )
        analysis = pipeline.analyze(request)
        assessment = assessment_engine.assess(request)
        analyses[case] = analysis
        assessments[case] = assessment
        (expected / f"{case}.manifest.json").write_text(
            ManifestJsonRenderer().render(analysis.manifest),
            encoding="utf-8",
        )
        (expected / f"{case}.manifest.txt").write_text(
            ManifestTextRenderer(language=language).render(analysis),
            encoding="utf-8",
        )
        (expected / f"{case}.assessment.json").write_text(
            CapabilityAssessmentJsonRenderer().render(assessment),
            encoding="utf-8",
        )
        (expected / f"{case}.assessment.txt").write_text(
            CapabilityAssessmentTextRenderer(language=language).render(assessment),
            encoding="utf-8",
        )

    risky_diff = CapabilityDiffer().compare(
        before=analyses["baseline"].manifest,
        after=analyses["risky-drift"].manifest,
    )
    remediation_diff = CapabilityDiffer().compare(
        before=analyses["risky-drift"].manifest,
        after=analyses["remediated"].manifest,
    )
    impact_engine = DeterministicManifestCapabilityChangeImpactEngine()
    risky_impact = impact_engine.compare(
        before=analyses["baseline"].manifest,
        after=analyses["risky-drift"].manifest,
    )
    remediation_impact = impact_engine.compare(
        before=analyses["risky-drift"].manifest,
        after=analyses["remediated"].manifest,
    )
    for name, result in (
        ("risky", risky_diff),
        ("remediation", remediation_diff),
    ):
        (expected / f"{name}.diff.json").write_text(
            CapabilityDiffJsonRenderer().render(result),
            encoding="utf-8",
        )
        (expected / f"{name}.diff.txt").write_text(
            CapabilityDiffTextRenderer(language=language).render(result),
            encoding="utf-8",
        )
    for name, result in (
        ("risky", risky_impact),
        ("remediation", remediation_impact),
    ):
        (expected / f"{name}.impact.json").write_text(
            CapabilityChangeImpactJsonRenderer().render(result),
            encoding="utf-8",
        )
        (expected / f"{name}.impact.txt").write_text(
            CapabilityChangeImpactTextRenderer(language=language).render(result),
            encoding="utf-8",
        )

    (expected / "management-summary.json").write_text(
        json.dumps(
            _management_summary(
                assessments,
                risky_diff,
                remediation_diff,
                risky_impact,
                remediation_impact,
            ),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _write_checksums(expected)


def main() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    for relative_root, language in DEMO_ROOTS:
        _freeze_one(repository_root / relative_root, language)
        print(f"Frozen Capability Demo artifacts: {relative_root / 'expected'}")


if __name__ == "__main__":
    main()
