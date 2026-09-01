"""Safe deterministic Rich text rendering for final Phase 1 Assessments."""

from __future__ import annotations

from dataclasses import dataclass
from io import StringIO

from rich import box
from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from agentsec.domain import Assessment, CoverageIssue, Evidence, Finding, Severity
from agentsec.fail_on import FailOnDecision, evaluate_assessment_fail_on
from agentsec.reporting._ordering import (
    coverage_issue_sort_key,
    finding_sort_key,
    severity_rank,
)
from agentsec.reporting.safety import SecretRedactor, sanitize_untrusted_text


@dataclass(frozen=True, slots=True)
class AssessmentTextLimits:
    """Bounds that keep terminal output deterministic and reviewable."""

    max_findings: int = 100
    max_evidence_per_finding: int = 10
    max_recommendations_per_finding: int = 10
    max_coverage_issues: int = 100
    max_text_characters: int = 512
    console_width: int = 120

    def __post_init__(self) -> None:
        for value, label in (
            (self.max_findings, "max_findings"),
            (self.max_evidence_per_finding, "max_evidence_per_finding"),
            (
                self.max_recommendations_per_finding,
                "max_recommendations_per_finding",
            ),
            (self.max_coverage_issues, "max_coverage_issues"),
            (self.max_text_characters, "max_text_characters"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{label} must be a positive integer")
        if (
            not isinstance(self.console_width, int)
            or isinstance(self.console_width, bool)
            or not 80 <= self.console_width <= 240
        ):
            raise ValueError("console_width must be between 80 and 240")


class AssessmentTextRenderer:
    """Render human-readable Assessment text with Rich and safe source handling."""

    def __init__(
        self,
        *,
        redactor: SecretRedactor | None = None,
        limits: AssessmentTextLimits | None = None,
    ) -> None:
        self._redactor = redactor if redactor is not None else SecretRedactor()
        self._limits = limits if limits is not None else AssessmentTextLimits()

    def render(
        self,
        assessment: Assessment,
        fail_on_decision: FailOnDecision | None = None,
        policy_summary: str | None = None,
    ) -> str:
        """Return deterministic, ANSI-free Rich terminal text."""

        if not isinstance(assessment, Assessment):
            raise TypeError("assessment text rendering requires an Assessment")
        output = StringIO()
        console = Console(
            file=output,
            width=self._limits.console_width,
            color_system=None,
            force_terminal=False,
            markup=False,
            highlight=False,
        )
        if fail_on_decision is not None:
            if not isinstance(fail_on_decision, FailOnDecision):
                raise TypeError("assessment Text fail-on context is invalid")
            expected = evaluate_assessment_fail_on(
                assessment, fail_on_decision.threshold
            )
            if fail_on_decision != expected:
                raise ValueError("assessment Text fail-on decision is inconsistent")
        if policy_summary is not None and not isinstance(policy_summary, str):
            raise TypeError("assessment Text policy summary must be text")
        if fail_on_decision is not None and policy_summary is not None:
            raise ValueError("assessment Text policy contexts are mutually exclusive")
        console.print(self._renderable(assessment, fail_on_decision, policy_summary))
        return output.getvalue()

    def _renderable(
        self,
        assessment: Assessment,
        fail_on_decision: FailOnDecision | None,
        policy_summary: str | None,
    ) -> Group:
        ordered_findings = tuple(sorted(assessment.findings, key=finding_sort_key))
        visible_findings = ordered_findings[: self._limits.max_findings]
        blocks: list[RenderableType] = [
            self._header_panel(assessment, fail_on_decision, policy_summary),
            self._summary_panel(assessment, ordered_findings),
            self._version_panel(assessment),
        ]
        if not assessment.coverage.complete:
            blocks.append(self._coverage_warning(assessment))
            blocks.append(self._coverage_details(assessment))
        if not ordered_findings:
            blocks.append(
                Panel(
                    Text(
                        "No findings were produced in the supported scan scope. "
                        "This does not prove that the Agent is globally safe."
                    ),
                    title=Text("Findings"),
                    border_style="dim",
                )
            )
        else:
            blocks.append(Text("Findings", style="bold"))
            blocks.extend(self._finding_panel(item) for item in visible_findings)
            omitted = len(ordered_findings) - len(visible_findings)
            if omitted:
                blocks.append(
                    Text(
                        f"WARNING: {omitted} finding(s) omitted by the Text Reporter "
                        "limit."
                    )
                )
        return Group(*blocks)

    def _header_panel(
        self,
        assessment: Assessment,
        fail_on_decision: FailOnDecision | None,
        policy_summary: str | None,
    ) -> Panel:
        status = "COMPLETE" if assessment.coverage.complete else "INCOMPLETE"
        body = Table.grid(padding=(0, 2))
        body.add_column(justify="right", no_wrap=True)
        body.add_column()
        body.add_row(
            Text("Target", style="bold"),
            Text(self._safe(assessment.metadata.target_root)),
        )
        body.add_row(Text("Status", style="bold"), Text(status))
        if policy_summary is not None:
            policy_text = self._safe(policy_summary)
        elif fail_on_decision is not None:
            policy_text = (
                "explicit --fail-on "
                f"{fail_on_decision.threshold.value}; "
                "CI exit-code blocking is enabled"
            )
        else:
            policy_text = "report-only; CI risk blocking is disabled"
        body.add_row(Text("Policy", style="bold"), Text(policy_text))
        return Panel(
            body,
            title=Text("AgentSec Assessment", style="bold"),
            border_style="bright_blue",
        )

    def _summary_panel(
        self,
        assessment: Assessment,
        findings: tuple[Finding, ...],
    ) -> Panel:
        severity_counts = {severity: 0 for severity in Severity}
        confidence_counts = {"A": 0, "B": 0, "C": 0, "D": 0}
        for finding in findings:
            severity_counts[finding.severity] += 1
            confidence_counts[finding.confidence.value] += 1
        highest = max(
            (finding.severity for finding in findings),
            key=severity_rank,
            default=Severity.NONE,
        )
        coverage = assessment.coverage
        body = Table.grid(padding=(0, 2))
        body.add_column(justify="right", no_wrap=True)
        body.add_column()
        body.add_row(Text("Assets", style="bold"), Text(str(len(assessment.assets))))
        body.add_row(Text("Changes", style="bold"), Text(str(len(assessment.changes))))
        body.add_row(Text("Findings", style="bold"), Text(str(len(findings))))
        body.add_row(
            Text("Highest severity", style="bold"), Text(highest.value.upper())
        )
        body.add_row(
            Text("Severity counts", style="bold"),
            Text(
                f"critical={severity_counts[Severity.CRITICAL]} "
                f"high={severity_counts[Severity.HIGH]} "
                f"medium={severity_counts[Severity.MEDIUM]} "
                f"low={severity_counts[Severity.LOW]} "
                f"none={severity_counts[Severity.NONE]}"
            ),
        )
        body.add_row(
            Text("Confidence counts", style="bold"),
            Text("A={A} B={B} C={C} D={D}".format(**confidence_counts)),
        )
        body.add_row(
            Text("Hard Gates", style="bold"),
            Text(f"matched={sum(item.hard_gate for item in findings)} (report-only)"),
        )
        cvss_gate_matches = sum(
            item.cvss_hard_gate is not None and item.cvss_hard_gate.triggered
            for item in findings
        )
        body.add_row(
            Text("CVSS Hard Gates", style="bold"),
            Text(f"matched={cvss_gate_matches} (report-only)"),
        )
        body.add_row(
            Text("Coverage", style="bold"),
            Text(
                f"discovered={coverage.discovered_assets} "
                f"scanned={coverage.scanned_assets} "
                f"skipped={coverage.skipped_assets} "
                f"issues={len(coverage.issues)}"
            ),
        )
        return Panel(body, title=Text("Summary", style="bold"), border_style="cyan")

    def _version_panel(self, assessment: Assessment) -> Panel:
        metadata = assessment.metadata
        body = Table.grid(padding=(0, 2))
        body.add_column(justify="right", no_wrap=True)
        body.add_column()
        body.add_row(
            Text("Scanner", style="bold"), Text(self._safe(metadata.scanner_version))
        )
        body.add_row(
            Text("Config schema", style="bold"),
            Text(self._safe(metadata.config_schema_version)),
        )
        body.add_row(
            Text("Domain schema", style="bold"),
            Text(self._safe(metadata.schema_version)),
        )
        body.add_row(
            Text("Rule pack", style="bold"),
            Text(self._safe(metadata.rule_pack_version)),
        )
        body.add_row(
            Text("Risk model", style="bold"),
            Text(self._safe(metadata.risk_model_version)),
        )
        body.add_row(
            Text("Started", style="bold"), Text(metadata.started_at.isoformat())
        )
        body.add_row(
            Text("Completed", style="bold"), Text(metadata.completed_at.isoformat())
        )
        if metadata.git_commit is not None:
            body.add_row(
                Text("Git commit", style="bold"), Text(self._safe(metadata.git_commit))
            )
        if metadata.git_dirty is not None:
            body.add_row(
                Text("Git dirty", style="bold"), Text(str(metadata.git_dirty).lower())
            )
        return Panel(
            body, title=Text("Version and provenance", style="bold"), border_style="dim"
        )

    def _coverage_warning(self, assessment: Assessment) -> Panel:
        coverage = assessment.coverage
        return Panel(
            Text(
                "WARNING: Scan coverage is incomplete. Findings are partial and "
                "must not be interpreted as a clean pass. "
                f"Skipped assets: {coverage.skipped_assets}; "
                f"coverage issues: {len(coverage.issues)}."
            ),
            title=Text("Coverage warning", style="bold"),
            border_style="yellow",
        )

    def _coverage_details(self, assessment: Assessment) -> Panel:
        coverage = assessment.coverage
        ordered_issues = tuple(sorted(coverage.issues, key=coverage_issue_sort_key))
        if not ordered_issues:
            return Panel(
                Text(
                    "No structured Coverage Issue was retained for "
                    f"{coverage.skipped_assets} skipped asset(s). The scan remains "
                    "incomplete; review upstream collection diagnostics."
                ),
                title=Text("Coverage issues (0 total)", style="bold"),
                border_style="yellow",
            )

        visible_issues = ordered_issues[: self._limits.max_coverage_issues]
        table = Table(box=box.SIMPLE, expand=True, show_lines=False)
        table.add_column("#", justify="right", no_wrap=True)
        table.add_column("Code", no_wrap=True)
        table.add_column("Asset")
        table.add_column("Reason")
        for index, issue in enumerate(visible_issues, start=1):
            table.add_row(
                str(index),
                issue.code.value,
                self._coverage_issue_path(issue),
                self._safe(issue.message),
            )

        content: list[RenderableType] = [table]
        omitted = len(ordered_issues) - len(visible_issues)
        if omitted:
            content.append(
                Text(
                    f"WARNING: {omitted} Coverage Issue(s) omitted by the Text "
                    "Reporter limit. Coverage remains incomplete."
                )
            )
        return Panel(
            Group(*content),
            title=Text(f"Coverage issues ({len(ordered_issues)} total)", style="bold"),
            border_style="yellow",
        )

    def _coverage_issue_path(self, issue: CoverageIssue) -> str:
        if issue.asset_path is None:
            return "(scan-wide)"
        return self._safe(issue.asset_path)

    def _finding_panel(self, finding: Finding) -> Panel:
        body = Table.grid(padding=(0, 2))
        body.add_column(justify="right", no_wrap=True)
        body.add_column()
        body.add_row(
            Text("Finding ID", style="bold"), Text(self._safe(finding.finding_id))
        )
        body.add_row(Text("Rule", style="bold"), Text(self._safe(finding.rule_id)))
        body.add_row(Text("Category", style="bold"), Text(finding.category.value))
        body.add_row(Text("Score", style="bold"), Text(f"{finding.score:.1f}"))
        body.add_row(
            Text("Severity", style="bold"), Text(finding.severity.value.upper())
        )
        body.add_row(Text("Likelihood", style="bold"), Text(finding.likelihood.value))
        body.add_row(Text("Impact", style="bold"), Text(finding.impact.value))
        body.add_row(Text("Confidence", style="bold"), Text(finding.confidence.value))
        if finding.vulnerability is not None:
            body.add_row(
                Text("Vulnerability", style="bold"),
                Text(self._safe(finding.vulnerability.vulnerability_id)),
            )
            if finding.vulnerability.cve_id is not None:
                body.add_row(
                    Text("CVE", style="bold"),
                    Text(self._safe(finding.vulnerability.cve_id)),
                )
            if finding.vulnerability.cwe_ids:
                body.add_row(
                    Text("CWE", style="bold"),
                    Text(self._safe(", ".join(finding.vulnerability.cwe_ids))),
                )
            body.add_row(
                Text("Vulnerability source", style="bold"),
                Text(self._safe(finding.vulnerability.source)),
            )
            body.add_row(
                Text("Association", style="bold"),
                Text(finding.vulnerability.association_method),
            )
        if finding.cvss is not None:
            body.add_row(
                Text("CVSS Base", style="bold"),
                Text(
                    f"{finding.cvss.base_score:.1f} "
                    f"({finding.cvss.base_severity.value.upper()})"
                ),
            )
            body.add_row(
                Text("CVSS Vector", style="bold"),
                Text(self._safe(finding.cvss.vector)),
            )
            body.add_row(
                Text("CVSS Verification", style="bold"),
                Text(finding.cvss.score_verification),
            )
            if finding.cvss.score_type != "base":
                assert finding.cvss.effective_score is not None
                assert finding.cvss.effective_severity is not None
                body.add_row(
                    Text("CVSS Effective", style="bold"),
                    Text(
                        f"{finding.cvss.effective_score:.1f} "
                        f"({finding.cvss.effective_severity.value.upper()})"
                    ),
                )
                body.add_row(
                    Text("CVSS Score Type", style="bold"),
                    Text(finding.cvss.score_type),
                )
        if finding.cvss_hard_gate is not None:
            gate = finding.cvss_hard_gate
            if gate.match is None:
                gate_status = "evaluated; not matched (report-only)"
            else:
                gate_status = f"MATCHED {gate.match.gate_id} (report-only; no CI block)"
            body.add_row(Text("CVSS Hard Gate", style="bold"), Text(gate_status))
            body.add_row(
                Text("CVSS Gate Score", style="bold"),
                Text(f"{gate.score:.1f} ({gate.severity.value.upper()})"),
            )
        body.add_row(
            Text("Hard Gate", style="bold"),
            Text(
                "MATCHED (report-only; no CI block)"
                if finding.hard_gate
                else "not matched"
            ),
        )
        body.add_row(
            Text("Description", style="bold"), Text(self._safe(finding.description))
        )

        content: list[RenderableType] = [body, Text("Evidence", style="bold")]
        evidence = finding.evidence[: self._limits.max_evidence_per_finding]
        content.extend(
            self._evidence_block(index, item)
            for index, item in enumerate(evidence, start=1)
        )
        omitted_evidence = len(finding.evidence) - len(evidence)
        if omitted_evidence:
            content.append(
                Text(f"WARNING: {omitted_evidence} evidence item(s) omitted.")
            )

        content.append(Text("Recommendations", style="bold"))
        recommendations = finding.recommendations[
            : self._limits.max_recommendations_per_finding
        ]
        content.extend(
            Text(f"{index}. {self._safe(item)}")
            for index, item in enumerate(recommendations, start=1)
        )
        omitted_recommendations = len(finding.recommendations) - len(recommendations)
        if omitted_recommendations:
            content.append(
                Text(f"WARNING: {omitted_recommendations} recommendation(s) omitted.")
            )

        title = Text(
            f"[{finding.severity.value.upper()}] {self._safe(finding.title)}",
            style="bold",
        )
        return Panel(
            Group(*content), title=title, border_style=_severity_style(finding.severity)
        )

    def _evidence_block(self, index: int, evidence: Evidence) -> Panel:
        body = Table.grid(padding=(0, 2))
        body.add_column(justify="right", no_wrap=True)
        body.add_column()
        body.add_row(Text("Source", style="bold"), Text(evidence.source_type.value))
        body.add_row(
            Text("Location", style="bold"), Text(self._evidence_location(evidence))
        )
        if evidence.field is not None:
            body.add_row(Text("Field", style="bold"), Text(self._safe(evidence.field)))
        if evidence.content_sha256 is not None:
            body.add_row(Text("SHA-256", style="bold"), Text(evidence.content_sha256))
        body.add_row(
            Text("Excerpt", style="bold"),
            Text(self._safe(evidence.excerpt) if evidence.excerpt is not None else "-"),
        )
        return Panel(body, title=Text(f"Evidence {index}"), box=box.ROUNDED)

    def _evidence_location(self, evidence: Evidence) -> str:
        if evidence.asset_path is None:
            return "-"
        path = self._safe(evidence.asset_path)
        if evidence.start_line is None:
            return path
        if evidence.end_line is None or evidence.end_line == evidence.start_line:
            return f"{path}:{evidence.start_line}"
        return f"{path}:{evidence.start_line}-{evidence.end_line}"

    def _safe(self, value: str) -> str:
        sanitized = sanitize_untrusted_text(value, redactor=self._redactor)
        limit = self._limits.max_text_characters
        if len(sanitized) <= limit:
            return sanitized
        return f"{sanitized[:limit]}… [truncated from {len(sanitized)} chars]"


def _severity_style(severity: Severity) -> str:
    return {
        Severity.NONE: "dim",
        Severity.LOW: "blue",
        Severity.MEDIUM: "yellow",
        Severity.HIGH: "red",
        Severity.CRITICAL: "bold red",
    }[severity]
