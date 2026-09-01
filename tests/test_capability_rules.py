"""P2I-02 deterministic Capability Rule seam and built-in Rule Pack tests."""

from __future__ import annotations

from pathlib import Path

from agentsec.application import AgentAnalysisPipeline, AgentAnalysisRequest
from agentsec.capability_rules import (
    BUILTIN_CAPABILITY_RULE_IDS,
    CapabilityCorrelation,
    CapabilityRuleCandidate,
    CapabilityRuleContext,
    CapabilityRuleEvaluation,
    CapabilityRuleFinding,
    CapabilityRuleLanguage,
    CapabilityRuleMetadata,
    CapabilityRuleRunResult,
    CapabilityRuleText,
    DeterministicCapabilityRuleRunner,
    builtin_capability_rules,
)
from agentsec.domain import (
    EvidenceConfidence,
    FindingCategory,
    ImpactLevel,
    LikelihoodLevel,
    Severity,
)
from agentsec.manifests import (
    AgentManifest,
    ManifestControl,
    ManifestControlKind,
    ManifestControlProfile,
    ManifestControlState,
    ManifestPermission,
    ManifestPermissionAction,
    ManifestPermissionEffect,
    ManifestPermissionProfile,
    ManifestRelationshipProfile,
    ManifestRelationState,
    ManifestResolutionStatus,
    ManifestResourceKind,
    ManifestResourceScope,
    ManifestRuntimeIdentityProfile,
    ManifestSourceLocator,
    ManifestSourceReference,
    ManifestSourceScope,
    UnknownExtractor,
)
from agentsec.risk import ImpactDimension, ImpactRating
from agentsec.versioning import (
    CAPABILITY_RISK_MODEL_VERSION,
    CAPABILITY_RULE_PACK_VERSION,
    current_versions,
)

_SECRET_MARKER = "p2i-02-secret-must-not-leak"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _analyze(project: Path) -> AgentManifest:
    return (
        AgentAnalysisPipeline()
        .analyze(AgentAnalysisRequest(project_root=project, agent_id="release-agent"))
        .manifest
    )


def _run(manifest: AgentManifest) -> CapabilityRuleRunResult:
    return DeterministicCapabilityRuleRunner(builtin_capability_rules()).run(manifest)


def _rule_findings(
    result: CapabilityRuleRunResult, rule_id: str
) -> tuple[CapabilityRuleFinding, ...]:
    return tuple(finding for finding in result.findings if finding.rule_id == rule_id)


def _add_permission(
    manifest: AgentManifest,
    *,
    target: str,
    action: ManifestPermissionAction,
    resource: ManifestResourceKind,
    scope: ManifestResourceScope,
    effect: ManifestPermissionEffect = ManifestPermissionEffect.UNKNOWN,
) -> AgentManifest:
    source = next(
        permission.sources[0]
        for permission in manifest.permissions.permissions
        if permission.target == target
    )
    permission = ManifestPermission(
        permission_id=f"permission:{action.value}:{target}:synthetic",
        action=action,
        effect=effect,
        resource=resource,
        scope=scope,
        target=target,
        sources=(source,),
    )
    permissions = tuple(
        sorted(
            (*manifest.permissions.permissions, permission),
            key=lambda item: item.permission_id,
        )
    )
    payload = manifest.model_dump(mode="python")
    payload["permissions"] = ManifestPermissionProfile(
        resolution=ManifestResolutionStatus.PARTIAL,
        declaration_sources=manifest.permissions.declaration_sources,
        permissions=permissions,
    ).model_dump(mode="python")
    payload["unknowns"] = ()
    return UnknownExtractor().extract(AgentManifest.model_validate(payload))


def test_capability_rule_versions_registry_and_bilingual_metadata_are_stable() -> None:
    versions = current_versions()
    rules = builtin_capability_rules()

    assert versions.capability_rule_pack == CAPABILITY_RULE_PACK_VERSION == "0.2.0"
    assert versions.capability_risk_model == CAPABILITY_RISK_MODEL_VERSION == "0.1.0"
    assert tuple(rule.metadata.rule_id for rule in rules) == BUILTIN_CAPABILITY_RULE_IDS
    assert BUILTIN_CAPABILITY_RULE_IDS == (
        "CAP-APPROVAL-001",
        "CAP-AUTONETWORK-001",
        "CAP-AUTOPROD-001",
        "CAP-AUTOSECRET-001",
        "CAP-CHAIN-001",
        "CAP-COVERAGE-001",
        "CAP-DELEGATE-001",
        "CAP-DELEGATEEXTERNAL-001",
        "CAP-DELEGATEPERSIST-001",
        "CAP-EXTERNAL-001",
        "CAP-EXTERNALEXEC-001",
        "CAP-EXTERNALPRIVILEGED-001",
        "CAP-EXTERNALUNVERIFIED-001",
        "CAP-EXTERNALWRITE-001",
        "CAP-MEMORYNETWORK-001",
        "CAP-MEMORYPROD-001",
        "CAP-MEMORYSECRET-001",
        "CAP-NONETWORKPOLICY-001",
        "CAP-NOSANDBOX-001",
        "CAP-NOSECRET-001",
        "CAP-PERSIST-001",
        "CAP-PRODADMIN-001",
        "CAP-PRODEXEC-001",
        "CAP-PRODIDENTITY-001",
        "CAP-PRODWRITE-001",
        "CAP-RELATIONUNKNOWN-001",
        "CAP-REQUIREDNOFILTER-001",
        "CAP-REQUIREDNOTIMEOUT-001",
        "CAP-SECRETPROD-001",
    )
    for rule in rules:
        english = rule.metadata.text_for(CapabilityRuleLanguage.EN)
        chinese = rule.metadata.text_for(CapabilityRuleLanguage.ZH)
        assert english.title
        assert chinese.title
        assert english.recommendations
        assert chinese.recommendations
        assert english != chinese
        assert rule.metadata.hard_gate is False


def test_chain_rule_uses_same_target_b_confidence_and_high_severity(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")
    _write(
        project / ".codex" / "config.toml",
        f"""
[mcp_servers.remote]
url = "https://example.invalid/mcp?token={_SECRET_MARKER}"
enabled = true
required = true
auth = "oauth"
bearer_token_env_var = "REMOTE_TOKEN"
default_tools_approval_mode = "prompt"
""".lstrip(),
    )
    manifest = _add_permission(
        _analyze(project),
        target="mcp-server:remote",
        action=ManifestPermissionAction.EXECUTE,
        resource=ManifestResourceKind.SHELL,
        scope=ManifestResourceScope.EXTERNAL,
    )

    result = _run(manifest)
    findings = _rule_findings(result, "CAP-CHAIN-001")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.correlation is CapabilityCorrelation.SAME_TARGET
    assert finding.confidence is EvidenceConfidence.B
    assert finding.likelihood is LikelihoodLevel.MODERATE
    assert finding.impact is ImpactLevel.VERY_HIGH
    assert finding.severity is Severity.HIGH
    assert finding.score == 8.0
    assert finding.hard_gate is False
    assert all(evidence.content_sha256 for evidence in finding.evidence)
    assert _SECRET_MARKER not in repr(finding)
    assert "example.invalid" not in repr(finding)


def test_chain_rule_correlates_parent_child_tool_family_with_c_confidence(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")
    _write(
        project / ".codex" / "config.toml",
        """
[mcp_servers.local]
command = "local-server"
bearer_token_env_var = "LOCAL_TOKEN"
enabled_tools = ["send"]
default_tools_approval_mode = "prompt"
""".lstrip(),
    )
    manifest = _add_permission(
        _analyze(project),
        target="mcp-tool:local:send",
        action=ManifestPermissionAction.NETWORK,
        resource=ManifestResourceKind.NETWORK,
        scope=ManifestResourceScope.EXTERNAL,
    )

    findings = _rule_findings(_run(manifest), "CAP-CHAIN-001")

    assert len(findings) == 1
    assert findings[0].correlation is CapabilityCorrelation.PARENT_CHILD
    assert findings[0].confidence is EvidenceConfidence.C
    assert findings[0].severity is Severity.HIGH
    assert findings[0].related_ids == (
        "mcp-server:local",
        "mcp-tool:local:send",
    )


def test_chain_rule_falls_back_to_agent_wide_d_without_cartesian_findings(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")
    _write(
        project / ".codex" / "config.toml",
        """
[mcp_servers.local]
command = "local-server"
bearer_token_env_var = "LOCAL_TOKEN"
default_tools_approval_mode = "prompt"

[mcp_servers.remote]
url = "https://example.invalid/mcp"
auth = "oauth"
""".lstrip(),
    )

    findings = _rule_findings(_run(_analyze(project)), "CAP-CHAIN-001")

    assert len(findings) == 1
    assert findings[0].correlation is CapabilityCorrelation.AGENT_WIDE
    assert findings[0].confidence is EvidenceConfidence.D
    assert findings[0].likelihood is LikelihoodLevel.LOW
    assert findings[0].severity is Severity.MEDIUM
    assert len(findings[0].related_ids) == 3


def test_chain_rule_has_a_safe_negative_without_all_three_actions(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")
    _write(
        project / ".codex" / "config.toml",
        '[mcp_servers.remote]\nurl = "https://example.invalid/mcp"\n',
    )

    assert not _rule_findings(_run(_analyze(project)), "CAP-CHAIN-001")


def test_approval_rule_detects_auto_and_missing_prompt_but_not_prompt(
    tmp_path: Path,
) -> None:
    risky = tmp_path / "risky"
    safe = tmp_path / "safe"
    risky.mkdir()
    safe.mkdir()
    _write(risky / "AGENTS.md", "# Agent\n")
    _write(safe / "AGENTS.md", "# Agent\n")
    _write(
        risky / ".codex" / "config.toml",
        """
[mcp_servers.release]
command = "release-server"
enabled = true
default_tools_approval_mode = "auto"
""".lstrip(),
    )
    _write(
        safe / ".codex" / "config.toml",
        """
[mcp_servers.release]
command = "release-server"
enabled = true
default_tools_approval_mode = "prompt"
""".lstrip(),
    )

    risky_findings = _rule_findings(_run(_analyze(risky)), "CAP-APPROVAL-001")
    safe_findings = _rule_findings(_run(_analyze(safe)), "CAP-APPROVAL-001")

    assert len(risky_findings) == 1
    assert risky_findings[0].correlation is CapabilityCorrelation.SAME_TARGET
    assert risky_findings[0].confidence is EvidenceConfidence.B
    assert risky_findings[0].severity is Severity.HIGH
    assert safe_findings == ()


def test_approval_rule_honors_prompt_permission_effect(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")
    _write(
        project / ".codex" / "rules" / "default.rules",
        'prefix_rule(pattern=["git", "status"], decision="prompt")\n',
    )

    assert not _rule_findings(_run(_analyze(project)), "CAP-APPROVAL-001")


def test_persistence_rule_combines_explicit_memory_with_sensitive_capability(
    tmp_path: Path,
) -> None:
    risky = tmp_path / "risky"
    safe = tmp_path / "safe"
    risky.mkdir()
    safe.mkdir()
    _write(
        risky / "AGENTS.md",
        "---\npersists_memory: release_state\n---\n# Agent\n",
    )
    _write(safe / "AGENTS.md", "# Agent\n")
    for project in (risky, safe):
        _write(
            project / ".codex" / "config.toml",
            """
[mcp_servers.remote]
url = "https://example.invalid/mcp"
bearer_token_env_var = "REMOTE_TOKEN"
""".lstrip(),
        )

    findings = _rule_findings(_run(_analyze(risky)), "CAP-PERSIST-001")

    assert len(findings) == 1
    assert findings[0].correlation is CapabilityCorrelation.AGENT_WIDE
    assert findings[0].confidence is EvidenceConfidence.D
    assert findings[0].severity is Severity.MEDIUM
    assert not _rule_findings(_run(_analyze(safe)), "CAP-PERSIST-001")


def test_delegation_rule_requires_unapproved_powerful_capability(
    tmp_path: Path,
) -> None:
    risky = tmp_path / "risky"
    safe = tmp_path / "safe"
    risky.mkdir()
    safe.mkdir()
    for project in (risky, safe):
        _write(
            project / "AGENTS.md",
            "---\ndelegates_to: [deployer]\n---\n# Agent\n",
        )
    _write(
        risky / ".codex" / "config.toml",
        """
[mcp_servers.release]
command = "release-server"
enabled = true
default_tools_approval_mode = "auto"
""".lstrip(),
    )
    _write(
        safe / ".codex" / "config.toml",
        """
[mcp_servers.release]
command = "release-server"
enabled = true
default_tools_approval_mode = "prompt"
""".lstrip(),
    )

    findings = _rule_findings(_run(_analyze(risky)), "CAP-DELEGATE-001")

    assert len(findings) == 1
    assert findings[0].correlation is CapabilityCorrelation.AGENT_WIDE
    assert findings[0].confidence is EvidenceConfidence.D
    assert findings[0].severity is Severity.MEDIUM
    assert not _rule_findings(_run(_analyze(safe)), "CAP-DELEGATE-001")


def test_external_rule_requires_enabled_required_credentialed_external_mcp(
    tmp_path: Path,
) -> None:
    risky = tmp_path / "risky"
    safe = tmp_path / "safe"
    risky.mkdir()
    safe.mkdir()
    for project in (risky, safe):
        _write(project / "AGENTS.md", "# Agent\n")
    _write(
        risky / ".codex" / "config.toml",
        """
[mcp_servers.remote]
url = "https://example.invalid/mcp"
enabled = true
required = true
auth = "oauth"
default_tools_approval_mode = "prompt"
""".lstrip(),
    )
    _write(
        safe / ".codex" / "config.toml",
        """
[mcp_servers.remote]
url = "https://example.invalid/mcp"
enabled = true
required = false
auth = "oauth"
default_tools_approval_mode = "prompt"
""".lstrip(),
    )

    findings = _rule_findings(_run(_analyze(risky)), "CAP-EXTERNAL-001")

    assert len(findings) == 1
    assert findings[0].correlation is CapabilityCorrelation.SAME_TARGET
    assert findings[0].confidence is EvidenceConfidence.B
    assert findings[0].severity is Severity.HIGH
    assert not _rule_findings(_run(_analyze(safe)), "CAP-EXTERNAL-001")


def test_coverage_rule_reports_high_impact_facts_under_incomplete_or_unknown_state(
    tmp_path: Path,
) -> None:
    incomplete = tmp_path / "incomplete"
    complete = tmp_path / "complete"
    incomplete.mkdir()
    complete.mkdir()
    _write(incomplete / "AGENTS.md", "# Agent\n")
    (incomplete / "AGENTS.override.md").write_bytes(b"\xff\xfe")
    _write(
        incomplete / ".codex" / "config.toml",
        """
[mcp_servers.local]
command = "local-server"
default_tools_approval_mode = "prompt"
""".lstrip(),
    )
    _write(complete / "AGENTS.md", "# Agent\n")
    _write(
        complete / ".codex" / "rules" / "default.rules",
        'prefix_rule(pattern=["git", "status"], decision="allow")\n',
    )

    findings = _rule_findings(_run(_analyze(incomplete)), "CAP-COVERAGE-001")

    assert findings
    assert all(
        finding.correlation is CapabilityCorrelation.INCOMPLETE_COVERAGE
        for finding in findings
    )
    assert all(finding.confidence is EvidenceConfidence.D for finding in findings)
    assert all(finding.severity is Severity.MEDIUM for finding in findings)
    assert not _rule_findings(_run(_analyze(complete)), "CAP-COVERAGE-001")


def test_coverage_rule_reports_relevant_unknown_with_complete_file_coverage(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")
    _write(
        project / ".codex" / "config.toml",
        """
[mcp_servers.release]
command = "release-server"
default_tools_approval_mode = "prompt"
""".lstrip(),
    )

    findings = _rule_findings(_run(_analyze(project)), "CAP-COVERAGE-001")

    assert len(findings) == 1
    assert findings[0].correlation is CapabilityCorrelation.INCOMPLETE_COVERAGE
    assert findings[0].related_ids == ("mcp-server:release",)
    assert findings[0].confidence is EvidenceConfidence.D


def test_all_builtin_rules_handle_incomplete_manifest_deterministically(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(
        project / "AGENTS.md",
        "---\ndelegates_to: [deployer]\npersists_memory: state\n---\n# Agent\n",
    )
    (project / "AGENTS.override.md").write_bytes(b"\xff\xfe")
    _write(
        project / ".codex" / "config.toml",
        """
[mcp_servers.local]
command = "local-server"
bearer_token_env_var = "LOCAL_TOKEN"

[mcp_servers.remote]
url = "https://example.invalid/mcp"
enabled = true
required = true
auth = "oauth"
""".lstrip(),
    )
    manifest = _analyze(project)
    runner = DeterministicCapabilityRuleRunner(builtin_capability_rules())

    first = runner.run(manifest)
    second = runner.run(manifest)

    assert first == second
    assert first.failures == ()
    assert first.evaluated_rule_ids == BUILTIN_CAPABILITY_RULE_IDS
    assert tuple(finding.rule_id for finding in first.findings) == tuple(
        sorted(finding.rule_id for finding in first.findings)
    )
    assert all(finding.evidence for finding in first.findings)


def test_runner_isolates_rule_failure_and_preserves_other_findings(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")
    _write(
        project / ".codex" / "config.toml",
        """
[mcp_servers.release]
command = "release-server"
enabled = true
default_tools_approval_mode = "auto"
""".lstrip(),
    )
    approval_rule = next(
        rule
        for rule in builtin_capability_rules()
        if rule.metadata.rule_id == "CAP-APPROVAL-001"
    )

    class FailingRule:
        metadata = CapabilityRuleMetadata(
            rule_id="CAP-TEST-999",
            category=FindingCategory.OTHER,
            texts=(
                CapabilityRuleText(
                    language=CapabilityRuleLanguage.EN,
                    title="Failing test rule",
                    description="Trusted test-only failure rule.",
                    recommendations=("Do not register this rule in production.",),
                ),
                CapabilityRuleText(
                    language=CapabilityRuleLanguage.ZH,
                    title="失败测试规则",
                    description="仅用于可信测试的失败规则。",
                    recommendations=("不要在生产规则包中注册此规则。",),
                ),
            ),
            impact_ratings=(
                ImpactRating(
                    dimension=ImpactDimension.INTEGRITY,
                    level=ImpactLevel.LOW,
                    rationale="Test-only impact rationale.",
                ),
            ),
        )

        def evaluate(self, context: CapabilityRuleContext) -> CapabilityRuleEvaluation:
            del context
            raise RuntimeError(f"unsafe rule failure {_SECRET_MARKER}")

    result = DeterministicCapabilityRuleRunner((FailingRule(), approval_rule)).run(
        _analyze(project)
    )

    assert [finding.rule_id for finding in result.findings] == ["CAP-APPROVAL-001"]
    assert tuple(failure.rule_id for failure in result.failures) == ("CAP-TEST-999",)
    assert result.complete is False
    assert _SECRET_MARKER not in repr(result.failures)


def test_runner_discards_partial_materialization_from_one_failed_rule(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")
    _write(
        project / ".codex" / "config.toml",
        """
[mcp_servers.release]
command = "release-server"
enabled = true
default_tools_approval_mode = "auto"
""".lstrip(),
    )
    manifest = _analyze(project)
    valid_reference = manifest.permissions.permissions[0].sources[0]
    missing_reference = ManifestSourceReference(
        locator=ManifestSourceLocator(
            scope=ManifestSourceScope.PROJECT,
            root_id="project",
            path="missing.toml",
        )
    )

    class PartiallyFailingRule:
        metadata = CapabilityRuleMetadata(
            rule_id="CAP-TEST-998",
            category=FindingCategory.OTHER,
            texts=(
                CapabilityRuleText(
                    language=CapabilityRuleLanguage.EN,
                    title="Partially failing test rule",
                    description="Trusted test-only materialization failure rule.",
                    recommendations=("Do not register this rule in production.",),
                ),
                CapabilityRuleText(
                    language=CapabilityRuleLanguage.ZH,
                    title="部分失败测试规则",
                    description="仅用于可信测试的物化失败规则。",
                    recommendations=("不要在生产规则包中注册此规则。",),
                ),
            ),
            impact_ratings=(
                ImpactRating(
                    dimension=ImpactDimension.INTEGRITY,
                    level=ImpactLevel.LOW,
                    rationale="Test-only impact rationale.",
                ),
            ),
        )

        def evaluate(self, context: CapabilityRuleContext) -> CapabilityRuleEvaluation:
            del context
            candidates = (
                CapabilityRuleCandidate(
                    correlation=CapabilityCorrelation.SAME_TARGET,
                    related_ids=("a-valid",),
                    evidence=(valid_reference,),
                    likelihood_basis=("Test-only valid candidate.",),
                    limitations=("Test-only limitation.",),
                ),
                CapabilityRuleCandidate(
                    correlation=CapabilityCorrelation.SAME_TARGET,
                    related_ids=("z-missing",),
                    evidence=(missing_reference,),
                    likelihood_basis=("Test-only missing candidate.",),
                    limitations=("Test-only limitation.",),
                ),
            )
            return CapabilityRuleEvaluation(candidates=candidates)

    approval_rule = next(
        rule
        for rule in builtin_capability_rules()
        if rule.metadata.rule_id == "CAP-APPROVAL-001"
    )
    result = DeterministicCapabilityRuleRunner(
        (PartiallyFailingRule(), approval_rule)
    ).run(manifest)

    assert [finding.rule_id for finding in result.findings] == ["CAP-APPROVAL-001"]
    assert tuple(failure.rule_id for failure in result.failures) == ("CAP-TEST-998",)


def _add_control(
    manifest: AgentManifest,
    *,
    target: str,
    kind: ManifestControlKind,
    state: ManifestControlState,
) -> AgentManifest:
    source = next(
        permission.sources[0]
        for permission in manifest.permissions.permissions
        if permission.target == target
    )
    control = ManifestControl(
        control_id=f"control:synthetic:{kind.value}:{target}",
        kind=kind,
        state=state,
        target=target,
        sources=(source,),
    )
    controls = tuple(
        sorted(
            (*manifest.controls.controls, control),
            key=lambda item: item.control_id,
        )
    )
    payload = manifest.model_dump(mode="python")
    payload["controls"] = ManifestControlProfile(
        resolution=ManifestResolutionStatus.PARTIAL,
        declaration_sources=manifest.controls.declaration_sources,
        controls=controls,
    ).model_dump(mode="python")
    payload["unknowns"] = ()
    return UnknownExtractor().extract(AgentManifest.model_validate(payload))


def _mark_remote_identity_privileged(manifest: AgentManifest) -> AgentManifest:
    identities = tuple(
        identity.model_copy(update={"privileged": True})
        if identity.identity_id == "identity:mcp-server:remote"
        else identity
        for identity in manifest.runtime_identities.identities
    )
    payload = manifest.model_dump(mode="python")
    payload["runtime_identities"] = ManifestRuntimeIdentityProfile(
        resolution=manifest.runtime_identities.resolution,
        declaration_sources=manifest.runtime_identities.declaration_sources,
        identities=identities,
    ).model_dump(mode="python")
    payload["unknowns"] = ()
    return UnknownExtractor().extract(AgentManifest.model_validate(payload))


def _mark_delegation_unknown(manifest: AgentManifest) -> AgentManifest:
    relations = tuple(
        relation.model_copy(update={"state": ManifestRelationState.UNKNOWN})
        if relation.kind.value == "delegates_to"
        else relation
        for relation in manifest.relationships.relations
    )
    payload = manifest.model_dump(mode="python")
    payload["relationships"] = ManifestRelationshipProfile(
        resolution=manifest.relationships.resolution,
        declaration_sources=manifest.relationships.declaration_sources,
        relations=relations,
    ).model_dump(mode="python")
    payload["unknowns"] = ()
    return UnknownExtractor().extract(AgentManifest.model_validate(payload))


def test_p2_14_extension_rules_have_reviewed_inventory_and_story_matches(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(
        project / "AGENTS.md",
        "---\ndelegates_to: [deployer]\npersists_memory: state\n---\n# Agent\n",
    )
    _write(
        project / ".codex" / "config.toml",
        """
[mcp_servers.local]
command = "local-server"
enabled = true
bearer_token_env_var = "LOCAL_TOKEN"
default_tools_approval_mode = "auto"

[mcp_servers.remote]
url = "https://example.invalid/mcp"
enabled = true
required = true
auth = "oauth"
default_tools_approval_mode = "auto"
""".lstrip(),
    )

    manifest = _analyze(project)
    result = _run(manifest)
    extension_ids = {
        finding.rule_id
        for finding in result.findings
        if finding.rule_id
        not in {
            "CAP-APPROVAL-001",
            "CAP-CHAIN-001",
            "CAP-COVERAGE-001",
            "CAP-DELEGATE-001",
            "CAP-EXTERNAL-001",
            "CAP-PERSIST-001",
        }
    }

    assert len(builtin_capability_rules()) == 29
    assert 20 <= len(builtin_capability_rules()) <= 30
    assert extension_ids >= {
        "CAP-AUTONETWORK-001",
        "CAP-AUTOSECRET-001",
        "CAP-DELEGATEEXTERNAL-001",
        "CAP-DELEGATEPERSIST-001",
        "CAP-EXTERNALUNVERIFIED-001",
        "CAP-MEMORYNETWORK-001",
        "CAP-MEMORYSECRET-001",
        "CAP-NOSANDBOX-001",
        "CAP-REQUIREDNOFILTER-001",
        "CAP-REQUIREDNOTIMEOUT-001",
    }
    assert all(finding.evidence for finding in result.findings)
    assert _SECRET_MARKER not in repr(result)
    assert "example.invalid" not in repr(result)

    safe_project = tmp_path / "safe"
    safe_project.mkdir()
    _write(safe_project / "AGENTS.md", "# Safe Agent\n")
    safe_result = _run(_analyze(safe_project))
    assert not {
        finding.rule_id
        for finding in safe_result.findings
        if finding.rule_id.startswith("CAP-")
        and finding.rule_id not in {"CAP-COVERAGE-001"}
    }


def test_p2_14_production_identity_and_unknown_relationship_rules(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(
        project / "AGENTS.md",
        "---\ndelegates_to: [deployer]\npersists_memory: state\n---\n# Agent\n",
    )
    _write(
        project / ".codex" / "config.toml",
        """
[mcp_servers.remote]
url = "https://example.invalid/mcp"
enabled = true
required = true
auth = "oauth"
default_tools_approval_mode = "auto"
""".lstrip(),
    )
    manifest = _analyze(project)
    target = "mcp-server:remote"
    for action, resource in (
        (ManifestPermissionAction.WRITE, ManifestResourceKind.PRODUCTION),
        (ManifestPermissionAction.EXECUTE, ManifestResourceKind.PRODUCTION),
        (ManifestPermissionAction.ADMIN, ManifestResourceKind.PRODUCTION),
        (ManifestPermissionAction.SECRET_ACCESS, ManifestResourceKind.SECRET_STORE),
    ):
        manifest = _add_permission(
            manifest,
            target=target,
            action=action,
            resource=resource,
            scope=ManifestResourceScope.PRODUCTION,
            effect=ManifestPermissionEffect.ALLOW,
        )
    manifest = _add_control(
        manifest,
        target=target,
        kind=ManifestControlKind.HUMAN_APPROVAL,
        state=ManifestControlState.ALLOW,
    )
    manifest = _mark_remote_identity_privileged(manifest)
    manifest = _mark_delegation_unknown(manifest)

    result = _run(manifest)
    ids = {finding.rule_id for finding in result.findings}

    assert {
        "CAP-AUTOPROD-001",
        "CAP-EXTERNALPRIVILEGED-001",
        "CAP-PRODADMIN-001",
        "CAP-PRODEXEC-001",
        "CAP-PRODIDENTITY-001",
        "CAP-PRODWRITE-001",
        "CAP-RELATIONUNKNOWN-001",
        "CAP-SECRETPROD-001",
    } <= ids
    assert all(finding.hard_gate is False for finding in result.findings)
    assert all(
        finding.confidence.value in {"B", "C", "D"} for finding in result.findings
    )


def test_p2_14_external_control_and_memory_production_rules(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(
        project / "AGENTS.md",
        "---\npersists_memory: state\n---\n# Agent\n",
    )
    _write(
        project / ".codex" / "config.toml",
        """
[mcp_servers.remote]
url = "https://example.invalid/mcp"
enabled = true
auth = "oauth"
default_tools_approval_mode = "prompt"
""".lstrip(),
    )
    manifest = _analyze(project)
    target = "mcp-server:remote"
    controls = tuple(
        control
        for control in manifest.controls.controls
        if not (
            control.target == target
            and control.kind is ManifestControlKind.NETWORK_POLICY
        )
    )
    payload = manifest.model_dump(mode="python")
    payload["controls"] = ManifestControlProfile(
        resolution=ManifestResolutionStatus.PARTIAL,
        declaration_sources=manifest.controls.declaration_sources,
        controls=controls,
    ).model_dump(mode="python")
    payload["unknowns"] = ()
    manifest = UnknownExtractor().extract(AgentManifest.model_validate(payload))
    for action, resource, scope in (
        (
            ManifestPermissionAction.WRITE,
            ManifestResourceKind.TOOL,
            ManifestResourceScope.EXTERNAL,
        ),
        (
            ManifestPermissionAction.EXECUTE,
            ManifestResourceKind.TOOL,
            ManifestResourceScope.EXTERNAL,
        ),
        (
            ManifestPermissionAction.SECRET_ACCESS,
            ManifestResourceKind.SECRET_STORE,
            ManifestResourceScope.EXTERNAL,
        ),
        (
            ManifestPermissionAction.ADMIN,
            ManifestResourceKind.PRODUCTION,
            ManifestResourceScope.PRODUCTION,
        ),
    ):
        manifest = _add_permission(
            manifest,
            target=target,
            action=action,
            resource=resource,
            scope=scope,
        )

    ids = {finding.rule_id for finding in _run(manifest).findings}

    assert {
        "CAP-EXTERNALEXEC-001",
        "CAP-EXTERNALWRITE-001",
        "CAP-MEMORYPROD-001",
        "CAP-NONETWORKPOLICY-001",
        "CAP-NOSECRET-001",
    } <= ids
