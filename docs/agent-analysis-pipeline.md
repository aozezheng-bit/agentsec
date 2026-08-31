# AgentSec Full Agent Analysis Pipeline

- Task: `P2I-01`
- Status: Complete
- Completion date: 2026-08-20
- Agent Manifest Schema: `0.3.0` (unchanged)
- Capability Diff Schema: `0.1.0` (unchanged)

## 1. Purpose

`AgentAnalysisPipeline` is the application-layer entry point that composes the
completed P2-04 through P2-11 static analysis stages into one deterministic
operation. Callers no longer need to manually preserve stage order or decide
when an already-associated Manifest can be reused.

The Pipeline produces a final validated `AgentManifest`, a bounded safe stage
trace, a Coverage-derived completion state, and the current version vector. It
does not add risk rules, reports, CLI commands, LLM analysis, or enforcement.

## 2. Public interface

```python
from pathlib import Path

from agentsec.application import AgentAnalysisPipeline, AgentAnalysisRequest

result = AgentAnalysisPipeline().analyze(
    AgentAnalysisRequest(
        project_root=Path("/workspace/release-agent"),
        working_directory=Path("/workspace/release-agent/service"),
        user_home=Path("/explicit/user-home"),
        codex_home=Path("/explicit/codex-home"),
        agent_id="release-agent",
    )
)

manifest = result.manifest
coverage_complete = result.complete
stage_trace = result.stages
versions = result.versions
```

Every root remains explicit. The Pipeline does not call `Path.home()`, infer
`CODEX_HOME`, or read process environment values. With the default Adapter,
`codex_home` is passed only to `CodexAdapter`; `user_home`, working directory,
and resource limits are passed through `FrameworkInspectionRequest`.

## 3. Stage order

The fixed order is:

```text
1. adapter_inspection
2. manifest_build
3. instruction_resolution
4. configuration_resolution
5. association_extraction
6. capability_extraction
7. relationship_extraction
8. unknown_extraction
9. final_validation
```

Each semantic stage is invoked once. `CapabilityExtractor` and
`RelationshipExtractor` now expose optimized application-layer entry points:

```python
CapabilityExtractor.extract_associated(manifest, inspection)
RelationshipExtractor.extract_associated(manifest, inspection)
```

Their existing public `extract(manifest, inspection)` APIs remain compatible and
still perform Association internally for standalone callers. The Pipeline runs
`AssociationExtractor` once, then uses the already-associated entry points to
avoid duplicate semantic work.

## 4. Request and result model

`AgentAnalysisRequest` contains only explicit trusted orchestration inputs:

```text
project_root
working_directory
user_home
codex_home
agent_id
FrameworkInspectionLimits
```

`AgentAnalysisResult` contains:

```text
manifest     final strict AgentManifest
stages       deterministic nine-stage trace
complete     exactly Manifest Coverage complete/incomplete
versions     current AgentSec VersionSet
```

`complete=true` means inspection Coverage is complete. It does not claim that
all runtime capabilities are known, that every profile is resolved, or that the
Agent is safe. Profile resolution and explicit `ManifestUnknown` entries remain
the source of truth for semantic uncertainty.

## 5. Safe Stage Trace

Every `AnalysisStageResult` contains only:

```text
stage
status: completed / partial / skipped / failed
input_items
output_items
safe error_code, only for failed stages
```

The first implementation uses `completed` for successful complete-Coverage
analysis and `partial` for successful incomplete-Coverage analysis. `skipped` is
reserved for a future optional-stage policy; all P2I-01 stages are required.

The trace never stores source text, parsed values, absolute target paths,
commands, endpoints, URL queries, headers, environment values, credentials, or
dependency exception messages.

## 6. Failure behavior

A required stage failure raises `AgentAnalysisError` with:

```text
stage
safe code:
  adapter_failure
  required_stage_failure
  final_validation_failure
completed safe stage trace plus one failed stage record
```

The dependency exception remains chained for controlled developer debugging,
but its message is not copied into the public AgentAnalysis error or trace.
Delivery layers must render only the safe stage and code, never an untrusted
cause traceback.

Incomplete asset Coverage is not a required-stage failure. The Pipeline returns
a valid Partial Manifest, materializes Coverage Unknowns, marks the safe trace
as partial, and sets `result.complete=false`.

## 7. Injection seam

The Pipeline constructor accepts injected implementations for:

```text
Framework Adapter
Manifest Builder
Instruction Resolver
Configuration Resolver
Association Extractor
Capability Extractor
Relationship Extractor
Unknown Extractor
```

This permits order/count tests and future framework composition without moving
framework logic into CLI code. The final strict `AgentManifest.model_validate`
step remains owned by the Pipeline.

## 8. Security boundary

P2I-01 never:

- executes scanned code, commands, Hooks, Skills, Rules, plugins, or MCP;
- connects to an MCP server or endpoint;
- follows source references or relationship targets;
- reads environment-variable, Header, token, credential, or memory values;
- copies parsed source values into Stage Trace;
- calls an LLM;
- creates Risk Findings or changes CI exit/enforcement policy;
- changes Agent Manifest, Capability Diff, Phase 1 Domain, Rule Pack, or Risk
  Model versions.

All previously documented Adapter, Parser, Manifest, Coverage, and Unknown
invariants remain in force.

## 9. Verification coverage

`tests/test_agent_analysis_pipeline.py` verifies:

1. byte-deterministic equality with the legacy manual P2-04～P2-11 chain;
2. every semantic component executes exactly once and in the expected order;
3. the optimized associated entry points preserve legacy public API behavior;
4. incomplete Coverage returns a usable Partial Manifest and visible Unknown;
5. dependency failure text is not copied into public Pipeline errors.

Existing Association, Capability, Relationship, Unknown, and Capability Diff
regressions also run unchanged, proving backward compatibility.

## 10. Next task

P2I-02 supplies the framework-neutral deterministic Capability Rule seam and
initial combination-risk pack. P2I-03 now supplies Manifest, Capability
Assessment, and Capability Diff Text/JSON reports. The next task is P2I-04,
which exposes the completed application and report layers through CLI commands.
