# AgentSec Domain Glossary

## Finding

An independently actionable, evidence-backed security result produced from one
stable detection meaning.

## Severity

The potential harm level of a Finding. Severity is independent from Evidence
Confidence and may be raised by a Hard Gate floor.

## Evidence Confidence

The strength of evidence supporting a Finding. Confidence never lowers Severity
and never disables a Hard Gate.

## Hard Gate

A deterministic policy condition that establishes a minimum risk level which
cannot be reduced by averaging or lower-scored signals. A matched Hard Gate is
metadata about the Finding; it is not itself a CI enforcement decision.

## Hard Gate Floor

The minimum High or Critical risk level established by a matched Hard Gate.
The effective risk is the greater of the base risk and the floor.

## Triggered Hard Gate

A Hard Gate with at least one matched deterministic condition. Triggered status
is independent from whether an external policy engine blocks delivery.

## Report-Only

A policy mode that records and applies Hard Gate metadata to the reported risk
but does not block CI or change process exit policy.
## StructuredDocument

A deterministic, source-backed flat tree produced from bounded decoded JSON,
YAML, or TOML text before framework-specific meaning is assigned.

## StructuredNode

One object, array, or scalar in a StructuredDocument with a normalized path,
typed kind, and 1-based inclusive source line range.

## StructuredParser

The deep-module interface implemented by the JSON, YAML, and TOML Parser
adapters. It parses data only and has no filesystem, environment, network, tool,
MCP, execution, or LLM authority.
## PrefixRuleDeclaration

An inert source-backed Codex `.rules` declaration containing a literal prefix
pattern, allow/prompt/forbidden decision, optional justification, and optional
inline match/non-match examples. It is parsed but not executed or evaluated.

## McpServerDeclaration

A static source-backed MCP configuration declaration. It records transport,
launch or endpoint metadata, environment names, tool policy, approval controls,
and unknown fields without starting or connecting to the server.

## SourceBackedValue

A parsed value bound to a normalized field path and 1-based inclusive source
line range. Its value is excluded from default `repr` output to reduce accidental
logging, but downstream serialization still requires redaction review.
## FrameworkAdapter

The deep-module interface implemented by each supported Agent framework. It
discovers and parses inert control assets into one neutral inspection result.

## FrameworkAssetLocator

A portable source locator containing project/user/plugin scope, a named source
root, and a safe relative POSIX path instead of an absolute host path.

## FrameworkInspectionResult

A deterministic tuple of parser-coherent framework asset records plus explicit
Coverage Issues and discovered/skipped counts. It is input to the future Agent
Manifest builder, not the Phase 1 RuleContext.

## CodexAdapter

The P2-04 non-executing Framework Adapter that discovers reviewed Codex Agent,
Skill, Rules, TOML, and MCP control assets under explicit project, working,
user-home, and optional Codex-home roots. It records inert parsed facts and
Coverage, not effective authorization or runtime capability.

## Agent Manifest

A versioned, deterministic, source-backed declaration inventory for one Agent
subject. It records what was declared and how completely each dimension has
been resolved; it is not an Effective Capability Profile, runtime attestation,
risk result, or authorization decision.

## Manifest Source

A portable control-asset identity and integrity record used as provenance for
Manifest facts. It contains scope, named root, relative path, format, roles,
hash, size, line count, and precedence without copying source content.

## Resolution Status

The explicit state of one Manifest dimension: unresolved, partial, resolved,
unknown, not applicable, or conflict. Unknown does not mean absent, denied, or
safe; unresolved means relevant declarations exist but final facts have not yet
been selected.

## Runtime Identity

A credential-free principal and authentication description used by an Agent or
tool. It is distinct from the Agent subject identity and never contains secret
values.

## Instruction Resolver

The deterministic, non-executing module that selects effective instruction
sources from Manifest Base/Override candidates, preserves user/project and
root/nested application order, records superseded sources and decision trace,
and marks incomplete coverage as partial rather than clean.

## Configuration Resolver

The deterministic source-level module that orders Framework, Rules, and MCP
configuration sources by explicit scope and precedence without merging raw
configuration values. Its `effective_order` carries precedence semantics; its
`effective_sources` carries canonical serialization order.

## Explicit Unknown

A P2-11 `ManifestUnknown` entry that makes a profile or item-level unresolved
fact machine-visible through a stable dimension, reason, field, and optional
source provenance. Unknown means insufficient deterministic evidence; it does
not mean absent, denied, or safe.

## Capability Diff

The P2-11 versioned comparison of two compatible Agent Manifests for the same
Agent and Framework. It reports added, removed, and modified capability items,
profile transitions, and Coverage state using stable IDs, safe changed-field
names, SHA-256 fingerprints, and source references. It does not copy complete
item values, replace file/text Diff, assign risk, or block CI.
## Agent Analysis Pipeline

The P2I-01 application service that composes Codex inspection, Manifest build,
instruction and configuration resolution, association, capability, relationship,
Unknown extraction, and final validation into one deterministic call. It does
not execute declarations, assign risk, call an LLM, or enforce policy.

## Analysis Stage Trace

Bounded operational metadata for one Agent Analysis Pipeline run. It records a
stable stage, completed/partial/skipped/failed status, safe item counts, and an
optional stable error code without source text, parsed values, secret values, or
dependency exception messages.

## Capability Rule

A P2I-02 deterministic rule over one finalized Agent Manifest. It correlates
normalized tools, permissions, controls, runtime identities, relationships,
Coverage, and Unknowns without reading source files or using a Markdown
`RuleContext`.

## Capability Correlation

The reviewed evidence-join scope for a Capability Finding: same target,
parent/child tool family, same source, explicit relation, Agent-wide, or
incomplete analysis. Correlation controls evidence Confidence and a reviewed
static reachability likelihood; Confidence never multiplies or lowers Severity.

## Capability Risk Model

The independently versioned P2I-02 policy for correlation, likelihood,
high-water-mark impact, NIST matrix scoring, Evidence Confidence, value-free
evidence, and report-only behavior. It does not redefine the Phase 1 Markdown
Risk Model.

## Capability Assessment

The P2I-03 deterministic application result combining one final Agent Analysis
Result with one Capability Rule Run Result. It is complete only when Manifest
Coverage and Rule execution are both complete; Findings themselves do not make
the assessment incomplete or activate enforcement.

## Capability Assessment Output

The independently versioned P2I-03 strict JSON wrapper containing fixed
report-only policy, derived management summary, canonical Agent Manifest,
Capability Findings, safe Stage Trace, and isolated Rule failures. It is distinct
from the Phase 1 Assessment Output and does not claim runtime reachability or
global Agent safety.

## Capability Report

A bounded bilingual Text presentation or strict canonical/versioned JSON
presentation of Agent Manifest, Capability Assessment, or Capability Diff. Text
limits may omit details with visible counts; canonical JSON remains complete
within upstream Parser and inspection limits.

## Report Artifact

A local Text or JSON Manifest, Capability Assessment, or Capability Diff output
written through the P2I-04 restricted writer. New artifacts are validated,
mode-0600, and atomic; replacement is allowed only for an existing valid artifact
of the same kind and format.

## Artifact Error

CLI exit code `4` when a required Manifest/Baseline artifact is missing, invalid,
incompatible, oversized, symbolic-linked, protected, or unsafe to create or
replace. It is distinct from incomplete analysis (`2`) and required semantic
analysis failure (`5`).

## Capability Drift Demo

The P2I-05 bilingual, inert story that compares reviewed baseline, risky, and
remediated Agent Manifests, shows deterministic combination Findings and
normalized Capability Diff, and includes an incomplete Coverage state. It is a
static governance demonstration, not a runtime exploit or enforcement action.

## Demo Offline Fallback

SHA-256-protected deterministic Manifest, Capability Assessment, Capability Diff,
localized Text, and management-summary artifacts used when live CLI presentation
is unavailable. Frozen output must be regenerated only after reviewed semantic
changes and revalidated before acceptance.
