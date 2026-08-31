AgentSec Phase 3 入口审查 / 0.4.0 候选版本
结论：no_go
当前包版本：0.4.0.dev0
候选版本：0.4.0
可验收：False

检查项
  authority_boundary: pass (required) - LLM, runtime-unverified authority, and deterministic CI boundaries are documented/enforced.
  candidate_artifacts: pending (required) - 0.4.0 candidate artifacts are not published because entry review is not yet Go.
  candidate_version_promotion: pending (required) - Package remains on the 0.4.0.dev0 development line.
  external_pilot_evidence: pending (required) - No external real-project Pilot report was supplied.
  package_api_and_typing: pass (required) - Curated API, CLI-independent ExitCode, and py.typed are present.
  phase2_task_records: pass (required) - P2-EXIT-01 through P2-EXIT-07 task records are present.
  release_signature_and_provenance: pending (optional) - Local build evidence is present; signatures and SLSA provenance are explicitly not claimed.
  supply_chain_evidence: pass (required) - Exact lockfiles, CycloneDX/license evidence, and build provenance are present.

Limitations
  - This review does not execute scanned Agent content or grant runtime authority.
  - LLM semantic analysis remains outside the current decision path; any future LLM output must remain candidate evidence.
  - Version and report records carry no authorization authority; deterministic Rules and reviewed Policy retain decision authority.
  - 0.4.0 candidate promotion is blocked until all required checks pass.
  - External real-project Pilot evidence is pending.
