AgentSec Phase 3 入口准备度 / 0.4.0 候选晋级审查
审查阶段：candidate_acceptance
状态机状态：candidate_go
结论：go
当前包版本：0.4.0
候选版本：0.4.0
本阶段可验收：True
可晋级候选版本：True
可构建候选产物：True
可进入 Phase 3 Shadow-only：True
可发布：True

检查项
  authority_boundary: pass (required) - LLM, runtime-unverified authority, and deterministic CI boundaries are documented/enforced.
  candidate_artifacts: pass (required) - 0.4.0 Wheel, sdist, and checksum evidence are consistent.
  candidate_verification: pass (required) - Candidate package verification evidence is complete.
  candidate_version_promotion: pass (required) - Package version is promoted to 0.4.0.
  entry_readiness_approval: pass (required) - Entry readiness is explicitly approved for candidate promotion.
  package_api_and_typing: pass (required) - Curated API, CLI-independent ExitCode, and py.typed are present.
  phase2_task_records: pass (required) - P2-EXIT-01 through P2-EXIT-07 task records are present.
  release_signature_and_provenance: pending (optional) - Local build evidence is present; signatures and SLSA provenance are explicitly not claimed.
  supply_chain_evidence: pass (required) - Exact lockfiles, CycloneDX/license evidence, and build provenance are present.

Limitations
  - This review does not execute scanned Agent content or grant runtime authority.
  - LLM semantic analysis remains outside the authorization path; any future LLM output must remain candidate evidence.
  - Version and report records carry no authorization authority; deterministic Rules and reviewed Policy retain decision authority.
  - Candidate acceptance does not claim remote publication, production deployment, runtime attestation, signatures, or SLSA provenance.
