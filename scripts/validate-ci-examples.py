#!/usr/bin/env python3
"""Validate P2-29 CI examples with deterministic local replay."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class ReplayCase:
    """One expected organization-policy CI outcome."""

    name: str
    project: Path
    policy: Path
    expected_exit: int
    reports_expected: bool = True
    trust_root: Path | None = None
    expect_policy_sha256: str | None = None
    policy_argument: str | None = None


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--agentsec",
        type=Path,
        help="Path to the installed agentsec executable.",
    )
    return parser.parse_args()


def _resolve_agentsec(repository_root: Path, requested: Path | None) -> Path:
    candidate = requested or repository_root / ".venv" / "bin" / "agentsec"
    resolved = candidate.resolve()
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise SystemExit(f"AgentSec executable is unavailable: {resolved}")
    return resolved


def _validate_github_workflow(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    document = yaml.load(text, Loader=yaml.BaseLoader)
    if not isinstance(document, dict):
        raise AssertionError("GitHub workflow must be a YAML mapping")
    triggers = document.get("on")
    if not isinstance(triggers, dict):
        raise AssertionError("GitHub workflow must declare mapping triggers")
    if not {"pull_request", "workflow_dispatch"} <= set(triggers):
        raise AssertionError("GitHub workflow must support PR and manual execution")
    required_fragments = (
        "scripts/run-agentsec-ci.sh",
        "actions/upload-artifact@v4",
        "github/codeql-action/upload-sarif@v4",
        "if: always()",
        "Enforce the preserved AgentSec exit code",
        'case "$AGENTSEC_EXIT_CODE" in',
        "exit 1",
        "exit 2",
        "exit 3",
        "exit 5",
        "exit 64",
    )
    for fragment in required_fragments:
        if fragment not in text:
            raise AssertionError(f"GitHub workflow is missing {fragment!r}")
    if "continue-on-error" in text:
        raise AssertionError(
            "GitHub workflow must not use continue-on-error to mask enforcement"
        )
    if "SARIF" not in text or "security-events: write" not in text:
        raise AssertionError("GitHub workflow must preserve SARIF upload permissions")


def _validate_github_trusted_workflow(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    document = yaml.load(text, Loader=yaml.BaseLoader)
    if not isinstance(document, dict):
        raise AssertionError("trusted GitHub workflow must be a YAML mapping")
    required_fragments = (
        "scripts/run-agentsec-ci.sh",
        "AGENTSEC_TRUST_ROOT",
        "AGENTSEC_EXPECT_POLICY_SHA256",
        "Check out trusted security policy repository",
        "persist-credentials: false",
        "Enforce the preserved AgentSec exit code",
        "if: always()",
    )
    for fragment in required_fragments:
        if fragment not in text:
            raise AssertionError(f"trusted GitHub workflow is missing {fragment!r}")
    if "continue-on-error" in text:
        raise AssertionError(
            "trusted GitHub workflow must not mask enforcement with continue-on-error"
        )
    if text.count("actions/checkout@v5") < 2:
        raise AssertionError(
            "trusted GitHub workflow must check out target and policy repositories"
        )


def _validate_gitlab_example(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    document = yaml.safe_load(text)
    if not isinstance(document, dict) or "agentsec" not in document:
        raise AssertionError("GitLab example must define an agentsec job")
    required_fragments = (
        "scripts/run-agentsec-ci.sh",
        "when: always",
        "agentsec-assessment.json",
        "agentsec-results.sarif",
        "agentsec-exit-code.txt",
    )
    for fragment in required_fragments:
        if fragment not in text:
            raise AssertionError(f"GitLab example is missing {fragment!r}")


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise AssertionError(f"Expected JSON object: {path}")
    return payload


def _replay_case(
    *,
    repository_root: Path,
    runner: Path,
    agentsec: Path,
    output_root: Path,
    case: ReplayCase,
) -> None:
    output_dir = output_root / case.name
    environment = os.environ.copy()
    environment["AGENTSEC_BIN"] = str(agentsec)
    if case.trust_root is not None:
        environment["AGENTSEC_TRUST_ROOT"] = str(case.trust_root)
    if case.expect_policy_sha256 is not None:
        environment["AGENTSEC_EXPECT_POLICY_SHA256"] = case.expect_policy_sha256
    policy_argument = case.policy_argument or str(case.policy)
    result = subprocess.run(
        [
            str(runner),
            str(case.project),
            policy_argument,
            str(output_dir),
        ],
        cwd=repository_root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != case.expected_exit:
        raise AssertionError(
            f"{case.name}: expected exit {case.expected_exit}, got "
            f"{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    recorded_exit = (output_dir / "agentsec-exit-code.txt").read_text(encoding="utf-8")
    if recorded_exit != f"{case.expected_exit}\n":
        raise AssertionError(f"{case.name}: exit-code artifact does not match")
    if not case.reports_expected:
        return

    assessment = _load_json(output_dir / "agentsec-assessment.json")
    sarif = _load_json(output_dir / "agentsec-results.sarif")
    if assessment.get("format") != "agentsec-organization-policy-assessment":
        raise AssertionError(f"{case.name}: unexpected Assessment report format")
    if sarif.get("version") != "2.1.0" or not sarif.get("runs"):
        raise AssertionError(f"{case.name}: invalid SARIF report")
    decision = assessment.get("decision")
    if not isinstance(decision, dict):
        raise AssertionError(f"{case.name}: missing organization decision")
    if decision.get("exit_code") != case.expected_exit:
        raise AssertionError(f"{case.name}: report decision exit code does not match")
    trust = assessment.get("trust")
    if case.expect_policy_sha256 is not None and (
        not isinstance(trust, dict) or trust.get("policy_digest_verified") is not True
    ):
        raise AssertionError(f"{case.name}: expected verified policy digest pin")
    if case.trust_root is not None and (
        not isinstance(trust, dict) or trust.get("trust_mode") != "external_trust_root"
    ):
        raise AssertionError(f"{case.name}: expected external trust root mode")


def main() -> int:
    """Validate workflow contracts and replay the documented outcome matrix."""

    args = _parse_args()
    root = _repository_root()
    agentsec = _resolve_agentsec(root, args.agentsec)
    runner = root / "scripts" / "run-agentsec-ci.sh"
    _validate_github_workflow(root / ".github" / "workflows" / "agentsec.yml")
    _validate_github_trusted_workflow(
        root / "docs" / "examples" / "ci" / "github-actions-trusted.yml"
    )
    _validate_gitlab_example(root / "docs" / "examples" / "ci" / "gitlab-ci.yml")

    with tempfile.TemporaryDirectory(prefix="agentsec-ci-validation-") as temporary:
        temporary_root = Path(temporary)
        invalid_policy = temporary_root / "invalid-policy.yaml"
        invalid_policy.write_text(
            "format: agentsec-organization-policy\nunknown: true\n",
            encoding="utf-8",
        )
        trust_bundle = temporary_root / "trust-root"
        trust_evidence = trust_bundle / "evidence"
        trust_evidence.mkdir(parents=True)
        registry_source = (
            root
            / "calibration"
            / "p2-15a-capchain-40"
            / "human-evidence"
            / "qualified-gate-registry.yaml"
        )
        report_source = registry_source.parent / (
            "hg-capchain-001-qualification-report-v2.json"
        )
        shutil.copy(registry_source, trust_evidence / registry_source.name)
        shutil.copy(report_source, trust_evidence / report_source.name)
        trusted_policy_path = trust_bundle / "organization-policy-enforce-example.yaml"
        trusted_policy_text = (
            (root / "policies" / "organization-policy-enforce-example.yaml")
            .read_text(encoding="utf-8")
            .replace(
                "registry_path: ../calibration/p2-15a-capchain-40/human-evidence/"
                "qualified-gate-registry.yaml",
                "registry_path: evidence/qualified-gate-registry.yaml",
            )
        )
        trusted_policy_path.write_text(trusted_policy_text, encoding="utf-8")
        pinned_policy_digest = hashlib.sha256(
            (
                root / "policies" / "organization-policy-enforce-example.yaml"
            ).read_bytes()
        ).hexdigest()
        cases = (
            ReplayCase(
                name="safe-allow",
                project=root / "demos" / "release-agent" / "baseline",
                policy=root / "policies" / "organization-policy-enforce-example.yaml",
                expected_exit=0,
            ),
            ReplayCase(
                name="risky-block",
                project=root / "demos" / "release-agent" / "risky-drift",
                policy=root / "policies" / "organization-policy-enforce-example.yaml",
                expected_exit=1,
            ),
            ReplayCase(
                name="incomplete-fail-closed",
                project=root / "demos" / "release-agent" / "malformed",
                policy=root / "policies" / "organization-policy-enforce-example.yaml",
                expected_exit=2,
            ),
            ReplayCase(
                name="invalid-policy",
                project=root / "demos" / "release-agent" / "baseline",
                policy=invalid_policy,
                expected_exit=3,
                reports_expected=False,
            ),
            ReplayCase(
                name="active-waiver-allow",
                project=root / "demos" / "release-agent" / "risky-drift",
                policy=root
                / "policies"
                / "ci"
                / "organization-policy-active-waiver.yaml",
                expected_exit=0,
            ),
            ReplayCase(
                name="expired-waiver-block",
                project=root / "demos" / "release-agent" / "risky-drift",
                policy=root
                / "policies"
                / "ci"
                / "organization-policy-expired-waiver.yaml",
                expected_exit=1,
            ),
            ReplayCase(
                name="trusted-pin-block",
                project=root / "demos" / "release-agent" / "risky-drift",
                policy=root / "policies" / "organization-policy-enforce-example.yaml",
                expected_exit=1,
                expect_policy_sha256=pinned_policy_digest,
            ),
            ReplayCase(
                name="trusted-pin-mismatch",
                project=root / "demos" / "release-agent" / "risky-drift",
                policy=root / "policies" / "organization-policy-enforce-example.yaml",
                expected_exit=3,
                reports_expected=False,
                expect_policy_sha256="0" * 64,
            ),
            ReplayCase(
                name="trusted-root-block",
                project=root / "demos" / "release-agent" / "risky-drift",
                policy=trusted_policy_path,
                expected_exit=1,
                trust_root=trust_bundle,
                policy_argument="organization-policy-enforce-example.yaml",
            ),
        )
        for case in cases:
            _replay_case(
                repository_root=root,
                runner=runner,
                agentsec=agentsec,
                output_root=temporary_root,
                case=case,
            )
            print(f"PASS {case.name}: exit {case.expected_exit}")

    print("P2-29 CI examples validated without executing scanned project content.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
