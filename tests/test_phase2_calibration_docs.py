"""Documentation guarantees for the P2-CAL-04A calibration handoff.

These tests pin the human-review and Hard Gate boundary statements that the
P2-CAL-04A documentation set must keep visible: the Task ID, the three Gate
Candidate IDs, the 20/20 reviewed-sample requirement, Seed Label limits, the
report-only enforcement mode, and the fact that ``hard_gate=true`` stays
disabled.
"""

from __future__ import annotations

import re
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[1]

REVIEWER_PACK_GUIDE = (
    REPOSITORY_ROOT / "docs" / "calibration-adjudication-reviewer-pack.md"
)
ADJUDICATION_REPORT = REPOSITORY_ROOT / "docs" / "calibration-adjudication-report.md"
PHASE2_SCOPE = REPOSITORY_ROOT / "docs" / "phase2-scope.md"
PHASE2_INTEGRATION_PLAN = REPOSITORY_ROOT / "docs" / "phase2-integration-plan.md"
HARD_GATE_PLAN = (
    REPOSITORY_ROOT / "docs" / "capability-calibration-hard-gate-enforcement-plan.md"
)
CALIBRATION_README = REPOSITORY_ROOT / "calibration" / "README.md"
SCHEMAS_README = REPOSITORY_ROOT / "schemas" / "README.md"
README = REPOSITORY_ROOT / "README.md"
CHANGELOG = REPOSITORY_ROOT / "CHANGELOG.md"
AGENT4_COMPLETION_REPORT = (
    REPOSITORY_ROOT / "docs" / "tasks" / "P2-CAL-04A-AGENT-04-completion-report.md"
)

KEY_DOCUMENTS = (
    REVIEWER_PACK_GUIDE,
    ADJUDICATION_REPORT,
    PHASE2_SCOPE,
    PHASE2_INTEGRATION_PLAN,
    HARD_GATE_PLAN,
    CALIBRATION_README,
    SCHEMAS_README,
    README,
    CHANGELOG,
    AGENT4_COMPLETION_REPORT,
)

GATE_CANDIDATE_IDS = (
    "HG-CAPCHAIN-001",
    "HG-PRODAUTO-001",
    "HG-EXTERNALPROD-001",
)

REQUIRED_GUIDE_SECTIONS = (
    "Reviewer recruitment requirements",
    "independent blind review process",
    "Ground Truth isolation strategy",
    "Label lifecycle",
    "Disagreement handling",
    "FP/FN classification vocabulary",
    "Case reuse and Gate statistics rules",
    "CLI usage after human review completes",
    "P2-15A preconditions",
    "Security boundaries",
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_key_calibration_documents_exist() -> None:
    """Every P2-CAL-04A handoff document is present in the repository."""

    for document in KEY_DOCUMENTS:
        assert document.is_file(), document


def test_p2_cal_04a_task_id_is_recorded() -> None:
    """The Task ID stays visible across the guide, plans, and changelog."""

    for document in (
        REVIEWER_PACK_GUIDE,
        PHASE2_SCOPE,
        PHASE2_INTEGRATION_PLAN,
        HARD_GATE_PLAN,
        CHANGELOG,
        AGENT4_COMPLETION_REPORT,
    ):
        assert "P2-CAL-04A" in _read(document), document


def test_three_gate_candidate_ids_are_documented() -> None:
    """All three approved report-only Gate Candidates stay named."""

    guide = _read(REVIEWER_PACK_GUIDE)
    for gate_id in GATE_CANDIDATE_IDS:
        assert gate_id in guide
        assert gate_id in _read(ADJUDICATION_REPORT)
        assert gate_id in _read(HARD_GATE_PLAN)


def test_twenty_positive_twenty_negative_sample_requirement() -> None:
    """The 20 Positive + 20 Negative/Near-miss per-Gate bar stays explicit."""

    guide = _read(REVIEWER_PACK_GUIDE)
    assert "at least 20 reviewed Positive Cases" in guide
    assert "at least 20 reviewed Negative/Near-miss Cases" in guide
    assert "20 Positive + 20 Negative/Near-miss" in guide

    for document in (PHASE2_SCOPE, PHASE2_INTEGRATION_PLAN, HARD_GATE_PLAN):
        text = _read(document)
        assert "20" in text and "Negative/Near-miss" in text, document


def test_seed_label_restrictions_are_documented() -> None:
    """Seed Labels are explicitly excluded from production review evidence."""

    guide = _read(REVIEWER_PACK_GUIDE)
    assert "Seed Labels cannot be used as production review results" in guide
    assert "seeded" in guide
    assert "more_data_required" in guide

    calibration_readme = _read(CALIBRATION_README)
    assert "seeded" in calibration_readme
    assert "not a final calibration" in calibration_readme


def test_report_only_enforcement_is_documented() -> None:
    """The report-only enforcement mode stays visible in every key document."""

    for document in (
        REVIEWER_PACK_GUIDE,
        ADJUDICATION_REPORT,
        PHASE2_SCOPE,
        PHASE2_INTEGRATION_PLAN,
        HARD_GATE_PLAN,
        CALIBRATION_README,
    ):
        assert "report_only" in _read(document) or "report-only" in _read(document), (
            document
        )


def test_hard_gate_true_remains_disabled() -> None:
    """Docs state hard_gate=true is not enabled; nothing claims activation."""

    guide = _read(REVIEWER_PACK_GUIDE)
    assert "hard_gate=true is currently not enabled" in guide

    for document in (PHASE2_SCOPE, PHASE2_INTEGRATION_PLAN, HARD_GATE_PLAN, CHANGELOG):
        text = _read(document)
        assert "hard_gate=true" in text, document
        assert re.search(
            r"hard_gate=true.{0,80}?remain(s)?\s+disabled", text, re.DOTALL
        ), document

    assert "ci_blocking_enabled=false" in guide
    assert "--fail-on" in guide


def test_hard_gate_scope_is_rescoped_to_one_qualified_gate() -> None:
    """P2-EXIT-04 records the formal one-Gate MVP scope (ADR-0064)."""

    adr = (
        REPOSITORY_ROOT
        / "docs"
        / "decisions"
        / "0064-hard-gate-phase2-scope-decision.md"
    )
    assert adr.is_file()

    for document in (PHASE2_SCOPE, PHASE2_INTEGRATION_PLAN, HARD_GATE_PLAN):
        text = _read(document)
        assert "3\u20135 calibrated Gate IDs" not in text, document
        assert "1 calibrated Gate ID: HG-CAPCHAIN-001" in text, document
        assert "ADR-0064" in text, document
        for gate_id in ("HG-PRODAUTO-001", "HG-EXTERNALPROD-001"):
            assert gate_id in text, document


def test_reviewer_pack_guide_covers_required_sections() -> None:
    """The guide keeps the ten mandated operational sections."""

    guide = _read(REVIEWER_PACK_GUIDE)
    for section in REQUIRED_GUIDE_SECTIONS:
        assert section in guide, section

    assert "pending → reviewed → adjudicated" in guide
    assert "Reviewer A and Reviewer B must perform blind, independent review" in guide
    assert "P2-CAL-04A only prepares Cases and the Reviewer Pack" in guide
    assert "P2-CAL-04A produces no Hard Gate qualification conclusion" in guide


def test_agent4_completion_report_contains_handoff_contract() -> None:
    """The Agent 4 report records every required handoff decision."""

    report = _read(AGENT4_COMPLETION_REPORT)
    for marker in (
        "Reviewer Pack handoff",
        "Coverage CLI handoff",
        "Current draft sample statistics",
        "QA verification",
        "Remaining human work and release boundary",
        "P2-15A remains blocked",
        "hard_gate=true",
        "CI blocking",
        "--fail-on",
    ):
        assert marker in report, marker

    for gate_id in GATE_CANDIDATE_IDS:
        assert gate_id in report


def test_reviewer_pack_guide_local_links_resolve() -> None:
    """Relative links inside the new guide never point at missing files."""

    guide = _read(REVIEWER_PACK_GUIDE)
    links = re.findall(r"\[[^\]]+\]\(([^)]+)\)", guide)
    for link in links:
        target = link.split("#", maxsplit=1)[0]
        if not target or target.startswith("#") or "://" in target:
            continue
        assert (REVIEWER_PACK_GUIDE.parent / target).resolve().exists(), link
