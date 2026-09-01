"""Security, validation, and atomicity tests for P2I-04 report artifact I/O."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from agentsec.application import (
    AgentAnalysisPipeline,
    AgentAnalysisRequest,
    CapabilityAssessmentEngine,
)
from agentsec.artifacts import (
    AgentManifestFileReader,
    AgentManifestReadCode,
    AgentManifestReadError,
    ReportArtifactFormat,
    ReportArtifactKind,
    ReportArtifactWriteCode,
    ReportArtifactWriteError,
    ReportArtifactWriter,
)
from agentsec.reporting import (
    CapabilityAssessmentJsonRenderer,
    ManifestJsonRenderer,
    ManifestTextRenderer,
)


def _analysis(tmp_path: Path):  # type: ignore[no-untyped-def]
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("# Agent\n", encoding="utf-8")
    result = AgentAnalysisPipeline().analyze(
        AgentAnalysisRequest(project_root=project, agent_id="release-agent")
    )
    return project, result


def test_manifest_reader_is_bounded_validated_and_no_follow(tmp_path: Path) -> None:
    project, analysis = _analysis(tmp_path)
    del project
    path = tmp_path / "manifest.json"
    path.write_text(ManifestJsonRenderer().render(analysis.manifest), encoding="utf-8")

    result = AgentManifestFileReader().read(path)

    assert result.manifest == analysis.manifest
    assert result.path == path.resolve()
    assert result.size_bytes == path.stat().st_size

    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(AgentManifestReadError) as symbolic:
        AgentManifestFileReader().read(link)
    assert symbolic.value.code is AgentManifestReadCode.SYMBOLIC_LINK

    with pytest.raises(AgentManifestReadError) as oversized:
        AgentManifestFileReader(max_file_size_bytes=10).read(path)
    assert oversized.value.code is AgentManifestReadCode.TOO_LARGE


def test_manifest_reader_rejects_invalid_json_without_leaking_payload(
    tmp_path: Path,
) -> None:
    secret = "manifest-reader-secret"
    path = tmp_path / "manifest.json"
    path.write_text(f'{{"schema_version":"0.3.0","{secret}":true}}', encoding="utf-8")

    with pytest.raises(AgentManifestReadError) as captured:
        AgentManifestFileReader().read(path)

    assert captured.value.code is AgentManifestReadCode.INVALID_MANIFEST
    assert secret not in str(captured.value)


def test_report_writer_creates_private_atomic_artifact_and_safe_replacement(
    tmp_path: Path,
) -> None:
    project, analysis = _analysis(tmp_path)
    del project
    content = ManifestJsonRenderer().render(analysis.manifest)
    output = tmp_path / "reports" / "manifest.json"
    writer = ReportArtifactWriter()

    created = writer.write(
        content,
        output,
        kind=ReportArtifactKind.AGENT_MANIFEST,
        output_format=ReportArtifactFormat.JSON,
    )

    assert created.path == output.resolve()
    assert created.replaced is False
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert list(output.parent.glob(".manifest.json.*.tmp")) == []
    assert AgentManifestFileReader().read(output).manifest == analysis.manifest

    with pytest.raises(ReportArtifactWriteError) as existing:
        writer.write(
            content,
            output,
            kind=ReportArtifactKind.AGENT_MANIFEST,
            output_format=ReportArtifactFormat.JSON,
        )
    assert existing.value.code is ReportArtifactWriteCode.OUTPUT_EXISTS

    replaced = writer.write(
        content,
        output,
        kind=ReportArtifactKind.AGENT_MANIFEST,
        output_format=ReportArtifactFormat.JSON,
        force=True,
    )
    assert replaced.replaced is True
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_report_writer_force_cannot_replace_unrelated_or_protected_file(
    tmp_path: Path,
) -> None:
    project, analysis = _analysis(tmp_path)
    del project
    content = ManifestJsonRenderer().render(analysis.manifest)
    writer = ReportArtifactWriter()
    unrelated = tmp_path / "important.json"
    unrelated.write_text("unrelated-sensitive-placeholder\n", encoding="utf-8")

    with pytest.raises(ReportArtifactWriteError) as invalid:
        writer.write(
            content,
            unrelated,
            kind=ReportArtifactKind.AGENT_MANIFEST,
            output_format=ReportArtifactFormat.JSON,
            force=True,
        )
    assert invalid.value.code is ReportArtifactWriteCode.EXISTING_OUTPUT_INVALID
    assert unrelated.read_text(encoding="utf-8") == "unrelated-sensitive-placeholder\n"

    protected = tmp_path / "before.json"
    protected.write_text(content, encoding="utf-8")
    with pytest.raises(ReportArtifactWriteError) as protected_error:
        writer.write(
            content,
            protected,
            kind=ReportArtifactKind.AGENT_MANIFEST,
            output_format=ReportArtifactFormat.JSON,
            force=True,
            protected_paths=(protected,),
        )
    assert protected_error.value.code is ReportArtifactWriteCode.PROTECTED_OUTPUT_PATH


def test_report_writer_validates_format_suffix_kind_and_text_identity(
    tmp_path: Path,
) -> None:
    project, analysis = _analysis(tmp_path)
    assessment = CapabilityAssessmentEngine().assess(
        AgentAnalysisRequest(project_root=project, agent_id="release-agent")
    )
    writer = ReportArtifactWriter()

    with pytest.raises(ReportArtifactWriteError) as suffix:
        writer.write(
            ManifestJsonRenderer().render(analysis.manifest),
            tmp_path / "AGENTS.md",
            kind=ReportArtifactKind.AGENT_MANIFEST,
            output_format=ReportArtifactFormat.JSON,
        )
    assert suffix.value.code is ReportArtifactWriteCode.INVALID_OUTPUT_PATH

    with pytest.raises(ReportArtifactWriteError) as wrong_kind:
        writer.write(
            CapabilityAssessmentJsonRenderer().render(assessment),
            tmp_path / "wrong.json",
            kind=ReportArtifactKind.AGENT_MANIFEST,
            output_format=ReportArtifactFormat.JSON,
        )
    assert wrong_kind.value.code is ReportArtifactWriteCode.INVALID_CONTENT

    text_path = tmp_path / "manifest.txt"
    writer.write(
        ManifestTextRenderer().render(analysis),
        text_path,
        kind=ReportArtifactKind.AGENT_MANIFEST,
        output_format=ReportArtifactFormat.TEXT,
    )
    assert text_path.read_text(encoding="utf-8").startswith("AgentSec Agent Manifest")

    link_target = tmp_path / "target.txt"
    link_target.write_text("keep\n", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(link_target)
    with pytest.raises(ReportArtifactWriteError) as symbolic:
        writer.write(
            ManifestTextRenderer().render(analysis),
            link,
            kind=ReportArtifactKind.AGENT_MANIFEST,
            output_format=ReportArtifactFormat.TEXT,
            force=True,
        )
    assert symbolic.value.code is ReportArtifactWriteCode.INVALID_OUTPUT_PATH
    assert link_target.read_text(encoding="utf-8") == "keep\n"


def test_report_writer_no_clobber_race_preserves_competing_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, analysis = _analysis(tmp_path)
    del project
    output = tmp_path / "manifest.json"
    original_link = os.link

    def competing_link(source: Path, target: Path) -> None:
        output.write_text("competitor\n", encoding="utf-8")
        original_link(source, target)

    monkeypatch.setattr(os, "link", competing_link)

    with pytest.raises(ReportArtifactWriteError) as captured:
        ReportArtifactWriter().write(
            ManifestJsonRenderer().render(analysis.manifest),
            output,
            kind=ReportArtifactKind.AGENT_MANIFEST,
            output_format=ReportArtifactFormat.JSON,
        )

    assert captured.value.code is ReportArtifactWriteCode.OUTPUT_EXISTS
    assert output.read_text(encoding="utf-8") == "competitor\n"
    assert list(tmp_path.glob(".manifest.json.*.tmp")) == []


def test_force_existing_artifact_read_uses_no_follow_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, analysis = _analysis(tmp_path)
    del project
    content = ManifestJsonRenderer().render(analysis.manifest)
    output = tmp_path / "manifest.json"
    output.write_text(content, encoding="utf-8")
    original_open = os.open
    observed_flags: list[int] = []

    def recording_open(path, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
        observed_flags.append(flags)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", recording_open)

    ReportArtifactWriter().write(
        content,
        output,
        kind=ReportArtifactKind.AGENT_MANIFEST,
        output_format=ReportArtifactFormat.JSON,
        force=True,
    )

    no_follow = getattr(os, "O_NOFOLLOW", 0)
    assert observed_flags
    if no_follow:
        assert any(flags & no_follow for flags in observed_flags)
