"""Deterministic source-level configuration precedence resolution."""

from __future__ import annotations

from pathlib import PurePosixPath

from agentsec.manifests.enums import (
    ManifestConfigurationResolutionAction,
    ManifestConfigurationResolutionReason,
    ManifestResolutionStatus,
    ManifestSourceScope,
)
from agentsec.manifests.models import (
    AgentManifest,
    ManifestConfigurationCandidate,
    ManifestConfigurationProfile,
    ManifestConfigurationResolutionStep,
)

_SCOPE_ORDER = {
    ManifestSourceScope.USER: 0,
    ManifestSourceScope.PROJECT: 1,
    ManifestSourceScope.PLUGIN: 2,
}


class ConfigurationResolutionError(RuntimeError):
    """Safe failure for an invalid or ambiguous configuration source set."""


class ConfigurationResolver:
    """Resolve source-level configuration order without reading config values."""

    def resolve(self, manifest: AgentManifest) -> AgentManifest:
        """Return a new Manifest with deterministic configuration source order."""

        if not isinstance(manifest, AgentManifest):
            raise TypeError("manifest must be AgentManifest")

        profile = manifest.configuration
        if not profile.candidates:
            return manifest

        candidate_locators = [
            candidate.source.locator.sort_key() for candidate in profile.candidates
        ]
        if len(candidate_locators) != len(set(candidate_locators)):
            raise ConfigurationResolutionError(
                "configuration candidates contain an ambiguous duplicate."
            )

        ordered_candidates = tuple(
            sorted(profile.candidates, key=self._application_sort_key)
        )
        effective_order = tuple(candidate.source for candidate in ordered_candidates)
        effective_sources = tuple(
            sorted(effective_order, key=lambda reference: reference.sort_key())
        )
        trace = tuple(
            self._step(
                candidate,
                previous=(ordered_candidates[index - 1] if index > 0 else None),
                incomplete_coverage=not manifest.coverage.complete,
            )
            for index, candidate in enumerate(ordered_candidates)
        )
        resolution = (
            ManifestResolutionStatus.PARTIAL
            if not manifest.coverage.complete
            else ManifestResolutionStatus.RESOLVED
        )
        resolved_profile = ManifestConfigurationProfile(
            resolution=resolution,
            candidates=profile.candidates,
            effective_sources=effective_sources,
            effective_order=effective_order,
            resolution_trace=trace,
        )
        payload = manifest.model_dump(mode="python")
        payload["configuration"] = resolved_profile.model_dump(mode="python")
        return AgentManifest.model_validate(payload)

    @staticmethod
    def _application_sort_key(
        candidate: ManifestConfigurationCandidate,
    ) -> tuple[int, int, str, str, str, str]:
        locator = candidate.source.locator
        return (
            _SCOPE_ORDER[locator.scope],
            candidate.precedence_rank,
            locator.root_id,
            locator.path,
            candidate.chain_key,
            ",".join(kind.value for kind in candidate.kinds),
        )

    @classmethod
    def _step(
        cls,
        candidate: ManifestConfigurationCandidate,
        *,
        previous: ManifestConfigurationCandidate | None,
        incomplete_coverage: bool,
    ) -> ManifestConfigurationResolutionStep:
        if incomplete_coverage:
            reason = ManifestConfigurationResolutionReason.INCOMPLETE_COVERAGE
        elif candidate.source.locator.scope is ManifestSourceScope.USER:
            reason = ManifestConfigurationResolutionReason.USER_SCOPE
        elif candidate.source.locator.scope is ManifestSourceScope.PROJECT:
            reason = (
                ManifestConfigurationResolutionReason.PROJECT_ROOT
                if cls._is_project_root_source(candidate)
                else ManifestConfigurationResolutionReason.NESTED_PROJECT
            )
        elif (
            previous is not None
            and candidate.precedence_rank == previous.precedence_rank
        ):
            reason = ManifestConfigurationResolutionReason.SAME_PRECEDENCE
        else:
            reason = ManifestConfigurationResolutionReason.NESTED_PROJECT
        return ManifestConfigurationResolutionStep(
            source=candidate.source,
            kinds=candidate.kinds,
            action=ManifestConfigurationResolutionAction.SELECTED,
            reason=reason,
            precedence_rank=candidate.precedence_rank,
            chain_key=candidate.chain_key,
        )

    @staticmethod
    def _is_project_root_source(
        candidate: ManifestConfigurationCandidate,
    ) -> bool:
        if candidate.source.locator.scope is not ManifestSourceScope.PROJECT:
            return False
        path_parts = PurePosixPath(candidate.source.locator.path).parts
        if not path_parts:
            return False
        return path_parts[0].startswith(".")
