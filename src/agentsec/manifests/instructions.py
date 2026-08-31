"""Deterministic Codex-style instruction inheritance and Override resolution."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import PurePosixPath

from agentsec.manifests.enums import (
    ManifestInstructionKind,
    ManifestInstructionResolutionAction,
    ManifestInstructionResolutionReason,
    ManifestResolutionStatus,
    ManifestSourceScope,
)
from agentsec.manifests.models import (
    AgentManifest,
    ManifestInstructionCandidate,
    ManifestInstructionProfile,
    ManifestInstructionResolutionStep,
)

_EXPECTED_BASENAME = {
    ManifestInstructionKind.BASE: "AGENTS.md",
    ManifestInstructionKind.OVERRIDE: "AGENTS.override.md",
}
_SCOPE_ORDER = {
    ManifestSourceScope.USER: 0,
    ManifestSourceScope.PROJECT: 1,
    ManifestSourceScope.PLUGIN: 2,
}


class InstructionResolutionError(RuntimeError):
    """Safe failure for an invalid or ambiguous instruction candidate set."""


@dataclass(frozen=True, slots=True)
class _InstructionSlot:
    """One scope/root/directory slot whose base and Override compete."""

    scope: ManifestSourceScope
    root_id: str
    directory: str

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.scope.value, self.root_id, self.directory)

    @property
    def chain_key(self) -> str:
        directory = self.directory or "."
        return f"{self.scope.value}:{self.root_id}:{directory}"


class InstructionResolver:
    """Resolve instruction inheritance without reading or executing source text."""

    def resolve(self, manifest: AgentManifest) -> AgentManifest:
        """Return a validated Manifest with final instruction-source decisions."""

        if not isinstance(manifest, AgentManifest):
            raise TypeError("manifest must be AgentManifest")

        profile = manifest.instructions
        if not profile.candidates:
            return manifest

        grouped: dict[
            _InstructionSlot,
            dict[ManifestInstructionKind, ManifestInstructionCandidate],
        ] = defaultdict(dict)
        for candidate in profile.candidates:
            slot = self._slot(candidate)
            if candidate.kind in grouped[slot]:
                raise InstructionResolutionError(
                    "instruction candidates contain an ambiguous duplicate."
                )
            grouped[slot][candidate.kind] = candidate

        ordered_slots = tuple(sorted(grouped, key=self._slot_sort_key))
        selected: list[ManifestInstructionCandidate] = []
        overridden: list[ManifestInstructionCandidate] = []
        trace: list[ManifestInstructionResolutionStep] = []
        has_conflict = False

        for slot in ordered_slots:
            decisions = grouped[slot]
            base = decisions.get(ManifestInstructionKind.BASE)
            override = decisions.get(ManifestInstructionKind.OVERRIDE)
            if base is not None and override is not None:
                # The Codex contract is slot-local: Override replaces the base
                # file for the same scope/root/directory, not all inherited files.
                overridden.append(base)
                selected.append(override)
                trace.extend(
                    (
                        self._step(
                            base,
                            slot=slot,
                            action=ManifestInstructionResolutionAction.OVERRIDDEN,
                            reason=ManifestInstructionResolutionReason.OVERRIDE_REPLACES_BASE,
                        ),
                        self._step(
                            override,
                            slot=slot,
                            action=ManifestInstructionResolutionAction.SELECTED,
                            reason=ManifestInstructionResolutionReason.OVERRIDE_REPLACES_BASE,
                        ),
                    )
                )
                continue

            candidates = tuple(decisions.values())
            if len(candidates) != 1:
                has_conflict = True
                trace.extend(
                    self._step(
                        candidate,
                        slot=slot,
                        action=ManifestInstructionResolutionAction.CONFLICT,
                        reason=ManifestInstructionResolutionReason.AMBIGUOUS_DUPLICATE,
                    )
                    for candidate in sorted(
                        candidates,
                        key=lambda item: item.source.sort_key(),
                    )
                )
                continue

            candidate = candidates[0]
            selected.append(candidate)
            reason = (
                ManifestInstructionResolutionReason.INHERITED
                if slot.directory
                else ManifestInstructionResolutionReason.ONLY_CANDIDATE
            )
            trace.append(
                self._step(
                    candidate,
                    slot=slot,
                    action=ManifestInstructionResolutionAction.SELECTED,
                    reason=reason,
                )
            )

        if has_conflict:
            resolved_profile = ManifestInstructionProfile(
                resolution=ManifestResolutionStatus.CONFLICT,
                candidates=profile.candidates,
                effective_sources=(),
                effective_order=(),
                overridden_sources=(),
                resolution_trace=tuple(trace),
            )
        else:
            selected_references = tuple(candidate.source for candidate in selected)
            effective_sources = tuple(
                sorted(selected_references, key=lambda reference: reference.sort_key())
            )
            overridden_sources = tuple(
                sorted(
                    (candidate.source for candidate in overridden),
                    key=lambda reference: reference.sort_key(),
                )
            )
            resolution = (
                ManifestResolutionStatus.PARTIAL
                if not manifest.coverage.complete
                else ManifestResolutionStatus.RESOLVED
            )
            resolved_profile = ManifestInstructionProfile(
                resolution=resolution,
                candidates=profile.candidates,
                effective_sources=effective_sources,
                effective_order=selected_references,
                overridden_sources=overridden_sources,
                resolution_trace=tuple(trace),
            )

        payload = manifest.model_dump(mode="python")
        payload["instructions"] = resolved_profile.model_dump(mode="python")
        return AgentManifest.model_validate(payload)

    @staticmethod
    def _slot(candidate: ManifestInstructionCandidate) -> _InstructionSlot:
        source = candidate.source.locator
        expected_basename = _EXPECTED_BASENAME[candidate.kind]
        basename = PurePosixPath(source.path).name
        if basename != expected_basename:
            raise InstructionResolutionError(
                "instruction candidate filename does not match its declared kind."
            )
        parent = PurePosixPath(source.path).parent.as_posix()
        return _InstructionSlot(
            scope=source.scope,
            root_id=source.root_id,
            directory="" if parent == "." else parent,
        )

    @staticmethod
    def _slot_sort_key(slot: _InstructionSlot) -> tuple[int, int, str, str]:
        return (
            _SCOPE_ORDER[slot.scope],
            len(PurePosixPath(slot.directory).parts) if slot.directory else 0,
            slot.root_id,
            slot.directory,
        )

    @staticmethod
    def _step(
        candidate: ManifestInstructionCandidate,
        *,
        slot: _InstructionSlot,
        action: ManifestInstructionResolutionAction,
        reason: ManifestInstructionResolutionReason,
    ) -> ManifestInstructionResolutionStep:
        return ManifestInstructionResolutionStep(
            source=candidate.source,
            action=action,
            reason=reason,
            precedence_rank=candidate.precedence_rank,
            chain_key=slot.chain_key,
        )
