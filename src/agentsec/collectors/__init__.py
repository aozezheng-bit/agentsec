"""Public interfaces for safe Agent control-asset collection."""

from agentsec.collectors.base import AssetCollector, CollectedAsset, CollectionResult
from agentsec.collectors.markdown import MarkdownAssetCollector
from agentsec.collectors.path_matching import DiscoveryPathMatcher
from agentsec.collectors.path_safety import (
    GuardedPath,
    PathGuard,
    PathGuardError,
    PathSafetyReason,
    SafePathKind,
)

__all__ = [
    "AssetCollector",
    "CollectedAsset",
    "CollectionResult",
    "DiscoveryPathMatcher",
    "GuardedPath",
    "PathGuard",
    "PathGuardError",
    "PathSafetyReason",
    "SafePathKind",
    "MarkdownAssetCollector",
]
