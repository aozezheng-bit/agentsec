"""Canonical fingerprints for configuration that affects baseline collection."""

from __future__ import annotations

import hashlib
import json

from agentsec.config import ProjectConfig


def fingerprint_collection_config(config: ProjectConfig) -> str:
    """Hash only effective configuration that can change collected assets."""

    payload = {
        "version": config.version,
        "discovery": config.discovery.model_dump(mode="json"),
        "limits": config.limits.model_dump(mode="json"),
    }
    canonical_json = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
