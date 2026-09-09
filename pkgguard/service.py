"""
pkgguard — built by Blvkware (https://blvkware.dev)
Licensed under the Apache License 2.0. See LICENSE.
Corpus loading and the shared service used by both the HTTP API and the CLI.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set

from .conflation import ConflationDetector
from .registries import SUPPORTED_ECOSYSTEMS, fetch
from .scoring import Assessment, assess

DATA_DIR = Path(os.environ.get("PKGGUARD_DATA_DIR", Path(__file__).parent.parent / "data"))

_CORPUS_FILES = {
    "npm": "top_npm.json",
    "pypi": "top_pypi.json",
    "crates": "top_crates.json",
}


@lru_cache(maxsize=8)
def load_popular(ecosystem: str) -> tuple:
    """Popular package names for an ecosystem, in descending popularity order."""
    fname = _CORPUS_FILES.get(ecosystem)
    if not fname:
        return tuple()
    path = DATA_DIR / fname
    if not path.exists():
        return tuple()
    with open(path, encoding="utf-8") as f:
        return tuple(json.load(f))


@lru_cache(maxsize=8)
def get_detector(ecosystem: str) -> ConflationDetector:
    return ConflationDetector(load_popular(ecosystem))


@lru_cache(maxsize=1)
def load_known_hallucinations() -> Dict[str, Set[str]]:
    """Names documented in public research/incident reports as LLM-invented.

    Kept small and sourced rather than speculative — see data/known_hallucinations.json
    for provenance on each entry."""
    path = DATA_DIR / "known_hallucinations.json"
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    return {
        eco: {name.lower() for name in names}
        for eco, names in raw.items()
        if eco in SUPPORTED_ECOSYSTEMS and isinstance(names, list)
    }


@lru_cache(maxsize=2048)
def _downloads_for(ecosystem: str, name: str) -> Optional[int]:
    """Monthly downloads for a package, cached. Only called when a typosquat
    candidate needs confirming, so this stays cheap in practice."""
    try:
        return fetch(name, ecosystem).monthly_downloads
    except Exception:
        return None


def verify_package(
    name: str,
    ecosystem: str,
    new_package_policy: str = "block",
) -> Assessment:
    eco = ecosystem.lower().strip()
    if eco not in SUPPORTED_ECOSYSTEMS:
        raise ValueError(f"Unsupported ecosystem '{ecosystem}'. Supported: {list(SUPPORTED_ECOSYSTEMS)}")

    facts = fetch(name, eco)
    detector = get_detector(eco)
    popular = load_popular(eco)
    known = load_known_hallucinations().get(eco, set())

    return assess(
        facts,
        detector,
        popular,
        known,
        popularity_lookup=lambda pkg: _downloads_for(eco, pkg),
        new_package_policy=new_package_policy,
    )


def verify_many(
    names: Sequence[str],
    ecosystem: str,
    new_package_policy: str = "block",
) -> List[Assessment]:
    return [verify_package(n, ecosystem, new_package_policy) for n in names]
