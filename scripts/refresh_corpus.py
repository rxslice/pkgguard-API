#!/usr/bin/env python3
"""
Refresh the popular-package corpora used for conflation and typosquat detection.

The corpora are the foundation of both detectors: a name can only be recognized
as a *blend of real packages* if those real packages are in the index. Ship the
generated files with the repo so the tool works offline, and re-run this
periodically (quarterly is plenty — package popularity moves slowly).

    python scripts/refresh_corpus.py --ecosystem npm --limit 3000
    python scripts/refresh_corpus.py --ecosystem pypi --limit 3000
    python scripts/refresh_corpus.py --ecosystem crates --limit 1500

All sources are free and unauthenticated.
"""
from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, List

UA = {"User-Agent": "pkgguard-corpus-refresh/0.1", "Accept": "application/json"}
DATA = Path(__file__).parent.parent / "data"

# Broad vocabulary so the harvest is not biased toward one part of the ecosystem.
NPM_SEEDS = [
    "react", "vue", "angular", "svelte", "node", "express", "koa", "fastify",
    "test", "jest", "mocha", "vitest", "build", "webpack", "rollup", "vite",
    "babel", "eslint", "prettier", "typescript", "cli", "util", "http", "https",
    "server", "client", "parse", "lint", "css", "sass", "postcss", "json",
    "async", "promise", "date", "time", "string", "array", "object", "stream",
    "file", "fs", "path", "config", "log", "error", "auth", "jwt", "crypto",
    "hash", "db", "sql", "mongo", "redis", "api", "graphql", "rest", "router",
    "state", "redux", "form", "ui", "component", "hook", "plugin", "loader",
    "bundler", "compiler", "format", "validate", "schema", "mock", "socket",
    "event", "queue", "cache", "image", "pdf", "csv", "yaml", "markdown",
    "template", "i18n", "aws", "google", "azure", "docker", "git", "shell",
    "color", "math", "random", "uuid", "lodash", "moment", "axios", "chalk",
]

PYPI_TOP_URL = "https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages.json"


def _get(url: str, retries: int = 4) -> dict:
    delay = 1.0
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=25) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (429, 503) and attempt < retries - 1:
                time.sleep(delay)
                delay *= 2
                continue
            raise
        except Exception:
            if attempt < retries - 1:
                time.sleep(delay)
                delay *= 2
                continue
            raise
    return {}


def harvest_npm_candidates() -> List[str]:
    names: set[str] = set()
    for i, seed in enumerate(NPM_SEEDS, 1):
        url = f"https://registry.npmjs.org/-/v1/search?text={urllib.parse.quote(seed)}&size=250"
        try:
            data = _get(url)
        except Exception as e:
            print(f"  [{i}/{len(NPM_SEEDS)}] {seed}: skipped ({e})")
            continue
        for o in data.get("objects", []):
            names.add(o["package"]["name"])
        print(f"  [{i}/{len(NPM_SEEDS)}] {seed}: {len(names)} unique so far")
        time.sleep(0.6)  # be a good citizen; the registry is free
    return sorted(names)


def rank_npm_by_downloads(names: List[str], limit: int) -> List[str]:
    """npm's bulk downloads endpoint accepts up to 128 comma-separated names."""
    scores: Dict[str, int] = {}
    unscoped = [n for n in names if not n.startswith("@")]
    scoped = [n for n in names if n.startswith("@")]

    for i in range(0, len(unscoped), 100):
        batch = unscoped[i:i + 100]
        url = "https://api.npmjs.org/downloads/point/last-month/" + ",".join(batch)
        try:
            data = _get(url)
        except Exception:
            time.sleep(1.0)
            continue
        if isinstance(data, dict):
            if "downloads" in data and "package" in data:  # single-result shape
                scores[data["package"]] = data.get("downloads", 0) or 0
            else:
                for name, rec in data.items():
                    if isinstance(rec, dict):
                        scores[name] = rec.get("downloads", 0) or 0
        print(f"  ranked {len(scores)}/{len(unscoped)}")
        time.sleep(0.4)

    # Scoped packages must be queried individually; only bother with a slice.
    for name in scoped[:300]:
        try:
            d = _get("https://api.npmjs.org/downloads/point/last-month/" + urllib.parse.quote(name, safe="@/"))
            scores[name] = d.get("downloads", 0) or 0
        except Exception:
            pass
        time.sleep(0.15)

    ranked = sorted(scores.items(), key=lambda kv: -kv[1])
    return [n for n, s in ranked if s > 0][:limit]


def refresh_npm(limit: int) -> List[str]:
    print("Harvesting npm candidate names...")
    candidates = harvest_npm_candidates()
    print(f"Harvested {len(candidates)} candidates. Ranking by monthly downloads...")
    return rank_npm_by_downloads(candidates, limit)


def refresh_pypi(limit: int) -> List[str]:
    print("Fetching top PyPI packages (pre-ranked by download count)...")
    data = _get(PYPI_TOP_URL)
    rows = data.get("rows", [])
    return [r["project"] for r in rows[:limit]]


def refresh_crates(limit: int) -> List[str]:
    print("Fetching top crates.io crates...")
    names: List[str] = []
    page = 1
    while len(names) < limit and page <= 20:
        url = f"https://crates.io/api/v1/crates?page={page}&per_page=100&sort=downloads"
        try:
            data = _get(url)
        except Exception as e:
            print(f"  page {page} failed: {e}")
            break
        crates = data.get("crates", [])
        if not crates:
            break
        names.extend(c["id"] for c in crates)
        print(f"  {len(names)} crates")
        page += 1
        time.sleep(0.5)
    return names[:limit]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ecosystem", required=True, choices=["npm", "pypi", "crates"])
    ap.add_argument("--limit", type=int, default=3000)
    args = ap.parse_args()

    fn = {"npm": refresh_npm, "pypi": refresh_pypi, "crates": refresh_crates}[args.ecosystem]
    names = fn(args.limit)

    if not names:
        print("No names harvested — aborting rather than writing an empty corpus.")
        return 1

    # Search-based harvesting is lossy — npm's relevance ranking omitted lodash,
    # jscodeshift and react-codemod from an 11,000-name harvest. Guarantee the
    # critical names are present regardless of what the harvest returned.
    must_path = DATA / "must_include.json"
    if must_path.exists():
        must = json.loads(must_path.read_text(encoding="utf-8")).get(args.ecosystem, [])
        have = set(names)
        added = [m for m in must if m not in have]
        names.extend(added)
        if added:
            print(f"Merged {len(added)} must-include names absent from the harvest.")

    DATA.mkdir(exist_ok=True)
    out = DATA / f"top_{args.ecosystem}.json"
    out.write_text(json.dumps(names, indent=0), encoding="utf-8")
    print(f"Wrote {len(names)} names to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
