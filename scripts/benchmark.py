#!/usr/bin/env python3
"""
Reproducible benchmark for pkgguard's scoring.

Run this after ANY change to conflation, typosquat, or scoring logic.

    python scripts/benchmark.py --sample 200

Two things are measured:

  1. FALSE POSITIVES — real, existing packages that are NOT in the popularity
     corpus. This is the honest test. Testing against packages that ARE in the
     corpus is meaningless: they short-circuit the conflation check and return
     a flattering 0%. An early version of this tool scored 0% that way and
     62.5% here.

  2. THREAT RECALL — documented real slopsquats, fabricated conflations, and
     classic typosquats that must be caught.

A change that improves one at the expense of the other is not an improvement.
Report both numbers together or not at all.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from pkgguard.service import load_popular, verify_package  # noqa: E402

THREATS = [
    ("react-codeshift", "npm", "REAL slopsquat, registered Jan 2026"),
    ("unused-imports", "npm", "REAL slopsquat, npm security-held"),
    ("react-codemodshift", "npm", "fabricated conflation"),
    ("express-fastify-router", "npm", "fabricated conflation"),
    ("lodash-ramda-utils", "npm", "fabricated conflation"),
    ("lodahs", "npm", "typosquat of lodash (transposition)"),
    ("expres", "npm", "typosquat of express (deletion)"),
]

BENIGN_CONTROL = ["express", "lodash", "queue", "page", "validate", "axios", "react-dom", "typescript"]


def load_out_of_corpus(path: Path, ecosystem: str) -> list:
    """Real package names known to exist but absent from the popularity corpus."""
    if not path.exists():
        return []
    names = json.loads(path.read_text(encoding="utf-8"))
    corpus = set(load_popular(ecosystem))
    return [n for n in names if n not in corpus and not n.startswith("@")]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=200)
    ap.add_argument("--candidates", default="/tmp/npm_candidates.json",
                    help="JSON list of real package names to draw the FP sample from.")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    print("=" * 70)
    print("THREAT RECALL")
    print("=" * 70)
    caught = 0
    for name, eco, note in THREATS:
        a = verify_package(name, eco)
        caught += a.verdict == "BLOCK"
        print(f"  {a.verdict:7} {a.risk_score:>4}  {name:24} {note}")
    print(f"\n  BLOCKed {caught}/{len(THREATS)}")

    print("\n" + "=" * 70)
    print("BENIGN CONTROL (must all ALLOW)")
    print("=" * 70)
    alarms = 0
    for name in BENIGN_CONTROL:
        a = verify_package(name, "npm")
        alarms += a.verdict != "ALLOW"
        print(f"  {a.verdict:7} {a.risk_score:>4}  {name}")
    print(f"\n  false alarms: {alarms}/{len(BENIGN_CONTROL)}")

    outside = load_out_of_corpus(Path(args.candidates), "npm")
    if not outside:
        print(f"\n[skipped FP benchmark: no candidate file at {args.candidates}]")
        print("Generate one with scripts/refresh_corpus.py, or supply --candidates.")
        return 0

    print("\n" + "=" * 70)
    print(f"FALSE POSITIVES — real packages outside the corpus (n={args.sample})")
    print("=" * 70)
    random.seed(args.seed)
    sample = random.sample(outside, min(args.sample, len(outside)))

    results = []
    for i, name in enumerate(sample, 1):
        try:
            a = verify_package(name, "npm")
        except Exception:
            continue
        if not a.exists:
            continue
        results.append(a)
        if i % 50 == 0:
            print(f"  ...{i}/{len(sample)}", flush=True)
        time.sleep(0.03)

    if not results:
        print("  no results")
        return 1

    tot = len(results)
    block = [r for r in results if r.verdict == "BLOCK"]
    review = [r for r in results if r.verdict == "REVIEW"]
    allow = [r for r in results if r.verdict == "ALLOW"]

    print(f"\n  BLOCK  {len(block):4} ({100*len(block)/tot:5.1f}%)   <-- hard false positives")
    print(f"  REVIEW {len(review):4} ({100*len(review)/tot:5.1f}%)")
    print(f"  ALLOW  {len(allow):4} ({100*len(allow)/tot:5.1f}%)")

    if block:
        print("\n  false positives:")
        for r in block[:10]:
            print(f"    {r.name} (score {r.risk_score})")
            for s in r.signals[:2]:
                print(f"       - {s[:100]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
