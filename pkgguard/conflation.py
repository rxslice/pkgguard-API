"""
pkgguard — built by Blvkware (https://blvkware.dev)
Licensed under the Apache License 2.0. See LICENSE.
Conflation detection.

This is the piece that existing tooling does not do.

Registries and typosquat scanners catch *misspellings* — names within a small
edit distance of a popular package (`reqeusts` vs `requests`). They do not
catch **conflations**: names an LLM invents by blending two real packages into
a third that never existed.

    jscodeshift  +  react-codemod   ->   react-codeshift   (registered by an
                                                            attacker in Jan 2026)

Edit distance from `react-codeshift` to either parent is large, so similarity
heuristics score it as unrelated and let it through. But every *token* in the
name comes from a real, popular package, and no real package contains the
whole combination. That is the signature this module looks for.

Algorithm
---------
1. Tokenize the candidate name (split on -, _, ., /, and camelCase).
2. For each token, find popular real packages whose own tokens contain it,
   plus packages where the token appears as a substring (catches glued
   tokens like `codeshift` inside `jscodeshift`).
3. If:
     - no single real package contains *all* the candidate's tokens, AND
     - at least two tokens each resolve to real popular packages, AND
     - those resolve to *different* source packages
   then the name is a probable conflation, and we report the parents.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SPLIT = re.compile(r"[-_./@]+")

# Tokens too generic to carry signal on their own. A name containing only
# these should not be reported as a conflation.
STOPWORDS: Set[str] = {
    "js", "ts", "py", "node", "lib", "core", "utils", "util", "common",
    "types", "type", "api", "sdk", "cli", "app", "web", "the", "a", "x",
    "2", "3", "v2", "v3", "next", "new", "plus", "pro",
}

MIN_TOKEN_LEN = 3


def tokenize(name: str) -> List[str]:
    """Split a package name into meaningful lowercase tokens.

    Order matters: camelCase boundaries must be split *before* lowercasing,
    or `myAwesomePackage` collapses into a single opaque token."""
    name = name.strip()
    # Split on separators first (an npm scope @scope/pkg yields both parts).
    parts = _SPLIT.split(name)
    tokens: List[str] = []
    for part in parts:
        if not part:
            continue
        for sub in _CAMEL.split(part):   # split while case is still intact
            sub = sub.lower().strip()
            if sub:
                tokens.append(sub)
    return tokens


@dataclass
class ConflationResult:
    is_conflation: bool
    confidence: float  # 0.0 - 1.0
    parents: List[str] = field(default_factory=list)
    explanation: Optional[str] = None
    matched_tokens: Dict[str, List[str]] = field(default_factory=dict)


class ConflationDetector:
    """Builds a token -> real-package index once, then scores candidates."""

    def __init__(self, popular_packages: Sequence[str]) -> None:
        # `popular_packages` is expected in descending popularity order; the
        # index position is used to rank parent candidates so we attribute a
        # conflation to `react-codemod` rather than some obscure package that
        # happens to share a token.
        self.packages: List[str] = list(popular_packages)
        self._package_set: Set[str] = {p.lower() for p in self.packages}
        self._rank: Dict[str, int] = {p.lower(): i for i, p in enumerate(self.packages)}
        self._token_index: Dict[str, Set[str]] = {}
        self._pkg_tokens: Dict[str, Set[str]] = {}

        for pkg in self.packages:
            toks = set(tokenize(pkg))
            self._pkg_tokens[pkg.lower()] = toks
            for t in toks:
                if len(t) < MIN_TOKEN_LEN:
                    continue
                self._token_index.setdefault(t, set()).add(pkg.lower())

    def _parent_score(self, pkg: str, token: str) -> tuple:
        """Sort key for ranking candidate parents. Lower is better.

        Prefers (a) packages where the shared token is a large share of the
        name — `jscodeshift` over `@babel/helper-builder-react-jsx` — and
        (b) more popular packages."""
        toks = self._pkg_tokens.get(pkg, set())
        token_share = len(token) / max(len(pkg), 1)
        few_tokens = len(toks)
        is_scoped = pkg.startswith("@")
        return (is_scoped, few_tokens, -token_share, self._rank.get(pkg, 10**6))

    # -- lookup helpers ---------------------------------------------------

    def _packages_for_token(self, token: str, limit: int = 12) -> List[str]:
        """Real packages that contain this token, either as a whole token or
        as a substring of one of their tokens (catches `codeshift` in
        `jscodeshift`)."""
        if len(token) < MIN_TOKEN_LEN or token in STOPWORDS:
            return []

        exact = self._token_index.get(token, set())
        if exact:
            return sorted(exact, key=lambda p: self._parent_score(p, token))[:limit]

        # Substring fallback — only for reasonably distinctive tokens.
        if len(token) < 5:
            return []
        hits: List[str] = []
        for pkg, toks in self._pkg_tokens.items():
            for t in toks:
                if len(t) >= len(token) and token in t:
                    hits.append(pkg)
                    break
        return sorted(hits, key=lambda p: self._parent_score(p, token))[:limit]

    def _exists_as_real_package(self, tokens: Sequence[str]) -> bool:
        """Does some real popular package contain every one of these tokens?"""
        meaningful = [t for t in tokens if len(t) >= MIN_TOKEN_LEN and t not in STOPWORDS]
        if not meaningful:
            return False
        for pkg, toks in self._pkg_tokens.items():
            if all(t in toks for t in meaningful):
                return True
        return False

    # -- main entrypoint --------------------------------------------------

    def analyze(self, name: str) -> ConflationResult:
        tokens = tokenize(name)
        meaningful = [t for t in tokens if len(t) >= MIN_TOKEN_LEN and t not in STOPWORDS]

        if len(meaningful) < 2:
            return ConflationResult(False, 0.0, explanation="Too few distinctive tokens to assess conflation.")

        if name.lower() in self._package_set:
            return ConflationResult(False, 0.0, explanation="Name is itself a known popular package.")

        if self._exists_as_real_package(meaningful):
            return ConflationResult(
                False, 0.0, explanation="A real popular package already contains this exact token combination."
            )

        matched: Dict[str, List[str]] = {}
        for t in meaningful:
            hits = self._packages_for_token(t)
            if hits:
                matched[t] = hits

        if len(matched) < 2:
            return ConflationResult(
                False,
                0.0,
                explanation="Fewer than two tokens map to real popular packages.",
                matched_tokens=matched,
            )

        # Pick the most plausible distinct parent for each matched token.
        parents: List[str] = []
        used: Set[str] = set()
        for t, hits in matched.items():
            # Prefer a parent not already claimed by another token.
            choice = next((h for h in hits if h not in used), hits[0])
            used.add(choice)
            parents.append(choice)

        distinct_parents = sorted(set(parents))
        if len(distinct_parents) < 2:
            return ConflationResult(
                False,
                0.0,
                explanation="All tokens trace back to the same real package.",
                matched_tokens=matched,
            )

        # Confidence scales with token coverage: the more of the candidate's
        # distinctive tokens are each borrowed from real packages, the stronger
        # the signal.
        coverage = len(matched) / len(meaningful)
        confidence = min(0.95, 0.45 + 0.5 * coverage)

        explanation = (
            f"Name appears to blend {len(distinct_parents)} real packages "
            f"({', '.join(distinct_parents[:3])}) into a combination that does not exist. "
            f"This is the signature of an LLM hallucination-by-conflation, which "
            f"edit-distance typosquat checks do not detect."
        )

        return ConflationResult(
            is_conflation=True,
            confidence=round(confidence, 2),
            parents=distinct_parents[:5],
            explanation=explanation,
            matched_tokens=matched,
        )
