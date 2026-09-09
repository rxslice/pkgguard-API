"""
pkgguard — built by Blvkware (https://blvkware.dev)
Licensed under the Apache License 2.0. See LICENSE.
Risk scoring: combine registry facts, conflation analysis, and typosquat
distance into a single actionable verdict.

Verdicts
--------
BLOCK    - Do not install. Either the package does not exist (a hallucination),
           or it exists but carries the signature of a slopsquat/typosquat.
REVIEW   - A human should look before installing. Real but low-reputation,
           or a plausible conflation that happens to exist.
ALLOW    - Established package, no signals fired.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from typing import Callable

from .conflation import ConflationDetector, ConflationResult
from .registries import PackageFacts

BLOCK = "BLOCK"
REVIEW = "REVIEW"
ALLOW = "ALLOW"

# Thresholds — tuned conservatively. A false BLOCK costs a developer 10 seconds;
# a false ALLOW can cost them their credentials.
NEW_PACKAGE_DAYS = 120
VERY_NEW_PACKAGE_DAYS = 30
LOW_DOWNLOADS = 1000
NEW_PACKAGE_POLICIES = ("block", "review")


def levenshtein(a: str, b: str) -> int:
    """Damerau-Levenshtein distance (optimal string alignment).

    Transpositions count as a single edit, not two. This matters: adjacent-key
    transposition is the most common human typo, so `lodahs` -> `lodash` must
    score 1, not 2, or short-name typosquats slip through the distance gate."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la

    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j

    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,        # deletion
                d[i][j - 1] + 1,        # insertion
                d[i - 1][j - 1] + cost, # substitution
            )
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)  # transposition
    return d[la][lb]


@dataclass
class TyposquatResult:
    is_typosquat: bool
    nearest: Optional[str] = None
    distance: Optional[int] = None
    explanation: Optional[str] = None


def check_typosquat(name: str, popular: Sequence[str], max_distance: int = 2) -> TyposquatResult:
    """Classic edit-distance check against popular package names.

    This returns a *candidate* only. Edit distance alone is not evidence: real
    packages sit 1-2 edits from popular ones by coincidence (`queue`, `page`,
    `validate` all do). The caller must confirm with an adoption-ratio check —
    see `confirm_typosquat` — before treating this as a risk signal.

    Deliberately kept separate from conflation detection: they catch different
    attack shapes, and a name can trip one without the other."""
    lowered = name.lower()
    if lowered in {p.lower() for p in popular}:
        return TyposquatResult(False)

    # Edit distance must scale with name length. Measured on 200 real npm
    # packages, a flat distance-2 threshold produced false matches between
    # genuinely distinct packages that merely share a suffix — `dcl-crypto` vs
    # `xml-crypto`, `ls-lint` vs `eslint`, `asyncemit` vs `asynckit`. Two edits
    # is only a small perturbation on a long name; on a short one it is a
    # different word. Real typos (`expres`, `lodahs`) are distance 1 and survive.
    effective_max = 1 if len(lowered) < 12 else max_distance

    best: Optional[str] = None
    best_d = 99
    for pkg in popular:
        p = pkg.lower()
        if abs(len(p) - len(lowered)) > effective_max:
            continue
        d = levenshtein(lowered, p)
        if d < best_d:
            best_d, best = d, pkg
            if d == 1:
                break

    if best is not None and 0 < best_d <= effective_max:
        return TyposquatResult(
            True,
            nearest=best,
            distance=best_d,
            explanation=(
                f"Name is {best_d} character edit(s) away from the popular package "
                f"'{best}'. This is the classic typosquat pattern."
            ),
        )
    return TyposquatResult(False)


# A typosquat's defining property is not its spelling — it is that it collects a
# tiny fraction of its target's traffic. `expres` is 14 years old with a real
# repo and 22k monthly downloads, which any age/history heuristic reads as
# legitimate; but `express` has 529 million, so `expres` captures 0.004% of its
# namesake. That ratio is the signal.
TYPOSQUAT_MAX_ADOPTION_RATIO = 0.01
TYPOSQUAT_MIN_TARGET_DOWNLOADS = 100_000


def confirm_typosquat(
    candidate_downloads: Optional[int],
    target_downloads: Optional[int],
) -> Optional[bool]:
    """Confirm or clear a typosquat candidate using adoption ratio.

    Returns True (confirmed), False (cleared), or None (not enough data —
    the caller should fall back to reputation heuristics)."""
    if target_downloads is None or candidate_downloads is None:
        return None
    if target_downloads < TYPOSQUAT_MIN_TARGET_DOWNLOADS:
        return False
    ratio = candidate_downloads / max(target_downloads, 1)
    return ratio < TYPOSQUAT_MAX_ADOPTION_RATIO


@dataclass
class Assessment:
    name: str
    ecosystem: str
    verdict: str
    risk_score: int  # 0-100, higher = more dangerous
    exists: bool
    signals: List[str] = field(default_factory=list)
    recommendation: Optional[str] = None
    facts: Optional[dict] = None
    conflation: Optional[dict] = None
    typosquat: Optional[dict] = None


def assess(
    facts: PackageFacts,
    conflation_detector: ConflationDetector,
    popular: Sequence[str],
    known_hallucinations: Optional[set] = None,
    popularity_lookup: Optional[Callable[[str], Optional[int]]] = None,
    new_package_policy: str = "block",
) -> Assessment:
    """Score a package.

    `popularity_lookup` maps a package name to its monthly download count. It is
    injected rather than called directly so the scorer stays pure and testable;
    the service layer supplies a cached registry-backed implementation."""
    if new_package_policy not in NEW_PACKAGE_POLICIES:
        raise ValueError(
            f"Unsupported new package policy '{new_package_policy}'. "
            f"Supported: {list(NEW_PACKAGE_POLICIES)}"
        )

    signals: List[str] = []
    score = 0
    confirmed_typosquat = False

    name_l = facts.name.lower()
    known_hallucinations = known_hallucinations or set()

    conf: ConflationResult = conflation_detector.analyze(facts.name)
    typo: TyposquatResult = check_typosquat(facts.name, popular)

    if facts.fetch_error:
        return Assessment(
            name=facts.name,
            ecosystem=facts.ecosystem,
            verdict=REVIEW,
            risk_score=50,
            exists=False,
            signals=[f"Could not reach the {facts.ecosystem} registry: {facts.fetch_error}"],
            recommendation="Registry lookup failed — retry before trusting this result. Do not treat as ALLOW.",
        )

    # --- Signal: on the known-hallucination corpus --------------------------
    if name_l in known_hallucinations:
        score += 60
        signals.append(
            "Name appears on the known-hallucination corpus — multiple frontier LLMs "
            "have been documented inventing this exact name."
        )

    # --- Signal: does not exist ---------------------------------------------
    if not facts.exists:
        score += 70
        signals.append(
            f"No package named '{facts.name}' exists on {facts.ecosystem}. If an AI "
            "assistant suggested it, this is a hallucination."
        )
        if conf.is_conflation:
            score += 10
            signals.append(conf.explanation or "Probable conflation of real package names.")

        return Assessment(
            name=facts.name,
            ecosystem=facts.ecosystem,
            verdict=BLOCK,
            risk_score=min(score, 100),
            exists=False,
            signals=signals,
            recommendation=(
                "Do not install. Verify the correct package name from official documentation. "
                "If this name was suggested by an AI assistant, treat it as fabricated — and note "
                "that an attacker may register it later even if it is unclaimed today."
            ),
            conflation=conf.__dict__ if conf.is_conflation else None,
            typosquat=typo.__dict__ if typo.is_typosquat else None,
        )

    # --- Package exists: assess its reputation ------------------------------
    #
    # Reputation gate. Measured on 800 real npm packages outside the popularity
    # corpus, raw conflation matching produced a 62.5% false-positive rate:
    # legitimate packages are *also* token blends (`mock-redis-client`,
    # `react-loading-hook`). Conflation is therefore NOT a standalone signal for
    # a package that exists and is established — it only carries weight when
    # reputation is already weak, which is exactly the slopsquat shape (an
    # attacker's freshly-registered package with no history).
    established = (
        (facts.age_days is not None and facts.age_days > NEW_PACKAGE_DAYS)
        and (facts.monthly_downloads is None or facts.monthly_downloads >= LOW_DOWNLOADS)
        and (facts.version_count is None or facts.version_count > 1)
    )

    if typo.is_typosquat:
        target_dl = None
        if popularity_lookup is not None and typo.nearest:
            try:
                target_dl = popularity_lookup(typo.nearest)
            except Exception:
                target_dl = None

        confirmed = confirm_typosquat(facts.monthly_downloads, target_dl)

        if confirmed is True:
            # A confirmed typosquat — close spelling AND a tiny fraction of the
            # target's traffic — is strong standalone evidence, so it must clear
            # the BLOCK threshold on its own rather than needing a second signal.
            score += 60
            confirmed_typosquat = True
            ratio = facts.monthly_downloads / max(target_dl, 1)
            signals.append(
                f"{typo.explanation} It captures {ratio:.4%} of '{typo.nearest}' downloads "
                f"({facts.monthly_downloads:,} vs {target_dl:,}) — the adoption gap of a typosquat, "
                f"not a sibling project."
            )
        elif confirmed is False:
            signals.append(
                f"Name is similar to '{typo.nearest}', but adoption is comparable — "
                "treated as a coincidental name collision, not a typosquat."
            )
        else:
            # No download data (e.g. PyPI). Fall back to reputation.
            if not established:
                score += 30
                signals.append(
                    f"{typo.explanation} Adoption data unavailable, and the package is "
                    "new/low-history — treating the similarity as unresolved."
                )
            else:
                signals.append(
                    f"Name is similar to '{typo.nearest}', but the package is established "
                    "and adoption data is unavailable — treated as coincidental."
                )

    if conf.is_conflation and not established:
        # Weighted so conflation alone cannot reach BLOCK. A real but obscure
        # package (`fpm-plugin-socket`, 102 downloads) is a token blend too;
        # only conflation *plus* a second weakness — brand-new, single version —
        # should stop an install outright.
        score += 30
        signals.append(
            (conf.explanation or "Probable conflation.")
            + " The name exists on the registry, which is consistent with a slopsquat: "
            "an attacker registering a name models are known to invent."
        )

    if facts.age_days is not None:
        if facts.age_days <= VERY_NEW_PACKAGE_DAYS:
            score += 30
            signals.append(f"Package is only {facts.age_days} days old.")
        elif facts.age_days <= NEW_PACKAGE_DAYS:
            score += 15
            signals.append(f"Package is relatively new ({facts.age_days} days old).")

    if facts.version_count is not None and facts.version_count <= 1:
        score += 15
        signals.append("Only a single published version — no release history.")

    if facts.monthly_downloads is not None and facts.monthly_downloads < LOW_DOWNLOADS:
        score += 15
        signals.append(f"Low adoption: {facts.monthly_downloads:,} downloads in the last month.")

    if not facts.repository:
        score += 10
        signals.append("No source repository linked in the registry metadata.")

    score = min(score, 100)

    if score >= 60:
        verdict = BLOCK
        rec = (
            "Do not install without verifying this is the package you intend. The combination "
            "of signals here matches known slopsquat/typosquat patterns."
        )
    elif score >= 25:
        verdict = REVIEW
        rec = (
            "Have a human confirm this package before installing. Check the linked repository "
            "and confirm the name against official documentation."
        )
    else:
        verdict = ALLOW
        rec = "No risk signals fired. Package appears established."
        if not signals:
            signals.append("Established package with no risk signals.")

    if (
        verdict == BLOCK
        and new_package_policy == "review"
        and facts.age_days is not None
        and facts.age_days <= VERY_NEW_PACKAGE_DAYS
        and name_l not in known_hallucinations
        and not confirmed_typosquat
    ):
        verdict = REVIEW
        signals.append(
            "New-package policy changed this result from BLOCK to REVIEW; "
            "confirm the package through trusted project documentation."
        )
        rec = (
            "Have a human confirm this new package before installing it. "
            "This policy avoids hard-blocking legitimate fresh releases."
        )

    return Assessment(
        name=facts.name,
        ecosystem=facts.ecosystem,
        verdict=verdict,
        risk_score=score,
        exists=True,
        signals=signals,
        recommendation=rec,
        facts={
            "created": facts.created,
            "age_days": facts.age_days,
            "version_count": facts.version_count,
            "monthly_downloads": facts.monthly_downloads,
            "repository": facts.repository,
            "description": facts.description,
        },
        conflation=conf.__dict__ if conf.is_conflation else None,
        typosquat=typo.__dict__ if typo.is_typosquat else None,
    )
