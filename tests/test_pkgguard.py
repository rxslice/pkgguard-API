import json
from pathlib import Path

import pytest

from pkgguard.cli import parse_install_command, parse_manifest
from pkgguard.conflation import ConflationDetector, tokenize
from pkgguard.registries import PackageFacts
from pkgguard.scoring import ALLOW, BLOCK, REVIEW, assess, check_typosquat, levenshtein

POPULAR = [
    "react", "react-dom", "react-router", "react-codemod", "jscodeshift",
    "lodash", "express", "axios", "webpack", "eslint", "babel-cli",
    "vue", "redux", "react-redux", "typescript", "jest",
]


@pytest.fixture(scope="module")
def detector():
    return ConflationDetector(POPULAR)


# --- tokenization ----------------------------------------------------------

def test_tokenize_splits_separators_and_camelcase():
    assert tokenize("react-codeshift") == ["react", "codeshift"]
    assert tokenize("@types/react-dom") == ["types", "react", "dom"]
    assert tokenize("myAwesomePackage") == ["my", "awesome", "package"]


# --- conflation ------------------------------------------------------------

def test_detects_the_real_react_codeshift_slopsquat(detector):
    """The documented Jan 2026 incident: jscodeshift + react-codemod blended
    into a name that never existed, then registered by a third party."""
    result = detector.analyze("react-codeshift")
    assert result.is_conflation is True
    assert "jscodeshift" in result.parents
    assert result.confidence > 0.5


def test_real_package_is_not_flagged_as_conflation(detector):
    assert detector.analyze("react-dom").is_conflation is False
    assert detector.analyze("express").is_conflation is False


def test_random_string_is_not_a_conflation(detector):
    """Gibberish has no real parents, so it should not be reported as a blend.
    Nonexistence is caught separately by the registry check."""
    assert detector.analyze("qwrtzplkjhg").is_conflation is False


def test_single_token_name_not_assessed(detector):
    assert detector.analyze("lodash").is_conflation is False


def test_conflation_requires_distinct_parents(detector):
    """A name whose tokens all come from the same package is not a blend."""
    result = detector.analyze("react-react")
    assert result.is_conflation is False


# --- typosquat -------------------------------------------------------------

def test_levenshtein_basic():
    assert levenshtein("kitten", "sitting") == 3
    assert levenshtein("abc", "abc") == 0


def test_detects_classic_typosquat():
    result = check_typosquat("lodahs", POPULAR)
    assert result.is_typosquat is True
    assert result.nearest == "lodash"


def test_exact_match_is_not_typosquat():
    assert check_typosquat("lodash", POPULAR).is_typosquat is False


def test_distant_name_is_not_typosquat():
    assert check_typosquat("completely-unrelated-thing", POPULAR).is_typosquat is False


# --- scoring ---------------------------------------------------------------

def test_nonexistent_package_is_blocked(detector):
    facts = PackageFacts(name="totally-made-up-pkg", ecosystem="npm", exists=False)
    result = assess(facts, detector, POPULAR)
    assert result.verdict == BLOCK
    assert result.exists is False
    assert result.risk_score >= 70


def test_established_package_is_allowed(detector):
    facts = PackageFacts(
        name="express", ecosystem="npm", exists=True,
        created="2010-01-01T00:00:00Z", age_days=6000,
        version_count=300, monthly_downloads=500_000_000,
        repository="https://github.com/expressjs/express",
    )
    result = assess(facts, detector, POPULAR)
    assert result.verdict == ALLOW
    assert result.risk_score < 25


def test_existing_but_brand_new_conflation_is_blocked(detector):
    """The dangerous case: the hallucinated name EXISTS because an attacker
    registered it. An existence-only check would wrongly pass this."""
    facts = PackageFacts(
        name="react-codeshift", ecosystem="npm", exists=True,
        created="2026-01-14T21:02:51Z", age_days=10,
        version_count=1, monthly_downloads=11, repository=None,
    )
    result = assess(facts, detector, POPULAR)
    assert result.verdict == BLOCK
    assert result.conflation is not None


def test_new_low_adoption_package_gets_review(detector):
    facts = PackageFacts(
        name="someones-new-helper", ecosystem="npm", exists=True,
        created="2026-06-01T00:00:00Z", age_days=90,
        version_count=3, monthly_downloads=50,
        repository="https://github.com/someone/someones-new-helper",
    )
    result = assess(facts, detector, POPULAR)
    assert result.verdict in (REVIEW, BLOCK)


def test_registry_failure_does_not_return_allow(detector):
    """A network failure must never be reported as safe."""
    facts = PackageFacts(name="whatever", ecosystem="npm", exists=False,
                         fetch_error="connection timed out")
    result = assess(facts, detector, POPULAR)
    assert result.verdict != ALLOW


# --- CLI parsing -----------------------------------------------------------

@pytest.mark.parametrize("cmd,eco,expected", [
    ("npm install react-codeshift lodash", "npm", ["react-codeshift", "lodash"]),
    ("npm i express", "npm", ["express"]),
    ("yarn add vue@3.2.1", "npm", ["vue"]),
    # Scoped npm packages keep their full @scope/name form — that IS the name.
    ("pnpm add @scope/thing", "npm", ["@scope/thing"]),
    ("pip install requests==2.31.0 flask", "pypi", ["requests", "flask"]),
    ("pip3 install --upgrade numpy", "pypi", ["numpy"]),
    ("cargo add serde", "crates", ["serde"]),
])
def test_parse_install_commands(cmd, eco, expected):
    got_eco, names = parse_install_command(cmd)
    assert got_eco == eco
    assert names == expected


def test_parse_unrecognized_command():
    eco, names = parse_install_command("ls -la")
    assert eco is None
    assert names == []


def test_parse_package_json(tmp_path: Path):
    p = tmp_path / "package.json"
    p.write_text(json.dumps({
        "dependencies": {"express": "^4.0.0", "lodash": "^4.17.0"},
        "devDependencies": {"jest": "^29.0.0"},
    }))
    eco, names = parse_manifest(p)
    assert eco == "npm"
    assert set(names) == {"express", "lodash", "jest"}


def test_parse_requirements_txt(tmp_path: Path):
    p = tmp_path / "requirements.txt"
    p.write_text("requests==2.31.0\n# a comment\nflask>=2.0\n-e .\nnumpy\n")
    eco, names = parse_manifest(p)
    assert eco == "pypi"
    assert set(names) == {"requests", "flask", "numpy"}
