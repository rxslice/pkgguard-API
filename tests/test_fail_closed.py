"""Regression tests for the 2026-11-13 audit (PKG-1 to PKG-4).

Every registry, model and subprocess call is mocked: nothing is installed.
"""
from __future__ import annotations

import asyncio
import time
from unittest.mock import Mock, patch

import pytest

from pkgguard import agent, api, toolgate
from pkgguard.parsing import parse_install_operands
from pkgguard.scoring import Assessment

ALLOW = lambda name, eco="npm": Assessment(name, eco, "ALLOW", 0, True)


def _allow_all(names, ecosystem, policy="block"):
    return [ALLOW(n, ecosystem) for n in names]


# --- PKG-1: operands that cannot be verified are never dropped -------------

@pytest.mark.parametrize("cmd,unverifiable", [
    ("npm install express ./unverified-local-package", ["./unverified-local-package"]),
    ("npm install express ../sibling", ["../sibling"]),
    ("npm install express /abs/path/pkg", ["/abs/path/pkg"]),
    ("npm install express someuser/somerepo", ["someuser/somerepo"]),
    ("npm install express github:someuser/somerepo", ["github:someuser/somerepo"]),
    ("npm install express git+https://example.invalid/r.git", ["git+https://example.invalid/r.git"]),
    ("npm install express https://example.invalid/pkg.tgz", ["https://example.invalid/pkg.tgz"]),
    ("npm install express ./pkg.tgz", ["./pkg.tgz"]),
    ("npm install lodash@npm:evil-package", ["lodash@npm:evil-package"]),
    ("npm install express file:../x", ["file:../x"]),
    ("pip install requests ./local_pkg", ["./local_pkg"]),
    ("pip install requests https://example.invalid/x.whl", ["https://example.invalid/x.whl"]),
    ("pip install requests @ https://example.invalid/x.whl", ["@", "https://example.invalid/x.whl"]),
    ("pip install requests dist/thing-1.0-py3-none-any.whl", ["dist/thing-1.0-py3-none-any.whl"]),
])
def test_unverifiable_operands_are_reported(cmd, unverifiable):
    _, names, bad = parse_install_operands(cmd)
    assert bad == unverifiable
    assert all(u not in names for u in bad)


@pytest.mark.parametrize("cmd", [
    "npm install express ./unverified-local-package",
    "npm install lodash@npm:evil-package",
    "npm install express someuser/somerepo",
    "pip install requests @ https://example.invalid/x.whl",
])
def test_mixed_command_is_not_safe_even_if_every_registry_name_passes(cmd):
    with patch.object(agent, "verify_many", side_effect=_allow_all):
        decision = agent.authorize_command(cmd)
    assert decision.decision == "REVIEW"
    assert decision.safe_to_execute is False
    assert agent.decision_to_dict(decision)["safe_to_execute"] is False


def test_plain_registry_names_still_allowed():
    with patch.object(agent, "verify_many", side_effect=_allow_all):
        decision = agent.authorize_command("npm install express @scope/thing lodash@4.17.21")
    assert decision.decision == "ALLOW"
    assert decision.packages == ["express", "@scope/thing", "lodash"]


def test_pypi_extras_are_checked_by_name():
    _, names, bad = parse_install_operands("pip install requests[socks]==2.31.0")
    assert names == ["requests"] and bad == []


# --- PKG-2: every uv install form reaches the gate ------------------------

@pytest.mark.parametrize("argv", [
    ["add", "requests"],
    ["pip", "install", "requests"],
    ["pip", "sync", "requirements.txt"],
    ["tool", "install", "ruff"],
])
def test_uv_install_forms_are_guarded(argv):
    with patch.object(toolgate, "run_guarded", return_value=0) as gate, \
         patch.object(toolgate.subprocess, "run", return_value=Mock(returncode=0)) as run:
        toolgate.main_uv(argv)
    assert gate.called, argv
    assert not run.called, argv


@pytest.mark.parametrize("argv", [["run", "pytest"], ["lock"], ["pip", "list"]])
def test_uv_non_install_forms_pass_through(argv):
    with patch.object(toolgate, "run_guarded", return_value=0) as gate, \
         patch.object(toolgate.subprocess, "run", return_value=Mock(returncode=0)) as run:
        toolgate.main_uv(argv)
    assert not gate.called and run.called


def test_uv_pip_sync_is_held_for_review_not_run():
    # The parser cannot read a requirements file, so the gate must refuse.
    with patch.object(toolgate.subprocess, "run", return_value=Mock(returncode=0)) as run:
        code = toolgate.run_guarded(["uv", "pip", "sync", "requirements.txt"], allow_review=False)
    assert code == 1 and not run.called


# --- PKG-3: REVIEW is not safe in the batch API ---------------------------

def _client():
    from fastapi.testclient import TestClient
    return TestClient(api.app)


def _batch(verdicts, **extra):
    results = [Assessment(f"p{i}", "npm", v, 50 if v != "ALLOW" else 0, v == "ALLOW") for i, v in enumerate(verdicts)]
    with patch.object(api, "verify_many", return_value=results):
        names = [r.name for r in results]
        return _client().post("/v1/verify", json={"names": names, "ecosystem": "npm", **extra}).json()


@pytest.mark.parametrize("verdicts,allow_review,safe", [
    (["ALLOW", "ALLOW"], False, True),
    (["REVIEW"], False, False),          # the audit's registry-timeout case
    (["ALLOW", "REVIEW"], False, False),
    (["ALLOW", "REVIEW"], True, True),   # explicit, separately approved override
    (["BLOCK"], True, False),            # BLOCK is never overridden
    (["ALLOW", "BLOCK"], False, False),
])
def test_batch_safe_to_proceed_requires_affirmative_allow(verdicts, allow_review, safe):
    body = _batch(verdicts, allow_review=allow_review)
    assert body["safe_to_proceed"] is safe


# --- PKG-4: verification does not block the event loop --------------------

def test_verification_runs_off_the_event_loop():
    import httpx

    def slow(*args, **kwargs):
        time.sleep(0.3)
        return ALLOW("express")

    async def scenario():
        transport = httpx.ASGITransport(app=api.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            start = time.perf_counter()

            async def health_done():
                await asyncio.sleep(0.02)  # let the verification start first
                await client.get("/v1/health")
                return time.perf_counter() - start
            _, done = await asyncio.gather(client.get("/v1/verify/npm/express"), health_done())
            return done

    with patch.object(api, "verify_package", side_effect=slow):
        delay = asyncio.run(scenario())
    assert delay < 0.2, f"health answered after {delay:.3f}s, behind a 0.3s verification"
