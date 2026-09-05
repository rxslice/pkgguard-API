"""
pkgguard — built by Blvkware (https://blvkware.dev)
Licensed under the Business Source License 1.1. See LICENSE.
pkgguard HTTP API
=================

Verifies package names against live registries and scores them for
hallucination / slopsquat risk before they get installed.

Run:
    uvicorn pkgguard.api:app --reload

Docs:
    http://127.0.0.1:8000/docs
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .registries import SUPPORTED_ECOSYSTEMS
from .service import verify_many, verify_package

app = FastAPI(
    title="pkgguard",
    version="0.1.0",
    description=(
        "Verify package names before installing them.\n\n"
        "LLM coding agents invent plausible-but-nonexistent package names at a measurable "
        "rate, and attackers pre-register those names on public registries — an attack "
        "class known as **slopsquatting**. Because hallucinated names are not misspellings, "
        "registry typosquat heuristics do not catch them.\n\n"
        "pkgguard checks a name against the live registry, then applies **conflation "
        "detection** (does this name blend two real packages into a third that never "
        "existed?), typosquat distance, and reputation signals — and returns "
        "`ALLOW` / `REVIEW` / `BLOCK`.\n\n"
        "No API key required. No proprietary data. Self-hostable."
    ),
)


class VerifyRequest(BaseModel):
    names: List[str] = Field(..., min_length=1, max_length=100, description="Package names to verify.")
    ecosystem: str = Field("npm", description=f"One of: {', '.join(SUPPORTED_ECOSYSTEMS)}")

    class Config:
        json_schema_extra = {
            "example": {"names": ["react-codeshift", "express", "reqeusts"], "ecosystem": "npm"}
        }


class AssessmentOut(BaseModel):
    name: str
    ecosystem: str
    verdict: str
    risk_score: int
    exists: bool
    signals: List[str]
    recommendation: Optional[str] = None
    facts: Optional[dict] = None
    conflation: Optional[dict] = None
    typosquat: Optional[dict] = None


class VerifyResponse(BaseModel):
    results: List[AssessmentOut]
    blocked: int
    review: int
    allowed: int
    safe_to_proceed: bool


@app.get("/v1/health", tags=["meta"])
async def health() -> dict:
    return {"status": "ok", "ecosystems": list(SUPPORTED_ECOSYSTEMS)}


@app.get("/v1/verify/{ecosystem}/{name:path}", response_model=AssessmentOut, tags=["verify"])
async def verify_one(ecosystem: str, name: str) -> AssessmentOut:
    """Verify a single package name. Convenient for quick manual checks and
    for tools that prefer a GET."""
    try:
        result = verify_package(name, ecosystem)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return AssessmentOut(**result.__dict__)


@app.post("/v1/verify", response_model=VerifyResponse, tags=["verify"])
async def verify_batch(payload: VerifyRequest) -> VerifyResponse:
    """Verify a batch of package names. This is the endpoint agent frameworks
    and CI pipelines should call — one round trip for a whole dependency set."""
    try:
        results = verify_many(payload.names, payload.ecosystem)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    out = [AssessmentOut(**r.__dict__) for r in results]
    blocked = sum(1 for r in out if r.verdict == "BLOCK")
    review = sum(1 for r in out if r.verdict == "REVIEW")
    allowed = sum(1 for r in out if r.verdict == "ALLOW")

    return VerifyResponse(
        results=out,
        blocked=blocked,
        review=review,
        allowed=allowed,
        safe_to_proceed=(blocked == 0),
    )
