"""
pkgguard — built by Blvkware (https://blvkware.dev)
Licensed under the Apache License 2.0. See LICENSE.
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

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from .registries import SUPPORTED_ECOSYSTEMS
from .scoring import NEW_PACKAGE_POLICIES
from .service import verify_many, verify_package
from .agent import authorize_command, decision_to_dict
from .auth import ApiPlan, authenticate
from .accounts import account_for_session, create_account, create_session, update_subscription
from .payments import create_checkout, verify_webhook

app = FastAPI(
    title="pkgguard",
    version="0.3.0",
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
        "API keys and plan-based rate limits are enabled with "
        "`PKGGUARD_REQUIRE_API_KEY=true`. Self-hostable."
    ),
)


class VerifyRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {"names": ["react-codeshift", "express", "reqeusts"], "ecosystem": "npm"}
        }
    )

    names: List[str] = Field(..., min_length=1, max_length=100, description="Package names to verify.")
    ecosystem: str = Field("npm", description=f"One of: {', '.join(SUPPORTED_ECOSYSTEMS)}")
    new_package_policy: str = Field(
        "block",
        description=f"Policy for very new packages: {', '.join(NEW_PACKAGE_POLICIES)}.",
    )


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


class AuthorizeRequest(BaseModel):
    command: str = Field(..., min_length=1, max_length=10000)
    new_package_policy: str = Field(
        "block",
        description=f"Policy for very new packages: {', '.join(NEW_PACKAGE_POLICIES)}.",
    )
    allow_review: bool = Field(
        False,
        description="Explicitly permit REVIEW results after a separate approval step.",
    )


class AuthorizeResponse(BaseModel):
    command: str
    decision: str
    ecosystem: Optional[str] = None
    packages: List[str]
    assessments: List[AssessmentOut]
    reason: str
    safe_to_execute: bool


class AccountCredentials(BaseModel):
    email: str = Field(..., min_length=3, max_length=320)
    password: str = Field(..., min_length=12, max_length=256)


class SessionResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class CheckoutRequest(BaseModel):
    price_id: str = Field(..., min_length=1, max_length=200)
    success_url: str = Field(..., min_length=1, max_length=2_000)
    cancel_url: str = Field(..., min_length=1, max_length=2_000)


def _session_account(request: Request):
    authorization = request.headers.get("Authorization", "")
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="A signed-in account is required.")
    account = account_for_session(authorization[7:].strip())
    if account is None:
        raise HTTPException(status_code=401, detail="Invalid or expired session.")
    return account


@app.get("/v1/health", tags=["meta"])
async def health() -> dict:
    return {"status": "ok", "ecosystems": list(SUPPORTED_ECOSYSTEMS)}


@app.post("/v1/accounts", response_model=SessionResponse, status_code=201, tags=["accounts"])
async def register_account(payload: AccountCredentials) -> SessionResponse:
    try:
        create_account(payload.email, payload.password)
        token = create_session(payload.email, payload.password)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    return SessionResponse(access_token=token)


@app.post("/v1/accounts/session", response_model=SessionResponse, tags=["accounts"])
async def login_account(payload: AccountCredentials) -> SessionResponse:
    try:
        token = create_session(payload.email, payload.password)
    except ValueError as error:
        raise HTTPException(status_code=401, detail=str(error))
    return SessionResponse(access_token=token)


@app.post("/v1/billing/checkout", tags=["billing"])
async def billing_checkout(payload: CheckoutRequest, request: Request) -> dict:
    account = _session_account(request)
    try:
        url = create_checkout(
            account["email"], payload.price_id, payload.success_url, payload.cancel_url
        )
    except (RuntimeError, ValueError) as error:
        raise HTTPException(status_code=503, detail=str(error))
    return {"url": url}


@app.post("/v1/billing/webhook", tags=["billing"])
async def billing_webhook(request: Request) -> dict:
    try:
        event = verify_webhook(await request.body(), request.headers.get("stripe-signature", ""))
    except (RuntimeError, ValueError, TypeError) as error:
        raise HTTPException(status_code=400, detail=str(error))
    event_type = event.get("type")
    data = event.get("data", {}).get("object", {})
    if event_type in {
        "checkout.session.completed",
        "customer.subscription.updated",
        "customer.subscription.deleted",
    }:
        metadata = data.get("metadata", {}) or {}
        email = metadata.get("pkgguard_email")
        if email:
            update_subscription(
                email,
                data.get("customer", ""),
                data.get("subscription", data.get("id", "")),
                "free" if event_type.endswith(".deleted") else metadata.get("pkgguard_plan", "pro"),
            )
    return {"received": True}


@app.post("/v1/agent/authorize", response_model=AuthorizeResponse, tags=["agent"])
async def authorize_agent_command(
    payload: AuthorizeRequest,
    response: Response,
    _plan: ApiPlan = Depends(authenticate),
) -> AuthorizeResponse:
    """Authorize an agent-generated install command without executing it."""
    try:
        decision = authorize_command(payload.command, payload.new_package_policy)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    response_data = decision_to_dict(decision, allow_review=payload.allow_review)
    return AuthorizeResponse(
        command=response_data["command"],
        decision=response_data["decision"],
        ecosystem=response_data["ecosystem"],
        packages=response_data["packages"],
        assessments=[AssessmentOut(**result) for result in response_data["assessments"]],
        reason=response_data["reason"],
        safe_to_execute=response_data["safe_to_execute"],
    )


@app.get("/v1/verify/{ecosystem}/{name:path}", response_model=AssessmentOut, tags=["verify"])
async def verify_one(
    ecosystem: str,
    name: str,
    response: Response,
    new_package_policy: str = Query("block", description="Policy for very new packages."),
    _plan: ApiPlan = Depends(authenticate),
) -> AssessmentOut:
    """Verify a single package name. Convenient for quick manual checks and
    for tools that prefer a GET."""
    try:
        result = verify_package(name, ecosystem, new_package_policy)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return AssessmentOut(**result.__dict__)


@app.post("/v1/verify", response_model=VerifyResponse, tags=["verify"])
async def verify_batch(
    payload: VerifyRequest,
    response: Response,
    _plan: ApiPlan = Depends(authenticate),
) -> VerifyResponse:
    """Verify a batch of package names. This is the endpoint agent frameworks
    and CI pipelines should call — one round trip for a whole dependency set."""
    try:
        results = verify_many(
            payload.names,
            payload.ecosystem,
            payload.new_package_policy,
        )
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
