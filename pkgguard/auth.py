"""API authentication and per-key request limits.

The API deliberately keeps billing-provider integration outside the package.
Your billing system provisions/revokes keys and assigns plans through the
``PKGGUARD_API_KEYS`` environment variable.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from fastapi import HTTPException, Request, Response


@dataclass(frozen=True)
class ApiPlan:
    name: str
    requests_per_minute: int


DEFAULT_PLANS = {
    "free": ApiPlan("free", 60),
    "pro": ApiPlan("pro", 1_000),
    "team": ApiPlan("team", 5_000),
}

_WINDOW_SECONDS = 60
_usage: Dict[str, Tuple[int, int]] = {}
_usage_lock = threading.Lock()


def _enabled() -> bool:
    return os.environ.get("PKGGUARD_REQUIRE_API_KEY", "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def _configured_keys() -> Dict[str, ApiPlan]:
    """Return hashed keys and plans from ``key=plan,key=plan`` configuration."""
    raw = os.environ.get("PKGGUARD_API_KEYS", "")
    keys: Dict[str, ApiPlan] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            secret, plan_name = item.split("=", 1)
        except ValueError:
            continue
        plan = DEFAULT_PLANS.get(plan_name.strip().lower())
        if secret.strip() and plan:
            digest = hashlib.sha256(secret.strip().encode("utf-8")).hexdigest()
            keys[digest] = plan
    return keys


def _extract_key(request: Request) -> Optional[str]:
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip() or None
    return request.headers.get("X-API-Key")


def _consume(digest: str, limit: int, now: int) -> Tuple[bool, int, int]:
    with _usage_lock:
        window_start, count = _usage.get(digest, (now, 0))
        if now - window_start >= _WINDOW_SECONDS:
            window_start, count = now, 0
        if count >= limit:
            _usage[digest] = (window_start, count)
            return False, 0, window_start + _WINDOW_SECONDS
        count += 1
        _usage[digest] = (window_start, count)
        return True, limit - count, window_start + _WINDOW_SECONDS


def authenticate(request: Request, response: Response) -> ApiPlan:
    """Authenticate a paid request and attach quota headers to its response."""
    if not _enabled():
        return ApiPlan("development", 0)

    configured = _configured_keys()
    secret = _extract_key(request)
    if secret:
        try:
            from .accounts import account_for_session
            account = account_for_session(secret)
        except (OSError, ValueError):
            account = None
        if account is not None:
            plan = DEFAULT_PLANS.get(account["plan"], DEFAULT_PLANS["free"])
            digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
            allowed, remaining, reset = _consume(
                digest, plan.requests_per_minute, int(time.time())
            )
            response.headers["X-RateLimit-Limit"] = str(plan.requests_per_minute)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            response.headers["X-RateLimit-Reset"] = str(reset)
            response.headers["X-Pkgguard-Plan"] = plan.name
            if not allowed:
                raise HTTPException(
                    status_code=429,
                    detail="Rate limit exceeded.",
                    headers={"Retry-After": str(max(1, reset - int(time.time())))},
                )
            return plan
    if not configured:
        raise HTTPException(
            status_code=503,
            detail="API authentication is enabled but no API keys are configured.",
        )
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest() if secret else ""
    plan = next(
        (candidate for key_digest, candidate in configured.items()
         if hmac.compare_digest(key_digest, digest)),
        None,
    )
    if plan is None:
        raise HTTPException(status_code=401, detail="A valid API key is required.")

    allowed, remaining, reset = _consume(digest, plan.requests_per_minute, int(time.time()))
    response.headers["X-RateLimit-Limit"] = str(plan.requests_per_minute)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    response.headers["X-RateLimit-Reset"] = str(reset)
    response.headers["X-Pkgguard-Plan"] = plan.name
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded.",
            headers={"Retry-After": str(max(1, reset - int(time.time())))},
        )
    return plan
