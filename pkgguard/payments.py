"""Stripe checkout and webhook helpers.

Stripe is intentionally optional for self-hosted/open-source installs. Hosted
deployments set ``STRIPE_SECRET_KEY`` and ``STRIPE_WEBHOOK_SECRET``.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import time
from typing import Any, Dict


def create_checkout(email: str, price_id: str, success_url: str, cancel_url: str) -> str:
    try:
        import stripe
    except ImportError as error:
        raise RuntimeError("Install pkgguard[payments] to enable Stripe.") from error
    secret_key = os.environ.get("STRIPE_SECRET_KEY")
    if not secret_key:
        raise RuntimeError("STRIPE_SECRET_KEY is not configured.")
    allowed_prices = {
        os.environ.get("PKGGUARD_STRIPE_PRICE_PRO", ""): "pro",
        os.environ.get("PKGGUARD_STRIPE_PRICE_TEAM", ""): "team",
    }
    plan = allowed_prices.get(price_id)
    if not plan:
        raise ValueError("Unsupported Stripe price.")
    stripe.api_key = secret_key
    session = stripe.checkout.Session.create(
        mode="subscription",
        customer_email=email,
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=success_url,
        cancel_url=cancel_url,
        metadata={"pkgguard_email": email, "pkgguard_plan": plan},
        subscription_data={
            "metadata": {"pkgguard_email": email, "pkgguard_plan": plan},
        },
    )
    return session.url


def verify_webhook(payload: bytes, signature: str) -> Dict[str, Any]:
    secret = os.environ.get("STRIPE_WEBHOOK_SECRET")
    if not secret:
        raise RuntimeError("STRIPE_WEBHOOK_SECRET is not configured.")
    timestamp = None
    signatures = []
    for part in signature.split(","):
        key, _, value = part.partition("=")
        if key == "t":
            timestamp = value
        elif key == "v1":
            signatures.append(value)
    if not timestamp or abs(time.time() - int(timestamp)) > 300:
        raise ValueError("Invalid or expired Stripe webhook timestamp.")
    signed = f"{timestamp}.".encode() + payload
    expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected, candidate) for candidate in signatures):
        raise ValueError("Invalid Stripe webhook signature.")
    import json
    return json.loads(payload)
