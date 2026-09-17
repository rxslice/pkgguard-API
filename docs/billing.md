---
title: pkgguard accounts, plans, and Stripe billing
description: Create pkgguard API accounts, start Stripe subscriptions, and receive subscription webhooks.
---

# Accounts and Stripe billing

The hosted API includes email/password accounts, 30-day bearer sessions,
Stripe Checkout subscriptions, and a signed webhook endpoint. Passwords are
stored with PBKDF2-HMAC-SHA256; raw passwords and session tokens are never
stored.

1. `POST /v1/accounts` with `email` and a 12-character minimum `password`.
2. Use the returned bearer token to call `POST /v1/billing/checkout`.
3. Configure Stripe to send subscription events to
   `/v1/billing/webhook`.
4. Persist `PKGGUARD_ACCOUNT_DB` on durable storage.

Set `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET`. Install the hosted
dependency with `pip install "pkgguard[api,payments]"`. Do not put Stripe
secret keys in source control or client-side code.
