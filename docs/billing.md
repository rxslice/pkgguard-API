---
title: pkgguard accounts, plans, and Stripe billing
description: Create pkgguard API accounts, start Stripe subscriptions, and receive subscription webhooks.
---

# Accounts and Stripe billing

## Launch plans

The hosted API starts with three deliberately simple plans. Limits are
request-based and the API returns `429` at the limit instead of creating
surprise overage charges.

| Plan | Price | Monthly checks | Rate limit |
|---|---:|---:|---:|
| Free | $0 | Included access | 60 requests/minute |
| Pro | $19/month | Included access | 1,000 requests/minute |
| Team | $79/month | Included access | 5,000 requests/minute |

These prices are a launch position for an API that is also open source: low
enough to trial inside a CI pipeline, with a clear step-up for teams running
agent fleets. Review usage and registry costs after the first 30 days before
adding annual billing or overage pricing.

The hosted API includes email/password accounts, 30-day bearer sessions,
Stripe Checkout subscriptions, and a signed webhook endpoint. Passwords are
stored with PBKDF2-HMAC-SHA256; raw passwords and session tokens are never
stored.

1. `POST /v1/accounts` with `email` and a 12-character minimum `password`.
2. Use the returned bearer token to call `POST /v1/billing/checkout`.
3. Configure Stripe to send subscription events to
   `/v1/billing/webhook`.
4. Persist `PKGGUARD_ACCOUNT_DB` on durable storage.

Set `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`,
`PKGGUARD_STRIPE_PRICE_PRO`, and `PKGGUARD_STRIPE_PRICE_TEAM`. Install the hosted
dependency with `pip install "pkgguard[api,payments]"`. Do not put Stripe
secret keys in source control or client-side code.
