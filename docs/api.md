---
title: pkgguard REST API reference
description: REST API reference for authenticated package security verification and agent install authorization.
---

# REST API reference

## Authentication

Use `Authorization: Bearer <api-key>` or `X-API-Key: <api-key>`.
Paid responses include `X-RateLimit-Limit`, `X-RateLimit-Remaining`,
`X-RateLimit-Reset`, and `X-Pkgguard-Plan`.

## Endpoints

| Method | Endpoint | Use |
|---|---|---|
| POST | `/v1/verify` | Verify up to 100 package names |
| GET | `/v1/verify/{ecosystem}/{name}` | Verify one package |
| POST | `/v1/agent/authorize` | Authorize an AI-generated install command |
| GET | `/v1/health` | Public liveness probe |

`401` means missing/invalid credentials, `429` means quota exceeded, and `503`
means a required hosted service is unavailable. Registry failures never become
an `ALLOW`.
