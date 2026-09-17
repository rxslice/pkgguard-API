---
title: pkgguard API quickstart
description: Verify package names with the pkgguard AI supply-chain security API.
---

# Quickstart

```bash
curl https://api.example.com/v1/verify \
  -H "Authorization: Bearer $PKGGUARD_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"names":["express","react-codeshift"],"ecosystem":"npm"}'
```

The API returns `ALLOW`, `REVIEW`, or `BLOCK` for each package plus
`safe_to_proceed`. Treat `safe_to_proceed: false` as a stop signal.

Supported ecosystems are `npm`, `pypi`, and `crates`. Batch requests accept up
to 100 names. The API checks registry existence, known hallucination reports,
conflation patterns, typosquat similarity, age, release history, adoption, and
repository metadata.
