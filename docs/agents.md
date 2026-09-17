---
title: pkgguard for AI coding agents and MCP
description: Gate AI-generated npm, pip, uv, yarn, pnpm, bun, poetry, and cargo installs with pkgguard.
---

# Agent integration

The agent endpoint authorizes a package-manager command without executing it:

```bash
curl -X POST https://api.example.com/v1/agent/authorize \
  -H "Authorization: Bearer $PKGGUARD_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"command":"npm install react-codeshift lodash"}'
```

Only recognized package-manager commands are considered. Shell chaining,
pipelines, redirects, interpolation, custom registries, and unknown commands
fail closed to `REVIEW`. Use `safe_to_execute` as the enforcement decision.

For local agent runtimes, `pkgguard-mcp` exposes
`authorize_install_command`. For CI, use the bundled GitHub Actions or run
`pkgguard --sarif scan-manifest package.json`.
