"""Minimal agent-facing MCP server for pkgguard.

This exposes a single tool that authorizes an install command before it reaches a
package manager. It is intentionally tiny and dependency-free so it can be used
inside agent runtime wrappers or local toolchains.
"""
from __future__ import annotations

import json
import sys
from typing import Any, Dict, List

from .agent import authorize_command, decision_to_dict


def _rpc_response(request_id: Any, result: Any = None, error: Any = None) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        payload["error"] = error
    else:
        payload["result"] = result
    return payload


def _authorize_tool(args: Dict[str, Any]) -> Dict[str, Any]:
    command = str(args.get("command", "")).strip()
    if not command:
        raise ValueError("command is required")
    allow_review = bool(args.get("allow_review", False))
    new_package_policy = str(args.get("new_package_policy", "block"))
    decision = authorize_command(command, new_package_policy)
    payload = decision_to_dict(decision, allow_review=allow_review)
    return {
        "decision": payload["decision"],
        "safe_to_execute": payload["safe_to_execute"],
        "ecosystem": payload["ecosystem"],
        "packages": payload["packages"],
        "reason": payload["reason"],
        "assessments": payload["assessments"],
    }


def _handle_request(request: Dict[str, Any]) -> Dict[str, Any]:
    method = request.get("method")
    request_id = request.get("id")

    if method == "initialize":
        return _rpc_response(
            request_id,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "pkgguard", "version": "0.1.0"},
            },
        )

    if method == "tools/list":
        return _rpc_response(
            request_id,
            {
                "tools": [
                    {
                        "name": "authorize_install_command",
                        "description": "Authorize an agent-generated install command before it reaches a package manager.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "command": {"type": "string", "description": "Package-manager install command to evaluate."},
                                "allow_review": {"type": "boolean", "description": "Explicitly permit REVIEW after a human approval step."},
                                "new_package_policy": {
                                    "type": "string",
                                    "enum": ["block", "review"],
                                    "description": "Policy for very new packages.",
                                },
                            },
                            "required": ["command"],
                        },
                    }
                ]
            },
        )

    if method == "tools/call":
        params = request.get("params", {})
        tool_name = params.get("name")
        if tool_name != "authorize_install_command":
            return _rpc_response(
                request_id,
                error={"code": -32601, "message": f"Unknown tool: {tool_name}"},
            )
        try:
            result = _authorize_tool(params.get("arguments", {}))
            return _rpc_response(request_id, {"content": [{"type": "text", "text": json.dumps(result, indent=2)}], "structuredContent": result})
        except ValueError as exc:
            return _rpc_response(request_id, error={"code": -32602, "message": str(exc)})
        except Exception as exc:  # pragma: no cover - guardrail for unexpected runtime failures
            return _rpc_response(request_id, error={"code": -32603, "message": f"Internal error: {exc}"})

    if method == "notifications/initialized":
        return None

    return _rpc_response(request_id, error={"code": -32601, "message": f"Method not found: {method}"})


def main() -> int:
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            sys.stdout.write(json.dumps(_rpc_response(None, error={"code": -32700, "message": "Parse error"})) + "\n")
            sys.stdout.flush()
            continue

        response = _handle_request(request)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
