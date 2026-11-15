import io
import json

import pytest

from pkgguard import mcp_server


def call(arguments):
    return mcp_server._handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "authorize_install_command", "arguments": arguments},
    })


@pytest.mark.parametrize("value", ["false", "true", 0, 1, [], {}, None])
def test_approval_requires_a_real_boolean(value, monkeypatch):
    def unexpected(*args):
        pytest.fail("invalid approval must be rejected before checking a command")
    monkeypatch.setattr(mcp_server, "authorize_command", unexpected)
    assert call({"command": "pip install requests", "allow_review": value})["error"]["code"] == -32602


@pytest.mark.parametrize("arguments", [None, [], "bad", 42, {"command": 42}, {"command": "  "},
                                         {"command": "pip install requests", "new_package_policy": "allow"}])
def test_invalid_arguments_are_parameter_errors(arguments):
    assert call(arguments)["error"]["code"] == -32602


def test_stdio_survives_invalid_envelopes(monkeypatch):
    requests = [None, [], 42, "bad", {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": None},
                {"jsonrpc": "2.0", "id": 3, "method": "ping"}]
    output = io.StringIO()
    monkeypatch.setattr(mcp_server.sys, "stdin", io.StringIO("\n".join(json.dumps(r) for r in requests)))
    monkeypatch.setattr(mcp_server.sys, "stdout", output)
    assert mcp_server.main() == 0
    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    assert len(responses) == len(requests)
    assert [r["error"]["code"] for r in responses[:4]] == [-32600] * 4
    assert responses[4]["error"]["code"] == -32602
    assert responses[-1] == {"jsonrpc": "2.0", "id": 3, "result": {}}


def test_notifications_never_execute_tool_calls(monkeypatch):
    def unexpected(*args):
        pytest.fail("a notification must not authorize an install")
    monkeypatch.setattr(mcp_server, "authorize_command", unexpected)
    assert mcp_server._handle_request({"jsonrpc": "2.0", "method": "tools/call", "params": {
        "name": "authorize_install_command", "arguments": {"command": "pip install requests"}}}) is None


@pytest.mark.parametrize("approved", [False, True])
def test_explicit_boolean_preserves_review_policy(approved, monkeypatch):
    from pkgguard.agent import CommandDecision
    monkeypatch.setattr(mcp_server, "authorize_command", lambda *args: CommandDecision(
        command="pip install new-package", decision="REVIEW", ecosystem="pypi", packages=["new-package"]))
    result = call({"command": "pip install new-package", "allow_review": approved})
    assert result["result"]["structuredContent"]["safe_to_execute"] is approved


def test_initialize_negotiates_protocol_version():
    from pkgguard.mcp_server import SUPPORTED_PROTOCOL_VERSIONS, _handle_request

    for version in ("2025-11-25", "2025-06-18", "2024-11-05"):
        reply = _handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": version}})
        assert reply["result"]["protocolVersion"] == version
    reply = _handle_request({"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {"protocolVersion": "1900-01-01"}})
    assert reply["result"]["protocolVersion"] == SUPPORTED_PROTOCOL_VERSIONS[0]


def test_tool_declares_read_only_and_output_schema():
    from pkgguard.mcp_server import _handle_request

    tool = _handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"][0]
    assert tool["annotations"]["readOnlyHint"] is True
    assert tool["outputSchema"]["type"] == "object"
    assert set(tool["outputSchema"]["required"]) <= {"decision", "safe_to_execute", "packages", "reason", "assessments"}


def test_unknown_tool_is_invalid_params():
    from pkgguard.mcp_server import _handle_request

    reply = _handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "nope", "arguments": {}}})
    assert reply["error"]["code"] == -32602
