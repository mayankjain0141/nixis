"""nixis hermes plugin — governance hook for hermes-agent.

Wires nixis-daemon into hermes via its hook protocol.  The plugin calls the
nixis HTTP API at http://127.0.0.1:9091/v1/check for each pre_tool_call event.
If the daemon is unreachable the hook fails open (does not block).

Socket path priority (for reference — HTTP is used here for simplicity):
  1. $NIXIS_SOCKET_PATH
  2. $XDG_RUNTIME_DIR/nixis/nixis.sock
  3. /tmp/nixis.sock

HTTP endpoints used:
  GET  http://127.0.0.1:9091/healthz       — liveness check
  POST http://127.0.0.1:9091/v1/check      — tool-call classification
"""

import json
import os
import urllib.error
import urllib.request
from typing import Any

_NIXIS_HTTP_BASE = "http://127.0.0.1:9091"
_CHECK_URL = _NIXIS_HTTP_BASE + "/v1/check"
_TIMEOUT_S = 0.2  # 200 ms — matches nixis-hook total budget


def _post_check(tool_name: str, args: Any, session_id: str) -> dict:
    """Call POST /v1/check and return the parsed response dict.

    Returns an empty dict on any error so the caller can fail open.
    """
    payload = json.dumps(
        {
            "tool": tool_name,
            "args": args if args is not None else {},
            "session_id": session_id,
        }
    ).encode()

    req = urllib.request.Request(
        _CHECK_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        # Daemon unreachable or response unreadable — fail open.
        return {}


def pre_tool_call(
    tool_name: str,
    args: Any = None,
    session_id: str = "",
    **kwargs: Any,
) -> dict | None:
    """Hook invoked before every tool call.

    Returns a block decision dict when nixis denies the call, otherwise
    returns None to allow hermes to proceed.
    """
    resp = _post_check(tool_name, args, session_id)

    decision = resp.get("decision", {})
    action = decision.get("action", "allow")

    if action == "deny":
        reason = decision.get("reason", "nixis policy violation")
        return {"decision": "block", "reason": reason}

    # allow / audit / require_approval all let the tool run.
    return None


def post_tool_call(
    tool_name: str,
    args: Any = None,
    result: Any = None,
    session_id: str = "",
    **kwargs: Any,
) -> None:
    """Hook invoked after every tool call — fire-and-forget audit log.

    Does not block; any error is silently discarded.
    """
    payload = json.dumps(
        {
            "tool": tool_name,
            "args": args if args is not None else {},
            "session_id": session_id,
            "event": "post_tool_call",
        }
    ).encode()

    req = urllib.request.Request(
        _NIXIS_HTTP_BASE + "/v1/audit",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=_TIMEOUT_S)
    except (urllib.error.URLError, OSError):
        pass


def on_session_start(session_id: str = "", **kwargs: Any) -> None:
    """Hook invoked at session start — placeholder for future telemetry."""


def on_session_end(session_id: str = "", **kwargs: Any) -> None:
    """Hook invoked at session end — placeholder for future telemetry."""
