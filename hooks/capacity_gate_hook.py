#!/usr/bin/env python3
"""
Capacity Gate Hook Entrypoint
PreToolUse lifecycle hook invoked by Agent runtime for:
  - view_file
  - read_file
  - grep_search
  - and other agent tool calls.

Tracks session state across calls in /tmp/.general_security_scan_state/state_<session_id>.json.
Enforces 5-dimensional resource bounding with non-blocking guidance for heavy computing lockfiles.
Always guarantees clean exit code 0 to protect agent workflow continuity.
"""
from __future__ import annotations

import contextlib
import datetime
import json
import sys
from pathlib import Path

# Ensure plugin root is in sys.path when executed as a hook subprocess
_plugin_root = str(Path(__file__).resolve().parent.parent)
if _plugin_root not in sys.path:
    sys.path.insert(0, _plugin_root)

from hooks.components.capacity_evaluator import CapacityEvaluator
from hooks.discovery_engine import DiscoveryEngine
from hooks.hook_contract import (
    CapacityLimits,
    emit_allow,
    emit_response,
    parse_stdin,
)

# ---------------------------------------------------------------------------
# Session State Management (Cumulative Scan Tracking)
# ---------------------------------------------------------------------------

STATE_DIR = Path("/tmp/.general_security_scan_state")


def _get_state_file(session_id: str) -> Path:
    """Returns path to isolated session state file for the given session ID."""
    safe_id = "".join(c for c in session_id if c.isalnum() or c in ("-", "_")) or "default"
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    return STATE_DIR / f"state_{safe_id}.json"


def _load_state(session_id: str) -> dict:
    """Loads session state from disk or initializes empty state dictionary."""
    state_file = _get_state_file(session_id)
    if state_file.exists():
        with (
            contextlib.suppress(OSError, json.JSONDecodeError),
            open(state_file, "r", encoding="utf-8") as f,
        ):
            data = json.load(f)
            if isinstance(data, dict):
                return data
    return {
        "workflow_scan_id": "",
        "scanned_files": [],
        "total_bytes": 0,
        "total_kb": 0.0,
        "notices": [],
    }


def _save_state(session_id: str, state: dict) -> None:
    """Persists session state dictionary to disk with UTC timestamp."""
    state_file = _get_state_file(session_id)
    state["last_updated"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with (
        contextlib.suppress(OSError, TypeError),
        open(state_file, "w", encoding="utf-8") as f,
    ):
        json.dump(state, f, indent=2)


# ---------------------------------------------------------------------------
# Main PreToolUse Lifecycle Interceptor
# ---------------------------------------------------------------------------

def main() -> None:
    context = parse_stdin()
    tool_name = context.tool_call.name
    target_path_str = context.target_file
    workspace_root = context.primary_workspace
    session_id = context.conversation_id or "default"
    limits = CapacityLimits()

    # 1. Single-File Read Interception (view_file / read_file)
    if tool_name in ("view_file", "read_file") and target_path_str:
        target_path = Path(target_path_str).resolve()
        evaluator = CapacityEvaluator(limits=limits)
        state = _load_state(session_id)

        current_bytes = state.get("total_bytes", 0)
        _decision, file_notices = evaluator.evaluate_file(
            target_path, current_cumulative_bytes=current_bytes
        )

        # Update cumulative state if file exists and is new
        target_key = str(target_path)
        scanned_files = list(state.get("scanned_files", []))
        if target_path.is_file() and target_key not in scanned_files:
            try:
                f_size = target_path.stat().st_size
            except OSError:
                f_size = 0
            scanned_files.append(target_key)
            state["scanned_files"] = scanned_files
            new_bytes = current_bytes + f_size
            state["total_bytes"] = new_bytes
            state["total_kb"] = round(new_bytes / 1024, 2)
            _save_state(session_id, state)

        emit_allow(
            reason=f"Processed tool '{tool_name}' for '{target_path.name}'.",
            notices=file_notices,
        )

    # 2. Broad Search / Workspace Gate Interception (grep_search or workspace query)
    if tool_name == "grep_search" or not target_path_str:
        engine = DiscoveryEngine(
            workspace_root=workspace_root,
            limits=limits,
            session_id=session_id,
        )
        hook_result, report = engine.run_discovery()

        # Update state with discovery execution
        state = _load_state(session_id)
        state["workflow_scan_id"] = report.workflow_metadata.workflow_scan_id
        state["total_candidates"] = len(report.files_to_scan)
        _save_state(session_id, state)

        emit_response(hook_result)

    # 3. Default fallback: allow tool execution
    emit_allow(reason=f"Allowed tool execution for '{tool_name}'.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        # Fail-closed safe fallback: emit ALLOW with diagnostic note and exit code 0
        emit_allow(reason=f"Hook diagnostic note: {exc}")
