"""
Integration tests for hooks/capacity_gate_hook.py
Validates CLI invocation, stdin parsing, session state persistence,
and non-blocking tool execution.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HOOK_SCRIPT = Path(__file__).resolve().parent.parent.parent.parent / "hooks" / "capacity_gate_hook.py"


def test_capacity_gate_hook_empty_stdin() -> None:
    proc = subprocess.run(
        [sys.executable, str(HOOK_SCRIPT)],
        check=False,
        input="",
        text=True,
        capture_output=True,
    )
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data["decision"] == "allow"


def test_capacity_gate_hook_view_file_interception(mock_workspace: Path) -> None:
    target = mock_workspace / "auth_service.py"
    session_id = "test_integration_sess_1"

    payload = {
        "toolCall": {
            "name": "view_file",
            "args": {"AbsolutePath": str(target)},
        },
        "conversationId": session_id,
        "workspacePaths": [str(mock_workspace)],
    }

    proc = subprocess.run(
        [sys.executable, str(HOOK_SCRIPT)],
        check=False,
        input=json.dumps(payload),
        text=True,
        capture_output=True,
    )
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data["decision"] == "allow"

    # Verify session state file was created
    state_file = Path(f"/tmp/.general_security_scan_state/state_{session_id}.json")
    assert state_file.exists()
    state = json.loads(state_file.read_text(encoding="utf-8"))
    assert str(target) in state["scanned_files"]
    assert state["total_bytes"] > 0


def test_capacity_gate_hook_grep_search_interception(mock_workspace: Path) -> None:
    session_id = "test_integration_sess_2"
    payload = {
        "toolCall": {
            "name": "grep_search",
            "args": {"Query": "API_KEY"},
        },
        "conversationId": session_id,
        "workspacePaths": [str(mock_workspace)],
    }

    proc = subprocess.run(
        [sys.executable, str(HOOK_SCRIPT)],
        check=False,
        input=json.dumps(payload),
        text=True,
        capture_output=True,
    )
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data["decision"] == "allow"
    assert "discoveryReport" in data
