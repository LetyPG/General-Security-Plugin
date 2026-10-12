"""
Unit tests for hooks/hook_contract.py
Comprehensive validation of hook contracts, data structures, serialization,
stdin parsing edge cases, and protocol emitter functions.
"""
from __future__ import annotations

import io
import json
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from hooks.hook_contract import (
    CapacityLimits,
    Decision,
    DiscoveryReport,
    HookContext,
    HookResult,
    InformativeNotice,
    NoticeLevel,
    OversizedFile,
    ToolCall,
    WorkflowScanMetadata,
    emit_allow,
    emit_ask,
    emit_deny,
    parse_stdin,
)

# ---------------------------------------------------------------------------
# Enums and Constants
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "decision, expected_value",
    [
        (Decision.ALLOW, "allow"),
        (Decision.DENY, "deny"),
        (Decision.ASK, "ask"),
    ],
)
def test_decision_enum_values(decision: Decision, expected_value: str) -> None:
    assert decision.value == expected_value
    assert isinstance(decision, str)


@pytest.mark.parametrize(
    "level, expected_value",
    [
        (NoticeLevel.INFO, "INFO"),
        (NoticeLevel.WARNING, "WARNING"),
        (NoticeLevel.CRITICAL, "CRITICAL"),
    ],
)
def test_notice_level_enum_values(level: NoticeLevel, expected_value: str) -> None:
    assert level.value == expected_value
    assert isinstance(level, str)


# ---------------------------------------------------------------------------
# WorkflowScanMetadata Tests
# ---------------------------------------------------------------------------

def test_workflow_scan_metadata_generate(tmp_path: Path) -> None:
    meta = WorkflowScanMetadata.generate(workspace_root=tmp_path, session_id="test_sess")
    assert meta.workflow_scan_id.startswith("scan_")
    assert meta.session_id == "test_sess"
    assert meta.workspace_root == str(tmp_path.resolve())
    assert meta.timestamp != ""
    assert "T" in meta.timestamp  # ISO-8601 format check

    d = meta.to_dict()
    assert d["workflow_scan_id"] == meta.workflow_scan_id
    assert d["workspace_root"] == str(tmp_path.resolve())


# ---------------------------------------------------------------------------
# CapacityLimits Tests
# ---------------------------------------------------------------------------

def test_capacity_limits_defaults() -> None:
    limits = CapacityLimits()
    assert limits.max_files == 50
    assert limits.max_single_file_kb == 256
    assert limits.max_aggregate_mb == 2.0
    assert limits.max_line_length == 1000

    d = limits.to_dict()
    assert d["max_files"] == 50
    assert d["max_single_file_kb"] == 256


def test_capacity_limits_immutability() -> None:
    limits = CapacityLimits()
    with pytest.raises(FrozenInstanceError):
        limits.max_files = 100  # type: ignore[misc]


# ---------------------------------------------------------------------------
# InformativeNotice Tests
# ---------------------------------------------------------------------------

def test_informative_notice_serialization() -> None:
    notice = InformativeNotice(
        level=NoticeLevel.WARNING,
        code="HIGH_COMPUTING_CONSUMPTION_LOCKFILE",
        message="Lockfile warning",
        file="package-lock.json",
        size_kb=512.4,
        suggested_action="Run scan_dependencies.sh",
    )
    d = notice.to_dict()
    assert d["level"] == "WARNING"
    assert d["code"] == "HIGH_COMPUTING_CONSUMPTION_LOCKFILE"
    assert d["file"] == "package-lock.json"
    assert d["size_kb"] == 512.4
    assert d["suggested_action"] == "Run scan_dependencies.sh"


def test_informative_notice_optional_fields() -> None:
    notice = InformativeNotice(
        level=NoticeLevel.INFO,
        code="GENERAL_INFO",
        message="Info only",
    )
    d = notice.to_dict()
    assert d["level"] == "INFO"
    assert "file" not in d
    assert "size_kb" not in d


# ---------------------------------------------------------------------------
# DiscoveryReport & HookResult Tests
# ---------------------------------------------------------------------------

def test_discovery_report_to_dict(tmp_path: Path) -> None:
    meta = WorkflowScanMetadata.generate(workspace_root=tmp_path)
    notice = InformativeNotice(level=NoticeLevel.INFO, code="TEST", message="msg")
    oversized = OversizedFile(path="big.sql", size_bytes=300000, size_kb=292.97)

    report = DiscoveryReport(
        workflow_metadata=meta,
        project_archetype="Node.js (AI Agent Managed)",
        files_to_scan=["src/index.js"],
        total_files_enumerated=20,
        excluded_files_count=10,
        total_scan_bytes=1024,
        total_scan_kb=1.0,
        notices=[notice],
        oversized_files=[oversized],
    )
    d = report.to_dict()
    assert d["workflow_scan_id"] == meta.workflow_scan_id
    assert d["project_archetype"] == "Node.js (AI Agent Managed)"
    assert d["files_to_scan_count"] == 1
    assert len(d["notices"]) == 1
    assert len(d["oversized_files"]) == 1


def test_hook_result_json_serialization(tmp_path: Path) -> None:
    meta = WorkflowScanMetadata.generate(workspace_root=tmp_path)
    result = HookResult(
        decision=Decision.ALLOW,
        reason="Test approval",
        workflow_metadata=meta,
    )
    json_str = result.to_json_str()
    data = json.loads(json_str)
    assert data["decision"] == "allow"
    assert data["reason"] == "Test approval"
    assert "workflow_metadata" in data


# ---------------------------------------------------------------------------
# HookContext & Stdin Parsing Tests
# ---------------------------------------------------------------------------

def test_hook_context_target_file_resolution() -> None:
    ctx1 = HookContext(tool_call=ToolCall(name="view_file", args={"AbsolutePath": "/a/b.py"}))
    assert ctx1.target_file == "/a/b.py"

    ctx2 = HookContext(tool_call=ToolCall(name="read_file", args={"TargetFile": "/c/d.py"}))
    assert ctx2.target_file == "/c/d.py"

    ctx3 = HookContext(tool_call=ToolCall(name="grep_search", args={"SearchPath": "/e/f"}))
    assert ctx3.target_file == "/e/f"


def test_parse_stdin_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    ctx = parse_stdin()
    assert ctx.tool_call.name == ""


def test_parse_stdin_invalid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("{malformed json"))
    ctx = parse_stdin()
    assert ctx.tool_call.name == ""


def test_parse_stdin_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "toolCall": {"name": "view_file", "args": {"AbsolutePath": "/test.py"}},
        "conversationId": "sess_1",
        "workspacePaths": ["/workspace"],
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    ctx = parse_stdin()
    assert ctx.tool_call.name == "view_file"
    assert ctx.target_file == "/test.py"
    assert ctx.conversation_id == "sess_1"


# ---------------------------------------------------------------------------
# Protocol Emitter Tests
# ---------------------------------------------------------------------------

def test_emit_response_and_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    output = io.StringIO()
    monkeypatch.setattr(sys, "stdout", output)

    with pytest.raises(SystemExit) as exc:
        emit_allow(reason="Allowed scan")
    assert exc.value.code == 0
    data = json.loads(output.getvalue().strip())
    assert data["decision"] == "allow"
    assert data["reason"] == "Allowed scan"


def test_emit_deny(monkeypatch: pytest.MonkeyPatch) -> None:
    output = io.StringIO()
    monkeypatch.setattr(sys, "stdout", output)

    with pytest.raises(SystemExit) as exc:
        emit_deny(reason="Blocked scan")
    assert exc.value.code == 0
    data = json.loads(output.getvalue().strip())
    assert data["decision"] == "deny"


def test_emit_ask(monkeypatch: pytest.MonkeyPatch) -> None:
    output = io.StringIO()
    monkeypatch.setattr(sys, "stdout", output)

    with pytest.raises(SystemExit) as exc:
        emit_ask(reason="Confirmation required")
    assert exc.value.code == 0
    data = json.loads(output.getvalue().strip())
    assert data["decision"] == "ask"
