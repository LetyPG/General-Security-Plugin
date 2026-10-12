"""
Hook Contract & Data Protocol
Defines the typed contract between the Agent Runtime PreToolUse lifecycle
and the general-security-plugin deterministic discovery and capacity gate engine.
Define canonical workflow metadata with unique id
"""
from __future__ import annotations

import datetime
import json
import sys
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Decision(str, Enum):
    """PreToolUse gate decision outcomes."""
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


class NoticeLevel(str, Enum):
    """Severity level of informative notices."""
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass
class WorkflowScanMetadata:
    workflow_scan_id: str
    timestamp: str  # ISO-8601 UTC string
    workspace_root: str
    session_id: str = ""

    @classmethod
    def generate(cls, workspace_root: str | Path, session_id: str = "") -> WorkflowScanMetadata:
        """Factory generating a unique workflow scan identifier with UTC timestamp."""
        now = datetime.datetime.now(datetime.timezone.utc)
        timestamp_iso = now.isoformat()
        timestamp_slug = now.strftime("%Y%m%d_%H%M%S")
        short_id = uuid.uuid4().hex[:8]
        scan_id = f"scan_{timestamp_slug}_{short_id}"
        return cls(
            workflow_scan_id=scan_id,
            timestamp=timestamp_iso,
            workspace_root=str(Path(workspace_root).resolve()),
            session_id=session_id or short_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InformativeNotice:
    """Non-blocking informative notification for users and agent context."""
    level: NoticeLevel
    code: str
    message: str
    file: str | None = None
    size_kb: float | None = None
    suggested_action: str = ""

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "level": self.level.value if isinstance(self.level, NoticeLevel) else str(self.level),
            "code": self.code,
            "message": self.message,
        }
        if self.file is not None:
            data["file"] = self.file
        if self.size_kb is not None:
            data["size_kb"] = self.size_kb
        if self.suggested_action:
            data["suggested_action"] = self.suggested_action
        return data


@dataclass(frozen=True)
class CapacityLimits:
    """Deterministic 5-dimensional computing boundaries."""
    max_files: int = 50
    max_single_file_kb: int = 256
    max_aggregate_mb: float = 2.0
    max_line_length: int = 1000

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class OversizedFile:
    """Metadata for files exceeding single-file threshold (> 256 KB)."""
    path: str
    size_bytes: int
    size_kb: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DiscoveryReport:
    """Canonical discovery and project sizing report."""
    workflow_metadata: WorkflowScanMetadata
    project_archetype: str
    files_to_scan: list[str]
    total_files_enumerated: int
    excluded_files_count: int
    total_scan_bytes: int
    total_scan_kb: float
    capacity_limits: CapacityLimits = field(default_factory=CapacityLimits)
    notices: list[InformativeNotice] = field(default_factory=list)
    oversized_files: list[OversizedFile] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "workflow_scan_id": self.workflow_metadata.workflow_scan_id,
            "timestamp": self.workflow_metadata.timestamp,
            "workspace_root": self.workflow_metadata.workspace_root,
            "project_archetype": self.project_archetype,
            "files_to_scan_count": len(self.files_to_scan),
            "files_to_scan": self.files_to_scan,
            "total_files_enumerated": self.total_files_enumerated,
            "excluded_files_count": self.excluded_files_count,
            "total_scan_bytes": self.total_scan_bytes,
            "total_scan_kb": self.total_scan_kb,
            "capacity_limits": self.capacity_limits.to_dict(),
            "notices": [n.to_dict() for n in self.notices],
            "oversized_files": [f.to_dict() for f in self.oversized_files],
        }


@dataclass
class ToolCall:
    """Normalized tool call payload extracted from agent PreToolUse event."""
    name: str
    args: dict[str, Any] = field(default_factory=dict)


@dataclass
class HookContext:
    """Input payload delivered to the hook via stdin by the Agent runtime."""
    tool_call: ToolCall
    step_idx: int = 0
    conversation_id: str = ""
    workspace_paths: list[str] = field(default_factory=list)
    transcript_path: str = ""
    artifact_directory_path: str = ""
    model_name: str = ""
    raw_payload: dict[str, Any] = field(default_factory=dict)

    @property
    def target_file(self) -> str | None:
        """Resolves target file path from common tool argument keys."""
        args = self.tool_call.args
        return (
            args.get("AbsolutePath")
            or args.get("TargetFile")
            or args.get("file_path")
            or args.get("FilePath")
            or args.get("SearchPath")
            or args.get("DirectoryPath")
        )

    @property
    def primary_workspace(self) -> Path:
        """Returns primary workspace root as absolute Path."""
        if self.workspace_paths:
            return Path(self.workspace_paths[0]).resolve()
        return Path.cwd().resolve()


@dataclass
class HookResult:
    """Standardized hook output payload emitted to stdout."""
    decision: Decision
    reason: str = ""
    workflow_metadata: WorkflowScanMetadata | None = None
    discovery_report: DiscoveryReport | None = None
    notices: list[InformativeNotice] = field(default_factory=list)
    permission_overrides: list[str] = field(default_factory=list)

    def to_json_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "decision": self.decision.value,
        }
        if self.reason:
            payload["reason"] = self.reason
        if self.workflow_metadata:
            payload["workflow_metadata"] = self.workflow_metadata.to_dict()
        if self.notices:
            payload["notices"] = [n.to_dict() for n in self.notices]
        if self.permission_overrides:
            payload["permissionOverrides"] = self.permission_overrides
        if self.discovery_report:
            payload["discoveryReport"] = self.discovery_report.to_dict()
        return payload

    def to_json_str(self) -> str:
        return json.dumps(self.to_json_dict(), indent=2)


# ---------------------------------------------------------------------------
# Protocol I/O Helpers
# ---------------------------------------------------------------------------

def parse_stdin() -> HookContext:
    """
    Parses JSON payload delivered on stdin from Agent runtime.
    Fail-closed safe: returns empty context on EOF, unparseable JSON, or IO errors.
    """
    try:
        raw_text = sys.stdin.read()
        if not raw_text.strip():
            return HookContext(tool_call=ToolCall(name=""))
        data = json.loads(raw_text)
        if not isinstance(data, dict):
            return HookContext(tool_call=ToolCall(name=""))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return HookContext(tool_call=ToolCall(name=""))

    raw_tool = data.get("toolCall", {})
    tool_call = ToolCall(
        name=raw_tool.get("name", ""),
        args=raw_tool.get("args", {})
    )

    return HookContext(
        tool_call=tool_call,
        step_idx=data.get("stepIdx", 0),
        conversation_id=data.get("conversationId", ""),
        workspace_paths=data.get("workspacePaths", []),
        transcript_path=data.get("transcriptPath", ""),
        artifact_directory_path=data.get("artifactDirectoryPath", ""),
        model_name=data.get("modelName", ""),
        raw_payload=data,
    )


def emit_response(result: HookResult, exit_code: int = 0) -> None:
    """Emits the HookResult JSON to stdout and exits with exit_code (0 by convention)."""
    sys.stdout.write(result.to_json_str() + "\n")
    sys.stdout.flush()
    sys.exit(exit_code)


def emit_allow(
    reason: str = "",
    metadata: WorkflowScanMetadata | None = None,
    report: DiscoveryReport | None = None,
    notices: list[InformativeNotice] | None = None,
) -> None:
    """Convenience emitter for Decision.ALLOW."""
    emit_response(
        HookResult(
            decision=Decision.ALLOW,
            reason=reason,
            workflow_metadata=metadata,
            discovery_report=report,
            notices=notices or [],
        )
    )


def emit_deny(
    reason: str,
    metadata: WorkflowScanMetadata | None = None,
    report: DiscoveryReport | None = None,
    notices: list[InformativeNotice] | None = None,
) -> None:
    """Convenience emitter for Decision.DENY."""
    emit_response(
        HookResult(
            decision=Decision.DENY,
            reason=reason,
            workflow_metadata=metadata,
            discovery_report=report,
            notices=notices or [],
        )
    )


def emit_ask(
    reason: str,
    metadata: WorkflowScanMetadata | None = None,
    report: DiscoveryReport | None = None,
    notices: list[InformativeNotice] | None = None,
) -> None:
    """Convenience emitter for Decision.ASK."""
    emit_response(
        HookResult(
            decision=Decision.ASK,
            reason=reason,
            workflow_metadata=metadata,
            discovery_report=report,
            notices=notices or [],
        )
    )
