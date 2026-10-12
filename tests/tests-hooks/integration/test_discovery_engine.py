"""
Integration tests for hooks/discovery_engine.py
Validates end-to-end discovery orchestration across all components.
"""
from __future__ import annotations

import json
from pathlib import Path

from hooks.discovery_engine import DiscoveryEngine, execute_discovery
from hooks.hook_contract import Decision, DiscoveryReport, HookResult


def test_discovery_engine_run(mock_workspace: Path) -> None:
    engine = DiscoveryEngine(workspace_root=mock_workspace, session_id="test_sess")
    result, report = engine.run_discovery()

    # Validate HookResult
    assert isinstance(result, HookResult)
    assert result.decision == Decision.ALLOW
    assert result.workflow_metadata is not None
    assert result.workflow_metadata.workflow_scan_id.startswith("scan_")

    # Validate DiscoveryReport
    assert isinstance(report, DiscoveryReport)
    assert report.total_files_enumerated > 0
    assert report.excluded_files_count > 0
    assert "Node.js (AI Agent Managed)" in report.project_archetype or "Polyglot" in report.project_archetype

    # Validate that pruned files were NOT included
    assert not any("node_modules" in f for f in report.files_to_scan)
    assert not any("dist" in f for f in report.files_to_scan)
    assert not any(".venv" in f for f in report.files_to_scan)

    # Validate that security files WERE included
    assert any("AGENTS.md" in f for f in report.files_to_scan)
    assert any(".env" in f for f in report.files_to_scan)
    assert any("auth_service.py" in f for f in report.files_to_scan)

    # Validate that lockfiles were included with notice
    assert any("package-lock.json" in f for f in report.files_to_scan)
    assert any(n.code == "HIGH_COMPUTING_CONSUMPTION_LOCKFILE" for n in report.notices)

    # Validate JSON serializability
    d = report.to_dict()
    assert json.dumps(d)


def test_execute_discovery_convenience_function(mock_workspace: Path) -> None:
    result, report = execute_discovery(workspace_root=mock_workspace)
    assert result.decision == Decision.ALLOW
    assert len(report.files_to_scan) > 0
