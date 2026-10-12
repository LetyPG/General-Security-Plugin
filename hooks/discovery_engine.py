"""
Discovery Engine Orchestrator
Coordinates the 4 discrete discovery components:
  1. ArchetypeDetector: Identifies ecosystems and AI Agent configurations (<10ms).
  2. ExclusionFilter: Fast native filesystem traversal pruning dependencies, build outputs, and binaries.
  3. RiskPrioritizer: Saturated 3-tier semantic classifier balancing candidates across 8 security disciplines.
  4. CapacityEvaluator: Assesses 5D resource boundaries and generates non-blocking lockfile notices.

Generates the canonical DiscoveryReport and HookResult with unique workflow_scan_id and UTC timestamp.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure plugin root is in sys.path when executed directly or via hook runner
_plugin_root = str(Path(__file__).resolve().parent.parent)
if _plugin_root not in sys.path:
    sys.path.insert(0, _plugin_root)

from hooks.components.archetype_detector import ArchetypeDetector
from hooks.components.capacity_evaluator import CapacityEvaluator
from hooks.components.exclusion_filter import ExclusionFilter
from hooks.components.risk_prioritizer import RiskPrioritizer
from hooks.hook_contract import (
    CapacityLimits,
    DiscoveryReport,
    HookResult,
    WorkflowScanMetadata,
)


class DiscoveryEngine:
    """Orchestrates deterministic discovery, risk prioritization, and capacity evaluation."""

    def __init__(
        self,
        workspace_root: str | Path,
        limits: CapacityLimits | None = None,
        workflow_metadata: WorkflowScanMetadata | None = None,
        session_id: str = "",
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.limits = limits if limits is not None else CapacityLimits()
        self.metadata = workflow_metadata or WorkflowScanMetadata.generate(
            self.workspace_root, session_id=session_id
        )

        # Decomposed deterministic components
        self.archetype_detector = ArchetypeDetector(self.workspace_root)
        self.exclusion_filter = ExclusionFilter(
            max_single_file_bytes=self.limits.max_single_file_kb * 1024
        )
        self.risk_prioritizer = RiskPrioritizer()
        self.capacity_evaluator = CapacityEvaluator(limits=self.limits)

    def run_discovery(self) -> tuple[HookResult, DiscoveryReport]:
        """
        Executes the 4-stage discovery pipeline:
          Stage 1: Detect project Archetype & Agent indicators
          Stage 2: Native exclusion traversal & pruning
          Stage 3: Saturated risk prioritization across 8 security disciplines (max 50)
          Stage 4: 5D capacity evaluation & lockfile guidance

        Returns:
          Tuple of (HookResult, DiscoveryReport)
        """
        # Stage 1: Archetype Detection
        project_archetype = self.archetype_detector.detect()

        # Stage 2: Native Exclusion Pruning
        (
            total_enumerated,
            excluded_count,
            eligible_files_raw,
            oversized_files,
        ) = self.exclusion_filter.scan(self.workspace_root)

        # Stage 3: Saturated Risk Prioritization (Max 50 files)
        prioritization = self.risk_prioritizer.prioritize(
            eligible_files_raw, max_allocation=self.limits.max_files
        )
        prioritized_files = prioritization.files

        # Stage 4: 5D Capacity Evaluation & Non-blocking Lockfile Handling
        eval_result = self.capacity_evaluator.evaluate(
            candidate_files=prioritized_files,
            oversized_files=oversized_files,
            raw_candidate_count=len(eligible_files_raw),
        )

        # Normalize file paths to relative strings for output consistency
        relative_files: list[str] = []
        for f in eval_result.eligible_files:
            try:
                relative_files.append(str(f.relative_to(self.workspace_root)))
            except ValueError:
                relative_files.append(str(f))

        # Build Canonical DiscoveryReport
        report = DiscoveryReport(
            workflow_metadata=self.metadata,
            project_archetype=project_archetype,
            files_to_scan=relative_files,
            total_files_enumerated=total_enumerated,
            excluded_files_count=excluded_count,
            total_scan_bytes=eval_result.total_bytes,
            total_scan_kb=eval_result.total_kb,
            capacity_limits=self.limits,
            notices=eval_result.notices,
            oversized_files=oversized_files,
        )

        # Build Standard HookResult
        hook_result = HookResult(
            decision=eval_result.decision,
            reason=eval_result.reason,
            workflow_metadata=self.metadata,
            discovery_report=report,
            notices=eval_result.notices,
        )

        return hook_result, report


def execute_discovery(
    workspace_root: str | Path,
    limits: CapacityLimits | None = None,
    session_id: str = "",
) -> tuple[HookResult, DiscoveryReport]:
    """Convenience functional interface for executing discovery."""
    engine = DiscoveryEngine(
        workspace_root=workspace_root,
        limits=limits,
        session_id=session_id,
    )
    return engine.run_discovery()


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    _res, rep = execute_discovery(target)
    print(json.dumps(rep.to_dict(), indent=2))
