"""
Skills Shared Infrastructure Package (`skills.common`).

ARCHITECTURAL GUIDANCE:
-----------------------
This package provides shared data contracts, parsing, traversal, masking, and reporting
utilities for the deterministic Python scanning scripts across all skills.

Notice:
- This directory is an internal supporting library, NOT an autonomous AI agent skill.
- It intentionally omits a `SKILL.md` file to prevent agent skill registries and discovery
  engines from misidentifying it as an LLM skill prompt.
- It enforces DRY, SOLID, and KISS principles across all deterministic skill components
  without altering the general plugin architecture.
"""
from __future__ import annotations

from skills.common.cli import parse_args
from skills.common.masking import is_placeholder, mask_secret
from skills.common.reporter import emit_findings
from skills.common.schema import Finding, Severity
from skills.common.traversal import walk_project_files

__all__ = [
    "Finding",
    "Severity",
    "emit_findings",
    "is_placeholder",
    "mask_secret",
    "parse_args",
    "walk_project_files",
]
