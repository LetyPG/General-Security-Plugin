"""
Terminal and JSON Reporter Utilities for Skill Scripts.

Renders formatted CLI outputs with severity color-coding and structured JSON streams.
"""
from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from skills.common.schema import Finding

# ANSI Terminal Colors
RED = "\033[0;31m"
YELLOW = "\033[0;33m"
GREEN = "\033[0;32m"
CYAN = "\033[0;36m"
MAGENTA = "\033[0;35m"
BOLD = "\033[1m"
RESET = "\033[0m"


def emit_findings(
    findings: Sequence[Finding],
    as_json: bool = False,
    no_color: bool = False,
    title: str = "Security Scan",
    project_root: str | Path | None = None,
) -> int:
    """
    Emits findings to stdout in either structured JSON or formatted terminal output.

    Returns:
        Total number of detected findings.
    """
    if as_json:
        data = [f.to_dict() for f in findings]
        print(json.dumps(data, indent=2))
        return len(findings)

    # Human-readable CLI formatting
    c_red = "" if no_color else RED
    c_yellow = "" if no_color else YELLOW
    c_green = "" if no_color else GREEN
    c_cyan = "" if no_color else CYAN
    c_bold = "" if no_color else BOLD
    c_reset = "" if no_color else RESET

    print(f"\n{c_bold}=== {title} ==={c_reset}")
    if project_root:
        print(f"Project: {project_root}")
    print(f"Total findings: {len(findings)}\n")

    if not findings:
        print(f"{c_green}✓ No issues detected.{c_reset}\n")
        return 0

    for f in findings:
        sev_color = c_red if f.severity in ("CRITICAL", "HIGH") else c_yellow
        loc = f"{f.file}:{f.line}" if f.line > 0 else f.file
        cwe_str = f" [{f.cwe_id}]" if f.cwe_id else ""

        print(f"  {sev_color}[{f.severity}]{c_reset} {c_bold}{f.category}{cwe_str}{c_reset} | {c_cyan}{loc}{c_reset}")
        print(f"    Pattern: {f.pattern}")
        if f.match:
            print(f"    Match: {f.match}")
        if f.detail:
            print(f"    Detail: {f.detail}")
        print()

    print(f"{c_red if len(findings) > 0 else c_green}Summary: {len(findings)} potential security findings.{c_reset}\n")
    return len(findings)
