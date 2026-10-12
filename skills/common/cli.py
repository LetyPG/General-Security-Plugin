"""
Unified CLI Argument Parser for Deterministic Skill Scripts.

Handles positional inputs, option flags, and dynamic ${ARGUMENTS} variable expansions.
"""
from __future__ import annotations

import argparse
import shlex
import sys
from collections.abc import Sequence
from pathlib import Path


def parse_args(
    prog_name: str,
    description: str,
    args: Sequence[str] | None = None,
) -> argparse.Namespace:
    """
    Parses CLI arguments with support for positional project root and ${ARGUMENTS}.

    Handles edge cases where an agent shell expansion passes:
      - Empty string: `python3 script.py ""`
      - Combined argument string: `python3 script.py "my_project --json"`
    """
    raw_args = list(sys.argv[1:] if args is None else args)

    # Normalize if a single quoted argument containing whitespace was passed (e.g., "${ARGUMENTS}")
    if len(raw_args) == 1 and (" " in raw_args[0] or "\t" in raw_args[0]):
        try:
            raw_args = shlex.split(raw_args[0])
        except ValueError:
            pass

    parser = argparse.ArgumentParser(
        prog=prog_name,
        description=description,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "project_root",
        nargs="?",
        default=".",
        help="Path to project root directory to scan (defaults to current working directory).",
    )
    parser.add_argument(
        "--target",
        "-t",
        nargs="*",
        default=[],
        help="Specific files or subdirectories to restrict scanning to (e.g., for Option A).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output findings as a structured JSON array to stdout.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI terminal color output.",
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=100,
        help="Maximum number of findings to report.",
    )

    parsed = parser.parse_args(raw_args)

    # Clean empty string project_root
    if not parsed.project_root or parsed.project_root.strip() == "":
        parsed.project_root = "."

    # Resolve project root path
    parsed.project_root = Path(parsed.project_root).resolve()

    return parsed
