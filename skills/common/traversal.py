"""
Safe Filesystem Traversal Utilities.

Traverses workspaces respecting exclusion lists, maximum file sizes, and security directories.
"""
from __future__ import annotations

import os
from collections.abc import Callable, Iterable
from pathlib import Path

# Standard directories excluded from security scans to avoid dependency/build noise
DEFAULT_EXCLUDED_DIRS: set[str] = {
    ".git",
    "node_modules",
    "vendor",
    "target",
    ".venv",
    "venv",
    "packages",
    "Pods",
    "bower_components",
    "dist",
    "build",
    "out",
    "bin",
    "_build",
    "coverage",
    ".next",
    ".nuxt",
    ".cache",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".terraform",
    ".tox",
    ".idea",
    ".vscode",
}

# Directories that must be scanned even if they start with a dot
SECURITY_RELEVANT_DOT_DIRS: set[str] = {
    ".github",
    ".gitlab",
    ".circleci",
    ".agent",
    ".claude",
    ".cursor",
    ".gemini",
    ".husky",
}


def is_excluded_dir(dir_name: str, parent_rel_path: str = "") -> bool:
    """Checks whether a directory name should be excluded from scanning."""
    # Special exception for .git/hooks if scanning git hooks
    if dir_name == "hooks" and parent_rel_path.endswith(".git"):
        return False

    if dir_name in DEFAULT_EXCLUDED_DIRS:
        return True

    return bool(dir_name.startswith(".") and dir_name not in SECURITY_RELEVANT_DOT_DIRS)


def walk_project_files(
    project_root: str | Path,
    allowed_extensions: set[str] | None = None,
    allowed_filenames: set[str] | None = None,
    custom_filter: Callable[[Path], bool] | None = None,
    max_file_size_kb: int = 512,
    target_paths: Iterable[str | Path] | None = None,
) -> list[Path]:
    """
    Safely traverses the project directory and returns eligible files for scanning.

    Args:
        project_root: Base project root directory.
        allowed_extensions: Optional set of lowercase file extensions (e.g. {'.py', '.ts'}).
        allowed_filenames: Optional set of exact lowercase filenames (e.g. {'dockerfile', 'package.json'}).
        custom_filter: Optional predicate returning True if file should be included.
        max_file_size_kb: Maximum single file size in KB (skips oversized files).
        target_paths: Optional list of explicit paths/files to restrict scope (for Option A).

    Returns:
        List of resolved Path objects eligible for analysis.
    """
    root = Path(project_root).resolve()
    if not root.exists():
        return []

    # If explicit target paths are specified, evaluate them directly
    if target_paths:
        explicit_files: list[Path] = []
        for tp in target_paths:
            path_obj = Path(tp)
            if not path_obj.is_absolute():
                path_obj = (root / path_obj).resolve()
            if path_obj.is_file() and path_obj.exists():
                explicit_files.append(path_obj)
            elif path_obj.is_dir() and path_obj.exists():
                # Recursively walk the subfolder
                explicit_files.extend(
                    walk_project_files(
                        path_obj,
                        allowed_extensions=allowed_extensions,
                        allowed_filenames=allowed_filenames,
                        custom_filter=custom_filter,
                        max_file_size_kb=max_file_size_kb,
                    )
                )
        return explicit_files

    eligible: list[Path] = []
    max_bytes = max_file_size_kb * 1024

    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)

        # In-place prune of excluded directories
        dirnames[:] = [
            d for d in dirnames if not is_excluded_dir(d, parent_rel_path=rel_dir)
        ]

        for fname in filenames:
            fname_lower = fname.lower()
            file_path = Path(dirpath) / fname

            # Check filename filter
            matched_name = allowed_filenames and (
                fname_lower in allowed_filenames
                or any(fname_lower.startswith(af) for af in allowed_filenames)
            )

            # Check extension filter
            matched_ext = allowed_extensions and (
                file_path.suffix.lower() in allowed_extensions
            )

            if (allowed_filenames or allowed_extensions) and not (matched_name or matched_ext):
                continue

            if custom_filter and not custom_filter(file_path):
                continue

            # Size guardrail
            try:
                if file_path.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue

            eligible.append(file_path)

    return eligible
