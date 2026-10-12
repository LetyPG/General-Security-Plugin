"""
Exclusion Filter Component
Fast, native filesystem traversal and pruning. Filters out heavy dependencies,
build artifacts, caches, and media assets, while preserving security-critical
dot-directories (.agent, .claude, .cursor, .gemini, .husky, CI/CD, .git/hooks)
and lockfiles.
"""
from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import ClassVar

try:
    from hooks.hook_contract import OversizedFile
except ImportError:
    from hook_contract import OversizedFile



class ExclusionFilter:
    """Prunes non-auditable directories and files using native OS traversal."""

    DEFAULT_EXCLUDED_DIRS: ClassVar[set[str]] = {
        # Dependencies
        "node_modules", "vendor", "target", ".venv", "venv", "packages", "Pods",
        "bower_components", "jspm_packages",
        # VCS internal metadata (note: .git is handled specifically to permit .git/hooks)
        ".svn", ".hg", ".bzr",
        # Build & Distribution Outputs
        "dist", "build", "out", "bin", "obj", "_build", "coverage", ".next", ".nuxt",
        # Caches & Temporary Directories
        ".cache", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
        "tmp", "temp", ".idea", ".vscode", ".terraform", ".tox",
    }

    # Security-relevant dot-directories that MUST be preserved
    SECURITY_RELEVANT_DOT_DIRS: ClassVar[set[str]] = {
        ".github",
        ".gitlab",
        ".circleci",
        ".agent",
        ".claude",
        ".cursor",
        ".gemini",
        ".husky",
    }

    # Known lockfiles retained for supply-chain analysis (Skill 4)
    KNOWN_LOCKFILES: ClassVar[set[str]] = {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "cargo.lock",
        "go.sum",
        "composer.lock",
        "gemfile.lock",
    }

    DEFAULT_EXCLUDED_FILE_PATTERNS: ClassVar[list[str]] = [
        # Build & Minified
        "*.min.js", "*.min.css", "*.bundle.js", "*.map", "*.chunk.js",
        # Media & Documents (non-code assets)
        "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.svg", "*.webp",
        "*.pdf", "*.doc", "*.docx", "*.xls", "*.xlsx", "*.ppt", "*.pptx",
        # Archives & Binaries
        "*.zip", "*.tar", "*.tar.gz", "*.tgz", "*.tar.bz2", "*.7z", "*.rar",
        "*.wasm", "*.exe", "*.so", "*.dylib", "*.dll", "*.class", "*.pyc",
        "*.bin", "*.iso", "*.dmg", "*.deb", "*.rpm",
        # Fonts
        "*.woff", "*.woff2", "*.ttf", "*.eot", "*.otf",
        # Database & Raw data dumps
        "*.sqlite", "*.sqlite3", "*.db", "*.parquet", "*.arrow", "*.dump",
        # OS / Editor clutter & default sample hooks
        ".ds_store", "thumbs.db", "*.sample",
    ]

    def __init__(
        self,
        max_single_file_bytes: int = 256 * 1024,  # 256 KB default
        excluded_dirs: set[str] | None = None,
        excluded_patterns: list[str] | None = None,
    ) -> None:
        self.max_single_file_bytes = max_single_file_bytes
        self.excluded_dirs = set(excluded_dirs) if excluded_dirs is not None else set(self.DEFAULT_EXCLUDED_DIRS)
        self.excluded_patterns = [p.lower() for p in (excluded_patterns if excluded_patterns is not None else self.DEFAULT_EXCLUDED_FILE_PATTERNS)]

    def is_file_excluded_by_pattern(self, filename: str) -> bool:
        """Checks if a filename matches exclusion glob patterns (case-insensitive)."""
        lower_name = filename.lower()
        for pattern in self.excluded_patterns:
            if fnmatch.fnmatch(lower_name, pattern):
                return True
        return False

    def is_lockfile(self, filename: str) -> bool:
        """Checks if filename matches any known dependency lockfile (case-insensitive)."""
        return filename.lower() in self.KNOWN_LOCKFILES

    def scan(
        self, workspace_root: str | Path
    ) -> tuple[int, int, list[Path], list[OversizedFile]]:
        """
        Walks workspace root with in-place directory pruning.
        Preserves security dot-directories and dependency lockfiles.

        Returns:
            total_enumerated: Count of all entries discovered
            excluded_count: Count of entries pruned by rules
            eligible_files: Filtered candidate file paths
            oversized_files: List of OversizedFile objects exceeding size threshold
        """
        root_path = Path(workspace_root).resolve()
        if not root_path.exists():
            raise FileNotFoundError(f"Workspace root does not exist: {workspace_root}")
        if not root_path.is_dir():
            raise NotADirectoryError(f"Workspace root is not a directory: {workspace_root}")

        total_enumerated = 0
        excluded_count = 0
        eligible_files: list[Path] = []
        oversized_files: list[OversizedFile] = []

        for current_dir, dirnames, filenames in os.walk(root_path, followlinks=False):
            rel_dir = Path(current_dir).relative_to(root_path)

            # Special handling if current directory is a .git directory
            # (either at root or inside a submodule)
            if rel_dir.name == ".git":
                pruned_git_subdirs: list[str] = []
                for d in list(dirnames):
                    if d != "hooks":
                        pruned_git_subdirs.append(d)
                        dirnames.remove(d)
                excluded_count += len(pruned_git_subdirs)
                # Skip all files directly inside .git root (e.g. HEAD, config)
                excluded_count += len(filenames)
                total_enumerated += len(dirnames) + len(pruned_git_subdirs) + len(filenames)
                continue

            # Standard directory pruning
            pruned_dirs: list[str] = []
            for d in list(dirnames):
                # Preserve .git so we can descend into .git/hooks
                if d == ".git":
                    continue

                # Excluded directory names (node_modules, vendor, dist, etc.)
                if d in self.excluded_dirs:
                    pruned_dirs.append(d)
                    dirnames.remove(d)
                    continue

                # Dot-directories: preserve security-critical allowlist, prune the rest
                if d.startswith(".") and d not in self.SECURITY_RELEVANT_DOT_DIRS:
                    pruned_dirs.append(d)
                    dirnames.remove(d)

            excluded_count += len(pruned_dirs)
            total_enumerated += len(dirnames) + len(pruned_dirs) + len(filenames)

            for fname in filenames:
                file_path = Path(current_dir) / fname

                # Pattern check (binaries, media, minified files)
                if self.is_file_excluded_by_pattern(fname):
                    excluded_count += 1
                    continue

                try:
                    stat_info = file_path.stat()
                    file_size = stat_info.st_size
                except OSError:
                    excluded_count += 1
                    continue

                # Single-file size gate check
                lockfile = self.is_lockfile(fname)
                if file_size > self.max_single_file_bytes:
                    oversized_files.append(
                        OversizedFile(
                            path=str(file_path.relative_to(root_path)),
                            size_bytes=file_size,
                            size_kb=round(file_size / 1024, 2),
                        )
                    )
                    # Non-lockfiles exceeding limit are discarded
                    # Known lockfiles are preserved as candidates for informative notice
                    if not lockfile:
                        excluded_count += 1
                        continue

                eligible_files.append(file_path)

        return total_enumerated, excluded_count, eligible_files, oversized_files
