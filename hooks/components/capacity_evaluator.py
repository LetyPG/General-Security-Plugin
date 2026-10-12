"""
Capacity Evaluator & Non-Blocking Exception Handler Component
Evaluates candidate files against 5-dimensional computing boundaries:
  1. MAX_FILES_TO_SCAN = 50
  2. MAX_SINGLE_FILE_SIZE_KB = 256 KB
  3. MAX_AGGREGATE_SCAN_SIZE_MB = 2.0 MB
  4. MAX_LINE_LENGTH = 1000 characters
  5. Sub-50ms deterministic execution, standard library only.

Specialized Lockfile Handling:
Heavy dependency lockfiles (package-lock.json, yarn.lock, poetry.lock, etc.)
do NOT block scans (decision = Decision.ALLOW). Instead, they attach structured
InformativeNotice warnings advising on computing consumption (> 2.0 MB) and
recommending host script execution (scan_dependencies.py).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

try:
    from hooks.hook_contract import (
        CapacityLimits,
        Decision,
        InformativeNotice,
        NoticeLevel,
        OversizedFile,
    )
except ImportError:
    from hook_contract import (
        CapacityLimits,
        Decision,
        InformativeNotice,
        NoticeLevel,
        OversizedFile,
    )



@dataclass
class CapacityEvaluationResult:
    """Outcome of 5-dimensional computing capacity assessment."""
    decision: Decision
    reason: str
    eligible_files: list[Path]
    total_bytes: int
    total_kb: float
    oversized_files: list[OversizedFile] = field(default_factory=list)
    notices: list[InformativeNotice] = field(default_factory=list)
    line_length_warnings: list[str] = field(default_factory=list)
    status: str = "APPROVED"

    @property
    def has_notices(self) -> bool:
        return len(self.notices) > 0


class CapacityEvaluator:
    """Evaluates candidate files against computing capacity boundaries with non-blocking guidance."""

    # Known lockfiles that require informative non-blocking guidance (Skill 4)
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

    def __init__(self, limits: CapacityLimits | None = None) -> None:
        self.limits = limits if limits is not None else CapacityLimits()

    def is_lockfile(self, file_path: Path | str) -> bool:
        """Determines if a path corresponds to a known dependency lockfile."""
        name = Path(file_path).name.lower()
        return name in self.KNOWN_LOCKFILES

    def check_line_lengths(self, file_path: Path, max_length: int | None = None) -> tuple[bool, int]:
        """
        Samples first 500 lines to detect minified files or long data blobs.
        Returns: (has_excessive_lines, max_detected_length)
        """
        threshold = max_length if max_length is not None else self.limits.max_line_length
        max_seen = 0
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for idx, line in enumerate(f):
                    line_len = len(line)
                    max_seen = max(max_seen, line_len)
                    if line_len > threshold:
                        return True, line_len
                    if idx >= 500:  # Sample first 500 lines for efficiency
                        break
        except OSError:
            pass
        return False, max_seen

    def build_lockfile_notice(self, file_path: Path | str, size_bytes: int) -> InformativeNotice:
        """Builds an informative, non-blocking notice for heavy dependency lockfiles."""
        fname = Path(file_path).name
        size_kb = round(size_bytes / 1024, 2)
        return InformativeNotice(
            level=NoticeLevel.WARNING,
            code="HIGH_COMPUTING_CONSUMPTION_LOCKFILE",
            file=fname,
            size_kb=size_kb,
            message=(
                f"Detected dependency lockfile: `{fname}` ({size_kb} KB). "
                f"Ingesting full lockfiles into LLM context will provoke high computing "
                f"consumption exceeding the {self.limits.max_aggregate_mb} MB guideline."
            ),
            suggested_action=(
                "Recommended: Run host script `python3 skills/audit-supply-chain-risk/scripts/scan_dependencies.py .` "
                "for deterministic dependency analysis without token overhead."
            ),
        )

    def evaluate(
        self,
        candidate_files: list[Path],
        oversized_files: list[OversizedFile] | None = None,
        raw_candidate_count: int | None = None,
    ) -> CapacityEvaluationResult:
        """
        Executes 5D boundary checks across candidate files.
        Guarantees non-blocking execution (decision = Decision.ALLOW) while generating
        structured informative notices for lockfiles, oversized assets, and volume limits.
        """
        oversized = list(oversized_files) if oversized_files is not None else []
        effective_raw_count = raw_candidate_count if raw_candidate_count is not None else len(candidate_files)

        total_bytes = 0
        validated_files: list[Path] = []
        notices: list[InformativeNotice] = []
        line_warnings: list[str] = []

        max_aggregate_bytes = int(self.limits.max_aggregate_mb * 1024 * 1024)

        # 1. Inspect candidate files
        for f in candidate_files:
            try:
                stat_info = f.stat()
                f_size = stat_info.st_size
            except OSError:
                continue

            total_bytes += f_size
            validated_files.append(f)

            # Check Lockfile Exception
            if self.is_lockfile(f):
                notices.append(self.build_lockfile_notice(f, f_size))

            # Check Line Length Gate (first 500 lines)
            has_long_lines, max_len = self.check_line_lengths(f, self.limits.max_line_length)
            if has_long_lines:
                warning_msg = (
                    f"{f.name}: line length {max_len} exceeds "
                    f"{self.limits.max_line_length} chars (potential minified asset)"
                )
                line_warnings.append(warning_msg)
                notices.append(
                    InformativeNotice(
                        level=NoticeLevel.INFO,
                        code="EXCESSIVE_LINE_LENGTH",
                        file=f.name,
                        size_kb=round(f_size / 1024, 2),
                        message=warning_msg,
                        suggested_action="Review file content or exclude minified bundle if not source code.",
                    )
                )

        total_kb = round(total_bytes / 1024, 2)

        # 2. Informative check: Aggregate Size (> 2.0 MB)
        if total_bytes > max_aggregate_bytes:
            notices.append(
                InformativeNotice(
                    level=NoticeLevel.WARNING,
                    code="AGGREGATE_SIZE_EXCEEDED",
                    size_kb=total_kb,
                    message=(
                        f"Aggregate scan volume ({total_kb} KB) exceeds guideline "
                        f"MAX_AGGREGATE_MB ({self.limits.max_aggregate_mb} MB)."
                    ),
                    suggested_action=(
                        "Proceeding with scan. Consider auditing prioritized files first "
                        "or running targeted skill scripts to optimize token consumption."
                    ),
                )
            )

        # 3. Informative check: Candidate Count Limit (MAX_FILES = 50)
        if effective_raw_count > self.limits.max_files:
            notices.append(
                InformativeNotice(
                    level=NoticeLevel.INFO,
                    code="CANDIDATE_COUNT_EXCEEDED",
                    message=(
                        f"Discovered {effective_raw_count} eligible candidates, exceeding "
                        f"MAX_FILES ({self.limits.max_files}). Prioritized top "
                        f"{len(validated_files)} security-critical files."
                    ),
                    suggested_action="Audit prioritized files first; run targeted sub-skills for secondary paths.",
                )
            )

        # 4. Informative check: Excluded oversized files
        for ov in oversized:
            if not self.is_lockfile(ov.path):
                notices.append(
                    InformativeNotice(
                        level=NoticeLevel.INFO,
                        code="OVERSIZED_FILE_EXCLUDED",
                        file=ov.path,
                        size_kb=ov.size_kb,
                        message=(
                            f"File {ov.path} ({ov.size_kb} KB) exceeds single-file limit "
                            f"({self.limits.max_single_file_kb} KB) and was excluded."
                        ),
                        suggested_action="Inspect file manually or run dedicated CLI scanner.",
                    )
                )

        # Non-blocking guardrail invariant: decision is ALWAYS ALLOW for lockfiles and guidance
        status = "NOTICES_GENERATED" if notices else "APPROVED"
        reason = (
            f"Within computing bounds with {len(notices)} informative notice(s)."
            if notices
            else "Within all 5-dimensional computing bounds."
        )

        return CapacityEvaluationResult(
            decision=Decision.ALLOW,
            reason=reason,
            eligible_files=validated_files,
            total_bytes=total_bytes,
            total_kb=total_kb,
            oversized_files=oversized,
            notices=notices,
            line_length_warnings=line_warnings,
            status=status,
        )

    def evaluate_file(
        self,
        file_path: Path | str,
        current_cumulative_bytes: int = 0,
    ) -> tuple[Decision, list[InformativeNotice]]:
        """
        Single-file gate check for PreToolUse interceptors (view_file / read_file).
        Returns: (Decision.ALLOW, notices)
        """
        path = Path(file_path)
        notices: list[InformativeNotice] = []

        try:
            stat_info = path.stat()
            file_size = stat_info.st_size
        except OSError:
            return Decision.ALLOW, notices

        # Lockfile handling: non-blocking informative guidance
        if self.is_lockfile(path):
            notices.append(self.build_lockfile_notice(path, file_size))

        # Single-file size threshold check (> 256 KB)
        max_single_bytes = self.limits.max_single_file_kb * 1024
        if file_size > max_single_bytes and not self.is_lockfile(path):
            notices.append(
                InformativeNotice(
                    level=NoticeLevel.WARNING,
                    code="SINGLE_FILE_SIZE_EXCEEDED",
                    file=path.name,
                    size_kb=round(file_size / 1024, 2),
                    message=(
                        f"File `{path.name}` ({round(file_size / 1024, 2)} KB) exceeds "
                        f"MAX_SINGLE_FILE_KB ({self.limits.max_single_file_kb} KB)."
                    ),
                    suggested_action="Read file in smaller slices or run deterministic CLI search.",
                )
            )

        # Cumulative volume check
        max_aggregate_bytes = int(self.limits.max_aggregate_mb * 1024 * 1024)
        if (current_cumulative_bytes + file_size) > max_aggregate_bytes:
            notices.append(
                InformativeNotice(
                    level=NoticeLevel.WARNING,
                    code="AGGREGATE_SIZE_EXCEEDED",
                    file=path.name,
                    size_kb=round((current_cumulative_bytes + file_size) / 1024, 2),
                    message=(
                        f"Cumulative volume will exceed MAX_AGGREGATE_MB "
                        f"({self.limits.max_aggregate_mb} MB) with `{path.name}`."
                    ),
                    suggested_action="Target specific sections using line ranges or offset parameters.",
                )
            )

        # Line length check
        has_long, max_len = self.check_line_lengths(path, self.limits.max_line_length)
        if has_long:
            notices.append(
                InformativeNotice(
                    level=NoticeLevel.INFO,
                    code="EXCESSIVE_LINE_LENGTH",
                    file=path.name,
                    size_kb=round(file_size / 1024, 2),
                    message=f"`{path.name}` contains lines with {max_len} chars exceeding {self.limits.max_line_length}.",
                    suggested_action="Verify if file is minified before processing.",
                )
            )

        return Decision.ALLOW, notices
