"""
Unit tests for hooks/components/capacity_evaluator.py
Validates 5D computing capacity evaluation and non-blocking lockfile handling.
"""
from __future__ import annotations

from pathlib import Path

from hooks.components.capacity_evaluator import (
    CapacityEvaluationResult,
    CapacityEvaluator,
)
from hooks.hook_contract import (
    CapacityLimits,
    Decision,
    NoticeLevel,
    OversizedFile,
)


def test_is_lockfile() -> None:
    evaluator = CapacityEvaluator()
    assert evaluator.is_lockfile("package-lock.json")
    assert evaluator.is_lockfile("yarn.lock")
    assert evaluator.is_lockfile("poetry.lock")
    assert evaluator.is_lockfile("Cargo.lock")
    assert not evaluator.is_lockfile("package.json")
    assert not evaluator.is_lockfile("main.py")


def test_check_line_lengths(tmp_path: Path) -> None:
    evaluator = CapacityEvaluator()

    normal_file = tmp_path / "normal.py"
    normal_file.write_text("print('line 1')\nprint('line 2')\n")
    has_long, max_len = evaluator.check_line_lengths(normal_file, max_length=1000)
    assert not has_long
    assert max_len < 1000

    long_file = tmp_path / "long.js"
    long_file.write_text("var min = \"" + "a" * 1200 + "\";\n")
    has_long_2, max_len_2 = evaluator.check_line_lengths(long_file, max_length=1000)
    assert has_long_2
    assert max_len_2 > 1000


def test_lockfile_handling_is_non_blocking_with_notice(tmp_path: Path) -> None:
    evaluator = CapacityEvaluator()
    p_lock = tmp_path / "package-lock.json"
    p_lock.write_text('{\n  "name": "pkg",\n  "version": "1.0.0"\n}\n')

    res = evaluator.evaluate([p_lock])

    # Invariant: scan must NEVER be blocked by lockfiles
    assert res.decision == Decision.ALLOW
    assert isinstance(res, CapacityEvaluationResult)
    assert res.status == "NOTICES_GENERATED"

    lock_notices = [n for n in res.notices if n.code == "HIGH_COMPUTING_CONSUMPTION_LOCKFILE"]
    assert len(lock_notices) == 1
    notice = lock_notices[0]
    assert notice.level == NoticeLevel.WARNING
    assert "package-lock.json" in notice.message
    assert "scan_dependencies.py" in notice.suggested_action


def test_candidate_count_exceeded_notice(tmp_path: Path) -> None:
    evaluator = CapacityEvaluator(limits=CapacityLimits(max_files=5))
    dummy_files = []
    for i in range(5):
        f = tmp_path / f"f_{i}.py"
        f.write_text("x = 1\n")
        dummy_files.append(f)

    res = evaluator.evaluate(dummy_files, raw_candidate_count=25)
    assert res.decision == Decision.ALLOW
    count_notices = [n for n in res.notices if n.code == "CANDIDATE_COUNT_EXCEEDED"]
    assert len(count_notices) == 1
    assert "Discovered 25 eligible candidates" in count_notices[0].message


def test_oversized_files_notice(tmp_path: Path) -> None:
    evaluator = CapacityEvaluator()
    f = tmp_path / "app.py"
    f.write_text("x = 1\n")

    oversized = [OversizedFile(path="data.dump", size_bytes=300000, size_kb=292.97)]
    res = evaluator.evaluate([f], oversized_files=oversized)

    assert res.decision == Decision.ALLOW
    over_notices = [n for n in res.notices if n.code == "OVERSIZED_FILE_EXCLUDED"]
    assert len(over_notices) == 1
    assert "data.dump" in over_notices[0].message


def test_single_file_evaluate_helper(tmp_path: Path) -> None:
    evaluator = CapacityEvaluator(limits=CapacityLimits(max_single_file_kb=10, max_aggregate_mb=0.05))

    # 1. Normal file
    normal = tmp_path / "small.py"
    normal.write_text("print(1)\n")
    dec, notices = evaluator.evaluate_file(normal)
    assert dec == Decision.ALLOW
    assert len(notices) == 0

    # 2. Lockfile
    lock = tmp_path / "yarn.lock"
    lock.write_text("# yarn lock\n")
    dec, notices_lock = evaluator.evaluate_file(lock)
    assert dec == Decision.ALLOW
    assert any(n.code == "HIGH_COMPUTING_CONSUMPTION_LOCKFILE" for n in notices_lock)

    # 3. Oversized regular file
    big = tmp_path / "big.py"
    big.write_bytes(b"x = 1\n" * 3000)  # > 10 KB
    dec, notices_big = evaluator.evaluate_file(big)
    assert dec == Decision.ALLOW
    assert any(n.code == "SINGLE_FILE_SIZE_EXCEEDED" for n in notices_big)
