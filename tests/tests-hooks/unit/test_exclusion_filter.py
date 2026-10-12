"""
Unit tests for hooks/components/exclusion_filter.py
Validates native traversal pruning, security dot-directory preservation,
lockfile retention, and single-file size bounding.
"""
from __future__ import annotations

from pathlib import Path

from hooks.components.exclusion_filter import ExclusionFilter


def test_is_lockfile() -> None:
    filter_comp = ExclusionFilter()
    assert filter_comp.is_lockfile("package-lock.json")
    assert filter_comp.is_lockfile("yarn.lock")
    assert filter_comp.is_lockfile("poetry.lock")
    assert filter_comp.is_lockfile("Cargo.lock")
    assert not filter_comp.is_lockfile("package.json")
    assert not filter_comp.is_lockfile("main.py")


def test_is_file_excluded_by_pattern() -> None:
    filter_comp = ExclusionFilter()
    assert filter_comp.is_file_excluded_by_pattern("bundle.min.js")
    assert filter_comp.is_file_excluded_by_pattern("styles.min.css")
    assert filter_comp.is_file_excluded_by_pattern("app.bundle.js")
    assert filter_comp.is_file_excluded_by_pattern("logo.png")
    assert filter_comp.is_file_excluded_by_pattern("binary.wasm")
    assert not filter_comp.is_file_excluded_by_pattern("auth.py")
    assert not filter_comp.is_file_excluded_by_pattern(".env")
    assert not filter_comp.is_file_excluded_by_pattern("AGENTS.md")


def test_scan_directory_pruning(tmp_path: Path) -> None:
    # Build directories that must be pruned
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("dep")
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "out.js").write_text("out")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "lib.py").write_text("lib")

    # Build valid files
    (tmp_path / "app.py").write_text("print(1)")

    filter_comp = ExclusionFilter()
    _total_enum, excluded_cnt, eligible, _oversized = filter_comp.scan(tmp_path)

    eligible_names = [f.name for f in eligible]
    assert "app.py" in eligible_names
    assert "dep.js" not in eligible_names
    assert "out.js" not in eligible_names
    assert "lib.py" not in eligible_names
    assert excluded_cnt > 0


def test_scan_preserves_security_dot_directories(tmp_path: Path) -> None:
    # Dot-directories to preserve
    agent_dir = tmp_path / ".agent"
    agent_dir.mkdir()
    (agent_dir / "settings.json").write_text("{}")

    ci_dir = tmp_path / ".github" / "workflows"
    ci_dir.mkdir(parents=True)
    (ci_dir / "ci.yml").write_text("ci")

    husky_dir = tmp_path / ".husky"
    husky_dir.mkdir()
    (husky_dir / "pre-commit").write_text("hook")

    # Regular unpreserved dot-directory
    (tmp_path / ".custom_dot").mkdir()
    (tmp_path / ".custom_dot" / "skip.txt").write_text("skip")

    filter_comp = ExclusionFilter()
    _total, _excluded, eligible, _over = filter_comp.scan(tmp_path)

    eligible_names = [f.name for f in eligible]
    assert "settings.json" in eligible_names
    assert "ci.yml" in eligible_names
    assert "pre-commit" in eligible_names
    assert "skip.txt" not in eligible_names


def test_scan_preserves_lockfiles_even_if_large(tmp_path: Path) -> None:
    # Create large lockfile (> 256 KB)
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text("{\n" + '  "dep": "1.0.0",\n' * 15000 + "}\n")  # ~300 KB

    # Create large regular file (> 256 KB)
    big_doc = tmp_path / "manual.txt"
    big_doc.write_text("x" * 300000)

    filter_comp = ExclusionFilter(max_single_file_bytes=256 * 1024)
    _total, _excluded, eligible, oversized = filter_comp.scan(tmp_path)

    eligible_names = [f.name for f in eligible]
    oversized_paths = [o.path for o in oversized]

    # Both are recorded in oversized
    assert any("package-lock.json" in p for p in oversized_paths)
    assert any("manual.txt" in p for p in oversized_paths)

    # BUT known lockfile is retained as candidate for notice generation,
    # while non-lockfile is excluded!
    assert "package-lock.json" in eligible_names
    assert "manual.txt" not in eligible_names
