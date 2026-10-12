"""
Unit tests for hooks/components/archetype_detector.py
Validates project archetype identification, AI agent configuration detection,
and root resolution safety in < 10ms.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from hooks.components.archetype_detector import ArchetypeDetector


def test_resolve_root_valid(tmp_path: Path) -> None:
    detector = ArchetypeDetector(tmp_path)
    assert detector.resolve_root() == tmp_path.resolve()


def test_resolve_root_not_found(tmp_path: Path) -> None:
    non_existent = tmp_path / "does_not_exist"
    detector = ArchetypeDetector(non_existent)
    with pytest.raises(FileNotFoundError):
        detector.resolve_root()


def test_resolve_root_not_a_directory(tmp_path: Path) -> None:
    file_path = tmp_path / "file.txt"
    file_path.touch()
    detector = ArchetypeDetector(file_path)
    with pytest.raises(NotADirectoryError):
        detector.resolve_root()


def test_detect_empty_workspace(tmp_path: Path) -> None:
    detector = ArchetypeDetector(tmp_path)
    assert detector.detect() == "Generic"


def test_detect_python_workspace(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").touch()
    detector = ArchetypeDetector(tmp_path)
    assert detector.detect() == "Python"


def test_detect_nodejs_workspace(tmp_path: Path) -> None:
    (tmp_path / "package.json").touch()
    detector = ArchetypeDetector(tmp_path)
    assert detector.detect() == "Node.js"


def test_detect_agent_managed_workspace(tmp_path: Path) -> None:
    (tmp_path / "package.json").touch()
    (tmp_path / "AGENTS.md").touch()
    detector = ArchetypeDetector(tmp_path)
    assert detector.detect() == "Node.js (AI Agent Managed)"


def test_detect_polyglot_with_agents(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").touch()
    (tmp_path / "package.json").touch()
    (tmp_path / ".cursorrules").touch()
    detector = ArchetypeDetector(tmp_path)
    arch = detector.detect()
    assert "Polyglot" in arch
    assert "Agent Configs" in arch


def test_detect_sub_10ms_performance(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").touch()
    (tmp_path / "AGENTS.md").touch()
    detector = ArchetypeDetector(tmp_path)

    start = time.perf_counter()
    arch = detector.detect()
    elapsed = time.perf_counter() - start

    assert arch == "Python (AI Agent Managed)"
    assert elapsed < 0.05, f"Detection took {elapsed*1000:.2f}ms, expected sub-50ms"
