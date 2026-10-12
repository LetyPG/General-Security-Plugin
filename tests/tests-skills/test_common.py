"""
Unit tests for skills.common shared infrastructure.
"""
from __future__ import annotations

import json
from pathlib import Path

from skills.common import (
    Finding,
    Severity,
    emit_findings,
    is_placeholder,
    mask_secret,
    parse_args,
    walk_project_files,
)


def test_severity_normalization() -> None:
    assert Severity.from_string("critical") == Severity.CRITICAL
    assert Severity.from_string("HIGH") == Severity.HIGH
    assert Severity.from_string("unknown") == Severity.MEDIUM


def test_finding_dataclass_and_json_serialization() -> None:
    finding = Finding(
        id=1,
        severity="high",
        category="Secrets",
        file="src/config.py",
        line=10,
        pattern="AWS Key",
        match="AKIA...7E2A",
        detail="Hardcoded key detected",
        cwe_id="CWE-798",
    )
    assert finding.severity == "HIGH"
    data = finding.to_dict()
    assert data["id"] == 1
    assert data["severity"] == "HIGH"
    assert data["cwe_id"] == "CWE-798"

    json_str = finding.to_json()
    loaded = json.loads(json_str)
    assert loaded["match"] == "AKIA...7E2A"


def test_mask_secret_zero_raw_secret_invariant() -> None:
    # Length > 12: keep first 4 and last 4
    masked = mask_secret("AKIA1234567890ABCDEF")
    assert masked == "AKIA...CDEF"

    # Length <= 12: redact completely
    assert mask_secret("shortsecret") == "[REDACTED]"
    assert mask_secret("") == "[REDACTED]"
    assert mask_secret("   ") == "[REDACTED]"


def test_is_placeholder() -> None:
    assert is_placeholder("example_api_key_12345") is True
    assert is_placeholder("my_dummy_token_value") is True
    assert is_placeholder("changeme_password") is True
    assert is_placeholder("test_secret_for_ci") is True
    assert is_placeholder("ghp_1234567890abcdef1234567890abcdef") is False


def test_parse_args_defaults() -> None:
    args = parse_args("test_scanner", "Test description", args=[])
    assert args.project_root == Path.cwd().resolve()
    assert args.json is False
    assert args.target == []


def test_parse_args_positional_and_flags() -> None:
    args = parse_args("test_scanner", "Test description", args=["/tmp", "--json", "--no-color"])
    assert args.project_root == Path("/tmp").resolve()
    assert args.json is True
    assert args.no_color is True


def test_parse_args_arguments_expansion_string() -> None:
    # Simulates ${ARGUMENTS} expanded as single string by shell
    args = parse_args("test_scanner", "Test description", args=["/tmp --json --target a.py b.py"])
    assert args.project_root == Path("/tmp").resolve()
    assert args.json is True
    assert args.target == ["a.py", "b.py"]


def test_parse_args_empty_string_argument() -> None:
    # Simulates ${ARGUMENTS} when empty: python3 script.py ""
    args = parse_args("test_scanner", "Test description", args=[""])
    assert args.project_root == Path.cwd().resolve()


def test_walk_project_files_filtering(tmp_path: Path) -> None:
    # Setup test workspace
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('hello')", encoding="utf-8")
    (tmp_path / "src" / "util.js").write_text("console.log()", encoding="utf-8")

    # Excluded dirs
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "bad.js").write_text("malicious()", encoding="utf-8")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "lib.py").write_text("pass", encoding="utf-8")

    # Security dot-dir preserved
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("name: CI", encoding="utf-8")

    # Scan python files only
    py_files = walk_project_files(tmp_path, allowed_extensions={".py"})
    py_names = [f.name for f in py_files]
    assert "app.py" in py_names
    assert "util.js" not in py_names
    assert "lib.py" not in py_names

    # Preserved dot dir
    all_files = walk_project_files(tmp_path)
    all_names = [f.name for f in all_files]
    assert "app.py" in all_names
    assert "util.js" in all_names
    assert "ci.yml" in all_names
    assert "bad.js" not in all_names


def test_walk_project_files_target_paths(tmp_path: Path) -> None:
    file_a = tmp_path / "a.py"
    file_b = tmp_path / "b.py"
    file_a.write_text("a", encoding="utf-8")
    file_b.write_text("b", encoding="utf-8")

    targets = [file_a]
    matched = walk_project_files(tmp_path, target_paths=targets)
    assert len(matched) == 1
    assert matched[0] == file_a


def test_emit_findings_json_output(capsys) -> None:
    finding = Finding(
        id=1,
        severity="CRITICAL",
        category="Secrets",
        file="secret.py",
        line=5,
        pattern="AWS Key",
        match="AKIA...7E2A",
    )
    count = emit_findings([finding], as_json=True)
    assert count == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert len(data) == 1
    assert data[0]["severity"] == "CRITICAL"


def test_emit_findings_cli_output(capsys) -> None:
    finding = Finding(
        id=1,
        severity="HIGH",
        category="Injection",
        file="app.py",
        line=12,
        pattern="SQLi",
        match="query()",
        detail="User input in raw query",
    )
    count = emit_findings([finding], as_json=False, no_color=True)
    assert count == 1
    captured = capsys.readouterr()
    assert "[HIGH] Injection" in captured.out
    assert "app.py:12" in captured.out
