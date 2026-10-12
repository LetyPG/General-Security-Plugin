"""
Unit tests for scan_code_patterns.py (audit-code-vulnerabilities deterministic script).
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

# Load script dynamically from hyphenated directory path
_script_path = (
    Path(__file__).resolve().parent.parent.parent
    / "skills"
    / "audit-code-vulnerabilities"
    / "scripts"
    / "scan_code_patterns.py"
)
_spec = importlib.util.spec_from_file_location("scan_code_patterns", _script_path)
_module = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules[_spec.name] = _module
_spec.loader.exec_module(_module)

CodePatternScanner = _module.CodePatternScanner


def test_scan_sqli_patterns(tmp_path: Path) -> None:
    py_file = tmp_path / "queries.py"
    py_file.write_text(
        'def get_user(uid):\n'
        '    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n',
        encoding="utf-8",
    )

    js_file = tmp_path / "queries.ts"
    js_file.write_text(
        'export function fetchAccount(name: string) {\n'
        '    db.query(`SELECT * FROM accounts WHERE name = ${name}`);\n'
        '}\n',
        encoding="utf-8",
    )

    scanner = CodePatternScanner(tmp_path)
    findings = scanner.scan()

    sqli = [f for f in findings if f.category == "SQLi"]
    assert len(sqli) == 2
    assert all(f.cwe_id == "CWE-89" for f in sqli)
    assert all(f.severity == "CRITICAL" for f in sqli)


def test_scan_command_injection(tmp_path: Path) -> None:
    py_file = tmp_path / "system.py"
    py_file.write_text(
        'import subprocess\n'
        'import os\n'
        'os.system("echo " + user_input)\n'
        'subprocess.run(cmd, shell=True)\n',
        encoding="utf-8",
    )

    scanner = CodePatternScanner(tmp_path)
    findings = scanner.scan()

    cmdi = [f for f in findings if f.category == "CMDi"]
    assert len(cmdi) == 2
    assert all(f.cwe_id == "CWE-78" for f in cmdi)


def test_scan_xss_and_dangerously_set_inner_html(tmp_path: Path) -> None:
    tsx_file = tmp_path / "Component.tsx"
    tsx_file.write_text(
        'export const RawBox = ({ html }) => {\n'
        '    return <div dangerouslySetInnerHTML={{ __html: html }} />;\n'
        '};\n',
        encoding="utf-8",
    )

    scanner = CodePatternScanner(tmp_path)
    findings = scanner.scan()

    xss = [f for f in findings if f.category == "XSS"]
    assert len(xss) == 1
    assert xss[0].cwe_id == "CWE-79"
    assert xss[0].severity == "HIGH"


def test_scan_insecure_deserialization(tmp_path: Path) -> None:
    py_file = tmp_path / "deser.py"
    py_file.write_text(
        'import pickle\n'
        'import yaml\n'
        'data = pickle.loads(payload)\n'
        'cfg = yaml.load(raw_stream)\n',
        encoding="utf-8",
    )

    scanner = CodePatternScanner(tmp_path)
    findings = scanner.scan()

    deser = [f for f in findings if f.category == "Deser"]
    assert len(deser) == 2
    assert all(f.cwe_id == "CWE-502" for f in deser)


def test_scan_crypto_weaknesses(tmp_path: Path) -> None:
    py_file = tmp_path / "crypto_test.py"
    py_file.write_text(
        'import hashlib\n'
        'h = hashlib.md5(b"secret").hexdigest()\n'
        'requests.get("https://internal", verify=False)\n',
        encoding="utf-8",
    )

    scanner = CodePatternScanner(tmp_path)
    findings = scanner.scan()

    crypto = [f for f in findings if f.category == "Crypto"]
    assert len(crypto) == 2
    cwes = {f.cwe_id for f in crypto}
    assert "CWE-327" in cwes
    assert "CWE-295" in cwes


def test_scan_path_traversal_and_ssrf(tmp_path: Path) -> None:
    py_file = tmp_path / "server.py"
    py_file.write_text(
        'from flask import request\n'
        'import requests\n'
        'f = open(request.args.get("filepath"))\n'
        'resp = requests.get(request.args.get("target_url"))\n',
        encoding="utf-8",
    )

    scanner = CodePatternScanner(tmp_path)
    findings = scanner.scan()

    categories = {f.category for f in findings}
    assert "PathTrav" in categories
    assert "SSRF" in categories


def test_scan_code_patterns_targeted_option_a(tmp_path: Path) -> None:
    file_a = tmp_path / "a.py"
    file_b = tmp_path / "b.py"

    file_a.write_text('os.system("ls")\n', encoding="utf-8")
    file_b.write_text('os.system("pwd")\n', encoding="utf-8")

    scanner = CodePatternScanner(tmp_path)
    findings = scanner.scan(target_paths=[file_a])
    assert len(findings) == 1
    assert findings[0].file == "a.py"


def test_scan_code_patterns_skips_minified_lines(tmp_path: Path) -> None:
    minified_file = tmp_path / "bundle.js"
    # Create line exceeding 1000 characters with an eval
    long_line = "var a=1;" * 200 + 'eval("hello");\n'
    minified_file.write_text(long_line, encoding="utf-8")

    scanner = CodePatternScanner(tmp_path)
    findings = scanner.scan()
    # Minified line should be skipped by the length guardrail
    assert len(findings) == 0
