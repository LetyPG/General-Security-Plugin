"""
Unit tests for scan_injections.py (audit-injection-risk deterministic script).
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

# Load script dynamically from hyphenated directory path
_script_path = (
    Path(__file__).resolve().parent.parent.parent
    / "skills"
    / "audit-injection-risk"
    / "scripts"
    / "scan_injections.py"
)
_spec = importlib.util.spec_from_file_location("scan_injections", _script_path)
_module = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules[_spec.name] = _module
_spec.loader.exec_module(_module)

InjectionScanner = _module.InjectionScanner


def test_detect_sqli_patterns(tmp_path: Path) -> None:
    py_file = tmp_path / "db.py"
    py_file.write_text(
        "cursor.execute(f\"SELECT * FROM users WHERE username = '{user_input}'\")\n",
        encoding="utf-8",
    )
    js_file = tmp_path / "repo.js"
    js_file.write_text(
        "const res = await db.query(`SELECT * FROM products WHERE id = ${prodId}`);\n",
        encoding="utf-8",
    )
    go_file = tmp_path / "store.go"
    go_file.write_text(
        "rows, err := db.Query(fmt.Sprintf(\"SELECT name FROM accounts WHERE id = %s\", accId))\n",
        encoding="utf-8",
    )

    scanner = InjectionScanner(tmp_path)
    findings = scanner.scan()

    patterns = {f.pattern for f in findings}
    assert "Python f-string SQL Injection" in patterns
    assert "JavaScript Template Literal SQL Injection" in patterns
    assert "Go fmt.Sprintf SQL Injection" in patterns
    assert all(f.cwe_id == "CWE-89" for f in findings)


def test_detect_command_injection(tmp_path: Path) -> None:
    py_file = tmp_path / "service.py"
    py_file.write_text(
        "os.system(f\"ping -c 1 {host}\")\n"
        "subprocess.Popen(user_cmd, shell=True)\n",
        encoding="utf-8",
    )
    js_file = tmp_path / "worker.js"
    js_file.write_text(
        "execSync(`tar -czf ${archiveName} /tmp/data`);\n",
        encoding="utf-8",
    )

    scanner = InjectionScanner(tmp_path)
    findings = scanner.scan()

    patterns = {f.pattern for f in findings}
    assert "Python os.system Command Execution" in patterns
    assert "Python Subprocess Shell=True Execution" in patterns
    assert "Node.js child_process.exec Command Injection" in patterns
    assert all(f.cwe_id == "CWE-78" for f in findings)


def test_detect_xss_patterns(tmp_path: Path) -> None:
    js_file = tmp_path / "view.jsx"
    js_file.write_text(
        "document.getElementById('out').innerHTML = rawPayload;\n"
        "<div dangerouslySetInnerHTML={{ __html: userBio }} />;\n",
        encoding="utf-8",
    )

    scanner = InjectionScanner(tmp_path)
    findings = scanner.scan()

    patterns = {f.pattern for f in findings}
    assert "Direct innerHTML Assignment (XSS)" in patterns
    assert "React dangerouslySetInnerHTML Without Sanitization" in patterns
    assert all(f.cwe_id == "CWE-79" for f in findings)


def test_detect_path_traversal(tmp_path: Path) -> None:
    py_file = tmp_path / "download.py"
    py_file.write_text(
        "with open(request.args.get('filename')) as f:\n"
        "    data = f.read()\n",
        encoding="utf-8",
    )
    js_file = tmp_path / "serve.js"
    js_file.write_text(
        "const content = fs.readFileSync(req.params.doc);\n",
        encoding="utf-8",
    )

    scanner = InjectionScanner(tmp_path)
    findings = scanner.scan()

    patterns = {f.pattern for f in findings}
    assert "Python Unvalidated File Path Access" in patterns
    assert "Node.js fs Unvalidated Path Access" in patterns
    assert all(f.cwe_id == "CWE-22" for f in findings)


def test_detect_ssrf(tmp_path: Path) -> None:
    py_file = tmp_path / "webhook.py"
    py_file.write_text(
        "resp = requests.get(request.args.get('target_url'))\n",
        encoding="utf-8",
    )
    js_file = tmp_path / "fetcher.js"
    js_file.write_text(
        "const res = await fetch(req.body.target_url);\n",
        encoding="utf-8",
    )

    scanner = InjectionScanner(tmp_path)
    findings = scanner.scan()

    patterns = {f.pattern for f in findings}
    assert "Python Requests Dynamic URL (SSRF)" in patterns
    assert "Node.js Fetch/Axios Dynamic URL (SSRF)" in patterns
    assert all(f.cwe_id == "CWE-918" for f in findings)


def test_detect_log_injection(tmp_path: Path) -> None:
    py_file = tmp_path / "auth.py"
    py_file.write_text(
        "logger.info(f\"User login attempt for {user_input}\")\n",
        encoding="utf-8",
    )
    js_file = tmp_path / "auth.ts"
    js_file.write_text(
        "console.log(`Failed token for ${req.params.user}`);\n",
        encoding="utf-8",
    )

    scanner = InjectionScanner(tmp_path)
    findings = scanner.scan()

    patterns = {f.pattern for f in findings}
    assert "Python Log Injection via Interpolation" in patterns
    assert "JavaScript Console Log Interpolation" in patterns
    assert all(f.cwe_id == "CWE-117" for f in findings)


def test_detect_nosql_injection(tmp_path: Path) -> None:
    js_file = tmp_path / "mongo.js"
    js_file.write_text(
        "const q = { $where: `this.name == '${req.query.name}'` };\n",
        encoding="utf-8",
    )

    scanner = InjectionScanner(tmp_path)
    findings = scanner.scan()

    patterns = {f.pattern for f in findings}
    assert "MongoDB $where Dynamic Expression Injection" in patterns
    assert all(f.cwe_id == "CWE-943" for f in findings)


def test_detect_xxe_and_ssti(tmp_path: Path) -> None:
    py_file = tmp_path / "parser.py"
    py_file.write_text(
        "tree = xml.etree.ElementTree.parse('input.xml')\n"
        "html = render_template_string(request.form.get('template'))\n",
        encoding="utf-8",
    )

    scanner = InjectionScanner(tmp_path)
    findings = scanner.scan()

    patterns = {f.pattern for f in findings}
    assert "Insecure Python XML Parser (XXE)" in patterns
    assert "Flask render_template_string Injection (SSTI)" in patterns
