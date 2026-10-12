"""
Unit tests for scan_secrets.py (audit-security-secrets deterministic script).
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

# Load script from hyphenated directory path
_script_path = (
    Path(__file__).resolve().parent.parent.parent
    / "skills"
    / "audit-security-secrets"
    / "scripts"
    / "scan_secrets.py"
)
_spec = importlib.util.spec_from_file_location("scan_secrets", _script_path)
_module = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules[_spec.name] = _module
_spec.loader.exec_module(_module)

SecretsScanner = _module.SecretsScanner


def test_scan_secrets_detects_aws_key_and_masks(tmp_path: Path) -> None:
    test_file = tmp_path / "aws_test.py"
    raw_key = "AKIA1234567890ABCDEF"
    test_file.write_text(f'AWS_KEY = "{raw_key}"\n', encoding="utf-8")

    scanner = SecretsScanner(tmp_path)
    findings = scanner.scan()

    aws_findings = [f for f in findings if f.pattern == "AWS Access Key"]
    assert len(aws_findings) == 1
    f = aws_findings[0]
    assert f.severity == "CRITICAL"
    assert f.line == 1
    # Check Zero-Raw-Secret invariant
    assert raw_key not in f.match
    assert f.match == "AKIA...CDEF"
    assert f.cwe_id == "CWE-798"


def test_scan_secrets_detects_anthropic_and_openai_tokens(tmp_path: Path) -> None:
    test_file = tmp_path / "ai_clients.py"
    raw_ant = "sk-ant-api03-abcdef1234567890abcdef1234"
    raw_oai = "sk-1234567890abcdef1234567890abcdef1234567890abcdef"
    test_file.write_text(
        f'anthropic_token = "{raw_ant}"\nopenai_token = "{raw_oai}"\n',
        encoding="utf-8",
    )

    scanner = SecretsScanner(tmp_path)
    findings = scanner.scan()

    patterns = {f.pattern for f in findings}
    assert "Anthropic API Key" in patterns
    assert "OpenAI API Key" in patterns

    for f in findings:
        assert raw_ant not in f.match
        assert raw_oai not in f.match


def test_scan_secrets_ignores_placeholders(tmp_path: Path) -> None:
    test_file = tmp_path / "placeholders.py"
    test_file.write_text(
        'api_key = "example_dummy_test_placeholder_key_12345"\n'
        'password = "changeme_to_your_real_password_12345"\n',
        encoding="utf-8",
    )

    scanner = SecretsScanner(tmp_path)
    findings = scanner.scan()
    assert len(findings) == 0


def test_scan_secrets_detects_db_connection_uri(tmp_path: Path) -> None:
    test_file = tmp_path / "db.py"
    test_file.write_text(
        'DB_URI = "postgres://dbuser:supersecretpass123@db.example.com:5432/mydb"\n',
        encoding="utf-8",
    )

    scanner = SecretsScanner(tmp_path)
    findings = scanner.scan()

    db_findings = [f for f in findings if f.pattern == "Database Connection String"]
    assert len(db_findings) == 1
    assert "supersecretpass123" not in db_findings[0].match


def test_scan_secrets_committed_env_file(tmp_path: Path) -> None:
    # Real .env file
    env_file = tmp_path / ".env"
    env_file.write_text("DB_PASSWORD=production_secret_value_123\nAPI_KEY=xyz\n", encoding="utf-8")

    # Example .env file should be ignored
    example_env = tmp_path / ".env.example"
    example_env.write_text("DB_PASSWORD=your_password_here\n", encoding="utf-8")

    scanner = SecretsScanner(tmp_path)
    findings = scanner.scan()

    env_findings = [f for f in findings if f.pattern == "Committed .env File"]
    assert len(env_findings) == 1
    assert env_findings[0].file == ".env"
    assert "2 environment variable(s)" in env_findings[0].match


def test_scan_secrets_agent_and_mcp_configs(tmp_path: Path) -> None:
    # Multi-agent config: mcp.json
    mcp_file = tmp_path / "mcp.json"
    mcp_data = {
        "mcpServers": {
            "db-tool": {
                "command": "node",
                "env": {
                    "api_key": "actual_live_secret_key_99999"
                }
            }
        }
    }
    mcp_file.write_text(json.dumps(mcp_data), encoding="utf-8")

    scanner = SecretsScanner(tmp_path)
    findings = scanner.scan()

    mcp_findings = [f for f in findings if f.pattern == "Agent/MCP Hardcoded Credential"]
    assert len(mcp_findings) == 1
    assert mcp_findings[0].severity == "CRITICAL"
    assert "actual_live_secret_key_99999" not in mcp_findings[0].match


def test_scan_secrets_targeted_paths_option_a(tmp_path: Path) -> None:
    file_a = tmp_path / "a.py"
    file_b = tmp_path / "b.py"

    file_a.write_text('token = "ghp_111111111111111111111111111111111111"\n', encoding="utf-8")
    file_b.write_text('token = "ghp_222222222222222222222222222222222222"\n', encoding="utf-8")

    scanner = SecretsScanner(tmp_path)
    # Target only file_a
    findings = scanner.scan(target_paths=[file_a])
    assert len(findings) == 1
    assert findings[0].file == "a.py"
