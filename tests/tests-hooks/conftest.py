"""
Shared pytest fixtures and test doubles for hook tests.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure plugin root is in sys.path
PLUGIN_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))


@pytest.fixture
def mock_workspace(tmp_path: Path) -> Path:
    """
    Creates a realistic mock project workspace for testing:
    - Root indicators (package.json, pyproject.toml)
    - AI Agent configs (AGENTS.md, .cursorrules)
    - Pruned directories (node_modules, dist, .venv, .cache)
    - Preserved dot-directories (.agent/settings.json, .github/workflows/deploy.yml)
    - Tier 1 files (.env, package.json, id_rsa.key, AGENTS.md)
    - Tier 2 files (auth_service.py, server.js, app.py)
    - Tier 3 files (package-lock.json, README.md)
    - Oversized file (> 256 KB)
    - File with long line (> 1000 chars)
    """
    ws = tmp_path / "mock_project"
    ws.mkdir()

    # Ecosystem & Agent markers
    (ws / "package.json").write_text('{"name": "mock-app"}', encoding="utf-8")
    (ws / "pyproject.toml").write_text('[project]\nname = "mock"', encoding="utf-8")
    (ws / "AGENTS.md").write_text("# Agent instructions\n", encoding="utf-8")
    (ws / ".cursorrules").write_text("rules: none\n", encoding="utf-8")

    # Tier 1 Critical files
    (ws / ".env").write_text("API_KEY=dummy_secret\n", encoding="utf-8")
    (ws / "id_rsa.key").write_text("-----BEGIN RSA PRIVATE KEY-----\nfake\n", encoding="utf-8")

    agent_dir = ws / ".agent"
    agent_dir.mkdir()
    (agent_dir / "settings.json").write_text('{"safe": true}\n', encoding="utf-8")

    ci_dir = ws / ".github" / "workflows"
    ci_dir.mkdir(parents=True)
    (ci_dir / "deploy.yml").write_text("name: Deploy\non: push\n", encoding="utf-8")

    # Tier 2 Source & Security files
    (ws / "auth_service.py").write_text("def verify_token(): pass\n", encoding="utf-8")
    (ws / "server.js").write_text("console.log('running');\n", encoding="utf-8")
    (ws / "app.py").write_text("print('hello')\n", encoding="utf-8")

    # Tier 3 Files (including lockfile)
    (ws / "package-lock.json").write_text('{\n  "name": "mock-app",\n  "lockfileVersion": 2\n}\n', encoding="utf-8")
    (ws / "README.md").write_text("# Readme\n", encoding="utf-8")

    # Excluded directories
    nm = ws / "node_modules" / "some_pkg"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text("module.exports = {};", encoding="utf-8")

    dist = ws / "dist"
    dist.mkdir()
    (dist / "bundle.min.js").write_text("var a=1;", encoding="utf-8")

    venv = ws / ".venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "site.py").write_text("x = 1", encoding="utf-8")

    # Excluded binary
    (ws / "icon.png").write_bytes(b"\x89PNG\r\n\x1a\n")

    # Oversized non-lockfile (> 256 KB)
    oversized = ws / "large_dump.sql"
    oversized.write_bytes(b"SELECT 1;\n" * 32000)  # ~320 KB

    # File with long line (> 1000 chars)
    long_file = ws / "minified_line.txt"
    long_file.write_text("x" * 1500 + "\n", encoding="utf-8")

    return ws
