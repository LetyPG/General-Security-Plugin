#!/usr/bin/env python3
"""
Secrets and Credentials Scanner.

Detects hardcoded secrets, API keys, private keys, database URIs,
committed .env files, and insecure agent configuration credentials.
Strictly enforces the Zero-Raw-Secret Output Invariant.
"""
from __future__ import annotations

import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path

# Ensure plugin root is in sys.path
_plugin_root = str(Path(__file__).resolve().parent.parent.parent.parent)
if _plugin_root not in sys.path:
    sys.path.insert(0, _plugin_root)

from skills.common import (
    Finding,
    emit_findings,
    is_placeholder,
    mask_secret,
    parse_args,
    walk_project_files,
)

# Supported extensions for general content scanning
SCAN_EXTENSIONS: set[str] = {
    ".js", ".ts", ".jsx", ".tsx", ".py", ".rb", ".go", ".java", ".rs",
    ".php", ".cs", ".swift", ".kt", ".sh", ".bash", ".json", ".yaml",
    ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".xml",
    ".env", ".md", ".txt", ".ipynb", ".tf", ".tfvars", ".dockerfile",
    ".makefile", ".pem", ".key",
}

# Regex pattern definitions: (severity, pattern_name, regex, cwe_id)
SIGNATURE_PATTERNS: list[tuple[str, str, re.Pattern[str], str]] = [
    (
        "CRITICAL",
        "AWS Access Key",
        re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"),
        "CWE-798",
    ),
    (
        "CRITICAL",
        "Private Key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "CWE-798",
    ),
    (
        "CRITICAL",
        "Anthropic API Key",
        re.compile(r"sk-ant-[a-zA-Z0-9_-]{20,}"),
        "CWE-798",
    ),
    (
        "CRITICAL",
        "OpenAI API Key",
        re.compile(r"sk-[a-zA-Z0-9]{48,}"),
        "CWE-798",
    ),
    (
        "CRITICAL",
        "GitHub Token",
        re.compile(r"(?:gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{82})"),
        "CWE-798",
    ),
    (
        "CRITICAL",
        "Database Connection String",
        re.compile(r"(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s'\"]+:[^\s'\"]+@"),
        "CWE-798",
    ),
    (
        "HIGH",
        "Stripe Key",
        re.compile(r"[sr]k_(?:live|test)_[A-Za-z0-9]{20,}"),
        "CWE-798",
    ),
    (
        "HIGH",
        "Slack Token",
        re.compile(r"xox[boaprs]-[0-9a-zA-Z-]{10,}"),
        "CWE-798",
    ),
    (
        "HIGH",
        "Google API Key",
        re.compile(r"AIza[0-9A-Za-z_-]{35}"),
        "CWE-798",
    ),
    (
        "HIGH",
        "SendGrid API Key",
        re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
        "CWE-798",
    ),
    (
        "MEDIUM",
        "JWT Token in Source",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "CWE-798",
    ),
]

GENERIC_SECRET_PATTERN = re.compile(
    r"(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?key|secret[_-]?key|"
    r"auth[_-]?token|password|passwd)\s*[=:]\s*['\"]([A-Za-z0-9+/=_-]{16,})['\"]"
)

MCP_CREDENTIAL_PATTERN = re.compile(
    r'"(?:password|secret|key|token|api_key)":\s*"(?!\$\{)([^"]{8,})"'
)

ENV_VAR_PATTERN = re.compile(r"^\s*[A-Z_]+=\S+")


class SecretsScanner:
    """Deterministic security scanner for hardcoded secrets and credentials."""

    def __init__(self, project_root: str | Path) -> None:
        self.project_root = Path(project_root).resolve()
        self.findings: list[Finding] = []
        self._finding_counter = 0

    def _next_id(self) -> int:
        self._finding_counter += 1
        return self._finding_counter

    def scan(self, target_paths: Sequence[str | Path] | None = None) -> list[Finding]:
        """Runs complete secrets analysis across project or targeted candidate paths."""
        self.findings.clear()
        self._finding_counter = 0

        # Step 1: Discover candidate files
        candidate_files = walk_project_files(
            self.project_root,
            allowed_extensions=SCAN_EXTENSIONS,
            allowed_filenames={"dockerfile", "makefile", ".env", ".cursorrules"},
            target_paths=target_paths,
        )

        # Step 2: Content scanning
        for file_path in candidate_files:
            rel_path = self._rel_path(file_path)
            self._scan_file_content(file_path, rel_path)

        # Step 3: Check committed .env files
        self._scan_committed_env_files(candidate_files)

        # Step 4: Check MCP and Agent configuration settings
        self._scan_agent_configs(candidate_files)

        return self.findings

    def _rel_path(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.project_root))
        except ValueError:
            return str(path)

    def _scan_file_content(self, file_path: Path, rel_path: str) -> None:
        """Inspects line-by-line file content against signatures and generic patterns."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, start=1):
                    # Guard: skip extremely long minified lines
                    if len(line) > 1000:
                        continue

                    # 1. Known vendor signatures
                    for severity, pattern_name, regex, cwe_id in SIGNATURE_PATTERNS:
                        match = regex.search(line)
                        if match:
                            raw_val = match.group(0)
                            if is_placeholder(raw_val):
                                continue

                            self.findings.append(
                                Finding(
                                    id=self._next_id(),
                                    severity=severity,
                                    category="Secrets",
                                    file=rel_path,
                                    line=line_num,
                                    pattern=pattern_name,
                                    match=mask_secret(raw_val),
                                    detail=f"Detected {pattern_name} in source code",
                                    cwe_id=cwe_id,
                                )
                            )

                    # 2. Generic secret assignments
                    gen_match = GENERIC_SECRET_PATTERN.search(line)
                    if gen_match:
                        secret_val = gen_match.group(1)
                        if not is_placeholder(secret_val):
                            self.findings.append(
                                Finding(
                                    id=self._next_id(),
                                    severity="HIGH",
                                    category="Secrets",
                                    file=rel_path,
                                    line=line_num,
                                    pattern="Hardcoded Secret Assignment",
                                    match=mask_secret(secret_val),
                                    detail="Generic sensitive credential assignment detected",
                                    cwe_id="CWE-798",
                                )
                            )
        except (OSError, UnicodeDecodeError):
            return

    def _scan_committed_env_files(self, candidates: Sequence[Path]) -> None:
        """Flags committed .env files that contain actual secret assignments."""
        env_names = {".env", ".env.local", ".env.production", ".env.staging"}
        ignored_templates = {".env.example", ".env.template", ".env.sample", ".env.test"}

        for file_path in candidates:
            fname_lower = file_path.name.lower()
            if fname_lower in ignored_templates or fname_lower.endswith((".example", ".sample", ".template")):
                continue

            if fname_lower in env_names or file_path.suffix.lower() == ".env":
                try:
                    count = 0
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if ENV_VAR_PATTERN.match(line):
                                count += 1

                    if count > 0:
                        rel_path = self._rel_path(file_path)
                        self.findings.append(
                            Finding(
                                id=self._next_id(),
                                severity="HIGH",
                                category="Secrets",
                                file=rel_path,
                                line=0,
                                pattern="Committed .env File",
                                match=f"{count} environment variable(s) found",
                                detail="Committed environment file contains plaintext configurations",
                                cwe_id="CWE-798",
                            )
                        )
                except OSError:
                    continue

    def _scan_agent_configs(self, candidates: Sequence[Path]) -> None:
        """
        Scans agent and MCP configuration files for hardcoded plaintext credentials.
        General-purpose: inspects configs across all agent frameworks
        (*mcp*.json, settings.json, *claude*.json, *gemini*.json, *agent*.json, .cursorrules).
        """
        config_patterns = ("mcp", "claude", "gemini", "agent", "settings")

        for file_path in candidates:
            fname_lower = file_path.name.lower()
            if not fname_lower.endswith(".json") and fname_lower != ".cursorrules":
                continue

            if not any(pat in fname_lower for pat in config_patterns):
                continue

            rel_path = self._rel_path(file_path)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for match in MCP_CREDENTIAL_PATTERN.finditer(content):
                    raw_cred = match.group(1)
                    if not is_placeholder(raw_cred):
                        self.findings.append(
                            Finding(
                                id=self._next_id(),
                                severity="CRITICAL",
                                category="Secrets",
                                file=rel_path,
                                line=0,
                                pattern="Agent/MCP Hardcoded Credential",
                                match=mask_secret(raw_cred),
                                detail="Unmasked credentials in agent/MCP configuration file",
                                cwe_id="CWE-798",
                            )
                        )
            except (OSError, json.JSONDecodeError):
                continue


def main() -> None:
    args = parse_args(
        prog_name="scan_secrets",
        description="Scans workspace for hardcoded secrets, API keys, credentials, and .env files.",
    )

    scanner = SecretsScanner(args.project_root)
    findings = scanner.scan(target_paths=args.target)

    # Apply max findings limit if set
    if args.max_findings and len(findings) > args.max_findings:
        findings = findings[: args.max_findings]

    emit_findings(
        findings,
        as_json=args.json,
        no_color=args.no_color,
        title="Security Review: Secrets & Credentials Scanner",
        project_root=args.project_root,
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
