#!/usr/bin/env python3
"""
AI Agent Environment Security Scanner.

Deterministic analyzer auditing AI agent configuration files, MCP server definitions,
permission boundaries, hook scripts, and agent governance settings across ecosystems.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Sequence

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

# Common agent instruction filenames
AGENT_INSTRUCTION_FILENAMES = {
    "agents.md",
    "claude.md",
    "gemini.md",
    "rules.mdc",
    "agent.md",
}

# Known agent configuration directories
AGENT_DIRS = (".agent", ".claude", ".gemini", ".cursor", ".codex")

# Known MCP configuration filenames
MCP_CONFIG_FILENAMES = {
    "mcp.json",
    "mcp-config.json",
    "mcp_config.json",
    "mcp-servers.json",
}

# Suspicious directive patterns in instruction files
AUTO_APPROVE_REGEX = re.compile(
    r"(?:always\s+approve|auto-?(?:execute|approve|accept)|skip\s+(?:confirm|permission|approval|check))",
    re.IGNORECASE,
)
SHELL_PROFILE_REGEX = re.compile(
    r"(?:\.bashrc|\.zshrc|\.profile|shell\s+config|export\s+PATH\s*=)",
    re.IGNORECASE,
)
EXTERNAL_URL_INSTRUCTION_REGEX = re.compile(
    r"(?:additional|more|extra|further|fetch|load)\s+instructions?\s+(?:from\s+)?https?://",
    re.IGNORECASE,
)
EXPAND_ACCESS_REGEX = re.compile(
    r"(?:access\s+(?:all|root|parent|system)\s+files|outside\s+(?:the\s+)?project|allow\s+path\s+['\"]?/(?:etc|root|home))",
    re.IGNORECASE,
)
OBFUSCATED_BLOCK_REGEX = re.compile(
    r"(?:[A-Za-z0-9+/]{4}){10,}={0,2}"
)

# Secret pattern checks in MCP env/args
SECRET_KEY_REGEX = re.compile(
    r"(?:api[_-]?key|secret|token|password|auth|private[_-]?key|credentials)",
    re.IGNORECASE,
)


class AIEnvironmentScanner:
    """Deterministic security scanner for AI agent configurations and MCP definitions."""

    def __init__(self, project_root: str | Path) -> None:
        self.project_root = Path(project_root).resolve()
        self.findings: list[Finding] = []
        self._finding_counter = 0

    def _next_id(self) -> int:
        self._finding_counter += 1
        return self._finding_counter

    def _rel_path(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.project_root))
        except ValueError:
            return str(path)

    def _add_finding(
        self,
        severity: str,
        category: str,
        file: str,
        line: int,
        pattern: str,
        match: str,
        detail: str,
        cwe_id: str,
    ) -> None:
        self.findings.append(
            Finding(
                id=self._next_id(),
                severity=severity,
                category=category,
                file=file,
                line=line,
                pattern=pattern,
                match=match,
                detail=detail,
                cwe_id=cwe_id,
            )
        )

    def scan(self, target_paths: Sequence[str | Path] | None = None) -> list[Finding]:
        """Scans project for AI environment, MCP, and agent governance misconfigurations."""
        self.findings.clear()
        self._finding_counter = 0

        candidate_files = walk_project_files(
            self.project_root,
            allowed_extensions={".md", ".json", ".yaml", ".yml", ".sh", ".bash", ".toml"},
            allowed_filenames={
                "agents.md", "claude.md", "gemini.md", ".cursorrules",
                "mcp.json", "mcp-config.json", "mcp_config.json", "settings.json",
            },
            target_paths=target_paths,
        )

        has_agent_governance = False

        for file_path in candidate_files:
            rel_path = self._rel_path(file_path)
            fname_lower = file_path.name.lower()

            # 1. Agent Instruction Files
            if fname_lower in AGENT_INSTRUCTION_FILENAMES or fname_lower.endswith(".cursorrules"):
                has_agent_governance = True
                self._scan_agent_instructions(file_path, rel_path)

            # 2. Standalone MCP Configuration Files
            if fname_lower in MCP_CONFIG_FILENAMES:
                self._scan_mcp_config_file(file_path, rel_path)

        # 3. Agent Directories (.agent/, .claude/, .gemini/, .cursor/)
        if self._scan_agent_directories():
            has_agent_governance = True

        # 4. Agent and Git Hooks Integrity
        self._scan_agent_and_git_hooks()

        # 5. Missing Agent Boundaries Check
        if not has_agent_governance:
            self._check_missing_agent_governance()

        return self.findings

    def _scan_agent_instructions(self, file_path: Path, rel_path: str) -> None:
        """Audits agent markdown instruction files (AGENTS.md, CLAUDE.md, .cursorrules)."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            return

        for line_num, raw_line in enumerate(lines, start=1):
            clean = raw_line.strip()
            if not clean:
                continue

            # Auto-approve / Skip confirmation directives
            if AUTO_APPROVE_REGEX.search(clean):
                self._add_finding(
                    severity="CRITICAL",
                    category="Agent Governance",
                    file=rel_path,
                    line=line_num,
                    pattern="Auto-Approve Directive",
                    match=clean[:80],
                    detail="Agent instruction instructs auto-approving actions or skipping human verification",
                    cwe_id="CWE-693",
                )

            # Dangerous permission bypass flag
            if "dangerously-skip-permissions" in clean.lower():
                self._add_finding(
                    severity="CRITICAL",
                    category="Agent Permissions",
                    file=rel_path,
                    line=line_num,
                    pattern="Dangerous Permission Bypass",
                    match=clean[:80],
                    detail="Explicit reference to --dangerously-skip-permissions flag",
                    cwe_id="CWE-250",
                )

            # Shell profile modification
            if SHELL_PROFILE_REGEX.search(clean):
                self._add_finding(
                    severity="HIGH",
                    category="Shell Environment",
                    file=rel_path,
                    line=line_num,
                    pattern="Shell Profile Modification",
                    match=clean[:80],
                    detail="Agent instructions reference modifying startup shell profiles (.bashrc, .zshrc, PATH)",
                    cwe_id="CWE-250",
                )

            # External URL instruction reference
            if EXTERNAL_URL_INSTRUCTION_REGEX.search(clean):
                self._add_finding(
                    severity="CRITICAL",
                    category="Untrusted Context",
                    file=rel_path,
                    line=line_num,
                    pattern="External Instruction Reference",
                    match=clean[:80],
                    detail="Agent instruction fetches or references dynamic instructions from external URL",
                    cwe_id="CWE-829",
                )

            # Broad filesystem access expansion
            if EXPAND_ACCESS_REGEX.search(clean):
                self._add_finding(
                    severity="HIGH",
                    category="Access Control",
                    file=rel_path,
                    line=line_num,
                    pattern="Filesystem Scope Expansion",
                    match=clean[:80],
                    detail="Agent instruction expands access beyond project directory bounds",
                    cwe_id="CWE-22",
                )

            # Large obfuscated Base64 / Hex block
            b64_match = OBFUSCATED_BLOCK_REGEX.search(clean)
            if b64_match and len(b64_match.group(0)) >= 40:
                self._add_finding(
                    severity="HIGH",
                    category="Obfuscated Content",
                    file=rel_path,
                    line=line_num,
                    pattern="Obfuscated Block in Instructions",
                    match=f"Base64 block (length={len(b64_match.group(0))})",
                    detail="Large encoded block detected inside agent instructions; verify decoded intent",
                    cwe_id="CWE-116",
                )

    def _scan_agent_directories(self) -> bool:
        """Audits configuration settings and command scripts in .agent/, .claude/, .gemini/, .cursor/."""
        found_agent_dir = False

        for agent_dir_name in AGENT_DIRS:
            target_dir = self.project_root / agent_dir_name
            if not target_dir.is_dir():
                continue

            found_agent_dir = True

            # 1. Audit settings.json
            settings_path = target_dir / "settings.json"
            if settings_path.is_file():
                self._scan_settings_json(settings_path, self._rel_path(settings_path), agent_dir_name)

            # 2. Audit custom commands / scripts
            for sub_name in ("commands", "scripts", "rules"):
                sub_dir = target_dir / sub_name
                if sub_dir.is_dir():
                    self._scan_custom_command_scripts(sub_dir)

        return found_agent_dir

    def _scan_settings_json(self, file_path: Path, rel_path: str, agent_prefix: str) -> None:
        """Inspects settings.json for dangerous flags, permission broadness, and embedded MCP servers."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                data = json.loads(content)
        except (OSError, json.JSONDecodeError):
            return

        # Check raw text for dangerously flags
        if '"dangerously' in content:
            self._add_finding(
                severity="CRITICAL",
                category="Agent Permissions",
                file=rel_path,
                line=0,
                pattern="Dangerous Permission in Settings",
                match=f"{agent_prefix}/settings.json contains 'dangerously' prefix",
                detail="Settings file enables dangerous unverified permission overrides",
                cwe_id="CWE-250",
            )

        # Check embedded mcpServers block
        if isinstance(data, dict):
            mcp_servers = data.get("mcpServers") or data.get("mcp_servers")
            if isinstance(mcp_servers, dict):
                self._audit_mcp_servers_dict(mcp_servers, rel_path)

    def _scan_custom_command_scripts(self, script_dir: Path) -> None:
        """Audits custom agent command definitions for unsafe shell execution."""
        for cmd_file in script_dir.glob("*"):
            if not cmd_file.is_file():
                continue

            rel_path = self._rel_path(cmd_file)
            try:
                with open(cmd_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                if re.search(r"(?:curl.*\|\s*(?:bash|sh)|wget.*\|\s*(?:bash|sh))", content, re.IGNORECASE):
                    self._add_finding(
                        severity="CRITICAL",
                        category="Agent Command",
                        file=rel_path,
                        line=0,
                        pattern="Remote Script Piping in Agent Command",
                        match=cmd_file.name,
                        detail="Agent command script pipes remote network payload directly to shell interpreter",
                        cwe_id="CWE-78",
                    )
                elif re.search(r"(?:eval\s+['\"\$]|exec\s+['\"\$])", content):
                    self._add_finding(
                        severity="HIGH",
                        category="Agent Command",
                        file=rel_path,
                        line=0,
                        pattern="Dynamic Evaluation in Agent Command",
                        match=cmd_file.name,
                        detail="Agent command script performs dynamic eval/exec on command arguments",
                        cwe_id="CWE-78",
                    )
            except OSError:
                pass

    def _scan_mcp_config_file(self, file_path: Path, rel_path: str) -> None:
        """Audits standalone MCP configuration files (mcp.json, etc.)."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return

        if isinstance(data, dict):
            servers = data.get("mcpServers") or data.get("mcp_servers") or data
            if isinstance(servers, dict):
                self._audit_mcp_servers_dict(servers, rel_path)

    def _audit_mcp_servers_dict(self, servers: dict[str, Any], rel_path: str) -> None:
        """Evaluates MCP server definitions for unpinned packages, hardcoded secrets, and plaintext transports."""
        for server_name, server_def in servers.items():
            if not isinstance(server_def, dict):
                continue

            cmd = server_def.get("command", "")
            args = server_def.get("args", [])
            env = server_def.get("env", {})
            url = server_def.get("url", "")

            # 1. Insecure Plaintext HTTP / WS URL
            if url and url.startswith(("http://", "ws://")):
                self._add_finding(
                    severity="HIGH",
                    category="MCP Transport",
                    file=rel_path,
                    line=0,
                    pattern="Plaintext MCP Endpoint",
                    match=f"Server '{server_name}': {url}",
                    detail="MCP server uses unencrypted HTTP/WS endpoint; susceptible to MITM interception",
                    cwe_id="CWE-319",
                )

            # 2. Unpinned NPX Package Installation
            if cmd == "npx" and isinstance(args, list):
                for arg in args:
                    if isinstance(arg, str) and not arg.startswith("-"):
                        # If package name lacks explicit version pin (@1.2.3)
                        if "@" not in arg.split("/")[-1]:
                            self._add_finding(
                                severity="HIGH",
                                category="MCP Supply Chain",
                                file=rel_path,
                                line=0,
                                pattern="Unpinned MCP NPX Package",
                                match=f"Server '{server_name}': npx {arg}",
                                detail=f"MCP server executes unpinned package '{arg}' via npx; vulnerable to supply chain hijacking",
                                cwe_id="CWE-1357",
                            )
                        break

            # 3. Hardcoded Secrets in Environment Variables
            if isinstance(env, dict):
                for k, v in env.items():
                    val_str = str(v).strip()
                    if val_str.startswith(("${", "$")):
                        continue  # Safe environment variable expansion

                    if SECRET_KEY_REGEX.search(k) and len(val_str) >= 8 and not is_placeholder(val_str):
                        self._add_finding(
                            severity="CRITICAL",
                            category="MCP Secret Exposure",
                            file=rel_path,
                            line=0,
                            pattern="Hardcoded Secret in MCP Config",
                            match=f"{k}={mask_secret(val_str)}",
                            detail=f"MCP server '{server_name}' hardcodes credentials in env['{k}'] instead of dynamic variable reference",
                            cwe_id="CWE-798",
                        )

            # 4. Hardcoded Secrets in Arguments
            if isinstance(args, list):
                for arg in args:
                    if isinstance(arg, str):
                        for match in re.finditer(r"--(?:api[_-]?key|secret|token|password)=([^\s]+)", arg, re.IGNORECASE):
                            val = match.group(1)
                            if not val.startswith("${") and not val.startswith("$") and not is_placeholder(val):
                                self._add_finding(
                                    severity="CRITICAL",
                                    category="MCP Secret Exposure",
                                    file=rel_path,
                                    line=0,
                                    pattern="Hardcoded Secret in MCP Arguments",
                                    match=mask_secret(val),
                                    detail=f"MCP server '{server_name}' specifies raw credentials in CLI argument list",
                                    cwe_id="CWE-798",
                                )

    def _scan_agent_and_git_hooks(self) -> None:
        """Audits hooks in .agent/hooks/, .claude/hooks/, .git/hooks/, and .husky/."""
        hook_dirs: list[Path] = [
            self.project_root / ".git" / "hooks",
            self.project_root / ".husky",
        ]
        for agent_dir in AGENT_DIRS:
            hook_dirs.append(self.project_root / agent_dir / "hooks")

        for hdir in hook_dirs:
            if not hdir.is_dir():
                continue

            for hook_file in hdir.iterdir():
                if not hook_file.is_file() or hook_file.name.endswith(".sample"):
                    continue

                rel_path = self._rel_path(hook_file)
                try:
                    with open(hook_file, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    # Remote execution chain
                    if re.search(r"(?:curl|wget).*\|\s*(?:bash|sh)", content, re.IGNORECASE):
                        self._add_finding(
                            severity="CRITICAL",
                            category="Hook Security",
                            file=rel_path,
                            line=0,
                            pattern="Remote Code Execution in Hook",
                            match=hook_file.name,
                            detail="Hook script downloads and pipes remote code to shell interpreter",
                            cwe_id="CWE-78",
                        )

                    # Environment harvesting
                    if re.search(r"(?:printenv|env\b|\$\{?(?:API|SECRET|KEY|TOKEN|PASSWORD|AWS))", content, re.IGNORECASE):
                        self._add_finding(
                            severity="HIGH",
                            category="Hook Security",
                            file=rel_path,
                            line=0,
                            pattern="Credential Access in Hook",
                            match=hook_file.name,
                            detail="Hook script accesses environment variables or secret parameters",
                            cwe_id="CWE-200",
                        )

                    # Silent file manipulation on sensitive configs
                    if re.search(r"sed\s+-i.*(?:\.env|settings\.json|mcp|auth)", content, re.IGNORECASE):
                        self._add_finding(
                            severity="HIGH",
                            category="Hook Security",
                            file=rel_path,
                            line=0,
                            pattern="Silent File Modification in Hook",
                            match=hook_file.name,
                            detail="Hook script silently modifies security configuration files via sed",
                            cwe_id="CWE-73",
                        )
                except OSError:
                    pass

    def _check_missing_agent_governance(self) -> None:
        """Advises creating an AGENTS.md file if no agent security boundaries are found."""
        self._add_finding(
            severity="LOW",
            category="Agent Governance",
            file="AGENTS.md",
            line=0,
            pattern="Missing Agent Security Boundaries (AGENTS.md)",
            match="No AGENTS.md, CLAUDE.md, GEMINI.md, or .cursorrules detected",
            detail="No agent instruction file or agent directory found; recommend establishing AGENTS.md with security boundaries",
            cwe_id="CWE-1188",
        )


def main() -> None:
    args = parse_args(
        prog_name="scan_ai_environment",
        description="Audits AI agent environment configuration, MCP servers, hooks, and permission boundaries.",
    )

    scanner = AIEnvironmentScanner(args.project_root)
    findings = scanner.scan(target_paths=args.target)

    if args.max_findings and len(findings) > args.max_findings:
        findings = findings[: args.max_findings]

    emit_findings(
        findings,
        as_json=args.json,
        no_color=args.no_color,
        title="Security Review: AI Agent Environment & Governance Scanner",
        project_root=args.project_root,
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
