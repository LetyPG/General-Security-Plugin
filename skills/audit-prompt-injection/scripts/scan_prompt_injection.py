#!/usr/bin/env python3
"""
Prompt Injection and Agent Manipulation Security Scanner.

Detects attacks designed to manipulate autonomous AI coding agents:
- Invisible unicode and zero-width characters (ZWSP, ZWNJ, etc.)
- Bidirectional control overrides (Trojan Source attack - CWE-1036)
- Agent-targeted directive overrides in code/comments
- Agent configuration integrity across all platforms (AGENTS.md, CLAUDE.md, GEMINI.md, .cursorrules)
- Encoded payloads in comments (Base64, Hex)
- Hidden elements in HTML/SVG/Markdown
- Package metadata prompt injection (package.json, pyproject.toml)
- Git & Husky hooks integrity
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
    parse_args,
    walk_project_files,
)

# Native Python Unicode regexes replacing external Perl dependency
ZWSP_REGEX = re.compile(r"[\u200B\u200C\u200D\u2060\uFEFF\u00AD]")
BIDI_REGEX = re.compile(r"[\u200E\u200F\u202A-\u202E\u2066-\u2069]")

# Agent directive keywords across multiple AI frameworks
AI_DIRECTIVE_PATTERNS = [
    r"ignore.*previous.*instruction",
    r"ignore.*above.*instruction",
    r"override.*(?:security|safety|restriction|permission|check)",
    r"you are now",
    r"new instruction",
    r"system prompt",
    r"forget.*(?:previous|above|earlier)",
    r"disregard.*(?:previous|above|earlier|all)",
    r"act as.*(?:admin|root|system|unrestricted)",
    r"maintenance mode",
    r"bypass.*(?:check|validation|security|auth|filter)",
    r"skip.*(?:security|validation|check|auth|verification)",
    r"disable.*(?:security|validation|check|auth|logging)",
    r"do not.*(?:log|report|alert|notify|check)",
    r"(?:AI|assistant|agent|model|Claude|GPT|LLM|Devin|Cursor|Copilot|Antigravity).*(?:execute|run|download|fetch|curl|send)",
    r"IMPORTANT.*(?:AI|assistant|agent|model).*(?:ignore|override|skip|bypass)",
    r"(?:hidden|secret).*instruction",
]
COMBINED_AI_DIRECTIVE_REGEX = re.compile("|".join(AI_DIRECTIVE_PATTERNS), re.IGNORECASE)

BASE64_COMMENT_REGEX = re.compile(
    r"(?://|#|/\*|\*|<!--)\s*.*(?:[A-Za-z0-9+/]{4}){15,}={0,2}"
)
HEX_COMMENT_REGEX = re.compile(
    r"(?://|#|/\*|\*|<!--)\s*.*(?:0x[0-9a-fA-F]{2}\s*){10,}"
)

# Agent instruction filenames across ecosystems
AGENT_INSTRUCTION_FILENAMES = {
    "agents.md",
    "claude.md",
    "gemini.md",
    ".cursorrules",
    "agent.md",
}

AGENT_DIRS = (".agent", ".claude", ".gemini", ".cursor")


class PromptInjectionScanner:
    """Deterministic scanner detecting prompt injection and agent manipulation vectors."""

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
        match: str = "",
        detail: str = "",
        cwe_id: str = "CWE-74",
    ) -> None:
        """Centralized helper to append structured findings without repeating boilerplate (DRY)."""
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
        """Runs prompt injection analysis across the codebase."""
        self.findings.clear()
        self._finding_counter = 0

        # Step 1: Discover text and code candidates
        candidate_files = walk_project_files(
            self.project_root,
            allowed_extensions={
                ".js", ".ts", ".jsx", ".tsx", ".py", ".rb", ".go", ".java", ".rs",
                ".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".sh", ".bash",
                ".html", ".htm", ".svg", ".xml", ".css", ".php", ".cs",
            },
            allowed_filenames={
                "agents.md", "claude.md", "gemini.md", ".cursorrules",
                "package.json", "pyproject.toml",
            },
            target_paths=target_paths,
        )

        has_agent_config = False

        for file_path in candidate_files:
            rel_path = self._rel_path(file_path)
            fname_lower = file_path.name.lower()

            # 1. Unicode & Directive line scanning
            self._scan_file_lines(file_path, rel_path)

            # 2. Agent Governance & Instruction integrity
            if fname_lower in AGENT_INSTRUCTION_FILENAMES:
                has_agent_config = True
                self._scan_agent_instruction_file(file_path, rel_path)

            # 3. Hidden elements in HTML/SVG/Markdown
            if file_path.suffix.lower() in (".html", ".htm", ".svg", ".md"):
                self._scan_hidden_elements(file_path, rel_path)

            # 4. Package metadata injection
            if fname_lower in ("package.json", "pyproject.toml"):
                self._scan_package_metadata(file_path, rel_path)

        # 5. Agent directories (.agent/, .claude/, .gemini/, .cursor/)
        if self._scan_agent_directories():
            has_agent_config = True

        # Check for missing agent configuration boundaries
        if not has_agent_config:
            self._check_missing_agent_config()

        # 6. Git and Husky hooks integrity
        self._scan_git_and_husky_hooks()

        return self.findings

    def _scan_file_lines(self, file_path: Path, rel_path: str) -> None:
        """Inspects line content for zero-width chars, bidi overrides, directives, and encoded blocks."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, start=1):
                    # Zero-width / invisible characters
                    zwsp_matches = ZWSP_REGEX.findall(line)
                    if zwsp_matches:
                        codepoints = ", ".join(f"U+{ord(c):04X}" for c in sorted(set(zwsp_matches)))
                        self._add_finding(
                            severity="CRITICAL",
                            category="Invisible Chars",
                            file=rel_path,
                            line=line_num,
                            pattern="Zero-Width Unicode Characters",
                            match=f"[Invisible zero-width character detected: {codepoints}]",
                            detail=f"Zero-width characters ({codepoints}) detected in file; may conceal instructions from human review",
                            cwe_id="CWE-1036",
                        )

                    # Bidirectional override characters (Trojan Source)
                    bidi_matches = BIDI_REGEX.findall(line)
                    if bidi_matches:
                        codepoints = ", ".join(f"U+{ord(c):04X}" for c in sorted(set(bidi_matches)))
                        self._add_finding(
                            severity="CRITICAL",
                            category="Bidi Override",
                            file=rel_path,
                            line=line_num,
                            pattern="Bidirectional Unicode Override",
                            match=f"[Bidi override character detected: {codepoints}]",
                            detail=f"Bidirectional control characters ({codepoints}) detected (Trojan Source attack vector)",
                            cwe_id="CWE-1036",
                        )

                    # Agent-targeted instructions
                    match = COMBINED_AI_DIRECTIVE_REGEX.search(line)
                    if match:
                        snippet = line.strip()[:100]
                        self._add_finding(
                            severity="CRITICAL",
                            category="Agent Directive",
                            file=rel_path,
                            line=line_num,
                            pattern="Agent Directive Override",
                            match=snippet,
                            detail="Directive addressing AI agents detected; review intent",
                            cwe_id="CWE-74",
                        )

                    # Encoded payloads in comments
                    b64_match = BASE64_COMMENT_REGEX.search(line)
                    if b64_match:
                        self._add_finding(
                            severity="HIGH",
                            category="Encoded Payload",
                            file=rel_path,
                            line=line_num,
                            pattern="Suspicious Base64 Comment",
                            match=line.strip()[:80],
                            detail="Suspicious base64-encoded block in comment — decode and verify content",
                            cwe_id="CWE-116",
                        )

                    hex_match = HEX_COMMENT_REGEX.search(line)
                    if hex_match:
                        self._add_finding(
                            severity="MEDIUM",
                            category="Encoded Payload",
                            file=rel_path,
                            line=line_num,
                            pattern="Hex-Encoded Comment",
                            match=line.strip()[:80],
                            detail="Hex-encoded byte block detected in comment",
                            cwe_id="CWE-116",
                        )
        except OSError:
            pass

    def _scan_agent_instruction_file(self, file_path: Path, rel_path: str) -> None:
        """Audits agent instruction files (AGENTS.md, CLAUDE.md, GEMINI.md, .cursorrules)."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            lines = content.splitlines()
            for line_num, line in enumerate(lines, start=1):
                clean = line.strip()

                if re.search(r"(?:always.*approve|auto.*(?:execute|approve|accept)|skip.*(?:confirm|permission|approval))", clean, re.IGNORECASE):
                    self._add_finding(
                        severity="CRITICAL",
                        category="Agent Config",
                        file=rel_path,
                        line=line_num,
                        pattern="Auto-Approve Directive",
                        match=clean,
                        detail="Instruction file contains auto-approve/skip-confirmation directive",
                        cwe_id="CWE-693",
                    )

                if re.search(r"(?:additional|more|extra|further).*instruction.*https?://", clean, re.IGNORECASE):
                    self._add_finding(
                        severity="CRITICAL",
                        category="Agent Config",
                        file=rel_path,
                        line=line_num,
                        pattern="External Instruction URL",
                        match=clean,
                        detail="Instruction file references external URL for additional instructions (untrusted context)",
                        cwe_id="CWE-829",
                    )

                if re.search(r"(?:bashrc|zshrc|profile|shell.*config|PATH.*export)", clean, re.IGNORECASE):
                    self._add_finding(
                        severity="HIGH",
                        category="Agent Config",
                        file=rel_path,
                        line=line_num,
                        pattern="Shell Modification Directive",
                        match=clean,
                        detail="Instruction file references shell environment configuration modification",
                        cwe_id="CWE-250",
                    )

                if "dangerously-skip-permissions" in clean:
                    self._add_finding(
                        severity="CRITICAL",
                        category="Agent Config",
                        file=rel_path,
                        line=line_num,
                        pattern="Dangerous Permission Flag",
                        match=clean,
                        detail="Instruction file references --dangerously-skip-permissions flag",
                        cwe_id="CWE-250",
                    )

            if re.search(r"(?:[A-Za-z0-9+/]{4}){12,}={0,2}", content):
                self._add_finding(
                    severity="HIGH",
                    category="Agent Config",
                    file=rel_path,
                    line=0,
                    pattern="Encoded Block in Agent Config",
                    match="Base64 encoded block detected",
                    detail="Agent instruction file contains large base64-encoded block",
                    cwe_id="CWE-116",
                )
        except OSError:
            pass

    def _scan_agent_directories(self) -> bool:
        """Audits settings and custom commands in .agent/, .claude/, .gemini/, .cursor/."""
        found_any = False
        for agent_dir in AGENT_DIRS:
            target_dir = self.project_root / agent_dir
            if not target_dir.is_dir():
                continue

            found_any = True
            settings_file = target_dir / "settings.json"
            if settings_file.is_file():
                try:
                    with open(settings_file, "r", encoding="utf-8", errors="ignore") as f:
                        settings_text = f.read()
                    if '"dangerously' in settings_text:
                        self._add_finding(
                            severity="CRITICAL",
                            category="Agent Config",
                            file=self._rel_path(settings_file),
                            line=0,
                            pattern="Dangerous Permission Override in Settings",
                            match="Dangerous permission flag in settings.json",
                            detail=f"{agent_dir}/settings.json contains dangerous permission override",
                            cwe_id="CWE-250",
                        )
                except OSError:
                    pass

            # Inspect custom commands / scripts
            for sub_name in ("commands", "scripts", "rules"):
                sub_dir = target_dir / sub_name
                if sub_dir.is_dir():
                    for cmd_file in sub_dir.glob("*"):
                        if cmd_file.is_file():
                            try:
                                with open(cmd_file, "r", encoding="utf-8", errors="ignore") as f:
                                    cmd_text = f.read()
                                if re.search(r"(?:curl|wget|nc|eval|exec|bash -c)", cmd_text, re.IGNORECASE):
                                    self._add_finding(
                                        severity="HIGH",
                                        category="Agent Config",
                                        file=self._rel_path(cmd_file),
                                        line=0,
                                        pattern="Dangerous Command in Agent Script",
                                        match=cmd_file.name,
                                        detail=f"Agent command file {cmd_file.name} executes potentially dangerous operations",
                                        cwe_id="CWE-78",
                                    )
                            except OSError:
                                pass
        return found_any

    def _check_missing_agent_config(self) -> None:
        """Recommends creating an AGENTS.md file if no agent boundaries are established."""
        self._add_finding(
            severity="LOW",
            category="Agent Config",
            file="AGENTS.md",
            line=0,
            pattern="Missing Agent Security Boundaries (AGENTS.md)",
            match="No AGENTS.md, CLAUDE.md, GEMINI.md, or .cursorrules found",
            detail="No agent instruction file or agent directory found; consider adding AGENTS.md with security boundaries",
            cwe_id="CWE-1188",
        )

    def _scan_hidden_elements(self, file_path: Path, rel_path: str) -> None:
        """Audits HTML, SVG, and Markdown files for hidden text containing AI directives."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # HTML / SVG hidden text
            if file_path.suffix.lower() in (".html", ".htm", ".svg"):
                if re.search(
                    r"(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|"
                    r"font-size\s*:\s*0|position\s*:\s*absolute.*left\s*:\s*-\d{4,}|"
                    r'style=["\'][^"\']*(?:display\s*:\s*none|opacity\s*:\s*0)[^"\']*["\'])'
                    r".*(?:AI|assistant|agent|instruction|execute|ignore|override|unrestricted)",
                    content,
                    re.IGNORECASE,
                ):
                    self._add_finding(
                        severity="CRITICAL",
                        category="Hidden Content",
                        file=rel_path,
                        line=0,
                        pattern="Hidden Element with AI Directive",
                        match="Hidden HTML/SVG text targeting AI",
                        detail="Hidden element styles (display:none/opacity:0) contain AI-targeted text",
                        cwe_id="CWE-74",
                    )

                if file_path.suffix.lower() == ".svg":
                    if re.search(
                        r'<text[^>]*(?:opacity=["\']0["\']|display=["\']none["\']|font-size=["\']0["\']|x=["\']-\d{4,})',
                        content,
                        re.IGNORECASE,
                    ):
                        self._add_finding(
                            severity="HIGH",
                            category="Hidden Content",
                            file=rel_path,
                            line=0,
                            pattern="Hidden Text in SVG",
                            match="Hidden text in SVG",
                            detail="SVG contains hidden text element (opacity=0, display=none, or off-screen)",
                            cwe_id="CWE-74",
                        )

                    if "<script" in content.lower():
                        self._add_finding(
                            severity="HIGH",
                            category="Hidden Content",
                            file=rel_path,
                            line=0,
                            pattern="SVG Contains Script Tag",
                            match="<script> in SVG",
                            detail="SVG image contains embedded <script> element",
                            cwe_id="CWE-79",
                        )
                    if "<foreignobject" in content.lower():
                        self._add_finding(
                            severity="MEDIUM",
                            category="Hidden Content",
                            file=rel_path,
                            line=0,
                            pattern="SVG ForeignObject Element",
                            match="<foreignObject> in SVG",
                            detail="SVG contains <foreignObject> capable of embedding arbitrary HTML",
                            cwe_id="CWE-79",
                        )

            # Markdown hidden HTML blocks
            elif file_path.suffix.lower() == ".md":
                if re.search(
                    r"<[^>]*(?:hidden|display:none)[^>]*>.*(?:AI|assistant|agent|instruction|execute|override)",
                    content,
                    re.IGNORECASE,
                ):
                    self._add_finding(
                        severity="CRITICAL",
                        category="Hidden Content",
                        file=rel_path,
                        line=0,
                        pattern="Hidden HTML in Markdown with AI Directive",
                        match="Hidden HTML in Markdown targeting AI",
                        detail="Hidden HTML tag in Markdown contains instructions addressed to AI agents",
                        cwe_id="CWE-74",
                    )
        except OSError:
            pass

    def _scan_package_metadata(self, file_path: Path, rel_path: str) -> None:
        """Audits package descriptions for AI instruction injections."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            suspicious_keywords = ("ai", "assistant", "agent", "instruction", "execute", "run", "curl", "wget", "bash")

            if file_path.name == "package.json":
                data = json.loads(content)
                desc = str(data.get("description", "")).lower()
                matched_kw = [kw for kw in suspicious_keywords if kw in desc]
                if matched_kw:
                    self._add_finding(
                        severity="MEDIUM",
                        category="Metadata Injection",
                        file=rel_path,
                        line=0,
                        pattern="Package Description Injection",
                        match=data.get("description", "")[:80],
                        detail=f"package.json description contains suspicious AI instruction keywords: {matched_kw}",
                        cwe_id="CWE-74",
                    )
            elif file_path.name == "pyproject.toml":
                if re.search(r'description\s*=\s*"[^"]*(?:AI|assistant|agent|instruction|execute|curl|bash)', content, re.IGNORECASE):
                    self._add_finding(
                        severity="MEDIUM",
                        category="Metadata Injection",
                        file=rel_path,
                        line=0,
                        pattern="pyproject.toml Description Injection",
                        match="Suspicious description field in pyproject.toml",
                        detail="pyproject.toml description contains AI instruction directives",
                        cwe_id="CWE-74",
                    )
        except (OSError, json.JSONDecodeError):
            pass

    def _scan_git_and_husky_hooks(self) -> None:
        """Audits Git hooks (.git/hooks/) and Husky hooks (.husky/) for exfiltration or network calls."""
        hook_targets: list[Path] = []

        git_hooks_dir = self.project_root / ".git" / "hooks"
        if git_hooks_dir.is_dir():
            hook_targets.extend(
                p for p in git_hooks_dir.iterdir()
                if p.is_file() and not p.name.endswith(".sample")
            )

        husky_dir = self.project_root / ".husky"
        if husky_dir.is_dir():
            hook_targets.extend(
                p for p in husky_dir.iterdir()
                if p.is_file() and not p.name.startswith("_")
            )

        for hook in hook_targets:
            rel_path = self._rel_path(hook)
            try:
                with open(hook, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                if re.search(r"(?:curl|wget|nc|ncat|fetch|http://|https://|ssh:|scp\s|rsync\s)", content, re.IGNORECASE):
                    self._add_finding(
                        severity="HIGH",
                        category="Git Hook",
                        file=rel_path,
                        line=0,
                        pattern="Network Access in Git Hook",
                        match=hook.name,
                        detail="Git hook initiates network connections; verify this is intentional",
                        cwe_id="CWE-829",
                    )

                if re.search(r"(?:base64.*decode|eval|exec.*\$)", content, re.IGNORECASE):
                    self._add_finding(
                        severity="CRITICAL",
                        category="Git Hook",
                        file=rel_path,
                        line=0,
                        pattern="Encoded Execution in Git Hook",
                        match=hook.name,
                        detail="Git hook contains encoded command execution or dynamic eval pattern",
                        cwe_id="CWE-78",
                    )

                if re.search(r"(?:printenv|env\b|\$\{?(?:API|SECRET|KEY|TOKEN|PASSWORD|AWS))", content, re.IGNORECASE):
                    self._add_finding(
                        severity="HIGH",
                        category="Git Hook",
                        file=rel_path,
                        line=0,
                        pattern="Environment Exfiltration in Git Hook",
                        match=hook.name,
                        detail="Git hook accesses environment variables or credentials",
                        cwe_id="CWE-200",
                    )
            except OSError:
                pass


def main() -> None:
    args = parse_args(
        prog_name="scan_prompt_injection",
        description="Scans project for prompt injection, zero-width characters, and AI agent manipulation.",
    )

    scanner = PromptInjectionScanner(args.project_root)
    findings = scanner.scan(target_paths=args.target)

    if args.max_findings and len(findings) > args.max_findings:
        findings = findings[: args.max_findings]

    emit_findings(
        findings,
        as_json=args.json,
        no_color=args.no_color,
        title="Security Review: Prompt Injection & Agent Integrity Scanner",
        project_root=args.project_root,
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
