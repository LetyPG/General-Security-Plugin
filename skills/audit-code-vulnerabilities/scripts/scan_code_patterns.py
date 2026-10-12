#!/usr/bin/env python3
"""
Code Vulnerability Pattern Scanner.

Detects common security flaws and OWASP/CWE anti-patterns in source code:
- SQL Injection (CWE-89)
- Cross-Site Scripting (CWE-79)
- Command Injection (CWE-78)
- Insecure Deserialization (CWE-502)
- Cryptographic Weaknesses (CWE-327 / CWE-326)
- Path Traversal (CWE-22)
- Server-Side Request Forgery (CWE-918)
- XML External Entity (CWE-611)
- Information Disclosure / Debug Flags (CWE-209)
- NoSQL Injection (CWE-943)
"""
from __future__ import annotations

import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass
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


@dataclass(slots=True)
class VulnerabilityPattern:
    """Specification for a code vulnerability detection rule."""

    severity: str
    category: str
    description: str
    regex: re.Pattern[str]
    cwe_id: str
    target_extensions: set[str]


VULN_PATTERNS: list[VulnerabilityPattern] = [
    # ── SQL Injection (CWE-89) ──
    VulnerabilityPattern(
        severity="CRITICAL",
        category="SQLi",
        description="String interpolation in SQL query (JS/TS)",
        regex=re.compile(r"(?:query|execute|raw)\s*\(\s*`[^`]*\$\{"),
        cwe_id="CWE-89",
        target_extensions={".js", ".ts", ".jsx", ".tsx"},
    ),
    VulnerabilityPattern(
        severity="CRITICAL",
        category="SQLi",
        description="String concatenation in SQL query (JS/TS)",
        regex=re.compile(r"(?:query|execute)\s*\(\s*['\"][^'\"]*['\"]\s*\+"),
        cwe_id="CWE-89",
        target_extensions={".js", ".ts"},
    ),
    VulnerabilityPattern(
        severity="CRITICAL",
        category="SQLi",
        description="f-string or format in SQL query (Python)",
        regex=re.compile(r"(?:execute|cursor\.execute|\.query)\s*\(\s*f['\"]"),
        cwe_id="CWE-89",
        target_extensions={".py"},
    ),
    VulnerabilityPattern(
        severity="CRITICAL",
        category="SQLi",
        description="%-format in SQL query (Python)",
        regex=re.compile(r"execute\s*\(\s*['\"][^'\"]*%s[^'\"]*['\"]\s*%"),
        cwe_id="CWE-89",
        target_extensions={".py"},
    ),
    VulnerabilityPattern(
        severity="CRITICAL",
        category="SQLi",
        description="String format in SQL (Go)",
        regex=re.compile(r'fmt\.Sprintf\s*\(\s*"(?:SELECT|INSERT|UPDATE|DELETE|DROP)'),
        cwe_id="CWE-89",
        target_extensions={".go"},
    ),
    # ── Cross-Site Scripting (CWE-79) ──
    VulnerabilityPattern(
        severity="HIGH",
        category="XSS",
        description="dangerouslySetInnerHTML usage",
        regex=re.compile(r"dangerouslySetInnerHTML"),
        cwe_id="CWE-79",
        target_extensions={".jsx", ".tsx", ".js", ".ts"},
    ),
    VulnerabilityPattern(
        severity="HIGH",
        category="XSS",
        description="innerHTML assignment",
        regex=re.compile(r"\.innerHTML\s*="),
        cwe_id="CWE-79",
        target_extensions={".js", ".ts", ".jsx", ".tsx"},
    ),
    VulnerabilityPattern(
        severity="HIGH",
        category="XSS",
        description="document.write with dynamic content",
        regex=re.compile(r"document\.write\s*\("),
        cwe_id="CWE-79",
        target_extensions={".js", ".ts", ".html"},
    ),
    VulnerabilityPattern(
        severity="MEDIUM",
        category="XSS",
        description="jQuery .html() with dynamic parameter",
        regex=re.compile(r"\.\s*html\s*\(\s*[a-zA-Z]"),
        cwe_id="CWE-79",
        target_extensions={".js", ".ts"},
    ),
    # ── Command Injection (CWE-78) ──
    VulnerabilityPattern(
        severity="CRITICAL",
        category="CMDi",
        description="shell=True in subprocess (Python)",
        regex=re.compile(r"subprocess\.\w+\s*\([^)]*shell\s*=\s*True"),
        cwe_id="CWE-78",
        target_extensions={".py"},
    ),
    VulnerabilityPattern(
        severity="CRITICAL",
        category="CMDi",
        description="os.system() usage (Python)",
        regex=re.compile(r"os\.system\s*\("),
        cwe_id="CWE-78",
        target_extensions={".py"},
    ),
    VulnerabilityPattern(
        severity="CRITICAL",
        category="CMDi",
        description="os.popen() usage (Python)",
        regex=re.compile(r"os\.popen\s*\("),
        cwe_id="CWE-78",
        target_extensions={".py"},
    ),
    VulnerabilityPattern(
        severity="HIGH",
        category="CMDi",
        description="exec() with template literal (JS)",
        regex=re.compile(r"exec\s*\(\s*`"),
        cwe_id="CWE-78",
        target_extensions={".js", ".ts"},
    ),
    VulnerabilityPattern(
        severity="HIGH",
        category="CMDi",
        description="exec() with string concatenation (JS)",
        regex=re.compile(r"exec\s*\(\s*['\"][^'\"]*['\"]\s*\+"),
        cwe_id="CWE-78",
        target_extensions={".js", ".ts"},
    ),
    VulnerabilityPattern(
        severity="HIGH",
        category="CMDi",
        description="eval() dynamic code execution",
        regex=re.compile(r"\beval\s*\("),
        cwe_id="CWE-78",
        target_extensions={".js", ".ts", ".py", ".rb", ".php"},
    ),
    # ── Insecure Deserialization (CWE-502) ──
    VulnerabilityPattern(
        severity="CRITICAL",
        category="Deser",
        description="pickle.loads on untrusted data (Python)",
        regex=re.compile(r"pickle\.loads?\s*\("),
        cwe_id="CWE-502",
        target_extensions={".py"},
    ),
    VulnerabilityPattern(
        severity="HIGH",
        category="Deser",
        description="yaml.load without safe loader (Python)",
        regex=re.compile(r"yaml\.load\s*\("),
        cwe_id="CWE-502",
        target_extensions={".py"},
    ),
    VulnerabilityPattern(
        severity="HIGH",
        category="Deser",
        description="Marshal.load on untrusted data (Ruby)",
        regex=re.compile(r"Marshal\.load\s*\("),
        cwe_id="CWE-502",
        target_extensions={".rb"},
    ),
    # ── Cryptographic Issues (CWE-327 / CWE-326) ──
    VulnerabilityPattern(
        severity="HIGH",
        category="Crypto",
        description="Broken hash algorithm (MD5)",
        regex=re.compile(r"(?:hashlib\.md5|MD5\.Create|MessageDigest.*MD5|crypto\.createHash\s*\(\s*['\"]md5)"),
        cwe_id="CWE-327",
        target_extensions={".py", ".js", ".ts", ".java", ".cs", ".go"},
    ),
    VulnerabilityPattern(
        severity="HIGH",
        category="Crypto",
        description="Weak hash algorithm (SHA-1)",
        regex=re.compile(r"(?:hashlib\.sha1|SHA1\.Create|MessageDigest.*SHA-1|crypto\.createHash\s*\(\s*['\"]sha1)"),
        cwe_id="CWE-327",
        target_extensions={".py", ".js", ".ts", ".java", ".cs"},
    ),
    VulnerabilityPattern(
        severity="HIGH",
        category="Crypto",
        description="Math.random() in sensitive operation (JS)",
        regex=re.compile(r"Math\.random\s*\(\s*\)"),
        cwe_id="CWE-338",
        target_extensions={".js", ".ts"},
    ),
    VulnerabilityPattern(
        severity="HIGH",
        category="Crypto",
        description="Insecure random module for cryptography (Python)",
        regex=re.compile(r"import random[^_]|from random import"),
        cwe_id="CWE-338",
        target_extensions={".py"},
    ),
    VulnerabilityPattern(
        severity="CRITICAL",
        category="Crypto",
        description="TLS certificate verification disabled",
        regex=re.compile(
            r"(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|"
            r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]0|InsecureSkipVerify\s*:\s*true)"
        ),
        cwe_id="CWE-295",
        target_extensions={".py", ".js", ".ts", ".go"},
    ),
    # ── Path Traversal (CWE-22) ──
    VulnerabilityPattern(
        severity="HIGH",
        category="PathTrav",
        description="Potential path traversal in file operations (JS)",
        regex=re.compile(r"(?:readFile|writeFile|createReadStream|readFileSync)\s*\(\s*(?:req\.|params\.|query\.|body\.)"),
        cwe_id="CWE-22",
        target_extensions={".js", ".ts"},
    ),
    VulnerabilityPattern(
        severity="HIGH",
        category="PathTrav",
        description="Potential path traversal in file operations (Python)",
        regex=re.compile(r"(?:open|Path)\s*\(\s*(?:request\.|form\.|args\.)"),
        cwe_id="CWE-22",
        target_extensions={".py"},
    ),
    # ── SSRF (CWE-918) ──
    VulnerabilityPattern(
        severity="HIGH",
        category="SSRF",
        description="HTTP request with user-controlled URL (Python)",
        regex=re.compile(r"(?:requests\.get|requests\.post|urllib\.request\.urlopen|httpx\.\w+)\s*\(\s*(?:request\.|form\.|args\.|data\.)"),
        cwe_id="CWE-918",
        target_extensions={".py"},
    ),
    VulnerabilityPattern(
        severity="HIGH",
        category="SSRF",
        description="HTTP request with user-controlled URL (JS)",
        regex=re.compile(r"(?:fetch|axios\.\w+|http\.get|https\.get)\s*\(\s*(?:req\.|params\.|query\.|body\.)"),
        cwe_id="CWE-918",
        target_extensions={".js", ".ts"},
    ),
    # ── XML External Entity (CWE-611) ──
    VulnerabilityPattern(
        severity="HIGH",
        category="XXE",
        description="XML parsing without entity restrictions (Python)",
        regex=re.compile(r"(?:etree\.parse|minidom\.parse|sax\.parse|xml\.dom\.minidom\.parseString)\s*\("),
        cwe_id="CWE-611",
        target_extensions={".py"},
    ),
    VulnerabilityPattern(
        severity="HIGH",
        category="XXE",
        description="XML parser missing secure processing flag (Java)",
        regex=re.compile(r"DocumentBuilderFactory\.newInstance\s*\("),
        cwe_id="CWE-611",
        target_extensions={".java"},
    ),
    # ── Information Disclosure / Debug Flags (CWE-209) ──
    VulnerabilityPattern(
        severity="MEDIUM",
        category="InfoDisc",
        description="Stack trace or error details in response",
        regex=re.compile(r"(?:res\.(?:send|json|write)\s*\(\s*(?:err|error)\.(?:stack|message)|traceback\.format_exc)"),
        cwe_id="CWE-209",
        target_extensions={".js", ".ts", ".py"},
    ),
    VulnerabilityPattern(
        severity="MEDIUM",
        category="InfoDisc",
        description="Application debug mode enabled",
        regex=re.compile(r"(?:DEBUG\s*=\s*True|app\.debug\s*=\s*True|debug:\s*true)"),
        cwe_id="CWE-489",
        target_extensions={".py", ".js", ".ts", ".json", ".yaml", ".yml"},
    ),
    # ── NoSQL Injection (CWE-943) ──
    VulnerabilityPattern(
        severity="HIGH",
        category="NoSQLi",
        description="MongoDB query accepting direct request parameter",
        regex=re.compile(r"\.find\s*\(\s*(?:req\.body|req\.query|req\.params)"),
        cwe_id="CWE-943",
        target_extensions={".js", ".ts"},
    ),
    VulnerabilityPattern(
        severity="HIGH",
        category="NoSQLi",
        description="MongoDB $where clause with dynamic input",
        regex=re.compile(r"\$where.*(?:req\.|params\.|query\.|body\.)"),
        cwe_id="CWE-943",
        target_extensions={".js", ".ts"},
    ),
]

ALL_SUPPORTED_EXTENSIONS: set[str] = {
    ext for pattern in VULN_PATTERNS for ext in pattern.target_extensions
}


class CodePatternScanner:
    """Deterministic security scanner for code vulnerability patterns."""

    def __init__(self, project_root: str | Path) -> None:
        self.project_root = Path(project_root).resolve()
        self.findings: list[Finding] = []
        self._finding_counter = 0

    def _next_id(self) -> int:
        self._finding_counter += 1
        return self._finding_counter

    def scan(self, target_paths: Sequence[str | Path] | None = None) -> list[Finding]:
        """Runs line-by-line pattern matching across code files."""
        self.findings.clear()
        self._finding_counter = 0

        candidate_files = walk_project_files(
            self.project_root,
            allowed_extensions=ALL_SUPPORTED_EXTENSIONS,
            target_paths=target_paths,
        )

        for file_path in candidate_files:
            rel_path = self._rel_path(file_path)
            self._scan_file(file_path, rel_path)

        return self.findings

    def _rel_path(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.project_root))
        except ValueError:
            return str(path)

    def _scan_file(self, file_path: Path, rel_path: str) -> None:
        ext = file_path.suffix.lower()
        applicable_rules = [p for p in VULN_PATTERNS if ext in p.target_extensions]
        if not applicable_rules:
            return

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, start=1):
                    # Guardrail: skip minified / excessively long lines
                    if len(line) > 1000:
                        continue

                    for rule in applicable_rules:
                        match = rule.regex.search(line)
                        if match:
                            snippet = line.strip()[:120]
                            self.findings.append(
                                Finding(
                                    id=self._next_id(),
                                    severity=rule.severity,
                                    category=rule.category,
                                    file=rel_path,
                                    line=line_num,
                                    pattern=rule.description,
                                    match=snippet,
                                    detail=f"{rule.description} ({rule.cwe_id})",
                                    cwe_id=rule.cwe_id,
                                )
                            )
        except (OSError, UnicodeDecodeError):
            return


def main() -> None:
    args = parse_args(
        prog_name="scan_code_patterns",
        description="Scans source code files for OWASP Top 10 and common vulnerability patterns.",
    )

    scanner = CodePatternScanner(args.project_root)
    findings = scanner.scan(target_paths=args.target)

    if args.max_findings and len(findings) > args.max_findings:
        findings = findings[: args.max_findings]

    emit_findings(
        findings,
        as_json=args.json,
        no_color=args.no_color,
        title="Security Review: Code Vulnerability Pattern Scanner",
        project_root=args.project_root,
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
