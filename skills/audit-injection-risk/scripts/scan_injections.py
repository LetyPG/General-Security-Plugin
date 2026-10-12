#!/usr/bin/env python3
"""
Injection Vulnerability and Input Validation Security Scanner.

Deterministic static analysis script detecting:
- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- Cross-Site Scripting / XSS (CWE-79)
- Path Traversal (CWE-22)
- Server-Side Request Forgery / SSRF (CWE-918)
- Log Injection (CWE-117)
- NoSQL Injection (CWE-943)
- XML External Entity / XXE (CWE-611)
- Server-Side Template Injection / SSTI (CWE-1336)
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

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


@dataclass(slots=True, frozen=True)
class InjectionRule:
    """Declarative specification for an injection vulnerability pattern."""

    pattern_name: str
    category: str
    severity: str
    cwe_id: str
    regex: re.Pattern[str]
    detail: str
    extensions: tuple[str, ...] = (
        ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".php", ".cs"
    )


INJECTION_RULES: tuple[InjectionRule, ...] = (
    # ── 1. SQL INJECTION (CWE-89) ──
    InjectionRule(
        pattern_name="Python f-string SQL Injection",
        category="SQL Injection",
        severity="CRITICAL",
        cwe_id="CWE-89",
        regex=re.compile(
            r"""(?:cursor\.execute|\.raw|\.execute)\s*\(\s*f["'].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)""",
            re.IGNORECASE,
        ),
        detail="Dynamic SQL query formatted via Python f-string; use parameterized query placeholders instead",
        extensions=(".py",),
    ),
    InjectionRule(
        pattern_name="SQL Query String Formatting",
        category="SQL Injection",
        severity="CRITICAL",
        cwe_id="CWE-89",
        regex=re.compile(
            r"""(?:cursor\.execute|\.raw|\.execute)\s*\(\s*["'].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM).*["']\s*[%+]""",
            re.IGNORECASE,
        ),
        detail="SQL query constructed via string concatenation or '%' formatting operator",
        extensions=(".py",),
    ),
    InjectionRule(
        pattern_name="JavaScript Template Literal SQL Injection",
        category="SQL Injection",
        severity="CRITICAL",
        cwe_id="CWE-89",
        regex=re.compile(
            r"""(?:\.query|\.raw|sequelize\.query|knex\.raw)\s*\(\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^`]*\$\{""",
            re.IGNORECASE,
        ),
        detail="SQL query constructed with unescaped JavaScript template literal string interpolation",
        extensions=(".js", ".ts", ".jsx", ".tsx"),
    ),
    InjectionRule(
        pattern_name="Go fmt.Sprintf SQL Injection",
        category="SQL Injection",
        severity="CRITICAL",
        cwe_id="CWE-89",
        regex=re.compile(
            r"""\.(?:Query|Exec|QueryRow)\s*\(\s*fmt\.Sprintf\s*\(\s*["'].*(?:SELECT|INSERT|UPDATE|DELETE)""",
            re.IGNORECASE,
        ),
        detail="Go database query formatted using fmt.Sprintf instead of parameter placeholders",
        extensions=(".go",),
    ),
    InjectionRule(
        pattern_name="Java Concatenated SQL Execution",
        category="SQL Injection",
        severity="CRITICAL",
        cwe_id="CWE-89",
        regex=re.compile(
            r"""\.(?:executeQuery|executeUpdate)\s*\(\s*["'].*(?:SELECT|INSERT|UPDATE|DELETE).*["']\s*\+""",
            re.IGNORECASE,
        ),
        detail="Java Statement query constructed with string concatenation; use PreparedStatement",
        extensions=(".java",),
    ),

    # ── 2. COMMAND INJECTION (CWE-78) ──
    InjectionRule(
        pattern_name="Python os.system Command Execution",
        category="Command Injection",
        severity="CRITICAL",
        cwe_id="CWE-78",
        regex=re.compile(
            r"""os\.system\s*\(\s*(?:f["']|["'].*["']\s*[%+]|[a-zA-Z_]\w*\b)""",
            re.IGNORECASE,
        ),
        detail="os.system() called with dynamic expression; use subprocess.run with argument list",
        extensions=(".py",),
    ),
    InjectionRule(
        pattern_name="Python Subprocess Shell=True Execution",
        category="Command Injection",
        severity="CRITICAL",
        cwe_id="CWE-78",
        regex=re.compile(
            r"""subprocess\.(?:Popen|call|run|check_output|check_call)\s*\([^)]*shell\s*=\s*True""",
            re.IGNORECASE,
        ),
        detail="subprocess invoked with shell=True allowing command separation character injection",
        extensions=(".py",),
    ),
    InjectionRule(
        pattern_name="Node.js child_process.exec Command Injection",
        category="Command Injection",
        severity="CRITICAL",
        cwe_id="CWE-78",
        regex=re.compile(
            r"""(?:child_process\.)?(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*\+)""",
            re.IGNORECASE,
        ),
        detail="child_process.exec executes shell string with dynamic interpolation; use execFile or spawn",
        extensions=(".js", ".ts", ".jsx", ".tsx"),
    ),
    InjectionRule(
        pattern_name="Go Command Injection via Shell",
        category="Command Injection",
        severity="CRITICAL",
        cwe_id="CWE-78",
        regex=re.compile(
            r"""exec\.Command\s*\(\s*["'](?:sh|bash)["']\s*,\s*["']-c["']\s*,\s*(?!["'])""",
            re.IGNORECASE,
        ),
        detail="exec.Command invokes shell interpreter (-c) with dynamic command argument",
        extensions=(".go",),
    ),

    # ── 3. CROSS-SITE SCRIPTING / XSS (CWE-79) ──
    InjectionRule(
        pattern_name="Direct innerHTML Assignment (XSS)",
        category="Cross-Site Scripting",
        severity="HIGH",
        cwe_id="CWE-79",
        regex=re.compile(
            r"""\.(?:innerHTML|outerHTML)\s*=\s*(?!["'][^"']*["']\s*;)""",
            re.IGNORECASE,
        ),
        detail="Direct assignment to innerHTML without sanitization; use textContent or DOMPurify.sanitize",
        extensions=(".js", ".ts", ".jsx", ".tsx"),
    ),
    InjectionRule(
        pattern_name="React dangerouslySetInnerHTML Without Sanitization",
        category="Cross-Site Scripting",
        severity="HIGH",
        cwe_id="CWE-79",
        regex=re.compile(
            r"""dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:""",
            re.IGNORECASE,
        ),
        detail="dangerouslySetInnerHTML injects raw HTML into DOM; ensure input is sanitized with DOMPurify",
        extensions=(".js", ".ts", ".jsx", ".tsx"),
    ),
    InjectionRule(
        pattern_name="document.write Untrusted Sinks",
        category="Cross-Site Scripting",
        severity="HIGH",
        cwe_id="CWE-79",
        regex=re.compile(
            r"""document\.write(?:ln)?\s*\(""",
            re.IGNORECASE,
        ),
        detail="document.write can write unescaped HTML/script directly into document stream",
        extensions=(".js", ".ts", ".jsx", ".tsx", ".html"),
    ),

    # ── 4. PATH TRAVERSAL (CWE-22) ──
    InjectionRule(
        pattern_name="Python Unvalidated File Path Access",
        category="Path Traversal",
        severity="HIGH",
        cwe_id="CWE-22",
        regex=re.compile(
            r"""(?:open|send_file)\s*\([^)]*(?:request\.(?:args|form|values|GET|POST)|user_path|filename)\b""",
            re.IGNORECASE,
        ),
        detail="File accessed directly via request parameter without os.path.realpath prefix validation",
        extensions=(".py",),
    ),
    InjectionRule(
        pattern_name="Node.js fs Unvalidated Path Access",
        category="Path Traversal",
        severity="HIGH",
        cwe_id="CWE-22",
        regex=re.compile(
            r"""fs\.(?:readFile|readFileSync|createReadStream)\s*\([^)]*req\.(?:query|params|body)""",
            re.IGNORECASE,
        ),
        detail="fs operation receives req parameter without path resolution within a trusted root directory",
        extensions=(".js", ".ts", ".jsx", ".tsx"),
    ),

    # ── 5. SERVER-SIDE REQUEST FORGERY / SSRF (CWE-918) ──
    InjectionRule(
        pattern_name="Python Requests Dynamic URL (SSRF)",
        category="Server-Side Request Forgery",
        severity="HIGH",
        cwe_id="CWE-918",
        regex=re.compile(
            r"""requests\.(?:get|post|put|delete|patch)\s*\([^)]*(?:request\.(?:args|form|values)|req\.(?:query|params|body)|user_url|target_url)""",
            re.IGNORECASE,
        ),
        detail="HTTP request initiated with user-controlled URL without hostname allowlist validation",
        extensions=(".py",),
    ),
    InjectionRule(
        pattern_name="Node.js Fetch/Axios Dynamic URL (SSRF)",
        category="Server-Side Request Forgery",
        severity="HIGH",
        cwe_id="CWE-918",
        regex=re.compile(
            r"""(?:axios\.(?:get|post)|fetch)\s*\(\s*(?:req\.(?:query|params|body)|user_url|target_url)""",
            re.IGNORECASE,
        ),
        detail="Fetch or Axios client requests user-provided URL without domain allowlist and private IP check",
        extensions=(".js", ".ts", ".jsx", ".tsx"),
    ),

    # ── 6. LOG INJECTION (CWE-117) ──
    InjectionRule(
        pattern_name="Python Log Injection via Interpolation",
        category="Log Injection",
        severity="MEDIUM",
        cwe_id="CWE-117",
        regex=re.compile(
            r"""logger?\.(?:info|error|warn|warning|debug|critical)\s*\(\s*f["'].*(?:user|req|token|pass|input)""",
            re.IGNORECASE,
        ),
        detail="User input formatted into log message without newline sanitization; risks log forgery",
        extensions=(".py",),
    ),
    InjectionRule(
        pattern_name="JavaScript Console Log Interpolation",
        category="Log Injection",
        severity="MEDIUM",
        cwe_id="CWE-117",
        regex=re.compile(
            r"""console\.(?:log|warn|error)\s*\(\s*`[^`]*\$\{[^}]*(?:user|req|input|param)""",
            re.IGNORECASE,
        ),
        detail="Console logging unescaped user parameter string interpolation",
        extensions=(".js", ".ts", ".jsx", ".tsx"),
    ),

    # ── 7. NOSQL INJECTION (CWE-943) ──
    InjectionRule(
        pattern_name="MongoDB $where Dynamic Expression Injection",
        category="NoSQL Injection",
        severity="HIGH",
        cwe_id="CWE-943",
        regex=re.compile(
            r"""\$(?:where)\s*:\s*(?:`[^`]*\$\{|f["']|["'][^"']*["']\s*\+)""",
            re.IGNORECASE,
        ),
        detail="MongoDB $where clause constructed with dynamic string interpolation; evaluate with standard query operators",
        extensions=(".js", ".ts", ".py"),
    ),

    # ── 8. XML EXTERNAL ENTITY / XXE (CWE-611) ──
    InjectionRule(
        pattern_name="Insecure Python XML Parser (XXE)",
        category="XML External Entity",
        severity="HIGH",
        cwe_id="CWE-611",
        regex=re.compile(
            r"""(?:xml\.etree\.ElementTree|minidom)\.parse\s*\(""",
            re.IGNORECASE,
        ),
        detail="Standard xml.etree/minidom parses XML without disabling entity expansion; use defusedxml",
        extensions=(".py",),
    ),
    InjectionRule(
        pattern_name="Java DocumentBuilderFactory XML Parser (XXE)",
        category="XML External Entity",
        severity="HIGH",
        cwe_id="CWE-611",
        regex=re.compile(
            r"""DocumentBuilderFactory\.newInstance\s*\(\s*\)""",
            re.IGNORECASE,
        ),
        detail="DocumentBuilderFactory requires explicit FEATURE_SECURE_PROCESSING and disallow-doctype-decl",
        extensions=(".java",),
    ),

    # ── 9. SERVER-SIDE TEMPLATE INJECTION / SSTI (CWE-1336) ──
    InjectionRule(
        pattern_name="Jinja2 Template from Dynamic String (SSTI)",
        category="Template Injection",
        severity="CRITICAL",
        cwe_id="CWE-1336",
        regex=re.compile(
            r"""jinja2\.Template\s*\([^)]*(?:request\.|req\.|user_input)""",
            re.IGNORECASE,
        ),
        detail="jinja2.Template instantiated directly with user input string; enables arbitrary server-side code execution",
        extensions=(".py",),
    ),
    InjectionRule(
        pattern_name="Flask render_template_string Injection (SSTI)",
        category="Template Injection",
        severity="CRITICAL",
        cwe_id="CWE-1336",
        regex=re.compile(
            r"""render_template_string\s*\([^)]*(?:request\.|req\.|user_input)""",
            re.IGNORECASE,
        ),
        detail="render_template_string renders untrusted string directly as Jinja2 template",
        extensions=(".py",),
    ),
)


class InjectionScanner:
    """Deterministic scanner detecting injection vulnerabilities and input validation flaws."""

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
        """Scans candidate source files for injection vulnerabilities."""
        self.findings.clear()
        self._finding_counter = 0

        # Collect unique target extensions
        all_exts = {ext for rule in INJECTION_RULES for ext in rule.extensions}

        candidate_files = walk_project_files(
            self.project_root,
            allowed_extensions=all_exts,
            target_paths=target_paths,
        )

        for file_path in candidate_files:
            rel_path = self._rel_path(file_path)
            file_ext = file_path.suffix.lower()

            # Select applicable rules for this file type
            applicable_rules = [r for r in INJECTION_RULES if file_ext in r.extensions]
            if not applicable_rules:
                continue

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, start=1):
                        stripped = line.strip()
                        if not stripped or stripped.startswith(("//", "#", "/*", "*")):
                            continue

                        for rule in applicable_rules:
                            if rule.regex.search(line):
                                self._add_finding(
                                    severity=rule.severity,
                                    category=rule.category,
                                    file=rel_path,
                                    line=line_num,
                                    pattern=rule.pattern_name,
                                    match=stripped[:100],
                                    detail=rule.detail,
                                    cwe_id=rule.cwe_id,
                                )
            except OSError:
                pass

        return self.findings


def main() -> None:
    args = parse_args(
        prog_name="scan_injections",
        description="Scans project source code for SQLi, CMDi, XSS, Path Traversal, SSRF, Log Injection, NoSQLi, XXE, and SSTI.",
    )

    scanner = InjectionScanner(args.project_root)
    findings = scanner.scan(target_paths=args.target)

    if args.max_findings and len(findings) > args.max_findings:
        findings = findings[: args.max_findings]

    emit_findings(
        findings,
        as_json=args.json,
        no_color=args.no_color,
        title="Security Review: Injection Vulnerability & Input Validation Scanner",
        project_root=args.project_root,
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
