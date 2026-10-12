---
name: audit-code-vulnerabilities
description: Audits code for vulnerabilities including OWASP Top 10 and language-specific flaws.  Detects insecure defaults, missing input validation, prototype pollution, race conditions,  insecure deserialization, and AI-specific coding failure patterns. Use when reviewing source  code for security flaws or asking "is this code secure?". Triggers on: "code security review",  "vulnerability scan", "OWASP check", "CWE scan", "secure code review".
type: skill
parent_agent: "orchestrator-general-security"
allowed_tools:
  - find_files
  - list_directory
  - read_file
  - grep_search
  - glob
allowed_commands: python3 scan_code_patterns.py [project_root]
temperature: 0.2
---

# Instructions

- Focus exclusively on **code vulnerability detection**.
- Analyze source code for OWASP Top 10 vulnerabilities and language-specific security flaws, with special emphasis on patterns that AI code generators consistently get wrong.

## Context

> Recent attacks have demonstrated the risks:
> - Veracode's 2025-2026 studies: 45% of AI-generated code introduces OWASP Top 10 flaws.
> - Java 72% failure rate. XSS 86% failure. Log injection 88% failure. AI generates functional code but systematically misses input validation, output encoding, and secure defaults.

## Scanning Tool

You MUST use the tool, provided within `skills/audit-code-vulnerabilities/scripts/` directory using Python in the project directory where scanning will be done. 
This script will scan for common code vulnerabilites including OWASP Top 10 and language-specific flaws.  Detects insecure defaults, missing input validation, prototype pollution, race conditions,  insecure deserialization, and AI-specific coding failure patterns.

The complete command: `python3 scan_code_patterns.py [project_root]`.

## Scanning Goals & Methodology

### AI-Specific Failure Patterns (highest priority)

1. **Missing Input Validation** — HTTP handlers using request data without validation/schema
2. **Insecure Defaults** — `debug=True`, `CORS(app)` allow-all, hardcoded secret keys, `verify=False`
3. **Prototype Pollution / Mass Assignment** — Object spread/merge from untrusted input without allowlist
4. **Race Conditions** — Check-then-act in async code (especially financial operations)

### OWASP Top 10

- **A01 Broken Access Control**: Routes without auth, missing authorization, IDOR, CORS `*`
- **A02 Crypto Failures**: MD5/SHA1 for passwords, ECB mode, hardcoded keys, `Math.random()` for tokens
- **A04 Insecure Design**: Client-only business logic, no rate limits, account enumeration
- **A05 Misconfiguration**: Debug mode in prod, stack traces in errors, default credentials
- **A08 Integrity Failures**: `eval()`/`exec()` on user input, `pickle.loads()`, `yaml.load()`
- **A09 Logging Failures**: Sensitive data in logs, string interpolation in log calls, no auth logging

### Language-Specific

**JS/TS:** eval, innerHTML, dangerouslySetInnerHTML, document.write, ReDoS, Object.assign from untrusted
**Python:** pickle.loads, yaml.load, os.system, subprocess shell=True, f-string SQL, assert for security
**Go:** fmt.Sprintf in SQL, HTTP without timeouts, ioutil.ReadAll without limits, unchecked errors
**Java:** Runtime.exec concatenation, XML without XXE protection, ObjectInputStream untrusted
**Rust:** excessive unsafe, transmute on untrusted data, unchecked indexing, panic in library code

## Scanning Strategy

1. Identify entry points (HTTP handlers, CLI args, message consumers)
2. Trace data flow from input to storage/output
3. Check validation at each trust boundary
4. Verify output encoding for context (HTML, SQL, shell, logs)
5. Review error handling for information disclosure

## Output

The scanning script (`python3 scan_code_patterns.py --json`) generates findings matching the canonical schema (`id`, `severity`, `category`, `file`, `line`, `pattern`, `match`, `detail`, `cwe_id`).

You MUST deliver your final code vulnerability assessment as a structured JSON object adhering to the format below:

```json
{
  "summary": {
    "total_findings": 1,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "findings": [
    {
      "id": 1,
      "severity": "CRITICAL",
      "category": "SQL Injection",
      "file": "src/api/users.py",
      "line": 42,
      "pattern": "Python f-string SQL query execution",
      "match": "cursor.execute(f\"SELECT * FROM users WHERE id = '{user_id}'\")",
      "detail": "Unsanitized user input formatted directly into SQL query string",
      "cwe_id": "CWE-89",
      "fixed_code": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
      "remediation": "Use parameterized queries or prepared statements instead of dynamic SQL string interpolation."
    }
  ]
}
```

Key invariants:
- **Remediation Context**: For each finding, include `fixed_code` demonstrating the secure implementation pattern alongside the `remediation` explanation.
- **Traceability**: Preserve exact `file`, `line`, `match` (vulnerable snippet), and corresponding `cwe_id`.
