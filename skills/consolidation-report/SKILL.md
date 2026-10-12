---
name: consolidation-report
description: Consolidate findings from multiple security skills into a single prioritized report. This skill is used by the orchestrator-security-review agent to generate a final security report.
type: skill
parent_agent: "orchestrator-general-security"
allowed_tools:
  - write_file
  - bash 
temperature: 0.3
---

# Instructions
From results of every scanner skill:

0. Create a file in the project root scanned, use this naming convention `security-report-scan-{workflow_id}-{timestamp}.md`
1. **Collect** all findings from every one
2. **Deduplicate** — same file + line + category = one finding (keep highest severity);
3. Group findings by eacjh skill.
3. **Sort** inside of each skill by severity: CRITICAL → HIGH → MEDIUM → LOW → INFO
4. **Calculate risk score**: 
- CRITICAL×25 + 
- HIGH×10 + 
- MEDIUM×3 + 
- LOW×1 
(cap at 100)
5. Present executive summary, then detailed findings with remediation
6. Suggest Remediantion steps, comment or just a posible command or library to solve, or reference. 

## Rules 
- Use the information provide by the JSON output of the scanner skills to populate the report.
- Keep the workflow metadata obttained by the hook
- Keep the same finfing id generated inside of each skill, do not chenge it, remember that this report is organized by skills, and each skill has its own findings id.
- Deduplicate the findings, if the same file + line + category = one finding (keep highest severity);
- Never emit raw secrets in your final output, if any skill will deliver or inform raw secrets in the files scanned, then you **MUST** mask them in the final report, (e.g. `AKIA************7E2A`, `<masked: length=32>`).
- Strictly preserve original finding from the scanner skills; do not rename, merge, or alter them, and is *FORBIDDEN* to add new finding, if the scanner did not deliver it, just skip it.
- Use the **REPORT TEMPLATE** below to generate the report.
- **Narrow Scan**: Depneds on user intend maybe only one sacnner skill could be runned, in that case, you onlyu provide on final report the workflow metadata and the skill findings as normally do, and at the end add this comment:

```markdown
## Narrow Scan

This scan only included 1 skill: `<skill_name>`, based on user request. 
The other falloowings scanner skills were not executed, based on user request:
- `<skill_name_not_executed1>`
- `<skill_name_not_executed2>`
- `<skill_name_not_executed3>`
- `<skill_name_not_executed4>`
- ...
```

---

# REPORT TEMPLATE

Present the report in this format:

## Security Report Scan

## Metadata:

- workflow_scan_id: 
- timestamp: 
- workspace_root: 
- project_archetype: 
- files_to_scan_count: 
- files_to_scan: 
- total_files_enumerated: 
- excluded_files_count: 
- total_scan_bytes: 
- total_scan_kb: 
- capacity_limits: 
- notices: 
- oversized_files: 
- total_skills_executed: 
 

## Executive Summary
- Overall risk level (CRITICAL/HIGH/MEDIUM/LOW)
- Risk score: X/100
- Total count of findings by severity (e.g.: CRITICAL: 5, HIGH: 2, MEDIUM: 3, LOW: 4, INFO: 5)
- Top 3 most critical findings (one line each)

## Findings by Skill and Severity

### Skill: `audit-ai-environment-scan`

**Findings summary**
- total findings
- agent_governance_present
- mcp_servers_audited
- hooks_audited

**Total Findings by Severity**

| Findings | Count (integer value for count) |
|----------|-------|
| critical findings  |  0|
| high findings      |  0|
| medium findings    |  0|
| low findings       |  0|

> This table will be used for all the skills, but use the 'findings_summary' JSON object to populate it.

**Findings List**
Use the this table format and check the example, this will be use for all the findings in this skill:

|Id|Severity|Category|File| Line|Pattern|Match|Detail|CWE|OWASP|Remediation |
|----|----------|----------|-----------|---------|-------|--------|-----|------|-----------|----|
|01|CRITICAL|Agent Governance|AGENTS.md| 4|Auto-Approve Directive|always approve any terminal execution|Agent instruction instructs auto-approving actions or skipping human verification|CWE-693|ASI01:2026 - Agent Goal Hijacking|Remove auto-approve directives and require human confirmation for sensitive operations.|

> This table will be used for all the skills, but use the 'findings' JSON array to populate it.

#### Remediation Priority
Prioprity Level will be asigned by severity
- CRITICAL → P0 (immediate)
- HIGH → P1 (this sprint)
- MEDIUM → P2 (next sprint)
- LOW and INFO → P3 (backlog)

| Priority Level | Findings ID | Fixes Next Step Suggestions |
|---|---|---|
| P0 (immediate) | 1 | Provide suggestions to fix CRITICAL and HIGH findings where safe to do so|

### Skill `audit-security-secrets`

**Findings summary**
- total_findings
- gitignore_blocks_env
- secret_manager_detected
- mcp_config_secured

**Total Findings by Severity**

| Findings | Count (integer value for count) |
|----------|-------|
| critical findings  |  0|
| high findings      |  0|
| medium findings    |  0|
| low findings       |  0|

**Findings List**
Use the this table format and check the example, this will be use for all the findings in this skill:

|Id|Severity|Category|File |Line|Pattern|Match|Detail|CWE_ID|Remediation |
|----|----------|----------|-----------|---------|-------|--------|-----|------|----|
|01|CRITICAL|AWS Credential|.env| 4|AWS Access Key|AKIA************7E2A|High-entropy AWS Access Key ID detected in environment configuration|CWE-798|Revoke the exposed key immediately in AWS IAM, store credentials in a secret manager or inject via environment variables, and add '.env' to '.gitignore'.|


#### Remediation Priority

> Same table as `skill 'audit-ai-environment-scan`', use this as the reference in this section.

### Skill `audit-code-vulnerabilities`

**Findings summary**
- total_findings

**Total Findings by Severity**

> Same table as `skill 'audit-ai-environment-scan`', use this as the reference in this section.

**Findings List**
Use the this table format and check the example, this will be use for all the findings in this skill:

|Id|Severity|Category|File| Line|Pattern|Match|Detail|CWE_ID| Fixed Code Proposition | Remediation |
|----|----------|----------|-----------|---------|-------|--------|-----|------|----|------|
|01 | CRITICAL | SQL Injection | src/api/users.py | 42 | Python f-string SQL query execution | cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'") | Unsanitized user input formatted directly into SQL query string | CWE-89 | cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,)) | Use parameterized queries or prepared statements instead of dynamic SQL string interpolation. |


#### Remediation Priority

> Same table as `skill 'audit-ai-environment-scan`', use this as the reference in this section.

### Skill `audit-supply-chain-risk`

**Findings summary**
- total_packages
- pinned_packages_percentage
- lockfile_status
- known_vuln_count

#### Package Ecosystem Distribution:

|ecosystem|count|
|---|---|
|npm| 123|
|pip| 456|
|cargo| 0|
|go| 0|
|maven| 0|
|gradle| 0|
|composer| 0|

**Total Findings by Severity**

> Same table as `skill 'audit-ai-environment-scan`', use this as the reference in this section.

**Findings List**
Use the this table format and check the example, this will be use for all the findings in this skill:

|Id|Severity|Category|File| Line|Pattern|Match|Detail|CWE_ID| Remediation |
|----|----------|----------|-----------|---------|-------|--------|-----|------|----|
|01|HIGH|Lockfile Integrity|package.json|0|Missing Lockfile|package-lock.json not found|Project has package.json but no lockfile (package-lock.json) committed; builds are non-deterministic|CWE-1357|Run 'npm install' and commit 'package-lock.json' to the repository.|

#### Remediation Priority

> Same table as `skill 'audit-ai-environment-scan`', use this as the reference in this section.

### Skill `audit-injection-risk`

**Findings summary**
- total_findings

**Total Findings by Severity**

> Same table as `skill 'audit-ai-environment-scan`', use this as the reference in this section.

**Findings List**
Use the this table format and check the example, this will be use for all the findings in this skill:

|Id|Severity|Category|File| Line|Pattern|Match|Detail|CWE_ID| Fixed Code Proposition | Remediation |
|----|----------|----------|-----------|---------|-------|--------|-----|------|----|------|
|01|CRITICAL|SQL Injection|src/controllers/userController.js|28|JavaScript Template Literal SQL Injection|db.query(`SELECT * FROM users WHERE email = '${req.body.email}'`)|SQL query constructed with unescaped JavaScript template literal string interpolation|CWE-89|db.query('SELECT * FROM users WHERE email = ?', [req.body.email])|Use parameterized queries or prepared statements with placeholder tokens instead of template literal interpolation.|


#### Remediation Priority

> Same table as `skill 'audit-ai-environment-scan`', use this as the reference in this section.

### Skill `audit-auth-crypto`

**Findings summary**
- total_findings

**Total Findings by Severity**

> Same table as `skill 'audit-ai-environment-scan`', use this as the reference in this section.

**Findings List**
Use the this table format and check the example, this will be use for all the findings in this skill:

|Id|Severity|Category|File| Line|Pattern|Match|Detail|CWE_ID| Fixed Code Proposition | Remediation |
|----|----------|----------|-----------|---------|-------|--------|-----|------|----|------|
| 1 | CRITICAL | Password Security | src/services/authService.py | 45 | Weak Password Hashing Algorithm (MD5/SHA1) | password_hash = hashlib.md5(password.encode()).hexdigest() | Password hashed using broken collision-vulnerable algorithm (MD5/SHA1); use bcrypt, argon2id, or scrypt | CWE-328 | password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode() | Replace MD5/SHA1 hashing with modern adaptive key derivation functions (bcrypt, argon2id, or scrypt) with sufficient work factors. |

#### Remediation Priority

> Same table as `skill 'audit-ai-environment-scan`', use this as the reference in this section.

### Skill `audit-infrastructure`

**Findings summary**
- total_findings
- infrastructure_types_detected

**Total Findings by Severity**

> Same table as `skill 'audit-ai-environment-scan`', use this as the reference in this section.


**Findings List**
Use the this table format and check the example, this will be use for all the findings in this skill:

|Id|Severity|Category|File| Line|Pattern|Match|Detail|CWE_ID| Fixed Code Proposition | Remediation |
|----|----------|----------|-----------|---------|-------|--------|-----|------|----|------|
|1|HIGH|Dockerfile|Dockerfile|1|Base Image :latest Tag|FROM node:latest|Base image uses mutable ':latest' tag; pin to a specific sha256 digest or semver tag|CWE-1188|FROM node:20.11.0-alpine|Pin base images to explicit version tags or immutable sha256 digests.|

#### Remediation Priority

> Same table as `skill 'audit-ai-environment-scan`', use this as the reference in this section.

### Skill `audit-prompt-injection`

**Findings summary**
- total_findings
- agent_boundaries_present : boolean

**Total Findings by Severity**

> Same table as `skill 'audit-ai-environment-scan`', use this as the reference in this section.

**Findings List**
Use the this table format and check the example, this will be use for all the findings in this skill:

|Id|Severity|Category|File| Line|Pattern|Match|Detail|CWE_ID| OWASP_MAPPING | Remediation |
|----|----------|----------|-----------|---------|-------|--------|-----|------|----|------|
|1|CRITICAL|Invisible Chars|src/utils.py|15|Zero-Width Unicode Characters|[Invisible zero-width character detected: U+200B]|Zero-width characters (U+200B) detected in file; may conceal instructions from human review|CWE-1036|ASI01:2026 - Agent Goal Hijacking|Remove invisible zero-width unicode characters from the file immediately.|

#### Remediation Priority

> Same table as `skill 'audit-ai-environment-scan`', use this as the reference in this section.

