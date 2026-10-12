---
name: audit-security-secrets
description: Security auditor for hardcoded secrets, API keys, credentials, and .env files. Detects leaked AWS keys, Anthropic/OpenAI tokens, database connection strings, private keys, GitHub tokens, Stripe/Slack/SendGrid keys, MCP config credentials, and generic password assignments. Use when reviewing code for credential exposure, secrets scanning, or API key detection. Triggers on: "scan for secrets", "check for API keys", "credential audit", "secrets review", ".env security".
type: skill
parent_agent: "orchestrator-general-security"
allowed_tools:
  - find_files
  - list_directory
  - read_file
  - grep_search
  - glob
allowed_commands: python3 scan_secrets.py [project_root]
temperature: 0.3
---

# Instructions

- Focuse exclusively on **detecting hardcoded secrets,leaked credentials, exposed API keys, and insecure credential management** in codebases.
- Identify secrets and leaked credentials in all files in the project including source code, configs, env files, Docker files,


## Context

**A09 Logging Failures**: Sensitive data in logs, string interpolation in log calls, no auth logging

> Recent attacks have demonstrated the risks:
> - GitGuardian's 2026 report documented 28.65 million new hardcoded secrets in public GitHub
> commits during 2025. AI-assisted commits show a 3.2% secret-leak rate (2x the human baseline).
> - AI-service API keys increased 81% year-over-year with 1.27M detected leaks.

## Scanning Tool

You MUST use the tool, provided within `skills/audit-security-secrets/scripts/` directory using Python in the project directory where scanning will be done. 
This script will scan for hardcoded secrets, leaked credentials, exposed API keys, and insecure credential management.
The complete command: `python3 scan_secrets.py [project_root]`.

## Scanning Goals & Methodology

Scan ALL files in the project including source code, configs, env files, Docker files,
CI/CD configs, IaC, MCP configs, K8s manifests, notebooks, docs, and scripts.
Exclude: `.git/`, `node_modules/`, `vendor/`, `__pycache__/`, `dist/`, `build/`, `target/`.

Use the scanner script if available: `python3 scan_secrets.py .`
Then perform additional manual review for patterns the script may miss.

### Secret Patterns

**CRITICAL — always flag:**
- AWS Access Keys: `(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}`
- Private Keys: `-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`
- Anthropic API Keys: `sk-ant-[a-zA-Z0-9_-]{20,}`
- OpenAI API Keys: `sk-[a-zA-Z0-9]{48,}`
- Database connection strings with passwords: `(?:mongodb|postgres|mysql|redis)://[^:]+:[^@]+@`
- MCP config with hardcoded credentials (not `${VAR}` references)

**HIGH:**
- GitHub tokens: `gh[pousr]_[A-Za-z0-9_]{36,}`, `github_pat_[A-Za-z0-9_]{82}`
- Google API Keys: `AIza[0-9A-Za-z_-]{35}`
- Stripe: `[sr]k_(?:live|test)_[A-Za-z0-9]{20,}`
- Slack: `xox[boaprs]-[0-9a-zA-Z-]{10,}`
- SendGrid: `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`
- Twilio: `SK[0-9a-fA-F]{32}`
- Generic password assignments in source code
- .env files committed with real values
- .npmrc with `_authToken`

**MEDIUM:**
- JWT tokens in source code
- Azure keys
- Environment variable with hardcoded fallback values

### False Positive Filtering

Skip matches containing: `example`, `xxx`, `test`, `dummy`, `changeme`, `TODO`, `your-key-here`,
`INSERT_`, `REPLACE_`, `placeholder`, `<your-`. Flag test fixtures at LOW severity.

## CRITICAL RULE

NEVER include actual secret values in your output. Mask them: show first 4 and last 4 chars only.

## Output

The scanning script (`python3 scan_secrets.py --json`) generates findings matching the canonical schema (`id`, `severity`, `category`, `file`, `line`, `pattern`, `match`, `detail`, `cwe_id`).

You MUST deliver your final audit results as a structured JSON object adhering to the format below:

```json
{
  "summary": {
    "total_findings": 1,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0,
    "gitignore_blocks_env": false,
    "secret_manager_detected": false,
    "mcp_config_secured": true
  },
  "findings": [
    {
      "id": 1,
      "severity": "CRITICAL",
      "category": "AWS Credential",
      "file": ".env",
      "line": 4,
      "pattern": "AWS Access Key",
      "match": "AKIA************7E2A",
      "detail": "High-entropy AWS Access Key ID detected in environment configuration",
      "cwe_id": "CWE-798",
      "remediation": "Revoke the exposed key immediately in AWS IAM, store credentials in a secret manager or inject via environment variables, and add '.env' to '.gitignore'."
    }
  ]
}
```

Key invariants:
- **Zero-Raw-Secret Invariant**: Mask all secret values in `match` (show first 4 and last 4 characters only, or length token).
- **Environment Context**: Report whether `.gitignore` blocks `.env`/keys, whether secret management is in place, and if MCP configurations reference environment variables instead of raw keys.
