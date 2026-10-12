# Skills Shared Infrastructure (`skills/common`)

> **Architectural Guidance & Design Rationale**
>
> **Notice for Developers & Agent Parsers:**  
> This directory (`skills/common/`) is an **internal shared infrastructure library** for deterministic Python scanning scripts across the plugin's skills.
> 
> * **It is NOT an AI Agent Skill:** It deliberately does **not** contain a `SKILL.md` file so that agent discovery engines (such as Antigravity, Claude Code, Cursor, Codex, Devin) do not index it as an LLM skill.
> * **Architectural Decision:** To adhere to **DRY (Don't Repeat Yourself)**, **Clean Code**, and **SOLID** principles, deterministic scanning scripts located in `skills/*/scripts/` require common functionality:
>   1. Structured finding data model (`Finding`).
>   2. Enforcing the **Zero-Raw-Secret Output Invariant** (deterministic credential masking).
>   3. Unified CLI argument parsing handling dynamic `${ARGUMENTS}` from agent tool calls and lifecycle hooks.
>   4. Safe filesystem traversal adhering to standard exclusion filters (`.git`, `node_modules`, `vendor`, `.venv`, etc.).
>   5. Standardized JSON and human-readable terminal reporting.
>
> Placing this module under `skills/common/` keeps the Python utilities co-located with the skill ecosystem while keeping the root namespace and hook architecture cleanly separated.

---

## Module Overview

| File | Purpose |
| :--- | :--- |
| [`__init__.py`](__init__.py) | Package initialization, architectural guidance header, and public interface exports. |
| [`schema.py`](schema.py) | `Finding` dataclass, `Severity` enum, and JSON serialization protocols. |
| [`masking.py`](masking.py) | Zero-Raw-Secret masking functions ensuring credentials are never emitted in plain text. |
| [`traversal.py`](traversal.py) | Safe file iteration respecting exclusion lists, maximum file sizes, and workspace bounds. |
| [`cli.py`](cli.py) | Unified argument parser supporting positional project paths, targeted file lists (`--target`), and `${ARGUMENTS}`. |
| [`reporter.py`](reporter.py) | Formatted terminal output with ANSI colors and canonical JSON report generation. |

---

## CLI Testing & Execution Helper

During automated agent workflows, these deterministic scripts consume candidate targets discovered and filtered by the **Capacity Gate Hook** (`hooks/capacity_gate_hook.py`) and **Discovery Engine** (`hooks/discovery_engine.py`) via `--target` or `${ARGUMENTS}`.

If a developer or auditor needs to manually test, debug, or verify any skill script directly from the command line, use this helper section as a quick reference.

### Universal CLI Arguments & Flags

All skill scripts consume the unified argument parser implemented in [`cli.py`](cli.py):

| Argument / Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `project_root` | Positional | `.` | Target project directory to scan (resolves to absolute path). |
| `--target`, `-t` | Optional list | `[]` | Specific files or directories to restrict scanning to (simulates hook-filtered targets). |
| `--json` | Flag | `False` | Emits structured JSON array to `stdout` for automated consumption. |
| `--no-color` | Flag | `False` | Disables ANSI color escapes (useful for raw logs or CI pipes). |
| `--max-findings` | Integer | `100` | Maximum number of findings to report before truncating. |

### Skill Scripts Reference Matrix

| Skill | Script Path | Security Focus | CLI Example |
| :--- | :--- | :--- | :--- |
| `audit-security-secrets` | `skills/audit-security-secrets/scripts/scan_secrets.py` | API keys, tokens, private keys (with Zero-Raw-Secret masking). | `python3 skills/audit-security-secrets/scripts/scan_secrets.py . --json` |
| `audit-code-vulnerabilities` | `skills/audit-code-vulnerabilities/scripts/scan_code_patterns.py` | Static code vulnerability patterns (OWASP Top 10). | `python3 skills/audit-code-vulnerabilities/scripts/scan_code_patterns.py .` |
| `audit-supply-chain-risk` | `skills/audit-supply-chain-risk/scripts/scan_dependencies.py` | Manifest dependencies, lockfiles, and untrusted registries. | `python3 skills/audit-supply-chain-risk/scripts/scan_dependencies.py . --json` |
| `audit-infrastructure` | `skills/audit-infrastructure/scripts/scan_infrastructure_configs.py` | Docker, Kubernetes, Terraform, and cloud IaC configurations. | `python3 skills/audit-infrastructure/scripts/scan_infrastructure_configs.py .` |
| `audit-prompt-injection` | `skills/audit-prompt-injection/scripts/scan_prompt_injection.py` | Direct/indirect prompt injection, delimiters, jailbreak patterns. | `python3 skills/audit-prompt-injection/scripts/scan_prompt_injection.py .` |
| `audit-ai-environment-scan` | `skills/audit-ai-environment-scan/scripts/scan_ai_environment.py` | Agent instructions (`AGENTS.md`), MCP configs, permission overrides. | `python3 skills/audit-ai-environment-scan/scripts/scan_ai_environment.py .` |
| `audit-injection-risk` | `skills/audit-injection-risk/scripts/scan_injections.py` | SQLi, Command Injection, XSS, Path Traversal, SSRF, SSTI. | `python3 skills/audit-injection-risk/scripts/scan_injections.py .` |
| `audit-auth-crypto` | `skills/audit-auth-crypto/scripts/scan_auth_crypto.py` | Weak hashing, JWT flaws, ECB ciphers, insecure PRNG, TLS flags. | `python3 skills/audit-auth-crypto/scripts/scan_auth_crypto.py .` |

### CLI Testing Scenarios

#### 1. Full Workspace Scan (Terminal Output)
```bash
python3 skills/audit-auth-crypto/scripts/scan_auth_crypto.py /path/to/project
```

#### 2. Emulating Hook-Targeted Discovery (Option A)
Simulate the Capacity Gate Hook passing high-priority candidate files to the script:
```bash
python3 skills/audit-code-vulnerabilities/scripts/scan_code_patterns.py . \
  --target src/auth.py src/database.py
```

#### 3. Structured JSON Output (Agent Tool Simulation)
Emit machine-readable JSON array matching the canonical finding schema:
```bash
python3 skills/audit-security-secrets/scripts/scan_secrets.py . --json
```

#### 4. CI/CD or Piped Output Without Colors
```bash
python3 skills/audit-injection-risk/scripts/scan_injections.py . --no-color --max-findings 50
```
