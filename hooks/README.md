# Capacity Gate and Discovery Hook Architecture

Deterministic, OS-level pre-tool execution gate and discovery engine designed for **`general-security-plugin`** to enforce computing boundaries, protect agent context windows, and balance scanning across all 8 security disciplines.
It is used by the orchestrator-general-security agent to protect agents context window from being overflowed by too many files or too large files.

---

## 1. Overview & Core Philosophy

The Capacity Gate Hook operates as an air-gap boundary and computing sizing guardrail for autonomous security audits. When an agent attempts to inspect files using tools such as `view_file`, `read_file`, or `grep_search`, the hook evaluates candidate targets against a 5-Dimensional Computing Sizing Contract before file content reaches the model context window.

### Core Architectural Principles
1. **Clean Code & Single Responsibility (SRP):** Each component has exactly one well-defined responsibility with zero external runtime dependencies (strictly Python standard library `>= 3.10`).
2. **Informative Guardrail, Not a Workflow Blocker:** Heavy dependency lockfiles (`package-lock.json`, `yarn.lock`, `poetry.lock`, `Cargo.lock`, etc.) generate clear, actionable notifications warning of high computing consumption rather than halting or failing the scan (`decision = allow`).
3. **Multi-Agent Runtime Portability:** Seamlessly compatible with Antigravity IDE, Claude Code, Cursor, Devin, GitHub Copilot, Codex, and Windsurf.
4. **End-to-End Traceability:** Every audit run is tagged with a unique `workflow_scan_id` (format `scan_<YYYYMMDD_HHMMSS>_<short_hex>`) and ISO UTC timestamp propagated across reports.

---

## 2. 5-Dimensional Computing Sizing Contract

1. **Candidate File Count Limit:** `MAX_FILES_TO_SCAN = 50` files maximum per scan.
2. **Single File Size Limit:** `MAX_SINGLE_FILE_SIZE_KB = 256 KB`. Files larger than 256 KB are pruned or warned to prevent context saturation.
3. **Aggregate Scan Size Guideline:** `MAX_AGGREGATE_SCAN_SIZE_MB = 2.0 MB` cumulative payload across the audit session.
4. **Line Length Limit:** `MAX_LINE_LENGTH = 1000` characters. Lines exceeding this limit trigger warnings to detect minified bundles or data dumps.
5. **Deterministic Latency & Reliability:** Sub-50ms execution overhead, standard library only, fail-safe exit code 0.

---

## 3. Architecture & Components

The hook architecture is organized into modular components adhering strictly to SRP:

| Component | Path | Responsibility |
| :--- | :--- | :--- |
| **Hook Contract** | [`hooks/hook_contract.py`](hook_contract.py) | Typed data structures (`WorkflowScanMetadata`, `InformativeNotice`, `CapacityLimits`, `DiscoveryReport`, `HookResult`), and JSON protocol I/O helpers. |
| **Archetype Detector** | [`hooks/components/archetype_detector.py`](components/archetype_detector.py) | Analyzes workspace root markers to detect ecosystems (Python, Node.js, Go, Rust, Java, etc.) and AI Agent workspace markers (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `mcp.json`). |
| **Exclusion Filter** | [`hooks/components/exclusion_filter.py`](components/exclusion_filter.py) | Prunes non-auditable directories (`node_modules`, `vendor`, `.venv`, `dist`, `build`, etc.) and binaries while preserving security dot-directories (`.agent`, `.claude`, `.cursor`, `.gemini`, `.husky`, CI/CD, `.git/hooks`) and lockfiles. |
| **Risk Prioritizer** | [`hooks/components/risk_prioritizer.py`](components/risk_prioritizer.py) | Saturated 3-tier semantic ranking across all 8 security disciplines: Tier 1 (50% quota = 25 files), Tier 2 (40% quota = 20 files with security handlers/entrypoints boosted), Tier 3 (10% quota = 5 files) with dynamic quota backfilling. |
| **Capacity Evaluator** | [`hooks/components/capacity_evaluator.py`](components/capacity_evaluator.py) | Evaluates candidate lists against 5D bounds and generates structured `InformativeNotice` warnings for heavy lockfiles and volume limits. |
| **Discovery Engine** | [`hooks/discovery_engine.py`](discovery_engine.py) | Unified orchestrator coordinating the 4 components and producing canonical `DiscoveryReport`. |
| **Capacity Gate Hook** | [`hooks/capacity_gate_hook.py`](capacity_gate_hook.py) | PreToolUse lifecycle entrypoint tracking cumulative session state in `/tmp/.general_security_scan_state/state_<session_id>.json`. |

---

## 4. Multi-Domain Skill Tiering & Allocation

To balance candidate selection across all 8 security disciplines within the `MAX_FILES_TO_SCAN = 50` boundary:

* **Tier 1 (High Attack Surfaces — Quota up to 25 files / 50%):**
  - **Agent Governance:** `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `mcp.json`, `mcp-config.json`, `.agent/*`, `.claude/*`, `.gemini/*`, `.husky/*`, `.git/hooks/*`
  - **Secrets & Keys:** `.env*`, `*.pem`, `*.key`, `id_rsa*`, `credentials*`
  - **Supply Chain Manifests:** `package.json`, `requirements.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `composer.json`
  - **Infrastructure & IaC:** `Dockerfile*`, `docker-compose*.yml`, `.github/workflows/*`, `*.tf`, `*.tfvars`
* **Tier 2 (Application Entrypoints & Security Logic — Quota up to 20 files / 40%):**
  - **Security Handlers & Sinks:** Files containing `auth`, `jwt`, `crypto`, `session`, `token`, `login`, `route`, `controller`, `handler`, `api`, `query`, `db`.
  - **Application Entrypoints:** `server.*`, `app.*`, `main.*`, `index.*`.
  - **Application Source Code:** General `.py`, `.ts`, `.js`, `.go`, `.java`, `.rs`, `.c`, etc.
* **Tier 3 (Supporting Assets & Lockfiles — Quota up to 5 files / 10%):**
  - Dependency lockfiles (`package-lock.json`, `yarn.lock`, `poetry.lock`, `Cargo.lock`, `go.sum`).
  - Auxiliary shell scripts (`*.sh`, `*.bash`).
  - Documentation and fixtures.

---

## 5. Non-Blocking Lockfile Exception Handling

When dependency lockfiles (`package-lock.json`, `yarn.lock`, `poetry.lock`, etc.) are detected:
- The hook **never halts or blocks** the audit (`decision = Decision.ALLOW`).
- An [`InformativeNotice`](hook_contract.py) is attached:
  ```json
  {
    "level": "WARNING",
    "code": "HIGH_COMPUTING_CONSUMPTION_LOCKFILE",
    "file": "package-lock.json",
    "size_kb": 512.4,
    "message": "Detected dependency lockfile: `package-lock.json` (512.4 KB). Ingesting full lockfiles into LLM context will provoke high computing consumption exceeding the 2.0 MB guideline.",
    "suggested_action": "Recommended: Run host script `python3 skills/audit-supply-chain-risk/scripts/scan_dependencies.py .` for deterministic dependency analysis without token overhead."
  }
  ```

---

## 6. Integration & Configuration

### PreToolUse Hook Configuration (`settings-addition.json`)
```json
{
  "plugins": {
    "general-security-plugin": {
      "enabled": true,
      "hooks": {
        "PreToolUse": [
          {
            "matcher": "view_file|read_file|grep_search",
            "hooks": [
              {
                "type": "command",
                "command": "python3 <absolute/path/to/repo>/general-security-plugin/hooks/capacity_gate_hook.py"
              }
            ]
          }
        ]
      }
    }
  }
}
```

### Agent Metadata Enforcement (`agents/orchestrator-security-review.md`)
```yaml
hook: python3 hooks/capacity_gate_hook.py
```

---

## 7. CLI Usage

### Standalone Discovery Engine
Run the discovery engine directly against any project workspace to preview archetypes, candidate files, and notices:

```bash
python3 hooks/discovery_engine.py /path/to/workspace
```
