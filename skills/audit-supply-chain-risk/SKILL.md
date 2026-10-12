---
name: audit-supply-chain-risk
description:  Audit software supply chain risks. Audits dependencies, lockfiles, version pinning, typosquatting risks, dependency confusion, post-install scripts, and known vulnerabilities.  Use when auditing npm/pip/cargo/go dependencies or checking for supply chain attacks. Triggers on: "dependency audit", "supply chain security", "npm audit", "check dependencies", "lockfile review", "typosquatting check", "package security".
type: skill
parent_agent: "orchestrator-general-security"
allowed_tools:
  - find_files
  - list_directory
  - read_file
  - grep_search
  - glob
allowed_commands: "python3 scan_dependencies.py [project_root]"
temperature: 0.2
---

# Instructions

- Focuse exclusively on **software supply chain security**.
- Audit project dependencies lockfiles, version pinning, typosquatting risks, dependency confusion, post-install scripts, and known vulnerabilities.
- Audit `npm`, `pip`, `cargo`, `go` dependencies or checking for supply chain attacks

## Context

AI tools suggest packages from training data that may be outdated, deprecated, or non-existent.

> Recent attacks have demonstrated the risks:
> - SANDWORM_MODE (Feb 2026): 19 malicious npm packages targeting AI coding agents. 
> - litellm 1.82.8 PyPI attack (Mar 2026): harvested SSH keys and cloud credentials. 
> - Slopsquatting: attackers register AI-hallucinated package names.

## Scanning Tool

You MUST use the tool, provided within `skills/audit-supply-chain-risk/scripts/` directory using Python in the project directory where scanning will be done. 
This script audit dependencies for security issues
The complete command: `python3 scan_dependencies.py [project_root]`.

## Scanning Goals & Methodology 

### Dependency List for scan supply chain vulnerabilities:

The fallowing table show a guiding list, but the respective action sacning for each ecosystem  is comment bellow

| Manager | Typical manifest files/Ecosystem | Languages covered |
| --- | --- | --- |
| **npm / yarn / pnpm** | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | JavaScript, TypeScript |
| **PyPI / pip / poetry** | `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `pyproject.toml` | Python |
| **Cargo / crates.io** | `Cargo.toml`, `Cargo.lock` | Rust |
| **Go Modules** | `go.mod`, `go.sum` | Go / Golang |
| **RubyGems / bundler** | `Gemfile`, `Gemfile.lock` | Ruby |
| **Composer / Packagist** | `composer.json`, `composer.lock` | PHP |
| **Maven / Gradle** | `pom.xml`, `build.gradle`, `build.gradle.kts` | Java, Kotlin, Scala, Groovy |
| **SwiftPM / CocoaPods** | `Package.swift`, `Podfile.lock` | Swift, Objective-C |
| **Pub** | `pubspec.yaml`, `pubspec.lock` | Dart, Flutter |
| **NuGet** | `.csproj`, `packages.config`, `packages.lock.json` | C#, F#, .NET |
| **Hex** | `mix.exs`, `mix.lock` | Elixir, Erlang |
| **Conan / vcpkg** | `conanfile.txt`, `conan.lock`, `vcpkg.json` | C, C++ |
| **OS Packages (apk / apt / rpm)** | `/lib/apk/db/installed`, `/var/lib/dpkg/status`, `/var/lib/rpm` | Paquetes base de SO / Contenedores |
| **GitHub Actions** | `.github/workflows/*.yml`, `.github/workflows/*.yaml` | CI/CD actions y dependencias de pipeline |

### Scan procedure
You MUST perform an in-depth analysis of dependencies based on the following criteria checks:

#### 1. Lockfile Integrity
[x] For each ecosystem: verify lockfile EXISTS, is not gitignored, matches manifest.

**Ecosystems:** `package.json`, `requirements.txt`, `pyproject.toml`, `Pipfile`, `go.mod`, `Cargo.toml`,
`Gemfile`, `composer.json`, `pom.xml`, `build.gradle`.

#### 2. Version Pinning
[x] Flag: `"*"`, `"latest"`, `">=x"`, `"^0.x"` (unstable semver), git deps on branches not commits.

#### 3. Known Vulnerabilities
[x] Run: `npm audit --production --json`, `pip-audit`, `cargo audit`, or equivalent.

#### 4. Suspicious Packages
[x] Check for typosquatting patterns: missing/extra hyphen, char swap, scope confusion.
[x] Flag packages with very low downloads, very recent creation, single-package publishers.

#### 5. Dependency Confusion
[x] Private packages should use scoped names. .npmrc/pip.conf should specify private registry.
[x] `--extra-index-url` (Python) can enable confusion attacks.

#### 6. Post-Install Scripts
[x] Check package.json postinstall/preinstall/install/prepare scripts for curl/wget/bash/eval.
[x] Check setup.py for suspicious cmdclass overrides.

#### 7. AI Tool Dependencies
[x] LLM client libraries (anthropic, openai, langchain) must be exact-pinned.
[x] torch/tensorflow from official channels only.


#### 8. GitHub Actions Workflow Security
[x] Analyze `.github/workflows/*.yml` for sensitive operations:
  - `run:` commands that could execute arbitrary code
  - Use of `eval`, `curl | bash`, `wget | bash`
  - Unbounded glob patterns for file operations
  - Excessive permissions in `permissions:` blocks
  - `shell: bash` without explicit command sanitization

[x] Check for insecure package installation patterns:
  - Missing `actions/*` inputs for security configuration
  - Direct dependency on GitHub repositories without version pinning
  - Downloading and executing scripts from untrusted sources

### For each finding asign a severity level:
| Severity | Description |
| --- | --- |
| CRITICAL | Catastrophic security implications |
| HIGH | Major security implications |
| MEDIUM | Moderate security implications |
| LOW | Minor security implications |
| INFO | Informational |

## Output

The scanning script (`python3 scan_dependencies.py --json`) generates findings matching the canonical schema (`id`, `severity`, `category`, `file`, `line`, `pattern`, `match`, `detail`, `cwe_id`).

You MUST deliver your final supply chain assessment as a structured JSON object adhering to the format below:

```json
{
  "summary": {
    "total_packages": {
      "npm": 123,
      "pip": 456,
      "cargo": 0,
      "go": 0,
      "maven": 0,
      "gradle": 0,
      "composer": 0
    },
    "pinned_packages_percentage": 78.5,
    "lockfile_status": "warning",
    "known_vuln_count": 1
  },
  "findings": [
    {
      "id": 1,
      "severity": "HIGH",
      "category": "Lockfile Integrity",
      "file": "package.json",
      "line": 0,
      "pattern": "Missing Lockfile",
      "match": "package-lock.json not found",
      "detail": "Project has package.json but no lockfile (package-lock.json) committed; builds are non-deterministic",
      "cwe_id": "CWE-1357",
      "remediation": "Run 'npm install' and commit 'package-lock.json' to the repository."
    },
    {
      "id": 2,
      "severity": "MEDIUM",
      "category": "Version Pinning",
      "file": "requirements.txt",
      "line": 14,
      "pattern": "Unpinned Dependency",
      "match": "requests>=2.0.0",
      "detail": "Package 'requests' uses loose range '>=2.0.0'; risk of receiving untested breaking or malicious updates",
      "cwe_id": "CWE-1104",
      "remediation": "Pin dependency to an exact version (e.g., 'requests==2.31.0') or use pip-tools/poetry to lock transitive dependencies."
    }
  ]
}
```

Key invariants:
- **Ecosystem Summary**: Report package counts across all detected ecosystems, pinning percentage, and overall lockfile health.
- **Traceability**: Each finding preserves the canonical schema (`id`, `severity`, `category`, `file`, `line`, `pattern`, `match`, `detail`, `cwe_id`) with concrete `remediation`.