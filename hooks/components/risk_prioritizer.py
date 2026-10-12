"""
Multi-Domain Risk Prioritizer Component
Categorizes candidate files across the 8 security disciplines into deterministic risk tiers:
- Tier 1 (50% quota = 25 files): Agent governance, secrets & keys, dependency manifests, CI/CD, IaC
- Tier 2 (40% quota = 20 files): Security sinks/handlers (auth, crypto, routes, DB) and entrypoints
- Tier 3 (10% quota = 5 files): Known lockfiles (retained for notices), utility scripts, documentation
Computes a balanced 50-file candidate allocation (MAX_FILES_TO_SCAN = 50) with dynamic backfilling.
"""
from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import ClassVar


class PrioritizationResult(tuple):
    """
    Tuple subclass representing prioritization outcome.
    Unpacks as (files, tier1_count, tier2_count) for seamless protocol compatibility,
    while exposing explicit attributes including tier3_count.
    """
    _files: list[Path]
    _t1: int
    _t2: int
    _t3: int

    def __new__(
        cls,
        files: list[Path],
        tier1_count: int,
        tier2_count: int,
        tier3_count: int = 0,
    ) -> PrioritizationResult:
        instance = super().__new__(cls, (files, tier1_count, tier2_count))
        instance._files = files
        instance._t1 = tier1_count
        instance._t2 = tier2_count
        instance._t3 = tier3_count
        return instance

    @property
    def files(self) -> list[Path]:
        return self._files

    @property
    def tier1_count(self) -> int:
        return self._t1

    @property
    def tier2_count(self) -> int:
        return self._t2

    @property
    def tier3_count(self) -> int:
        return self._t3


class RiskPrioritizer:
    """Categorizes and balances candidate files across all 8 security disciplines."""

    # -----------------------------------------------------------------------
    # Tier 1 Patterns & Definitions (High Attack Surfaces)
    # -----------------------------------------------------------------------

    # Agent Governance (Skills 1 & 8)
    AGENT_GOVERNANCE_FILES: ClassVar[set[str]] = {
        "agents.md",
        "claude.md",
        ".cursorrules",
        "mcp.json",
        "mcp-config.json",
        "gemini.md",
    }
    AGENT_GOVERNANCE_DIRS: ClassVar[tuple[str, ...]] = (
        ".agent",
        ".claude",
        ".gemini",
        ".cursor",
        ".husky",
    )

    # Secrets and Cryptographic Keys (Skill 2)
    SECRETS_PATTERNS: ClassVar[list[str]] = [
        ".env*",
        "*.env",
        "*.env.*",
        "*.pem",
        "*.key",
        "*.p12",
        "*.pfx",
        "*.pkcs12",
        "*.crt",
        "*.cer",
        "id_rsa*",
        "id_ed25519*",
        "id_dsa*",
        "id_ecdsa*",
        "credentials*",
        "*secret*.json",
        "*secret*.yaml",
        "*secret*.yml",
        "*secret*.toml",
        "*secret*.env",
    ]

    # Supply Chain Manifests (Skill 4) - Note: lockfiles are Tier 3
    SUPPLY_CHAIN_MANIFESTS: ClassVar[set[str]] = {
        "package.json",
        "requirements.txt",
        "pyproject.toml",
        "pipfile",
        "go.mod",
        "cargo.toml",
        "composer.json",
        "gemfile",
        "pom.xml",
        "setup.py",
        "setup.cfg",
    }
    SUPPLY_CHAIN_MANIFEST_PATTERNS: ClassVar[list[str]] = [
        "requirements*.txt",
        "build.gradle*",
        "settings.gradle*",
    ]

    # Infrastructure & CI/CD (Skill 7)
    INFRASTRUCTURE_PATTERNS: ClassVar[list[str]] = [
        "dockerfile*",
        "*.dockerfile",
        "docker-compose*.yml",
        "docker-compose*.yaml",
        "jenkinsfile*",
        "*.tf",
        "*.tfvars",
        "containerfile*",
    ]
    CI_CD_PATH_MARKERS: ClassVar[tuple[str, ...]] = (
        ".github/workflows",
        ".gitlab-ci",
        ".circleci",
        "azure-pipelines",
    )

    # -----------------------------------------------------------------------
    # Tier 2 Patterns & Definitions (Application Code & Entrypoints)
    # -----------------------------------------------------------------------

    # Security Handlers & Sinks (Skills 5 & 6 Boost)
    SECURITY_HANDLER_KEYWORDS: ClassVar[tuple[str, ...]] = (
        "auth",
        "jwt",
        "crypto",
        "session",
        "token",
        "login",
        "password",
        "security",
        "perm",
        "role",
        "rbac",
        "route",
        "controller",
        "handler",
        "api",
        "query",
        "db",
        "exec",
        "sink",
        "sanitize",
        "validator",
    )

    # Application Entrypoints
    ENTRYPOINT_PATTERNS: ClassVar[list[str]] = [
        "server.*",
        "app.*",
        "main.*",
        "index.*",
        "manage.py",
        "wsgi.py",
        "asgi.py",
    ]

    # General Application Source Extensions
    SOURCE_EXTENSIONS: ClassVar[set[str]] = {
        ".py",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".scala",
        ".cs",
        ".c",
        ".cpp",
        ".cc",
        ".cxx",
        ".h",
        ".hpp",
        ".php",
        ".rb",
        ".swift",
        ".lua",
        ".pl",
        ".pm",
        ".sql",
    }

    # -----------------------------------------------------------------------
    # Tier 3 Patterns & Definitions (Lockfiles, Utilities, General Docs)
    # -----------------------------------------------------------------------

    # Known lockfiles (Skill 4 notice targets)
    KNOWN_LOCKFILES: ClassVar[set[str]] = {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "cargo.lock",
        "go.sum",
        "composer.lock",
        "gemfile.lock",
        "bun.lockb",
        "bun.lock",
    }

    # Utility script extensions
    SCRIPT_EXTENSIONS: ClassVar[set[str]] = {
        ".sh",
        ".bash",
        ".zsh",
        ".bat",
        ".ps1",
    }

    @classmethod
    def is_agent_governance(cls, file_path: Path) -> bool:
        """Checks if file is an agent configuration or lifecycle hook."""
        fname = file_path.name.lower()
        if fname in cls.AGENT_GOVERNANCE_FILES:
            return True

        norm_parts = [p.lower() for p in file_path.parts]
        for part in norm_parts[:-1]:  # check parent directories
            if part in cls.AGENT_GOVERNANCE_DIRS:
                return True

        rel_str = str(file_path).replace("\\", "/").lower()
        return bool(".git/hooks" in rel_str or rel_str.startswith(".git/hooks"))


    @classmethod
    def is_lockfile(cls, fname: str) -> bool:
        """Checks if filename matches any known lockfile."""
        return fname.lower() in cls.KNOWN_LOCKFILES

    @classmethod
    def get_tier(cls, file_path: Path | str) -> int:
        """
        Determines the risk tier (1 = Critical/High Surface, 2 = Source/Security Sinks, 3 = Supporting/Lockfiles).
        Case-insensitive evaluation strictly prioritizes:
        - Agent governance, secrets, manifests, CI/CD -> Tier 1
        - Application entrypoints, security handlers, source code -> Tier 2
        - Lockfiles, utility scripts, documentation, fixtures -> Tier 3
        """
        path = Path(file_path)
        fname = path.name.lower()
        rel_str = str(path).replace("\\", "/").lower()

        # Lockfiles are always Tier 3 (must not be treated as generic Tier 1 JSON/YAML)
        if cls.is_lockfile(fname):
            return 3

        # -------------------------------------------------------------------
        # Check Tier 1: Agent Governance, Secrets, Manifests, CI/CD, IaC
        # -------------------------------------------------------------------
        if cls.is_agent_governance(path):
            return 1

        for marker in cls.CI_CD_PATH_MARKERS:
            if marker in rel_str:
                return 1

        # Check Secrets Patterns
        for pat in cls.SECRETS_PATTERNS:
            if fnmatch.fnmatch(fname, pat.lower()):
                return 1

        # Check Supply Chain Manifests (exact match)
        if fname in cls.SUPPLY_CHAIN_MANIFESTS:
            return 1

        # Check Supply Chain Manifest Patterns (glob match)
        for pat in cls.SUPPLY_CHAIN_MANIFEST_PATTERNS:
            if fnmatch.fnmatch(fname, pat.lower()):
                return 1

        # Check Infrastructure & IaC
        for pat in cls.INFRASTRUCTURE_PATTERNS:
            if fnmatch.fnmatch(fname, pat.lower()):
                return 1

        if any(marker in rel_str for marker in ("k8s/", "kubernetes/", "helm/")) and fname.endswith((".yaml", ".yml", ".json")):
            return 1


        # -------------------------------------------------------------------
        # Check Tier 2: Application Entrypoints, Security Sinks, Source Code
        # -------------------------------------------------------------------
        suffix = path.suffix.lower()

        # Check if file has source extension
        is_source = suffix in cls.SOURCE_EXTENSIONS

        # Check if file contains security keywords in name/stem
        has_security_keyword = any(kw in fname for kw in cls.SECURITY_HANDLER_KEYWORDS)

        # Check if file matches entrypoint patterns
        is_entrypoint = any(fnmatch.fnmatch(fname, pat.lower()) for pat in cls.ENTRYPOINT_PATTERNS)

        if is_source or has_security_keyword or is_entrypoint:
            return 2

        # -------------------------------------------------------------------
        # Fallback: Tier 3 (Lockfiles, scripts, docs, data fixtures, templates)
        # -------------------------------------------------------------------
        return 3

    @classmethod
    def _tier1_priority(cls, file_path: Path) -> int:
        """Sub-priority within Tier 1 (lower number = higher priority)."""
        fname = file_path.name.lower()
        if cls.is_agent_governance(file_path):
            return 0  # Agent governance (Skills 1 & 8)
        if any(fnmatch.fnmatch(fname, pat.lower()) for pat in cls.SECRETS_PATTERNS):
            return 1  # Secrets & keys (Skill 2)
        if fname in cls.SUPPLY_CHAIN_MANIFESTS or any(fnmatch.fnmatch(fname, p.lower()) for p in cls.SUPPLY_CHAIN_MANIFEST_PATTERNS):
            return 2  # Dependency manifests (Skill 4)
        return 3  # Infrastructure & CI/CD (Skill 7)

    @classmethod
    def _tier2_priority(cls, file_path: Path) -> int:
        """Sub-priority within Tier 2 (lower number = higher priority)."""
        fname = file_path.name.lower()
        if any(kw in fname for kw in cls.SECURITY_HANDLER_KEYWORDS):
            return 0  # Boosted security handlers & sinks (Skills 5 & 6)
        if any(fnmatch.fnmatch(fname, pat.lower()) for pat in cls.ENTRYPOINT_PATTERNS):
            return 1  # Application entrypoints (Skill 3)
        return 2  # General application source

    @classmethod
    def _tier3_priority(cls, file_path: Path) -> int:
        """Sub-priority within Tier 3 (lower number = higher priority)."""
        fname = file_path.name.lower()
        if cls.is_lockfile(fname):
            return 0  # Lockfiles retained for Skill 4 notice
        if file_path.suffix.lower() in cls.SCRIPT_EXTENSIONS:
            return 1  # Utility scripts
        return 2  # Docs, fixtures, fallback assets

    def prioritize(
        self,
        files: list[Path | str],
        max_allocation: int = 50,
    ) -> PrioritizationResult:
        """
        Sorts candidates across the 3 semantic tiers and balances them into max_allocation.

        Quota distribution (for max_allocation = 50):
        - Tier 1: up to 25 files (50%)
        - Tier 2: up to 20 files (40%)
        - Tier 3: up to 5 files (10%)
        - Backfills any unused quota slots dynamically across tiers in priority order (T1 -> T2 -> T3).

        Returns:
            PrioritizationResult tuple: (files, tier1_count, tier2_count, tier3_count)
        """
        if max_allocation <= 0 or not files:
            return PrioritizationResult([], 0, 0, 0)

        # Deduplicate while preserving input ordering
        seen: set[Path] = set()
        unique_paths: list[Path] = []
        for f in files:
            p = Path(f)
            if p not in seen:
                seen.add(p)
                unique_paths.append(p)

        tier1: list[Path] = []
        tier2: list[Path] = []
        tier3: list[Path] = []

        for p in unique_paths:
            tier = self.get_tier(p)
            if tier == 1:
                tier1.append(p)
            elif tier == 2:
                tier2.append(p)
            else:
                tier3.append(p)

        # Stable sort within each tier using domain sub-priority, path depth, and alphabetical name
        tier1.sort(key=lambda p: (self._tier1_priority(p), len(p.parts), str(p).lower()))
        tier2.sort(key=lambda p: (self._tier2_priority(p), len(p.parts), str(p).lower()))
        tier3.sort(key=lambda p: (self._tier3_priority(p), len(p.parts), str(p).lower()))

        # Saturated quota allocation
        q1 = round(max_allocation * 0.50)
        q2 = round(max_allocation * 0.40)
        q3 = max(0, max_allocation - q1 - q2)


        take1 = min(len(tier1), q1)
        take2 = min(len(tier2), q2)
        take3 = min(len(tier3), q3)

        selected1 = tier1[:take1]
        selected2 = tier2[:take2]
        selected3 = tier3[:take3]

        rem1 = tier1[take1:]
        rem2 = tier2[take2:]
        rem3 = tier3[take3:]

        # Backfill unused slots across tiers (Priority: Tier 1 -> Tier 2 -> Tier 3)
        remaining_slots = max_allocation - (len(selected1) + len(selected2) + len(selected3))

        if remaining_slots > 0 and rem1:
            backfill1 = rem1[:remaining_slots]
            selected1.extend(backfill1)
            remaining_slots -= len(backfill1)

        if remaining_slots > 0 and rem2:
            backfill2 = rem2[:remaining_slots]
            selected2.extend(backfill2)
            remaining_slots -= len(backfill2)

        if remaining_slots > 0 and rem3:
            backfill3 = rem3[:remaining_slots]
            selected3.extend(backfill3)
            remaining_slots -= len(backfill3)

        final_files = selected1 + selected2 + selected3

        return PrioritizationResult(
            files=final_files,
            tier1_count=len(selected1),
            tier2_count=len(selected2),
            tier3_count=len(selected3),
        )
