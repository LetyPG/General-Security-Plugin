#!/usr/bin/env python3
"""
Dependency and Supply Chain Scanner.

Audits project dependencies, manifests, lockfiles, version pinning,
suspicious lifecycle scripts, and dependency confusion risks across package ecosystems:
- Node.js (package.json, npm, yarn, pnpm)
- Python (requirements.txt, pyproject.toml, Pipfile)
- Go (go.mod, go.sum)
- Rust (Cargo.toml, Cargo.lock)
- Ruby (Gemfile, Gemfile.lock)
- PHP (composer.json, composer.lock)
- Java (pom.xml, build.gradle)
"""
from __future__ import annotations

import json
import re
import subprocess
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
)

# Manifest to expected lockfiles mapping: manifest -> (lockfiles, ecosystem_name)
LOCKFILE_REQUIREMENTS: dict[str, tuple[tuple[str, ...], str]] = {
    "package.json": (
        ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"),
        "Node.js",
    ),
    "pyproject.toml": (
        ("poetry.lock", "uv.lock", "pdm.lock"),
        "Python",
    ),
    "Pipfile": (
        ("Pipfile.lock",),
        "Python (Pipenv)",
    ),
    "go.mod": (
        ("go.sum",),
        "Go",
    ),
    "Cargo.toml": (
        ("Cargo.lock",),
        "Rust",
    ),
    "Gemfile": (
        ("Gemfile.lock",),
        "Ruby",
    ),
    "composer.json": (
        ("composer.lock",),
        "PHP",
    ),
}

TRACKED_LOCKFILES: set[str] = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.lock",
    "go.sum",
    "Gemfile.lock",
    "composer.lock",
    "poetry.lock",
}

DANGEROUS_COMMAND_KEYWORDS = ("curl", "wget", "sh ", "bash ", "eval", "exec", "nc ", "http://", "https://")


class DependencyScanner:
    """Deterministic scanner for software supply-chain vulnerabilities."""

    def __init__(self, project_root: str | Path) -> None:
        self.project_root = Path(project_root).resolve()
        self.findings: list[Finding] = []
        self._finding_counter = 0

    def _next_id(self) -> int:
        self._finding_counter += 1
        return self._finding_counter

    def scan(self, target_paths: Sequence[str | Path] | None = None) -> list[Finding]:
        """Runs dependency and supply chain audit across project."""
        self.findings.clear()
        self._finding_counter = 0

        # If specific targets are provided (Option A), check if they are manifests
        manifests_to_check = self._resolve_target_manifests(target_paths)

        # 1. Lockfile verification
        self._check_lockfiles(manifests_to_check)

        # 2. Check .gitignore for lockfile exclusion
        self._check_gitignore_for_lockfiles()

        # 3. Version pinning analysis
        self._check_version_pinning(manifests_to_check)

        # 4. Dangerous lifecycle install scripts in package.json
        self._check_lifecycle_scripts(manifests_to_check)

        # 5. Dependency confusion risks
        self._check_dependency_confusion()

        return self.findings

    def _resolve_target_manifests(self, target_paths: Sequence[str | Path] | None) -> set[str]:
        """Identifies which manifests exist in the project or target paths."""
        known_manifests = {
            "package.json", "requirements.txt", "pyproject.toml",
            "Pipfile", "go.mod", "Cargo.toml", "Gemfile", "composer.json",
            "pom.xml", "build.gradle",
        }

        if target_paths:
            explicit = set()
            for tp in target_paths:
                p = Path(tp)
                name = p.name
                if name in known_manifests and (self.project_root / p).exists():
                    explicit.add(name)
            if explicit:
                return explicit

        return {m for m in known_manifests if (self.project_root / m).is_file()}

    def _check_lockfiles(self, manifests: set[str]) -> None:
        """Flags missing lockfiles when dependencies are defined."""
        for manifest, (expected_locks, ecosystem) in LOCKFILE_REQUIREMENTS.items():
            if manifest not in manifests:
                continue

            manifest_path = self.project_root / manifest
            if not manifest_path.exists():
                continue

            found_lock = any((self.project_root / lock).exists() for lock in expected_locks)
            if not found_lock:
                expected_str = ", ".join(expected_locks)
                self.findings.append(
                    Finding(
                        id=self._next_id(),
                        severity="CRITICAL",
                        category="SupplyChain",
                        file=manifest,
                        line=0,
                        pattern="Missing Lockfile",
                        match=f"No lockfile found for {manifest}",
                        detail=f"{ecosystem}: {manifest} exists but no lockfile found. Expected one of: {expected_str}",
                        cwe_id="CWE-1357",
                    )
                )

    def _check_gitignore_for_lockfiles(self) -> None:
        """Flags lockfiles listed in .gitignore (lockfiles should always be committed)."""
        gitignore_path = self.project_root / ".gitignore"
        if not gitignore_path.is_file():
            return

        try:
            with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, start=1):
                    cleaned = line.strip()
                    if not cleaned or cleaned.startswith("#"):
                        continue

                    for lockfile in TRACKED_LOCKFILES:
                        if lockfile in cleaned:
                            self.findings.append(
                                Finding(
                                    id=self._next_id(),
                                    severity="HIGH",
                                    category="SupplyChain",
                                    file=".gitignore",
                                    line=line_num,
                                    pattern="Lockfile in .gitignore",
                                    match=cleaned,
                                    detail=f"Lockfile '{lockfile}' is ignored in .gitignore — lockfiles must be committed to ensure reproducible builds",
                                    cwe_id="CWE-1357",
                                )
                            )
        except OSError:
            return

    def _check_version_pinning(self, manifests: set[str]) -> None:
        """Detects loose version ranges (wildcards, >=, latest) and unstable semver (^0.x)."""
        # Node.js: package.json
        if "package.json" in manifests:
            pkg_path = self.project_root / "package.json"
            try:
                with open(pkg_path, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)

                all_deps: dict[str, str] = {}
                for key in ("dependencies", "devDependencies", "peerDependencies"):
                    if isinstance(data.get(key), dict):
                        all_deps.update(data[key])

                for dep_name, version_spec in all_deps.items():
                    if not isinstance(version_spec, str):
                        continue

                    # Wildcard or loose ranges
                    if version_spec in ("*", "latest") or ">=" in version_spec:
                        self.findings.append(
                            Finding(
                                id=self._next_id(),
                                severity="HIGH",
                                category="SupplyChain",
                                file="package.json",
                                line=0,
                                pattern="Unpinned Dependency Range",
                                match=f'"{dep_name}": "{version_spec}"',
                                detail=f"Loose version range '{version_spec}' allows unexpected upstream modifications",
                                cwe_id="CWE-1104",
                            )
                        )
                    # Unstable 0.x caret ranges
                    elif version_spec.startswith("^0."):
                        self.findings.append(
                            Finding(
                                id=self._next_id(),
                                severity="MEDIUM",
                                category="SupplyChain",
                                file="package.json",
                                line=0,
                                pattern="Unstable Semver Range",
                                match=f'"{dep_name}": "{version_spec}"',
                                detail=f"Dependency '{dep_name}' on ^0.x has no semver stability guarantee",
                                cwe_id="CWE-1104",
                            )
                        )
            except (OSError, json.JSONDecodeError):
                pass

        # Python: requirements.txt
        if "requirements.txt" in manifests:
            req_path = self.project_root / "requirements.txt"
            try:
                with open(req_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, start=1):
                        cleaned = line.strip()
                        if not cleaned or cleaned.startswith(("#", "-r", "-i", "--")):
                            continue

                        # Check if line starts with package name but lacks exact '==' pin
                        if re.match(r"^[a-zA-Z0-9_\-\.]+", cleaned) and "==" not in cleaned:
                            self.findings.append(
                                Finding(
                                    id=self._next_id(),
                                    severity="HIGH",
                                    category="SupplyChain",
                                    file="requirements.txt",
                                    line=line_num,
                                    pattern="Unpinned Python Dependency",
                                    match=cleaned,
                                    detail=f"Dependency '{cleaned}' lacks exact version pinning (==<version>)",
                                    cwe_id="CWE-1104",
                                )
                            )
            except OSError:
                pass

    def _check_lifecycle_scripts(self, manifests: set[str]) -> None:
        """Inspects package.json scripts for dangerous postinstall/preinstall command hooks."""
        if "package.json" not in manifests:
            return

        pkg_path = self.project_root / "package.json"
        try:
            with open(pkg_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)

            scripts = data.get("scripts", {})
            if not isinstance(scripts, dict):
                return

            dangerous_hooks = ("postinstall", "preinstall", "install", "prepare")
            for hook_name in dangerous_hooks:
                cmd = scripts.get(hook_name)
                if isinstance(cmd, str) and any(kw in cmd for kw in DANGEROUS_COMMAND_KEYWORDS):
                    self.findings.append(
                        Finding(
                            id=self._next_id(),
                            severity="CRITICAL",
                            category="SupplyChain",
                            file="package.json",
                            line=0,
                            pattern="Suspicious Lifecycle Script",
                            match=f'"{hook_name}": "{cmd}"',
                            detail=f"Lifecycle script '{hook_name}' executes shell/network commands during install",
                            cwe_id="CWE-829",
                        )
                    )
        except (OSError, json.JSONDecodeError):
            pass

    def _check_dependency_confusion(self) -> None:
        """Audits package configuration for dependency confusion attack vectors."""
        pkg_path = self.project_root / "package.json"
        npmrc_path = self.project_root / ".npmrc"

        if pkg_path.is_file() and not npmrc_path.is_file():
            try:
                with open(pkg_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                # Check for scoped packages
                if re.search(r'"@[a-z0-9\-]+/', content):
                    self.findings.append(
                        Finding(
                            id=self._next_id(),
                            severity="MEDIUM",
                            category="SupplyChain",
                            file="package.json",
                            line=0,
                            pattern="Missing Scoped Registry Config",
                            match="Scoped dependencies without .npmrc",
                            detail="Scoped packages detected without local .npmrc registry specification (potential dependency confusion)",
                            cwe_id="CWE-829",
                        )
                    )
            except OSError:
                pass

        # Python pip extra-index-url check
        for pip_conf_name in ("pip.conf", "setup.cfg"):
            p = self.project_root / pip_conf_name
            if p.is_file():
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        for line_num, line in enumerate(f, start=1):
                            if "extra-index-url" in line:
                                self.findings.append(
                                    Finding(
                                        id=self._next_id(),
                                        severity="MEDIUM",
                                        category="SupplyChain",
                                        file=pip_conf_name,
                                        line=line_num,
                                        pattern="Insecure extra-index-url",
                                        match=line.strip(),
                                        detail="extra-index-url allows PyPI namespace confusion attacks; use find-links or trusted private index",
                                        cwe_id="CWE-829",
                                    )
                                )
                except OSError:
                    pass

    def run_npm_audit(self) -> list[Finding]:
        """Optional native npm audit runner if npm is installed."""
        if not (self.project_root / "package.json").is_file():
            return []

        try:
            result = subprocess.run(
                ["npm", "audit", "--production", "--json"],
                cwd=str(self.project_root),
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if result.stdout:
                audit_data = json.loads(result.stdout)
                vulns = audit_data.get("vulnerabilities", {})
                audit_findings = []
                for pkg_name, info in vulns.items():
                    sev = str(info.get("severity", "moderate")).upper()
                    if sev in ("CRITICAL", "HIGH"):
                        audit_findings.append(
                            Finding(
                                id=self._next_id(),
                                severity=sev,
                                category="SupplyChain",
                                file="package.json",
                                line=0,
                                pattern=f"npm audit vulnerability: {pkg_name}",
                                match=f"{pkg_name} ({sev})",
                                detail=f"Known CVE vulnerability reported by npm audit for {pkg_name}",
                                cwe_id="CWE-1395",
                            )
                        )
                return audit_findings
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
        return []


def main() -> None:
    args = parse_args(
        prog_name="scan_dependencies",
        description="Audits software supply chain, lockfiles, version pinning, and install scripts.",
    )

    scanner = DependencyScanner(args.project_root)
    findings = scanner.scan(target_paths=args.target)

    if args.max_findings and len(findings) > args.max_findings:
        findings = findings[: args.max_findings]

    emit_findings(
        findings,
        as_json=args.json,
        no_color=args.no_color,
        title="Security Review: Dependency & Supply Chain Scanner",
        project_root=args.project_root,
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
