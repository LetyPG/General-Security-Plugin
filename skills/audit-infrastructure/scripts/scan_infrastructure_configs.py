#!/usr/bin/env python3
"""
Infrastructure and Configuration Security Scanner.

Audits cloud configurations, containers, pipelines, and IaC:
- Dockerfiles & docker-compose manifests
- CI/CD pipelines (GitHub Actions, GitLab CI)
- Terraform / IaC (*.tf, *.tfvars, *.tfstate)
- Kubernetes manifests (Pods, Deployments, Secrets)
- Package manager configs (.npmrc, pip.conf)
- Unrestricted CORS headers
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
    mask_secret,
    parse_args,
    walk_project_files,
)

SENSITIVE_PORTS = ("22", "3389", "3306", "5432", "27017")

CORS_REGEX = re.compile(
    r"Access-Control-Allow-Origin.*\*|cors\(\s*\)|origin:\s*(?:true|\*|['\"]?\*)",
    re.IGNORECASE,
)


@dataclass(slots=True)
class ConfigRule:
    """Declarative specification for line-level infrastructure configuration checks."""

    severity: str
    category: str
    pattern_name: str
    regex: re.Pattern[str]
    detail: str
    cwe_id: str
    mask_match: bool = False


# Declarative rule sets for line-by-line inspection (DRY & Open/Closed)
COMPOSE_RULES: list[ConfigRule] = [
    ConfigRule(
        severity="CRITICAL",
        category="Docker",
        pattern_name="Privileged Container",
        regex=re.compile(r"privileged:\s*true", re.IGNORECASE),
        detail="Container runs with extended host privileges, allowing potential container breakout",
        cwe_id="CWE-250",
    ),
    ConfigRule(
        severity="HIGH",
        category="Docker",
        pattern_name="Host Network Mode",
        regex=re.compile(r"network_mode:\s*['\"]?host['\"]?", re.IGNORECASE),
        detail="Container shares host network namespace, bypassing isolation boundaries",
        cwe_id="CWE-250",
    ),
    ConfigRule(
        severity="CRITICAL",
        category="Docker",
        pattern_name="Mounted Docker Socket",
        regex=re.compile(r"docker\.sock"),
        detail="Mounting docker.sock gives the container full root control over host Docker daemon",
        cwe_id="CWE-250",
    ),
    ConfigRule(
        severity="CRITICAL",
        category="Docker",
        pattern_name="Host Root Filesystem Mount",
        regex=re.compile(r"^\s*-\s+/:/\w"),
        detail="Host root filesystem (/) mounted inside container",
        cwe_id="CWE-250",
    ),
    ConfigRule(
        severity="HIGH",
        category="Docker",
        pattern_name="Hardcoded Credential in Compose",
        regex=re.compile(r"(?:PASSWORD|SECRET|KEY|TOKEN)=(?!\$\{)[^\s]+", re.IGNORECASE),
        detail="Credential hardcoded in docker-compose environment directive",
        cwe_id="CWE-798",
        mask_match=True,
    ),
]

WORKFLOW_RULES: list[ConfigRule] = [
    ConfigRule(
        severity="MEDIUM",
        category="CI/CD",
        pattern_name="Unpinned GitHub Action",
        regex=re.compile(r"uses:\s+[^@]+@v\d"),
        detail="Action pinned to mutable major tag (@vX) instead of immutable full commit SHA",
        cwe_id="CWE-1104",
    ),
    ConfigRule(
        severity="MEDIUM",
        category="CI/CD",
        pattern_name="Untrusted GitHub Context in Workflow",
        regex=re.compile(r"\$\{\{\s*github\.event\."),
        detail="Direct interpolation of github.event context into run blocks can enable command injection",
        cwe_id="CWE-78",
    ),
    ConfigRule(
        severity="HIGH",
        category="CI/CD",
        pattern_name="Workflow Write-All Permissions",
        regex=re.compile(r"permissions:\s*write-all"),
        detail="Workflow grants write-all permissions; adhere to principle of least privilege",
        cwe_id="CWE-250",
    ),
    ConfigRule(
        severity="MEDIUM",
        category="CI/CD",
        pattern_name="Self-Hosted Runner Usage",
        regex=re.compile(r"runs-on:\s*self-hosted"),
        detail="Self-hosted runners must be isolated from untrusted fork pull requests",
        cwe_id="CWE-250",
    ),
]

TERRAFORM_LINE_RULES: list[ConfigRule] = [
    ConfigRule(
        severity="CRITICAL",
        category="IaC",
        pattern_name="Hardcoded Credential in Terraform",
        regex=re.compile(r'(?:password|secret_key|access_key)\s*=\s*"(?!\$\{)', re.IGNORECASE),
        detail="Plaintext credential assigned in Terraform configuration",
        cwe_id="CWE-798",
        mask_match=True,
    ),
    ConfigRule(
        severity="HIGH",
        category="IaC",
        pattern_name="Public S3 Bucket ACL",
        regex=re.compile(r'acl\s*=\s*"public', re.IGNORECASE),
        detail="S3 bucket configured with public ACL",
        cwe_id="CWE-284",
    ),
    ConfigRule(
        severity="HIGH",
        category="IaC",
        pattern_name="Storage Encryption Disabled",
        regex=re.compile(r"encrypted\s*=\s*false", re.IGNORECASE),
        detail="Storage resource configured with encryption disabled",
        cwe_id="CWE-311",
    ),
]

K8S_LINE_RULES: list[ConfigRule] = [
    ConfigRule(
        severity="CRITICAL",
        category="K8s",
        pattern_name="Privileged K8s Container",
        regex=re.compile(r"privileged:\s*true"),
        detail="Container runs with privileged: true, allowing node takeover",
        cwe_id="CWE-250",
    ),
    ConfigRule(
        severity="HIGH",
        category="K8s",
        pattern_name="hostPath Volume Mount",
        regex=re.compile(r"^hostPath:"),
        detail="hostPath volume mounts can be abused for host node escape",
        cwe_id="CWE-250",
    ),
    ConfigRule(
        severity="HIGH",
        category="K8s",
        pattern_name="hostNetwork Enabled",
        regex=re.compile(r"hostNetwork:\s*true"),
        detail="hostNetwork enabled gives container access to node network interfaces",
        cwe_id="CWE-250",
    ),
]


class InfrastructureScanner:
    """Deterministic security scanner for infrastructure, container, and CI/CD configurations."""

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
        match: str = "",
        detail: str = "",
        cwe_id: str = "",
    ) -> None:
        """Centralized helper to append structured findings without repeating boilerplate (DRY)."""
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

    def _scan_lines_against_rules(
        self,
        lines: Sequence[str],
        rel_path: str,
        rules: Sequence[ConfigRule],
    ) -> None:
        """Evaluates a collection of lines against a declarative set of ConfigRules."""
        for line_num, line in enumerate(lines, start=1):
            clean = line.strip()
            for rule in rules:
                if rule.regex.search(clean):
                    match_val = mask_secret(clean) if rule.mask_match else clean[:80]
                    self._add_finding(
                        severity=rule.severity,
                        category=rule.category,
                        file=rel_path,
                        line=line_num,
                        pattern=rule.pattern_name,
                        match=match_val,
                        detail=rule.detail,
                        cwe_id=rule.cwe_id,
                    )

    def scan(self, target_paths: Sequence[str | Path] | None = None) -> list[Finding]:
        """Runs infrastructure and config audits across project or targeted paths."""
        self.findings.clear()
        self._finding_counter = 0

        candidate_files = walk_project_files(
            self.project_root,
            allowed_extensions={
                ".tf", ".tfvars", ".tfstate", ".yaml", ".yml",
                ".json", ".js", ".ts", ".py", ".conf",
            },
            allowed_filenames={
                "dockerfile", "containerfile", ".dockerignore",
                ".gitlab-ci.yml", ".npmrc", "pip.conf",
            },
            target_paths=target_paths,
        )

        for file_path in candidate_files:
            fname = file_path.name.lower()
            rel_path = self._rel_path(file_path)

            if fname.startswith(("dockerfile", "containerfile")) or file_path.suffix.lower() == ".dockerfile":
                self._scan_dockerfile(file_path, rel_path)
            elif "docker-compose" in fname or fname in ("compose.yml", "compose.yaml"):
                self._scan_docker_compose(file_path, rel_path)
            elif ".github/workflows" in str(file_path) and file_path.suffix.lower() in (".yml", ".yaml"):
                self._scan_github_workflow(file_path, rel_path)
            elif fname == ".gitlab-ci.yml":
                self._scan_gitlab_ci(file_path, rel_path)
            elif file_path.suffix.lower() == ".tf":
                self._scan_terraform(file_path, rel_path)
            elif file_path.suffix.lower() == ".tfvars":
                self._scan_tfvars(file_path, rel_path)
            elif file_path.suffix.lower() == ".tfstate":
                self._scan_tfstate(rel_path)
            elif file_path.suffix.lower() in (".yml", ".yaml"):
                self._scan_kubernetes(file_path, rel_path)
            elif fname == ".npmrc":
                self._scan_npmrc(file_path, rel_path)
            elif fname == "pip.conf":
                self._scan_pip_conf(file_path, rel_path)

            if file_path.suffix.lower() in (".js", ".ts", ".py"):
                self._scan_cors(file_path, rel_path)

        return self.findings

    def _scan_dockerfile(self, file_path: Path, rel_path: str) -> None:
        """Audits Dockerfile for root user, untagged images, and sensitive arguments."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            has_user = False
            for line_num, line in enumerate(lines, start=1):
                clean_line = line.strip()

                if clean_line.startswith("FROM "):
                    if ":latest" in clean_line:
                        self._add_finding(
                            severity="HIGH",
                            category="Docker",
                            file=rel_path,
                            line=line_num,
                            pattern="Base Image :latest Tag",
                            match=clean_line,
                            detail="Using :latest tag allows untested upstream changes; pin to specific digest or immutable version tag",
                            cwe_id="CWE-1104",
                        )
                    elif ":" not in clean_line and "scratch" not in clean_line.lower():
                        self._add_finding(
                            severity="HIGH",
                            category="Docker",
                            file=rel_path,
                            line=line_num,
                            pattern="Untagged Base Image",
                            match=clean_line,
                            detail="No base image tag specified (implies :latest)",
                            cwe_id="CWE-1104",
                        )

                if clean_line.startswith("USER "):
                    has_user = True

                if re.search(r"^(?:ENV|ARG)\s+.*(?:PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL)\s*=", clean_line, re.IGNORECASE):
                    self._add_finding(
                        severity="CRITICAL",
                        category="Docker",
                        file=rel_path,
                        line=line_num,
                        pattern="Sensitive ENV/ARG in Dockerfile",
                        match=clean_line[:80],
                        detail="Sensitive credential declared in Dockerfile ARG/ENV persists in container image layer history",
                        cwe_id="CWE-798",
                    )

                if re.match(r"^COPY\s+\.\s+", clean_line):
                    dockerignore = file_path.parent / ".dockerignore"
                    if not dockerignore.is_file():
                        self._add_finding(
                            severity="MEDIUM",
                            category="Docker",
                            file=rel_path,
                            line=line_num,
                            pattern="COPY . without .dockerignore",
                            match=clean_line,
                            detail="COPY . without .dockerignore may inadvertently package sensitive files (.git, .env) into image",
                            cwe_id="CWE-200",
                        )

                if re.match(r"^ADD\s+https?://", clean_line):
                    self._add_finding(
                        severity="MEDIUM",
                        category="Docker",
                        file=rel_path,
                        line=line_num,
                        pattern="ADD with Remote URL",
                        match=clean_line,
                        detail="ADD with remote URL bypasses package verification; use curl/wget with SHA256 checksum verification",
                        cwe_id="CWE-829",
                    )

            if not has_user:
                self._add_finding(
                    severity="HIGH",
                    category="Docker",
                    file=rel_path,
                    line=0,
                    pattern="Missing USER Directive",
                    match="No USER directive defined",
                    detail="Container executes as root by default; specify a non-root USER",
                    cwe_id="CWE-250",
                )
        except OSError:
            pass

    def _scan_docker_compose(self, file_path: Path, rel_path: str) -> None:
        """Audits docker-compose files for privileged mode, sockets, and mounts via COMPOSE_RULES."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            self._scan_lines_against_rules(lines, rel_path, COMPOSE_RULES)
        except OSError:
            pass

    def _scan_github_workflow(self, file_path: Path, rel_path: str) -> None:
        """Audits GitHub Actions workflow files for untrusted checkouts, injection, and unpinned actions."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            lines = content.splitlines()
            self._scan_lines_against_rules(lines, rel_path, WORKFLOW_RULES)

            # Context-aware pull_request_target checkout analysis
            if "pull_request_target" in content:
                if re.search(r"ref.*pull_request\.head", content):
                    self._add_finding(
                        severity="CRITICAL",
                        category="CI/CD",
                        file=rel_path,
                        line=0,
                        pattern="pull_request_target with Head Checkout",
                        match="pull_request_target + ref: pull_request.head",
                        detail="Dangerous combination: pull_request_target runs in repo context while checking out untrusted PR head",
                        cwe_id="CWE-829",
                    )
                else:
                    self._add_finding(
                        severity="HIGH",
                        category="CI/CD",
                        file=rel_path,
                        line=0,
                        pattern="pull_request_target Trigger",
                        match="on: pull_request_target",
                        detail="pull_request_target runs with repository write permissions and secrets; verify workflow safety",
                        cwe_id="CWE-829",
                    )
        except OSError:
            pass

    def _scan_gitlab_ci(self, file_path: Path, rel_path: str) -> None:
        """Audits GitLab CI configuration for hardcoded secrets and bypassed security jobs."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            lines = content.splitlines()
            for line_num, line in enumerate(lines, start=1):
                clean = line.strip()

                if re.search(r"(?:PASSWORD|SECRET|TOKEN|KEY)\s*:\s*(?!\$)", clean, re.IGNORECASE):
                    self._add_finding(
                        severity="CRITICAL",
                        category="CI/CD",
                        file=rel_path,
                        line=line_num,
                        pattern="Hardcoded Secret in GitLab CI",
                        match=mask_secret(clean),
                        detail="Secret credential hardcoded in GitLab CI configuration",
                        cwe_id="CWE-798",
                    )

                if "allow_failure: true" in clean:
                    window = lines[max(0, line_num - 6) : line_num]
                    if any(kw in "\n".join(window).lower() for kw in ("security", "scan", "audit", "sast", "dast")):
                        self._add_finding(
                            severity="HIGH",
                            category="CI/CD",
                            file=rel_path,
                            line=line_num,
                            pattern="Security Job Allows Failure",
                            match=clean,
                            detail="allow_failure: true configured on a security scanning job",
                            cwe_id="CWE-693",
                        )
        except OSError:
            pass

    def _scan_terraform(self, file_path: Path, rel_path: str) -> None:
        """Audits Terraform code for open security groups, credentials, and storage encryption."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            lines = content.splitlines()
            self._scan_lines_against_rules(lines, rel_path, TERRAFORM_LINE_RULES)

            # Security group window inspection for management/DB ports
            for line_num, line in enumerate(lines, start=1):
                clean = line.strip()
                if re.search(r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]', clean):
                    window = lines[max(0, line_num - 11) : line_num]
                    window_text = "\n".join(window)
                    for port in SENSITIVE_PORTS:
                        if re.search(rf"from_port\s*=\s*{port}", window_text):
                            self._add_finding(
                                severity="CRITICAL",
                                category="IaC",
                                file=rel_path,
                                line=line_num,
                                pattern="Open Security Group on Sensitive Port",
                                match=f"0.0.0.0/0 on port {port}",
                                detail=f"Security group allows unrestricted 0.0.0.0/0 ingress on sensitive port {port}",
                                cwe_id="CWE-284",
                            )
        except OSError:
            pass

    def _scan_tfvars(self, file_path: Path, rel_path: str) -> None:
        """Audits .tfvars files for plaintext credentials."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, start=1):
                    clean = line.strip()
                    if re.search(r"(?:password|secret|key|token)\s*=", clean, re.IGNORECASE):
                        self._add_finding(
                            severity="CRITICAL",
                            category="IaC",
                            file=rel_path,
                            line=line_num,
                            pattern="Credentials in .tfvars File",
                            match=mask_secret(clean),
                            detail=".tfvars file contains credentials; use variable injection or a secrets manager",
                            cwe_id="CWE-798",
                        )
        except OSError:
            pass

    def _scan_tfstate(self, rel_path: str) -> None:
        """Flags committed .tfstate files (must never be committed)."""
        self._add_finding(
            severity="CRITICAL",
            category="IaC",
            file=rel_path,
            line=0,
            pattern="Terraform State File in Repository",
            match=".tfstate committed",
            detail="Terraform state files contain unencrypted infrastructure secrets and must use remote state backend",
            cwe_id="CWE-312",
        )

    def _scan_kubernetes(self, file_path: Path, rel_path: str) -> None:
        """Audits Kubernetes manifests for security context and plaintext Secrets."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            if re.search(r"kind:\s*Secret", content):
                self._add_finding(
                    severity="HIGH",
                    category="K8s",
                    file=rel_path,
                    line=0,
                    pattern="Plaintext Kubernetes Secret",
                    match="kind: Secret",
                    detail="Plaintext Secret manifest in repository; use SealedSecrets or ExternalSecrets operator",
                    cwe_id="CWE-312",
                )

            if re.search(r"kind:\s*(?:Deployment|Pod|DaemonSet|StatefulSet)", content):
                lines = content.splitlines()
                self._scan_lines_against_rules(lines, rel_path, K8S_LINE_RULES)

                if "runAsNonRoot: true" not in content:
                    self._add_finding(
                        severity="HIGH",
                        category="K8s",
                        file=rel_path,
                        line=0,
                        pattern="Missing runAsNonRoot: true",
                        match="securityContext missing runAsNonRoot: true",
                        detail="Workload securityContext is missing runAsNonRoot: true",
                        cwe_id="CWE-250",
                    )

                if "readOnlyRootFilesystem: true" not in content:
                    self._add_finding(
                        severity="MEDIUM",
                        category="K8s",
                        file=rel_path,
                        line=0,
                        pattern="Missing readOnlyRootFilesystem: true",
                        match="securityContext missing readOnlyRootFilesystem: true",
                        detail="Workload securityContext is missing readOnlyRootFilesystem: true",
                        cwe_id="CWE-250",
                    )

                if "resources:" not in content:
                    self._add_finding(
                        severity="LOW",
                        category="K8s",
                        file=rel_path,
                        line=0,
                        pattern="No Resource Limits",
                        match="Missing resources: limits",
                        detail="Container has no resource limits configured, presenting a DoS risk",
                        cwe_id="CWE-400",
                    )
        except OSError:
            pass

    def _scan_npmrc(self, file_path: Path, rel_path: str) -> None:
        """Audits .npmrc for hardcoded authentication tokens."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, start=1):
                    clean = line.strip()
                    if re.search(r"_authToken|_auth\s*=", clean):
                        self._add_finding(
                            severity="CRITICAL",
                            category="Config",
                            file=rel_path,
                            line=line_num,
                            pattern="Auth Token in .npmrc",
                            match=mask_secret(clean),
                            detail="Plaintext authentication token hardcoded in .npmrc file",
                            cwe_id="CWE-798",
                        )
        except OSError:
            pass

    def _scan_pip_conf(self, file_path: Path, rel_path: str) -> None:
        """Audits pip.conf for plaintext passwords/tokens."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, start=1):
                    clean = line.strip()
                    if re.search(r"(?:password|token)", clean, re.IGNORECASE):
                        self._add_finding(
                            severity="HIGH",
                            category="Config",
                            file=rel_path,
                            line=line_num,
                            pattern="Credentials in pip.conf",
                            match=mask_secret(clean),
                            detail="Plaintext credential found in pip.conf",
                            cwe_id="CWE-798",
                        )
        except OSError:
            pass

    def _scan_cors(self, file_path: Path, rel_path: str) -> None:
        """Audits source code for overly permissive CORS headers."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, start=1):
                    clean = line.strip()
                    if CORS_REGEX.search(clean):
                        self._add_finding(
                            severity="HIGH",
                            category="CORS",
                            file=rel_path,
                            line=line_num,
                            pattern="Unrestricted CORS Policy",
                            match=clean[:80],
                            detail="Wildcard/unrestricted CORS configuration permits arbitrary origins",
                            cwe_id="CWE-942",
                        )
        except OSError:
            pass


def main() -> None:
    args = parse_args(
        prog_name="scan_infrastructure_configs",
        description="Audits infrastructure, Docker, CI/CD pipelines, Terraform, K8s, and config files.",
    )

    scanner = InfrastructureScanner(args.project_root)
    findings = scanner.scan(target_paths=args.target)

    if args.max_findings and len(findings) > args.max_findings:
        findings = findings[: args.max_findings]

    emit_findings(
        findings,
        as_json=args.json,
        no_color=args.no_color,
        title="Security Review: Configuration & Infrastructure Auditor",
        project_root=args.project_root,
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
