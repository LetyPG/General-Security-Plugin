---
name: audit-infrastructure
description: Audit infrastructure security. Audits Dockerfiles, docker-compose,  Kubernetes manifests, CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins), Terraform/IaC,  and cloud configurations. Detects privileged containers, exposed ports, insecure pipelines,  public S3 buckets, and unencrypted resources. Triggers on: "Docker security", "K8s audit",  "CI/CD security", "Terraform review", "infrastructure hardening", "pipeline security".
type: skill
parent_agent: "orchestrator-general-security"
allowed_tools:
  - find_files
  - list_directory
  - read_file
  - grep_search
  - glob
allowed_commands: python3 scan_infrastructure_configs.py [project_root]
temperature: 0.2
---

# Instructions 

- Focus exclusively on **infrastructure configuration security**:  Docker, Kubernetes, CI/CD pipelines, IaC, and cloud configurations.
- Detects privileged containers, exposed ports, insecure pipelines,  public S3 buckets, and unencrypted resources. 

## Context

- **CWE-250**: Execution with Unnecessary Privileges: Containers running as root or with elevated privileges (privileged: true), missing capabilities drop.
- **CWE-200**: Exposure of Sensitive Information (CIS Kubernetes / AWS CIS Foundation): Exposed services and resources, in ports or folders  (ej. 0.0.0.0/0, SSH, RDP)
- **OWASP Top 10 CI/CD**: CICD-SEC-1 (Insufficient Flow Control Mechanisms): Use of unverified or untrusted actions in CI/CD pipelines,Lack of proper input validation for pipeline parameters, without spinning up dedicated runners for untrusted PRs
- **CWE-732**: Incorrect Permission Assignment for Critical Resource: Default permissions in IaaC, S3 bucket policies, RBAC policies with admin and cluster-admin. S3 public buckets (BlockPublicAccess: false)
- **CWE-957**: Improper Limitation of a Domain or Component: Insecure Kubernetes Cluster Roles and RoleBindings, excessive RBAC permissions in cluster environments. Misconfigured RBAC can allow users or applications to perform actions beyond their intended scope

> Reference risk and attack: 
> May 28, 2026 (official alert published by CISA)*  **CVE Reference:** **CVE-2026-48027** (also linked to the *Megalodon* pipeline malware campaign).
>**Summary:** Malicious actors compromised CI/CD pipelines and automated accounts to inject backdoors into the Nx Console extension and GitHub repositories, stealing developer credentials and affecting software dependencies prior to deployment.

---

## Scanning Tool

You MUST use the tool, provided within `skills/audit-infrastructure/scripts/` directory using Python in the project directory where scanning will be done. 
This script will scan configuration files for security issues

The complete command: `python3 scan_infrastructure_configs.py [project_root]`.

## Scanning Goals & Methodology
The fallowing infrastructure is what this agent will audit:

### Check Docker Configurations
- [x] Base image: specific tag, not :latest. USER directive (non-root). No secrets in ENV/ARG.
- [x] No COPY . . without .dockerignore. Multi-stage builds preferred.
- [x] docker-compose: no privileged:true, no host network, no docker.sock mount, no host root mount.
- [x] No cap_add:ALL. No hardcoded creds in environment. Ports bind 127.0.0.1 when possible.

### Check Kubernetes Configurations
- [x] `runAsNonRoot:true`, `readOnlyRootFilesystem:true`, `allowPrivilegeEscalation:false`.
- [x] `capabilities drop:["ALL"]. Resource limits. No hostPath/hostNetwork/hostPID.
- [x] `automountServiceAccountToken:false` unless needed. Images digest-pinned.
- [x] `RBAC`: no wildcards, no `cluster-admin` for apps. Secrets not plaintext in manifests.

### Check CI/CD — GitHub Actions
- [x] Actions pinned to commit SHA. No unverified third-party actions.
- [x] No `pull_request_target` with `PR head` checkout (RCE vector).
- [x] `GITHUB_TOKEN` minimum permissions. No self-hosted runners for untrusted PRs.
- [x] Secrets via `${{ secrets.NAME }}` only. Artifacts clean of secrets.

### Check CI/CD — General
- [x] No hardcoded credentials in pipeline configs. Security jobs don't `allow_failure`.
- [x] Production deploys require manual approval. Logs mask secrets. Install from lockfile.

### Check Terraform / IaC
- [x] State file remote+encrypted, not in repo. No hardcoded creds in .tf/.tfvars.
- [x] Security groups: no 0.0.0.0/0 on management/DB ports. S3: public access blocked.
- [x] RDS: not public. Encryption at rest and transit. IAM least privilege. Versions pinned.

---

## Remediations suggestions base on mitigation and control practices:

The fallowing remediation practices base on OWASP Top 10 Aplication Risk and CWE are some examples of remediations suggestions base on mitigation and control practices:

- Pin dependencies and actions to specific hashes (`commit SHAs`), never to floating tags.
- Restrict write permissions by default in workflows.
- Audit local pipeline configuration files (`YAML`) to prevent executions with elevated privileges or unsanitized environment variables.
- Use multi-stage builds to minimize the final image size and reduce the attack surface.
- Implement a "least privilege" approach by running containers as non-root users and dropping unnecessary capabilities.
- Configure proper resource limits and resource quotas to prevent container breakouts and resource exhaustion attacks.
- Employ `securityContext` to enforce immutability (`readOnlyRootFilesystem`) and prevent privilege escalation (`allowPrivilegeEscalation: false`).
          

>You can provide a broader range of remediation practices base on the context of the scanning project including code fixes.

---

## Constraints

Key invariants:
- **Remediation Context**: For each infrastructure finding, include `fixed_config` showing the remediated configuration block alongside `remediation`.
- **Empty State Handling**: If no infrastructure files are detected, return `findings: []` with `infrastructure_types_detected: []` and an informational summary note.
- You **MUST** run the san process only in the infraetructire configurations mentionaltes before, this is your scanning scope.
- In case a different infrastructure exists , yo **WON'T** scan or analyze it, and you will inform user tghis out of your scope, it prevents hallucination or not confidence expertise analysis.

---

## Output

The scanning script (`python3 scan_infrastructure_configs.py --json`) generates findings matching the canonical schema (`id`, `severity`, `category`, `file`, `line`, `pattern`, `match`, `detail`, `cwe_id`).

You MUST deliver your final infrastructure configuration audit as a structured JSON object adhering to the format below:

```json
{
  "summary": {
    "total_findings": 1,
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0,
    "infrastructure_types_detected": [
      "Dockerfile",
      "GitHub Actions"
    ]
  },
  "findings": [
    {
      "id": 1,
      "severity": "HIGH",
      "category": "Dockerfile",
      "file": "Dockerfile",
      "line": 1,
      "pattern": "Base Image :latest Tag",
      "match": "FROM node:latest",
      "detail": "Base image uses mutable ':latest' tag; pin to a specific sha256 digest or semver tag",
      "cwe_id": "CWE-1188",
      "fixed_config": "FROM node:20.11.0-alpine",
      "remediation": "Pin base images to explicit version tags or immutable sha256 digests."
    }
  ]
}
```


