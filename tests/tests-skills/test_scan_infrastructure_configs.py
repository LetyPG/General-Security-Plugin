"""
Unit tests for scan_infrastructure_configs.py (audit-infrastructure deterministic script).
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

# Load script dynamically from hyphenated directory path
_script_path = (
    Path(__file__).resolve().parent.parent.parent
    / "skills"
    / "audit-infrastructure"
    / "scripts"
    / "scan_infrastructure_configs.py"
)
_spec = importlib.util.spec_from_file_location("scan_infrastructure_configs", _script_path)
_module = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules[_spec.name] = _module
_spec.loader.exec_module(_module)

InfrastructureScanner = _module.InfrastructureScanner


def test_scan_dockerfile_misconfigurations(tmp_path: Path) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM ubuntu:latest\n"
        "ENV DB_PASSWORD=my_insecure_pass_123\n"
        "COPY . /app\n"
        "CMD ['python', 'app.py']\n",
        encoding="utf-8",
    )

    scanner = InfrastructureScanner(tmp_path)
    findings = scanner.scan()

    patterns = {f.pattern for f in findings}
    assert "Base Image :latest Tag" in patterns
    assert "Missing USER Directive" in patterns
    assert "Sensitive ENV/ARG in Dockerfile" in patterns
    assert "COPY . without .dockerignore" in patterns


def test_scan_docker_compose_privileged_and_socket(tmp_path: Path) -> None:
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "version: '3'\n"
        "services:\n"
        "  web:\n"
        "    image: nginx\n"
        "    privileged: true\n"
        "    network_mode: host\n"
        "    volumes:\n"
        "      - /var/run/docker.sock:/var/run/docker.sock\n",
        encoding="utf-8",
    )

    scanner = InfrastructureScanner(tmp_path)
    findings = scanner.scan()

    patterns = {f.pattern for f in findings}
    assert "Privileged Container" in patterns
    assert "Host Network Mode" in patterns
    assert "Mounted Docker Socket" in patterns


def test_scan_github_workflow_misconfigurations(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    wf_file = wf_dir / "ci.yml"
    wf_file.write_text(
        "name: CI\n"
        "on:\n"
        "  pull_request_target:\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v3\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: echo '${{ github.event.issue.title }}'\n",
        encoding="utf-8",
    )

    scanner = InfrastructureScanner(tmp_path)
    findings = scanner.scan()

    patterns = {f.pattern for f in findings}
    assert "pull_request_target with Head Checkout" in patterns
    assert "Workflow Write-All Permissions" in patterns
    assert "Unpinned GitHub Action" in patterns
    assert "Untrusted GitHub Context in Workflow" in patterns


def test_scan_terraform_open_security_group_and_secrets(tmp_path: Path) -> None:
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(
        'resource "aws_security_group" "allow_ssh" {\n'
        '  ingress {\n'
        '    from_port = 22\n'
        '    to_port = 22\n'
        '    protocol = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        '  }\n'
        '}\n'
        'resource "aws_db_instance" "default" {\n'
        '  password = "plaintext_db_password_123"\n'
        '  encrypted = false\n'
        '}\n',
        encoding="utf-8",
    )

    scanner = InfrastructureScanner(tmp_path)
    findings = scanner.scan()

    patterns = {f.pattern for f in findings}
    assert "Open Security Group on Sensitive Port" in patterns
    assert "Hardcoded Credential in Terraform" in patterns
    assert "Storage Encryption Disabled" in patterns


def test_scan_committed_tfstate_file(tmp_path: Path) -> None:
    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text('{"version": 4, "resources": []}', encoding="utf-8")

    scanner = InfrastructureScanner(tmp_path)
    findings = scanner.scan()

    patterns = {f.pattern for f in findings}
    assert "Terraform State File in Repository" in patterns


def test_scan_kubernetes_manifest_security(tmp_path: Path) -> None:
    k8s_file = tmp_path / "deployment.yaml"
    k8s_file.write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: app\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: web\n"
        "          image: nginx\n"
        "          securityContext:\n"
        "            privileged: true\n",
        encoding="utf-8",
    )

    secret_file = tmp_path / "secret.yaml"
    secret_file.write_text(
        "apiVersion: v1\n"
        "kind: Secret\n"
        "metadata:\n"
        "  name: app-secret\n"
        "data:\n"
        "  pw: c2VjcmV0\n",
        encoding="utf-8",
    )

    scanner = InfrastructureScanner(tmp_path)
    findings = scanner.scan()

    patterns = {f.pattern for f in findings}
    assert "Privileged K8s Container" in patterns
    assert "Missing runAsNonRoot: true" in patterns
    assert "Plaintext Kubernetes Secret" in patterns


def test_scan_npmrc_and_cors(tmp_path: Path) -> None:
    npmrc = tmp_path / ".npmrc"
    npmrc.write_text("//registry.npmjs.org/:_authToken=npm_live_token_12345\n", encoding="utf-8")

    js_file = tmp_path / "server.js"
    js_file.write_text('res.setHeader("Access-Control-Allow-Origin", "*");\n', encoding="utf-8")

    scanner = InfrastructureScanner(tmp_path)
    findings = scanner.scan()

    patterns = {f.pattern for f in findings}
    assert "Auth Token in .npmrc" in patterns
    assert "Unrestricted CORS Policy" in patterns


def test_scan_configs_targeted_option_a(tmp_path: Path) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM alpine:latest\n", encoding="utf-8")
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("privileged: true\n", encoding="utf-8")

    scanner = InfrastructureScanner(tmp_path)
    # Target only Dockerfile
    findings = scanner.scan(target_paths=[dockerfile])
    files = {f.file for f in findings}
    assert "Dockerfile" in files
    assert "docker-compose.yml" not in files
