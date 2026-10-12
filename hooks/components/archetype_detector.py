"""
Archetype Detector Component
Resolves workspace root and detects project ecosystem(s) and AI Agent workspace markers
from root metadata indicators without reading full project source trees.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import ClassVar


class ArchetypeDetector:
    """Detects software project archetype and AI Agent configurations from workspace root markers."""

    # Primary language and infrastructure ecosystem markers
    ECOSYSTEM_MARKERS: ClassVar[dict[str, list[str]]] = {
        "Node.js": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
        "Python": ["pyproject.toml", "requirements.txt", "Pipfile", "setup.py", "poetry.lock"],
        "Go": ["go.mod", "go.sum"],
        "Rust": ["Cargo.toml", "Cargo.lock"],
        "Java / Kotlin": ["pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle"],
        "Ruby": ["Gemfile", "Gemfile.lock"],
        ".NET / C#": ["*.csproj", "*.sln", "*.fsproj", "Directory.Build.props"],
        "PHP": ["composer.json", "composer.lock"],
        "Terraform / IaC": ["main.tf", "versions.tf", "*.tf"],
        "Docker / Container": ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"],
        "Kubernetes / Helm": ["Chart.yaml", "Chart.lock"],
    }

    # AI Coding Agent workspace markers, it can be expanded if new agent marker detected
    AGENT_WORKSPACE_MARKERS: ClassVar[list[str]] = [
        "AGENTS.md",
        "CLAUDE.md",
        ".cursorrules",
        "mcp.json",
        "mcp-config.json",
        ".agent",
        ".claude",
        ".gemini",
        ".cursor",
    ]

    def __init__(self, workspace_root: str | Path) -> None:
        self.workspace_root = Path(workspace_root).resolve()

    def resolve_root(self) -> Path:
        """Returns canonical absolute workspace root path."""
        if not self.workspace_root.exists():
            raise FileNotFoundError(f"Workspace root does not exist: {self.workspace_root}")
        if not self.workspace_root.is_dir():
            raise NotADirectoryError(f"Workspace root is not a directory: {self.workspace_root}")
        return self.workspace_root

    def detect(self) -> str:
        """
        Evaluates presence of ecosystem and AI agent markers at workspace root.
        Returns a formatted archetype string, e.g.:
          - 'Node.js (AI Agent Managed)'
          - 'Polyglot (Python, Go + Agent Configs)'
          - 'Python'
          - 'Generic (AI Agent Managed)'
        """
        try:
            root = self.resolve_root()
            root_entries = set(os.listdir(root))
        except (OSError, FileNotFoundError, NotADirectoryError):
            return "Undetermined"

        # 1. Detect AI Agent Workspace Markers
        has_agent_markers = any(
            marker in root_entries
            or any(entry.lower() == marker.lower() for entry in root_entries)
            for marker in self.AGENT_WORKSPACE_MARKERS
        )

        # 2. Detect Ecosystems
        matched_ecosystems: list[str] = []
        for ecosystem, markers in self.ECOSYSTEM_MARKERS.items():
            for marker in markers:
                if "*" in marker:
                    extension = marker.replace("*", "")
                    if any(entry.endswith(extension) for entry in root_entries):
                        matched_ecosystems.append(ecosystem)
                        break
                else:
                    if marker in root_entries:
                        matched_ecosystems.append(ecosystem)
                        break

        # 3. Format Composite Archetype
        if not matched_ecosystems:
            base_archetype = "Generic"
        elif len(matched_ecosystems) == 1:
            base_archetype = matched_ecosystems[0]
        else:
            # Filter core languages vs container/infra
            infra_names = {"Docker / Container", "Terraform / IaC", "Kubernetes / Helm"}
            core_languages = [e for e in matched_ecosystems if e not in infra_names]
            if len(core_languages) == 1:
                base_archetype = core_languages[0]
            elif len(core_languages) > 1:
                langs_str = ", ".join(core_languages[:2])
                if has_agent_markers:
                    return f"Polyglot ({langs_str} + Agent Configs)"
                return f"Polyglot ({langs_str})"
            else:
                base_archetype = matched_ecosystems[0]

        if has_agent_markers:
            return f"{base_archetype} (AI Agent Managed)"

        return base_archetype
