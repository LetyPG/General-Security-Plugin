"""
Finding Data Models and Serialization Protocols.

Defines the canonical finding structure used by all deterministic security scanning scripts.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Vulnerability and risk severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_string(cls, val: str) -> Severity:
        """Safely parses string to Severity enum, defaulting to MEDIUM."""
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError:
            return cls.MEDIUM


@dataclass(slots=True)
class Finding:
    """Canonical security finding data model across all security skills."""

    id: int
    severity: str
    category: str
    file: str
    line: int
    pattern: str
    match: str
    detail: str = ""
    cwe_id: str = ""

    def __post_init__(self) -> None:
        # Normalize severity to uppercase string
        self.severity = Severity.from_string(self.severity).value

    def to_dict(self) -> dict[str, Any]:
        """Serializes finding to plain dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Serializes finding to JSON string."""
        return json.dumps(self.to_dict())
