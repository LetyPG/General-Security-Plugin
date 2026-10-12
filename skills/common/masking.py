"""
Zero-Raw-Secret Masking and Placeholder Filtering Utilities.

Strictly enforces the Zero-Raw-Secret Output Invariant across all skill outputs.
"""
from __future__ import annotations

import re

# Common placeholder and test token substrings to suppress false positives
PLACEHOLDER_REGEX = re.compile(
    r"(example|placeholder|changeme|xxx|test|dummy|todo|your.?key|insert|replace|<your_|"
    r"sample|fake|mock|default)",
    re.IGNORECASE,
)


def mask_secret(value: str) -> str:
    """
    Masks a sensitive string to enforce the Zero-Raw-Secret Invariant.

    - If value length > 12: retains first 4 and last 4 characters with middle masked.
    - If value length <= 12: fully replaces with [REDACTED].
    """
    clean_val = value.strip().strip("'\"")
    if not clean_val:
        return "[REDACTED]"

    if len(clean_val) > 12:
        return f"{clean_val[:4]}...{clean_val[-4:]}"
    return "[REDACTED]"


def is_placeholder(value: str) -> bool:
    """Returns True if the string contains obvious placeholder or test patterns."""
    return bool(PLACEHOLDER_REGEX.search(value))
