#!/usr/bin/env python3
"""
Authentication, Session, and Cryptography Security Scanner.

Deterministic static analysis script detecting:
- Broken password hashing (MD5/SHA1 for passwords, low bcrypt rounds - CWE-328, CWE-916)
- JWT misconfigurations (none algorithm, verify=False, missing expiration - CWE-345, CWE-347)
- Insecure cryptographic ciphers & ECB mode (CWE-327)
- Insecure PRNG for security tokens (Math.random, random.randint - CWE-338)
- Timing attack vulnerabilities in token/HMAC comparisons (CWE-208)
- Disabled TLS / certificate validation (verify=False, rejectUnauthorized: false - CWE-295)
- Insecure cookie attributes (httpOnly: false, secure: false - CWE-614, CWE-1004)
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

# Ensure plugin root is in sys.path
_plugin_root = str(Path(__file__).resolve().parent.parent.parent.parent)
if _plugin_root not in sys.path:
    sys.path.insert(0, _plugin_root)

from skills.common import (
    Finding,
    emit_findings,
    parse_args,
    walk_project_files,
)


@dataclass(slots=True, frozen=True)
class AuthCryptoRule:
    """Declarative specification for an auth/crypto vulnerability pattern."""

    pattern_name: str
    category: str
    severity: str
    cwe_id: str
    regex: re.Pattern[str]
    detail: str
    extensions: tuple[str, ...] = (
        ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".php", ".cs"
    )


AUTH_CRYPTO_RULES: tuple[AuthCryptoRule, ...] = (
    # ── 1. PASSWORD HASHING (CWE-328 / CWE-916) ──
    AuthCryptoRule(
        pattern_name="Weak Password Hashing Algorithm (MD5/SHA1)",
        category="Password Security",
        severity="CRITICAL",
        cwe_id="CWE-328",
        regex=re.compile(
            r"""(?:(?:hashlib\.(?:md5|sha1)|crypto\.createHash\s*\(\s*['"](?:md5|sha1)['"]\)).*(?:password|passwd|pwd)|(?:password|passwd|pwd).*(?:hashlib\.(?:md5|sha1)|crypto\.createHash\s*\(\s*['"](?:md5|sha1)['"]\)))""",
            re.IGNORECASE,
        ),
        detail="Password hashed using broken collision-vulnerable algorithm (MD5/SHA1); use bcrypt, argon2id, or scrypt",
        extensions=(".py", ".js", ".ts"),
    ),
    AuthCryptoRule(
        pattern_name="Java Weak Password Digest",
        category="Password Security",
        severity="CRITICAL",
        cwe_id="CWE-328",
        regex=re.compile(
            r"""MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-1)["']\).*(?:password|passwd|pwd)""",
            re.IGNORECASE,
        ),
        detail="Java MessageDigest initialized with MD5/SHA-1 for password hashing; use argon2-jvm or PBKDF2WithHmacSHA512",
        extensions=(".java",),
    ),
    AuthCryptoRule(
        pattern_name="Low Bcrypt Work Factor",
        category="Password Security",
        severity="HIGH",
        cwe_id="CWE-916",
        regex=re.compile(
            r"""(?:bcrypt\.gensalt\s*\(\s*(?:rounds\s*=\s*)?[1-9]\b|bcrypt\.hash(?:Sync)?\s*\([^,]+,\s*[1-9]\s*\))""",
            re.IGNORECASE,
        ),
        detail="Bcrypt salt generated with fewer than 10 work rounds; insufficient workload against GPU cracking",
        extensions=(".py", ".js", ".ts"),
    ),

    # ── 2. JWT MISCONFIGURATIONS (CWE-345 / CWE-347) ──
    AuthCryptoRule(
        pattern_name="JWT 'none' Algorithm Allowed",
        category="JWT Security",
        severity="CRITICAL",
        cwe_id="CWE-347",
        regex=re.compile(
            r"""(?:algorithms?\s*[:=]\s*\[?\s*['"]none['"]|algorithm\s*[:=]\s*['"]none['"])""",
            re.IGNORECASE,
        ),
        detail="JWT parser permits 'none' algorithm; allows attackers to forge arbitrary tokens without signatures",
        extensions=(".py", ".js", ".ts", ".go", ".java"),
    ),
    AuthCryptoRule(
        pattern_name="JWT Signature Verification Disabled",
        category="JWT Security",
        severity="CRITICAL",
        cwe_id="CWE-347",
        regex=re.compile(
            r"""(?:jwt\.decode\s*\([^)]*(?:verify\s*=\s*False|verify_signature['"]?\s*:\s*False)|verifyOptions\s*:\s*\{\s*ignoreExpiration\s*:\s*true)""",
            re.IGNORECASE,
        ),
        detail="JWT token decoded without signature verification enabled; unauthenticated token manipulation possible",
        extensions=(".py", ".js", ".ts"),
    ),

    # ── 3. BROKEN CIPHERS & MODES (CWE-327) ──
    AuthCryptoRule(
        pattern_name="Broken Legacy Cipher (DES/RC4/Blowfish)",
        category="Cryptography",
        severity="HIGH",
        cwe_id="CWE-327",
        regex=re.compile(
            r"""(?:crypto\.createCipher(?:iv)?\s*\(\s*['"](?:des|rc4|blowfish|bf|3des)|Cipher\.getInstance\s*\(\s*["'](?:DES|DESede|RC4|Blowfish)|algorithms\.(?:DES|TripleDES|Blowfish|ARC4))""",
            re.IGNORECASE,
        ),
        detail="Use of broken/deprecated legacy cipher (DES/RC4/Blowfish); migrate to AES-256-GCM or ChaCha20-Poly1305",
        extensions=(".py", ".js", ".ts", ".java"),
    ),
    AuthCryptoRule(
        pattern_name="Insecure AES ECB Mode",
        category="Cryptography",
        severity="HIGH",
        cwe_id="CWE-327",
        regex=re.compile(
            r"""(?:AES\.MODE_ECB|Cipher\.getInstance\s*\(\s*["']AES/ECB|crypto\.createCipher(?:iv)?\s*\(\s*['"]aes-\d+-ecb['"]|modes\.ECB\s*\(\s*\))""",
            re.IGNORECASE,
        ),
        detail="AES initialized in ECB mode; ECB mode lacks semantic security and leaks plaintext pattern structures",
        extensions=(".py", ".js", ".ts", ".java"),
    ),
    AuthCryptoRule(
        pattern_name="Weak RSA Key Size (< 2048 bits)",
        category="Cryptography",
        severity="HIGH",
        cwe_id="CWE-326",
        regex=re.compile(
            r"""(?:rsa\.generate_private_key\s*\([^)]*key_size\s*=\s*(?:512|1024)\b|RSA\.generate\s*\(\s*(?:512|1024)\b|generateKeyPair(?:Sync)?\s*\(\s*['"]rsa['"]\s*,\s*\{[^}]*modulusLength\s*:\s*(?:512|1024)\b)""",
            re.IGNORECASE,
        ),
        detail="RSA key generated with fewer than 2048 bits; factorable with modern computing resources",
        extensions=(".py", ".js", ".ts"),
    ),

    # ── 4. INSECURE PRNG FOR SECRETS (CWE-338) ──
    AuthCryptoRule(
        pattern_name="Insecure Math.random() for Security Tokens",
        category="Insecure Randomness",
        severity="HIGH",
        cwe_id="CWE-338",
        regex=re.compile(
            r"""(?:Math\.random\s*\(\s*\).*(?:token|session|auth|secret|key|salt|password|pwd|nonce)|(?:token|session|auth|secret|key|salt|password|pwd|nonce).*(?:Math\.random\s*\(\s*\)))""",
            re.IGNORECASE,
        ),
        detail="Math.random() is a non-cryptographic PRNG and predictable; use crypto.randomBytes() or crypto.getRandomValues()",
        extensions=(".js", ".ts", ".jsx", ".tsx"),
    ),
    AuthCryptoRule(
        pattern_name="Python Insecure random Module for Secrets",
        category="Insecure Randomness",
        severity="HIGH",
        cwe_id="CWE-338",
        regex=re.compile(
            r"""(?:token|session|auth|secret|key|salt|password|pwd|nonce)\s*=\s*.*random\.(?:random|randint|choice|choices|randrange)\s*\(""",
            re.IGNORECASE,
        ),
        detail="Standard random module (Mersenne Twister) used for sensitive value generation; use Python 'secrets' module",
        extensions=(".py",),
    ),

    # ── 5. TIMING ATTACKS (CWE-208) ──
    AuthCryptoRule(
        pattern_name="Non-Constant-Time Token Comparison",
        category="Timing Attack",
        severity="MEDIUM",
        cwe_id="CWE-208",
        regex=re.compile(
            r"""(?:===|==)\s*(?:computed_hash|signature|hmac_val|expected_token|auth_token)\b|(?:computed_hash|signature|hmac_val|expected_token|auth_token)\s*(?:===|==)""",
            re.IGNORECASE,
        ),
        detail="Direct equality comparison on secret tokens or HMAC signatures leaks timing information; use constant-time comparison",
        extensions=(".py", ".js", ".ts"),
    ),

    # ── 6. DISABLED TLS / CERTIFICATE VALIDATION (CWE-295) ──
    AuthCryptoRule(
        pattern_name="Python Requests verify=False (TLS Disabled)",
        category="Transport Security",
        severity="CRITICAL",
        cwe_id="CWE-295",
        regex=re.compile(
            r"""(?:requests\.(?:get|post|put|delete|patch|request)|httpx\.(?:get|post|Client)|urllib3\.PoolManager)\s*\([^)]*verify\s*=\s*False""",
            re.IGNORECASE,
        ),
        detail="TLS certificate validation explicitly disabled (verify=False); enables Man-in-the-Middle (MITM) attacks",
        extensions=(".py",),
    ),
    AuthCryptoRule(
        pattern_name="Node.js rejectUnauthorized: false (TLS Disabled)",
        category="Transport Security",
        severity="CRITICAL",
        cwe_id="CWE-295",
        regex=re.compile(
            r"""rejectUnauthorized\s*:\s*false""",
            re.IGNORECASE,
        ),
        detail="TLS rejectUnauthorized disabled in HTTPS/TLS agent; accepts unverified or self-signed certificates",
        extensions=(".js", ".ts"),
    ),
    AuthCryptoRule(
        pattern_name="Go InsecureSkipVerify: true (TLS Disabled)",
        category="Transport Security",
        severity="CRITICAL",
        cwe_id="CWE-295",
        regex=re.compile(
            r"""InsecureSkipVerify\s*:\s*true""",
            re.IGNORECASE,
        ),
        detail="Go tls.Config disables server certificate verification (InsecureSkipVerify=true)",
        extensions=(".go",),
    ),

    # ── 7. INSECURE COOKIE ATTRIBUTES (CWE-614 / CWE-1004) ──
    AuthCryptoRule(
        pattern_name="Cookie httpOnly Flag Disabled",
        category="Session Security",
        severity="MEDIUM",
        cwe_id="CWE-1004",
        regex=re.compile(
            r"""(?:res\.cookie|set_cookie)\s*\([^)]*httpOnly\s*:\s*false""",
            re.IGNORECASE,
        ),
        detail="Cookie explicitly configured with httpOnly: false; accessible to client-side scripts via document.cookie",
        extensions=(".js", ".ts", ".py"),
    ),
    AuthCryptoRule(
        pattern_name="Cookie secure Flag Disabled",
        category="Session Security",
        severity="MEDIUM",
        cwe_id="CWE-614",
        regex=re.compile(
            r"""(?:res\.cookie|set_cookie)\s*\([^)]*secure\s*:\s*false""",
            re.IGNORECASE,
        ),
        detail="Cookie explicitly configured with secure: false; transmitted over unencrypted HTTP connections",
        extensions=(".js", ".ts", ".py"),
    ),
)


class AuthCryptoScanner:
    """Deterministic static scanner detecting authentication, cryptography, and session vulnerabilities."""

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
        match: str,
        detail: str,
        cwe_id: str,
    ) -> None:
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

    def scan(self, target_paths: Sequence[str | Path] | None = None) -> list[Finding]:
        """Scans project source files for auth, crypto, and session vulnerabilities."""
        self.findings.clear()
        self._finding_counter = 0

        all_exts = {ext for rule in AUTH_CRYPTO_RULES for ext in rule.extensions}

        candidate_files = walk_project_files(
            self.project_root,
            allowed_extensions=all_exts,
            target_paths=target_paths,
        )

        for file_path in candidate_files:
            rel_path = self._rel_path(file_path)
            file_ext = file_path.suffix.lower()

            applicable_rules = [r for r in AUTH_CRYPTO_RULES if file_ext in r.extensions]
            if not applicable_rules:
                continue

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, start=1):
                        stripped = line.strip()
                        if not stripped or stripped.startswith(("//", "#", "/*", "*")):
                            continue

                        for rule in applicable_rules:
                            if rule.regex.search(line):
                                self._add_finding(
                                    severity=rule.severity,
                                    category=rule.category,
                                    file=rel_path,
                                    line=line_num,
                                    pattern=rule.pattern_name,
                                    match=stripped[:100],
                                    detail=rule.detail,
                                    cwe_id=rule.cwe_id,
                                )
            except OSError:
                pass

        return self.findings


def main() -> None:
    args = parse_args(
        prog_name="scan_auth_crypto",
        description="Audits authentication, cryptography, session management, and JWT security.",
    )

    scanner = AuthCryptoScanner(args.project_root)
    findings = scanner.scan(target_paths=args.target)

    if args.max_findings and len(findings) > args.max_findings:
        findings = findings[: args.max_findings]

    emit_findings(
        findings,
        as_json=args.json,
        no_color=args.no_color,
        title="Security Review: Authentication & Cryptography Auditor",
        project_root=args.project_root,
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
