---
name: audit-auth-crypto
description: Audit authentication, authorization, session management, and cryptography exposure. Checks password hashing, JWT implementation, OAuth/OIDC flows, IDOR, RBAC, session cookies, crypto algorithm selection, timing attacks, rate limiting, and security headers. Triggers on: "auth review", "authentication security", "JWT audit", "crypto check", "session security", "authorization review", "is my auth secure".
type: skill
parent_agent: "orchestrator-general-security"
allowed_tools:
  - find_files
  - list_directory
  - read_file
  - grep_search
  - glob
allowed_commands: python3 scan_auth_crypto.py [project_root]
temperature: 0.3
---

# Instructions 
Focus exclusively on **authentication, authorization, session management, and cryptographic implementations** and identify exposure vulnerabilities.

## Context 
- **A02 Crypto Failures**: MD5/SHA1 for passwords, ECB mode, hardcoded keys, `Math.random()` for tokens

## Scanning Tool

You MUST use the tool provided within `skills/audit-auth-crypto/scripts/` directory using Python in the project directory where scanning will be done. 
This script performs deterministic static analysis for broken password hashing, JWT misconfigurations, insecure ciphers/modes, insecure randomness, timing attacks, and disabled TLS verification.

The complete command: `python3 scan_auth_crypto.py [project_root]`.

## Scanning Goals & Methodology

### Password Handling
- Must use bcrypt (cost≥12), scrypt, or argon2id. Flag MD5/SHA1/SHA256 for passwords.
- Constant-time comparison required. Min length ≥8, max ≥64.
- Reset tokens: single-use, time-limited, high-entropy.

### JWT / Token Auth
- Algorithm: RS256/ES256 (flag HS256 with weak secret). Must reject "none" algorithm.
- Must validate: exp, iss, aud. Expiration short (15-60 min).
- No sensitive data in payload. Refresh tokens rotated on use.
- Flag: jwt.sign without expiration, jwt.verify without algorithm allowlist.

### OAuth / OIDC
- State parameter required. PKCE for public clients.
- Redirect URI exact match. Token exchange server-side only.
- Access tokens NOT in localStorage.

### Authorization
- Every endpoint checks auth server-side. IDOR: ownership verified at data layer.
- Deny-by-default. Role changes require re-authentication. Multi-tenancy isolation.

### Session Management
- IDs: crypto-random ≥128 bits, regenerated after login.
- Cookies: httpOnly, secure, sameSite=Lax/Strict. Server-side invalidation on logout.

### Cryptography
**Secure (2026):** SHA-256+, bcrypt/argon2id, AES-256-GCM, ChaCha20-Poly1305, RSA≥2048, Ed25519, TLS 1.2+
**Flag:** MD5, SHA1, DES, 3DES, RC4, ECB mode, RSA<2048, hardcoded keys/IVs, Math.random()/random for security, verify=False, rejectUnauthorized:false

### Timing Attacks
- Password/token/HMAC comparison must use constant-time function.
- Flag direct === comparison of secrets.

### Rate Limiting
- Login, password reset, API endpoints must be rate-limited server-side.

### Security Headers (web apps)
- HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Cache-Control.

---

## Remediations suggestions base on mitigation and control practices:

The fallowing remediation practices base on OWASP Top 10 Aplication Risk and CWE are some examples of remediations suggestions base on mitigation and control practices:
1. Classify data: Identify information that is sensitive under regulations (such as the Payment Card Industry Data Security Standard [PCI DSS] or privacy laws) and apply proportionate controls.
2. Do not store unnecessary data: The most secure protection method is to discard confidential information as soon as it is no longer required.
3. Encrypt in transit: Enforce the use of modern TLS (TLS 1.2 or 1.3) and enable security policies such as HSTS (HTTP Strict Transport Security).
4. Encrypt at rest using strong algorithms: Use robust industry standards like AES-256 for symmetric encryption and specific hashing algorithms with salts and variable cost factors (such as Argon2 or Bcrypt) for passwords.
5. Avoid custom cryptography: Never attempt to create custom encryption algorithms ("don't roll your own crypto"). Use standard, widely validated cryptographic libraries.

>You can provide a broader range of remediation practices base on the context of the scanning project including code fixes.
---
## Constraints

Key invariants:
- **Traceability**: Each finding preserves `file`, `line`, exact vulnerable snippet in `match`, and corresponding `cwe_id`.
- **Concrete Hardening**: Provide `fixed_code` demonstrating secure cryptographic primitives and proper parameters alongside a clear `remediation` explanation.
- **Empty State**: If no auth or crypto issues are detected, return `findings: []` with zeros across all summary severities.
---

## Output

The scanning script (`python3 scan_auth_crypto.py --json`) generates findings matching the canonical schema (`id`, `severity`, `category`, `file`, `line`, `pattern`, `match`, `detail`, `cwe_id`).

You MUST deliver your final authentication and cryptographic assessment as a structured JSON object adhering to the format below:

```json
{
  "summary": {
    "total_findings": 1,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "findings": [
    {
      "id": 1,
      "severity": "CRITICAL",
      "category": "Password Security",
      "file": "src/services/authService.py",
      "line": 45,
      "pattern": "Weak Password Hashing Algorithm (MD5/SHA1)",
      "match": "password_hash = hashlib.md5(password.encode()).hexdigest()",
      "detail": "Password hashed using broken collision-vulnerable algorithm (MD5/SHA1); use bcrypt, argon2id, or scrypt",
      "cwe_id": "CWE-328",
      "fixed_code": "password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()",
      "remediation": "Replace MD5/SHA1 hashing with modern adaptive key derivation functions (bcrypt, argon2id, or scrypt) with sufficient work factors."
    }
  ]
}
```

## Constraints
- **Traceability**: Each finding preserves `file`, `line`, exact vulnerable snippet in `match`, and corresponding `cwe_id`.
- **Concrete Hardening**: Provide `fixed_code` demonstrating secure cryptographic primitives and proper parameters alongside a clear `remediation` explanation.
- **Empty State**: If no auth or crypto issues are detected, return `findings: []` with zeros across all summary severities.
