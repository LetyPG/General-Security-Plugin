"""
Unit tests for scan_auth_crypto.py (audit-auth-crypto deterministic script).
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

# Load script dynamically from hyphenated directory path
_script_path = (
    Path(__file__).resolve().parent.parent.parent
    / "skills"
    / "audit-auth-crypto"
    / "scripts"
    / "scan_auth_crypto.py"
)
_spec = importlib.util.spec_from_file_location("scan_auth_crypto", _script_path)
_module = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules[_spec.name] = _module
_spec.loader.exec_module(_module)

AuthCryptoScanner = _module.AuthCryptoScanner


def test_detect_weak_password_hashing(tmp_path: Path) -> None:
    py_file = tmp_path / "auth.py"
    py_file.write_text(
        "password_hash = hashlib.md5(password.encode()).hexdigest()\n"
        "salt = bcrypt.gensalt(rounds=4)\n",
        encoding="utf-8",
    )
    js_file = tmp_path / "hash.js"
    js_file.write_text(
        "const h = crypto.createHash('sha1').update(pwd).digest('hex');\n",
        encoding="utf-8",
    )

    scanner = AuthCryptoScanner(tmp_path)
    findings = scanner.scan()

    patterns = {f.pattern for f in findings}
    assert "Weak Password Hashing Algorithm (MD5/SHA1)" in patterns
    assert "Low Bcrypt Work Factor" in patterns


def test_detect_jwt_misconfigurations(tmp_path: Path) -> None:
    py_file = tmp_path / "jwt_service.py"
    py_file.write_text(
        "payload = jwt.decode(token, verify=False)\n"
        "decoded = jwt.decode(token, algorithms=['none'])\n",
        encoding="utf-8",
    )

    scanner = AuthCryptoScanner(tmp_path)
    findings = scanner.scan()

    patterns = {f.pattern for f in findings}
    assert "JWT Signature Verification Disabled" in patterns
    assert "JWT 'none' Algorithm Allowed" in patterns


def test_detect_insecure_ciphers_and_modes(tmp_path: Path) -> None:
    py_file = tmp_path / "crypto_utils.py"
    py_file.write_text(
        "cipher = AES.new(key, AES.MODE_ECB)\n"
        "rsa_key = RSA.generate(1024)\n",
        encoding="utf-8",
    )
    js_file = tmp_path / "legacy.js"
    js_file.write_text(
        "const c = crypto.createCipher('des', secretKey);\n",
        encoding="utf-8",
    )

    scanner = AuthCryptoScanner(tmp_path)
    findings = scanner.scan()

    patterns = {f.pattern for f in findings}
    assert "Insecure AES ECB Mode" in patterns
    assert "Weak RSA Key Size (< 2048 bits)" in patterns
    assert "Broken Legacy Cipher (DES/RC4/Blowfish)" in patterns


def test_detect_insecure_randomness(tmp_path: Path) -> None:
    js_file = tmp_path / "tokens.js"
    js_file.write_text(
        "const sessionToken = Math.random().toString(36) + 'token';\n",
        encoding="utf-8",
    )
    py_file = tmp_path / "tokens.py"
    py_file.write_text(
        "auth_token = random.randint(100000, 999999)\n",
        encoding="utf-8",
    )

    scanner = AuthCryptoScanner(tmp_path)
    findings = scanner.scan()

    patterns = {f.pattern for f in findings}
    assert "Insecure Math.random() for Security Tokens" in patterns
    assert "Python Insecure random Module for Secrets" in patterns


def test_detect_timing_attack(tmp_path: Path) -> None:
    js_file = tmp_path / "verify.js"
    js_file.write_text(
        "if (userToken === expected_token) { return true; }\n",
        encoding="utf-8",
    )

    scanner = AuthCryptoScanner(tmp_path)
    findings = scanner.scan()

    patterns = {f.pattern for f in findings}
    assert "Non-Constant-Time Token Comparison" in patterns


def test_detect_disabled_tls(tmp_path: Path) -> None:
    py_file = tmp_path / "client.py"
    py_file.write_text(
        "resp = requests.get('https://internal.bank', verify=False)\n",
        encoding="utf-8",
    )
    js_file = tmp_path / "agent.js"
    js_file.write_text(
        "const agent = new https.Agent({ rejectUnauthorized: false });\n",
        encoding="utf-8",
    )
    go_file = tmp_path / "tls.go"
    go_file.write_text(
        "cfg := &tls.Config{InsecureSkipVerify: true}\n",
        encoding="utf-8",
    )

    scanner = AuthCryptoScanner(tmp_path)
    findings = scanner.scan()

    patterns = {f.pattern for f in findings}
    assert "Python Requests verify=False (TLS Disabled)" in patterns
    assert "Node.js rejectUnauthorized: false (TLS Disabled)" in patterns
    assert "Go InsecureSkipVerify: true (TLS Disabled)" in patterns


def test_detect_insecure_cookie_attributes(tmp_path: Path) -> None:
    js_file = tmp_path / "server.js"
    js_file.write_text(
        "res.cookie('session_id', sid, { httpOnly: false });\n"
        "res.cookie('token', t, { secure: false });\n",
        encoding="utf-8",
    )

    scanner = AuthCryptoScanner(tmp_path)
    findings = scanner.scan()

    patterns = {f.pattern for f in findings}
    assert "Cookie httpOnly Flag Disabled" in patterns
    assert "Cookie secure Flag Disabled" in patterns
