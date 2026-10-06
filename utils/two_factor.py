"""
two_factor.py — TOTP-based two-factor authentication (RFC 6238), plus
one-time backup codes for account recovery if the user loses their
authenticator app.
"""
import secrets
import string

import pyotp


def generate_totp_secret() -> str:
    """Base32 secret, compatible with Google Authenticator / Authy / 1Password."""
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str, issuer: str) -> str:
    """otpauth:// URI that a QR-code generator (or manual entry) can use."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp_code(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    code = code.strip().replace(" ", "")
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=1)
    except Exception:
        return False


def generate_backup_codes(count: int = 8) -> list[str]:
    """Human-friendly one-time codes, e.g. 'x7k2-9f3q'."""
    alphabet = string.ascii_lowercase + string.digits
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(alphabet) for _ in range(8))
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes
