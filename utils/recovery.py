"""
recovery.py — Generates the one-time account-recovery code shown to a
user at registration (and whenever they regenerate it). This code is the
ONLY way to reset a forgotten password without already knowing it,
because it doubles as the key that unlocks a spare, separately-wrapped
copy of the user's RSA private key (see utils/key_manager.py).
"""
import secrets
import string

_ALPHABET = string.ascii_uppercase + string.digits
_GROUP_COUNT = 5
_GROUP_LEN = 4


def generate_recovery_code() -> str:
    """Human-friendly, high-entropy code, e.g. 'K7QX-9F3M-2LWP-8HDT-4RCN'."""
    groups = []
    for _ in range(_GROUP_COUNT):
        groups.append("".join(secrets.choice(_ALPHABET) for _ in range(_GROUP_LEN)))
    return "-".join(groups)


def normalize_recovery_code(raw: str) -> str:
    """Uppercases and strips whitespace so users can paste a code with
    stray spaces/lowercase letters and still have it match."""
    return "".join(raw.split()).upper()