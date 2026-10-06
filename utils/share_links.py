"""
share_links.py — "Capability URL" public sharing, in the spirit of
Firefox Send / WeTransfer secure links.

A share link lets someone WITHOUT an account fetch a file. To keep this
consistent with the rest of the system's rule ("the server never stores
an AES file key in recoverable form"), the file's AES key is re-wrapped
with a symmetric key derived (via PBKDF2-HMAC-SHA256) from the link's own
random token. Knowing the token — i.e. holding the URL — is both how you
look the link up AND the only way to reconstruct the key that decrypts it.
An optional password adds a second factor on top of "possession of the URL".
"""
import os
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_ITERATIONS = 200_000
_SALT_SIZE = 16
_NONCE_SIZE = 12


def generate_token(n_bytes: int = 32) -> str:
    return secrets.token_urlsafe(n_bytes)


def _derive_key(token: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_ITERATIONS)
    return kdf.derive(token.encode("utf-8"))


def wrap_key_for_link(aes_key: bytes, token: str):
    """Returns (salt_hex, wrapped_hex)."""
    salt = os.urandom(_SALT_SIZE)
    key = _derive_key(token, salt)
    nonce = os.urandom(_NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, aes_key, None)
    return salt.hex(), (nonce.hex() + ciphertext.hex())


def unwrap_key_for_link(salt_hex: str, wrapped_hex: str, token: str) -> bytes:
    salt = bytes.fromhex(salt_hex)
    key = _derive_key(token, salt)
    blob = bytes.fromhex(wrapped_hex)
    nonce, ciphertext = blob[:_NONCE_SIZE], blob[_NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ciphertext, None)
