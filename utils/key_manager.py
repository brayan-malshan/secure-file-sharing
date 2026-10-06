"""
key_manager.py — Handles generating a keypair for a new user, storing the
private key encrypted-at-rest on disk, and retrieving it later when the
user needs to decrypt an AES file key (i.e. on every file download).
"""
import os

from utils.crypto import (
    generate_rsa_keypair,
    encrypt_private_key_for_storage,
    decrypt_private_key_from_storage,
    load_private_key,
)


def create_user_keypair(username: str, password: str, keys_dir: str, recovery_code: str | None = None):
    """
    Generates a fresh RSA keypair for a new user, writes the encrypted
    private key to disk, and returns (public_pem_str, private_key_path,
    recovery_key_path). recovery_key_path is None if no recovery_code is
    given (kept optional so existing callers/tests don't break).
    """
    os.makedirs(keys_dir, exist_ok=True)

    _private_key_obj, public_pem, private_pem = generate_rsa_keypair()

    encrypted_blob = encrypt_private_key_for_storage(private_pem, password)

    filename = f"{username}_private.key"
    path = os.path.join(keys_dir, filename)
    with open(path, "wb") as f:
        f.write(encrypted_blob)
    os.chmod(path, 0o600)  # owner read/write only

    recovery_key_path = None
    if recovery_code:
        recovery_key_path = create_recovery_envelope(username, recovery_code, private_pem, keys_dir)

    return public_pem.decode("utf-8"), path, recovery_key_path


def load_user_private_key(private_key_path: str, password: str):
    """
    Decrypts and loads a user's RSA private key object using their password.
    Raises an exception (InvalidTag from AESGCM) if the password is wrong —
    callers should catch this and treat it as an authentication failure.
    """
    with open(private_key_path, "rb") as f:
        blob = f.read()
    private_pem = decrypt_private_key_from_storage(blob, password)
    return load_private_key(private_pem)



# ---------------------------------------------------------------------------
# Recovery envelope — a SECOND, independent copy of the same private key,
# encrypted with a one-time recovery code instead of the account password.
# This is what makes a real "forgot password" flow possible without the
# server ever holding a plaintext copy of anyone's private key: the
# recovery code is functionally a second password, known only to the user.
# ---------------------------------------------------------------------------

def create_recovery_envelope(username: str, recovery_code: str, private_pem: bytes, keys_dir: str) -> str:
    """Writes a recovery-code-encrypted copy of `private_pem` to disk and
    returns its path. Called at registration and again any time the
    recovery code is regenerated or consumed (rotated after use)."""
    os.makedirs(keys_dir, exist_ok=True)
    encrypted_blob = encrypt_private_key_for_storage(private_pem, recovery_code)
    filename = f"{username}_recovery.key"
    path = os.path.join(keys_dir, filename)
    with open(path, "wb") as f:
        f.write(encrypted_blob)
    os.chmod(path, 0o600)
    return path


def load_private_key_via_recovery(recovery_key_path: str, recovery_code: str) -> bytes:
    """Attempts to unlock the recovery envelope with a user-supplied
    recovery code. Returns the private key PEM bytes on success. Raises
    an exception (InvalidTag) if the code is wrong — treat exactly like a
    failed password check."""
    with open(recovery_key_path, "rb") as f:
        blob = f.read()
    return decrypt_private_key_from_storage(blob, recovery_code)