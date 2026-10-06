"""
crypto.py — Core cryptographic primitives for the Secure File Sharing System.

Design:
  - Each user has an RSA-3072 keypair (RSA-OAEP / SHA-256 padding).
  - Each FILE gets a fresh random AES-256 key, used once, never reused.
  - The file is encrypted with AES-256-GCM (authenticated encryption —
    detects tampering, not just confidentiality).
  - The AES key is then "wrapped" (encrypted) with the RECIPIENT's RSA
    public key, once per recipient. This means:
      * The server never stores an AES key in the clear.
      * Revoking one user's access does not require re-encrypting the file.
      * Only someone holding the matching RSA private key can unwrap it.
"""
import hashlib
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

RSA_KEY_SIZE = 3072
AES_KEY_SIZE = 32  # 256 bits
GCM_NONCE_SIZE = 12  # 96 bits, standard for GCM
PBKDF2_ITERATIONS = 480_000  # OWASP 2023+ recommendation for PBKDF2-HMAC-SHA256
SALT_SIZE = 16


# ---------------------------------------------------------------------------
# RSA keypair generation
# ---------------------------------------------------------------------------

def generate_rsa_keypair():
    """Generate a new RSA-3072 keypair. Returns (private_key_obj, public_pem_bytes, private_pem_bytes_unencrypted)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return private_key, public_pem, private_pem


def load_public_key(pem_bytes):
    return serialization.load_pem_public_key(pem_bytes)


def load_private_key(pem_bytes):
    return serialization.load_pem_private_key(pem_bytes, password=None)


# ---------------------------------------------------------------------------
# Password-based encryption of the user's PRIVATE key at rest
# (so a stolen database/disk alone can't yield usable private keys)
# ---------------------------------------------------------------------------

def _derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_private_key_for_storage(private_pem: bytes, password: str) -> bytes:
    """Wrap the private key PEM with AES-256-GCM using a key derived from the
    user's password. Output layout: salt(16) || nonce(12) || ciphertext."""
    salt = os.urandom(SALT_SIZE)
    key = _derive_key_from_password(password, salt)
    nonce = os.urandom(GCM_NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, private_pem, None)
    return salt + nonce + ciphertext


def decrypt_private_key_from_storage(blob: bytes, password: str) -> bytes:
    salt, nonce, ciphertext = blob[:SALT_SIZE], blob[SALT_SIZE:SALT_SIZE + GCM_NONCE_SIZE], blob[SALT_SIZE + GCM_NONCE_SIZE:]
    key = _derive_key_from_password(password, salt)
    return AESGCM(key).decrypt(nonce, ciphertext, None)


# ---------------------------------------------------------------------------
# AES-256-GCM file encryption
# ---------------------------------------------------------------------------

def generate_aes_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def encrypt_file_data(plaintext: bytes, aes_key: bytes):
    """Returns (ciphertext, nonce_hex)."""
    nonce = os.urandom(GCM_NONCE_SIZE)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    return ciphertext, nonce.hex()


def decrypt_file_data(ciphertext: bytes, aes_key: bytes, nonce_hex: str) -> bytes:
    nonce = bytes.fromhex(nonce_hex)
    return AESGCM(aes_key).decrypt(nonce, ciphertext, None)


# ---------------------------------------------------------------------------
# Streaming AES-256-GCM (for large files — never holds the whole file in RAM)
#
# Format on disk: a sequence of frames, each:
#   [4-byte big-endian chunk length] [ciphertext+16-byte GCM tag]
# Each chunk gets its own nonce = 8-byte random prefix (fixed per file,
# returned as nonce_hex) + 4-byte big-endian chunk counter. GCM's security
# depends on never reusing a (key, nonce) pair — the counter guarantees
# every chunk in a file gets a unique nonce.
# ---------------------------------------------------------------------------

STREAM_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB plaintext per chunk
_NONCE_PREFIX_SIZE = 8
_CHUNK_COUNTER_SIZE = 4
_FRAME_LEN_SIZE = 4


def _chunk_nonce(nonce_prefix: bytes, counter: int) -> bytes:
    return nonce_prefix + counter.to_bytes(_CHUNK_COUNTER_SIZE, "big")


def encrypt_stream(read_chunk, write_bytes, aes_key: bytes, chunk_size: int = STREAM_CHUNK_SIZE):
    """
    Encrypts an incoming file chunk-by-chunk without ever holding the full
    file in memory.

    read_chunk: callable() -> bytes, returns up to `chunk_size` bytes,
                b"" at end of stream (like file.read(n)).
    write_bytes: callable(bytes) -> None, writes to the output (e.g. an
                 open file handle's .write).

    Returns (nonce_prefix_hex, sha256_hex_of_plaintext).
    """
    nonce_prefix = os.urandom(_NONCE_PREFIX_SIZE)
    aesgcm = AESGCM(aes_key)
    hasher = hashlib.sha256()
    counter = 0

    while True:
        chunk = read_chunk(chunk_size)
        if not chunk:
            break
        hasher.update(chunk)
        nonce = _chunk_nonce(nonce_prefix, counter)
        ciphertext = aesgcm.encrypt(nonce, chunk, None)
        write_bytes(len(ciphertext).to_bytes(_FRAME_LEN_SIZE, "big"))
        write_bytes(ciphertext)
        counter += 1

    return nonce_prefix.hex(), hasher.hexdigest()


def decrypt_stream(read_exact, aes_key: bytes, nonce_prefix_hex: str):
    """
    Generator that yields decrypted plaintext chunks one at a time.

    read_exact: callable(n) -> bytes, returns exactly n bytes (or fewer
                only at true EOF — like a file handle's .read(n) on a
                normal file). Raises cryptography.exceptions.InvalidTag
                if any chunk fails authentication (tampering/corruption).
    """
    nonce_prefix = bytes.fromhex(nonce_prefix_hex)
    aesgcm = AESGCM(aes_key)
    counter = 0

    while True:
        len_bytes = read_exact(_FRAME_LEN_SIZE)
        if not len_bytes:
            break  # clean end of file
        if len(len_bytes) != _FRAME_LEN_SIZE:
            raise ValueError("Corrupt file: truncated frame header.")
        frame_len = int.from_bytes(len_bytes, "big")
        ciphertext = read_exact(frame_len)
        if len(ciphertext) != frame_len:
            raise ValueError("Corrupt file: truncated frame body.")
        nonce = _chunk_nonce(nonce_prefix, counter)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)  # raises InvalidTag on tamper
        yield plaintext
        counter += 1


# ---------------------------------------------------------------------------
# RSA-OAEP wrapping of AES keys (the "hybrid" part of hybrid encryption)
# ---------------------------------------------------------------------------

_OAEP_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def wrap_aes_key(aes_key: bytes, recipient_public_key) -> str:
    """Encrypt an AES key with a recipient's RSA public key. Returns hex string."""
    wrapped = recipient_public_key.encrypt(aes_key, _OAEP_PADDING)
    return wrapped.hex()


def unwrap_aes_key(wrapped_hex: str, recipient_private_key) -> bytes:
    wrapped = bytes.fromhex(wrapped_hex)
    return recipient_private_key.decrypt(wrapped, _OAEP_PADDING)


# ---------------------------------------------------------------------------
# Integrity
# ---------------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()