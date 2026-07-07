import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

CHUNK_SIZE = 1024 * 1024  # 1 MB
NONCE_SIZE = 12
KEY_SIZE = 32  # AES-256
SALT_SIZE = 16
HMAC_SIZE = 32
PBKDF2_ITERATIONS = 200_000


def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derive a 256-bit key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password)


def encrypt_chunk(key: bytes, chunk: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Encrypt a chunk using AES-256-GCM. Returns (nonce, ciphertext+tag)."""
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, chunk, aad)
    return nonce, ct


def decrypt_chunk(key: bytes, nonce: bytes, ct: bytes, aad: bytes = b"") -> bytes:
    """Decrypt a chunk using AES-256-GCM."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, aad)


def compute_hmac(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA256 for integrity verification."""
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac(key: bytes, data: bytes, mac: bytes) -> bool:
    """Constant-time HMAC verification."""
    return hmac.compare_digest(compute_hmac(key, data), mac)
