"""Fernet encryption for sensitive settings stored in the database."""

import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken

# Fields that must be encrypted at rest
SENSITIVE_KEYS = {"kea_password", "rndc_key", "tsig_key_secret"}

# Path to the auto-generated key file (used when SECRET_KEY env var is absent)
# DATA_DIR can be overridden so the key file lives on the host mount.
_BASE_DIR = os.path.dirname(os.path.dirname(__file__))
_KEY_FILE = os.path.join(os.environ.get("DATA_DIR", _BASE_DIR), ".encryption_key")

# Prefix stored in the DB to mark an encrypted value
_ENC_PREFIX = "enc:"


def _build_fernet() -> Fernet:
    """Return a Fernet instance keyed from SECRET_KEY env var or a local key file."""
    secret = os.environ.get("SECRET_KEY", "").strip()
    if secret:
        # Derive a deterministic 32-byte key from the secret
        raw = hashlib.sha256(secret.encode()).digest()
        return Fernet(base64.urlsafe_b64encode(raw))

    # Persist a randomly-generated key in a root-only readable file
    if os.path.exists(_KEY_FILE):
        with open(_KEY_FILE, "rb") as f:
            key = f.read().strip()
    else:
        key = Fernet.generate_key()
        with open(_KEY_FILE, "wb") as f:
            f.write(key)
        os.chmod(_KEY_FILE, 0o600)

    return Fernet(key)


def encrypt(value: str) -> str:
    """Encrypt *value* and return a prefixed ciphertext string safe for DB storage."""
    if not value:
        return value
    token = _build_fernet().encrypt(value.encode()).decode()
    return _ENC_PREFIX + token


def decrypt(value: str) -> str:
    """Decrypt a prefixed ciphertext string.

    If the value is not prefixed (plain-text legacy row) it is returned as-is
    so that the DB can be re-encrypted on the next save.
    """
    if not value or not value.startswith(_ENC_PREFIX):
        return value  # unencrypted legacy value – returned as-is
    try:
        return _build_fernet().decrypt(value[len(_ENC_PREFIX):].encode()).decode()
    except InvalidToken:
        # Key mismatch or corrupted data – return empty rather than crash
        return ""
