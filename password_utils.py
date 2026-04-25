"""
Watcher IDS Dashboard — Password Utilities
Shared PBKDF2-SHA256 hashing used by both AuthManager and UserManager.
Single source of truth — previously duplicated across auth.py and users.py.
"""

import hashlib
import hmac
import secrets

from config import PBKDF2_ITERS


def hash_password(password: str) -> str:
    """
    Hash a plaintext password using PBKDF2-SHA256.
    Returns a string in the form  salt$hex_digest
    """
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), PBKDF2_ITERS
    )
    return f"{salt}${h.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """
    Constant-time comparison of a plaintext password against a stored hash.
    Returns False on any error (malformed stored value, empty inputs, etc.).
    """
    try:
        salt, h = stored.split("$", 1)
        check = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), PBKDF2_ITERS
        )
        return hmac.compare_digest(check.hex(), h)
    except Exception:
        return False
