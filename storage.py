"""
storage.py

Handles:
- Storage initialization
- User directories
- JSON/Text/Byte file operations
- Password-derived KEK
- Encryption/decryption of private keys
"""

import os
import json
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from models import (
    BASE_DIR,
    USERS_DIR,
    MSGS_DIR,
    b64e,
    b64d,
)


# ======================================================
# Initialize Storage
# ======================================================

def initialize_storage():
    """
    Create the application's storage folders.
    """
    for directory in (BASE_DIR, USERS_DIR, MSGS_DIR):
        directory.mkdir(parents=True, exist_ok=True)


# ======================================================
# User Helpers
# ======================================================

def user_path(username):
    return USERS_DIR / username.lower()


def user_exists(username):
    return user_path(username).exists()


# ======================================================
# Key Encryption Key (KEK)
# ======================================================

def derive_kek(password: str, salt: bytes) -> bytes:
    """
    SHA-256(salt || password)
    """
    return hashlib.sha256(
        salt + password.encode()
    ).digest()


# ======================================================
# Encrypt Private Keys
# ======================================================

def encrypt_blob(raw: bytes, password: str) -> dict:

    salt = os.urandom(16)

    kek = derive_kek(
        password,
        salt
    )

    nonce = os.urandom(12)

    ciphertext = AESGCM(
        kek
    ).encrypt(
        nonce,
        raw,
        None
    )

    return {
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "ct": b64e(ciphertext)
    }


# ======================================================
# Decrypt Private Keys
# ======================================================

def decrypt_blob(blob: dict, password: str) -> bytes:

    kek = derive_kek(
        password,
        b64d(blob["salt"])
    )

    return AESGCM(
        kek
    ).decrypt(
        b64d(blob["nonce"]),
        b64d(blob["ct"]),
        None
    )


# ======================================================
# JSON Helpers
# ======================================================

def save_json(path, data):
    path.write_text(
        json.dumps(data, indent=2)
    )


def load_json(path):
    return json.loads(
        path.read_text()
    )


# ======================================================
# Text Helpers
# ======================================================

def save_text(path, text):
    path.write_text(text)


def load_text(path):
    return path.read_text()


# ======================================================
# Byte Helpers
# ======================================================

def save_bytes(path, data):
    path.write_bytes(data)


def load_bytes(path):
    return path.read_bytes()