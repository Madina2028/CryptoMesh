"""
auth.py

User registration and authentication.
"""

import bcrypt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from models import DH_PARAMETERS
from storage import (
    user_path,
    user_exists,
    encrypt_blob,
    decrypt_blob,
    save_bytes,
    save_text,
    save_json,
    load_bytes,
    load_json,
)


# =========================
# Register User
# =========================

def register_user(data):

    username = data.get("username", "").strip().lower()
    password = data.get("password", "")

    if not username or not password:
        return {"error": "Username and password required"}, 400

    if len(password) < 4:
        return {"error": "Password must be at least 4 characters"}, 400

    if user_exists(username):
        return {"error": "User already exists"}, 409

    ud = user_path(username)
    ud.mkdir(parents=True, exist_ok=True)

    # bcrypt password hash
    pw_hash = bcrypt.hashpw(
        password.encode(),
        bcrypt.gensalt()
    )

    save_bytes(
        ud / "pw_hash.txt",
        pw_hash
    )

    # Long-term Diffie-Hellman key pair
    dh_priv = DH_PARAMETERS.generate_private_key()

    dh_priv_int = dh_priv.private_numbers().x
    dh_pub_int = dh_priv.public_key().public_numbers().y

    # RSA signing key pair
    rsa_priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    rsa_priv_pem = rsa_priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    )

    rsa_pub_pem = rsa_priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Encrypt private keys
    save_json(
        ud / "dh_priv.json",
        encrypt_blob(str(dh_priv_int).encode(), password)
    )

    save_json(
        ud / "rsa_priv.json",
        encrypt_blob(rsa_priv_pem, password)
    )

    # Save public keys
    save_text(
        ud / "dh_pub.txt",
        str(dh_pub_int)
    )

    save_bytes(
        ud / "rsa_pub.pem",
        rsa_pub_pem
    )

    return {
        "success": True,
        "steps": [
            {
                "step": "Password Hashing (bcrypt)",
                "detail": f"bcrypt(password) -> {pw_hash.decode()[:29]}…"
            },
            {
                "step": "DH Keypair (2048-bit MODP group)",
                "detail": f"private x sampled, public y = g^x mod p -> {hex(dh_pub_int)[:34]}…"
            },
            {
                "step": "RSA Signing Keypair (2048-bit)",
                "detail": "Generated for STS key confirmation and message signatures"
            },
            {
                "step": "Private Key Encryption at Rest",
                "detail": "SHA-256(salt ‖ password) -> 32-byte KEK -> AES-256-GCM wraps DH and RSA private keys"
            }
        ]
    }, 200


# =========================
# Login
# =========================

def login_user(data):

    username = data.get("username", "").strip().lower()
    password = data.get("password", "")

    if not user_exists(username):
        return {"error": "User not found"}, 404

    ud = user_path(username)

    stored = load_bytes(
        ud / "pw_hash.txt"
    )

    if not bcrypt.checkpw(password.encode(), stored):
        return {"error": "Invalid password"}, 401

    try:
        blob = load_json(
            ud / "dh_priv.json"
        )

        decrypt_blob(
            blob,
            password
        )

    except Exception:
        return {"error": "Key decryption failed"}, 401

    return {
        "success": True,
        "username": username,
        "steps": [
            {
                "step": "bcrypt.checkpw",
                "detail": "Constant-time comparison against stored hash"
            },
            {
                "step": "KEK derivation",
                "detail": "SHA-256(salt ‖ password) -> 32-byte KEK"
            },
            {
                "step": "Private key unlock",
                "detail": "AES-256-GCM.decrypt(KEK, encrypted_priv) -> raw DH/RSA keys"
            }
        ]
    }, 200


# =========================
# List Users
# =========================

def list_users():

    from models import USERS_DIR

    return [
        p.name
        for p in USERS_DIR.iterdir()
        if p.is_dir()
    ]