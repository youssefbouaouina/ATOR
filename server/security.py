import hashlib
import hmac
import os
import secrets


def generate_api_key():
    return "ator_" + secrets.token_urlsafe(32)


def hash_secret(secret, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, 120_000)
    return salt.hex() + "$" + digest.hex()


def verify_secret(secret, stored):
    try:
        salt_hex, digest_hex = stored.split("$", 1)
    except ValueError:
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", secret.encode(), bytes.fromhex(salt_hex), 120_000)
    return hmac.compare_digest(candidate.hex(), digest_hex)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def new_client_id():
    return "host-" + secrets.token_hex(8)


def random_token(nbytes=16):
    return secrets.token_hex(nbytes)


def constant_time_eq(a, b):
    return hmac.compare_digest(str(a), str(b))
