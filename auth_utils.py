"""Băm và xác minh mật khẩu bằng PBKDF2-HMAC-SHA256."""
from __future__ import annotations

import hashlib
import hmac
import secrets

ALGORITHM_TAG = "pbkdf2_sha256"
SALT_BYTES = 16
HASH_BYTES = 32
MIN_ITERATIONS = 10_000
MAX_ITERATIONS = 2_000_000


def hash_password(plain_password: str, iterations: int) -> str:
    if not isinstance(plain_password, str) or not plain_password:
        raise ValueError("Mật khẩu không được để trống.")
    if not isinstance(iterations, int) or not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
        raise ValueError("Số vòng PBKDF2 nằm ngoài phạm vi hỗ trợ.")
    salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, iterations)
    return f"{ALGORITHM_TAG}${iterations}${salt.hex()}${digest.hex()}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    if not isinstance(plain_password, str) or not isinstance(stored_hash, str):
        return False
    if len(stored_hash) > 128:
        return False
    parts = stored_hash.split("$")
    if (
        len(parts) != 4
        or parts[0] != ALGORITHM_TAG
        or len(parts[2]) != SALT_BYTES * 2
        or len(parts[3]) != HASH_BYTES * 2
    ):
        return False
    try:
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected = bytes.fromhex(parts[3])
    except (ValueError, TypeError):
        return False
    if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
        return False
    if len(salt) != SALT_BYTES or len(expected) != HASH_BYTES:
        return False
    digest = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(digest, expected)


def generate_temp_password(length: int = 18) -> str:
    if not isinstance(length, int) or not 12 <= length <= 128:
        raise ValueError("Độ dài mật khẩu tạm phải từ 12 đến 128.")
    alphabet = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))
