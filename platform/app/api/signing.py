"""Ed25519 request signing shared by /enroll and /report (DESIGN.md §4.2).

The plugin signs:  f"{timestamp}\\n{nonce}\\n{sha256_hex(body)}"
with its private key, and sends the signature base64-encoded (standard alphabet, padded).
"""

import base64
import binascii
import hashlib
import re

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

NONCE_RE = re.compile(r"^[0-9a-f]{32}$")  # 16 random bytes, hex
TIMESTAMP_RE = re.compile(r"^\d{9,11}$")
SIGNATURE_RE = re.compile(r"^[A-Za-z0-9+/]{86}==$")  # 64 bytes


def decode_public_key(b64: str) -> bytes:
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError("public key is not valid base64") from e
    if len(raw) != 32:
        raise ValueError("public key must be 32 bytes")
    return raw


def key_id_for(public_key_b64: str) -> str:
    """First 16 hex chars of sha256(raw public key). The plugin computes the same value."""
    return hashlib.sha256(decode_public_key(public_key_b64)).hexdigest()[:16]


def signed_message(timestamp: str, nonce: str, body: bytes) -> bytes:
    return f"{timestamp}\n{nonce}\n{hashlib.sha256(body).hexdigest()}".encode()


def verify(
    public_key_b64: str, timestamp: str, nonce: str, body: bytes, signature_b64: str
) -> bool:
    if not SIGNATURE_RE.match(signature_b64):
        return False
    try:
        key = VerifyKey(decode_public_key(public_key_b64))
        key.verify(signed_message(timestamp, nonce, body), base64.b64decode(signature_b64))
    except (ValueError, BadSignatureError):
        return False
    return True
