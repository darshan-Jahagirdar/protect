"""Passwords, authenticator codes and setup links for dashboard sign-in (DESIGN.md §4.13).

Standard library and PyNaCl only, so there is nothing new to trust:
- Passwords: scrypt (hashlib), a random salt per user, compared in constant time.
- Authenticator codes: TOTP (RFC 6238; SHA-1, 6 digits, 30 s), the kind Google and Microsoft
  Authenticator show. A code is accepted one step either side of now, and never twice.
- The TOTP secret is stored encrypted (SecretBox) with a key derived from PROTECT_SECRET_KEY,
  so a copied database alone can't produce codes. Changing that key means everyone sets up
  their authenticator again (python -m app.cli reset-user).
- Setup links carry a random token; only its SHA-256 is stored, and it expires.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from datetime import datetime, timedelta
from urllib.parse import quote

import segno
from nacl.exceptions import CryptoError
from nacl.secret import SecretBox

from app.db import utcnow
from app.models import User

# scrypt cost: 32 MB and about 0.1 s per check, fine for a handful of sign-ins a day.
_N, _R, _P = 2**15, 8, 1
_MAXMEM = 64 * 1024 * 1024

PASSWORD_MIN = 12
PASSWORD_MAX = 200
TOTP_STEP = 30
TOTP_DIGITS = 6
SETUP_LINK_HOURS = 24
MAX_FAILURES = 5
LOCKOUT = timedelta(minutes=15)
ISSUER = "Protect"


# --- Passwords ------------------------------------------------------------------------------


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, maxmem=_MAXMEM)
    b64 = base64.b64encode
    return f"scrypt${_N}${_R}${_P}${b64(salt).decode()}${b64(digest).decode()}"


def verify_password(stored: str | None, password: str) -> bool:
    """False for a wrong password, an unset one, or a malformed hash."""
    if not stored:
        _burn(password)  # take as long as a real check, so timing doesn't reveal accounts
        return False
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(digest)
        got = hashlib.scrypt(
            password.encode(),
            salt=base64.b64decode(salt),
            n=int(n),
            r=int(r),
            p=int(p),
            maxmem=_MAXMEM,
            dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, expected)


def _burn(password: str) -> None:
    hashlib.scrypt(password.encode(), salt=b"0" * 16, n=_N, r=_R, p=_P, maxmem=_MAXMEM)


def password_problem(password: str, confirm: str, email: str) -> str | None:
    """Why a new password isn't acceptable, or None."""
    if password != confirm:
        return "The two passwords don't match."
    if len(password) < PASSWORD_MIN:
        return f"Use at least {PASSWORD_MIN} characters. A short sentence is easiest to remember."
    if len(password) > PASSWORD_MAX:
        return f"Use at most {PASSWORD_MAX} characters."
    if password.strip().lower() in (email.lower(), email.split("@")[0].lower()):
        return "Don't use your email address as the password."
    return None


# --- Authenticator codes (TOTP) -------------------------------------------------------------


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()


def _code_at(secret: str, step: int) -> str:
    mac = hmac.new(base64.b32decode(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    number = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10**TOTP_DIGITS).zfill(TOTP_DIGITS)


def totp_code(secret: str, now: float | None = None) -> str:
    return _code_at(secret, int((now if now is not None else time.time()) // TOTP_STEP))


def check_totp(
    secret: str, code: str, last_step: int | None, now: float | None = None
) -> int | None:
    """The time step the code belongs to, or None. A step at or before last_step is refused,
    so a code someone saw over your shoulder can't be used again."""
    code = code.replace(" ", "")
    if len(code) != TOTP_DIGITS or not code.isdigit():
        return None
    current = int((now if now is not None else time.time()) // TOTP_STEP)
    for step in (current - 1, current, current + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(_code_at(secret, step), code):
            return step
    return None


def otpauth_uri(secret: str, email: str) -> str:
    label = quote(f"{ISSUER}:{email}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={ISSUER}&digits=6&period=30"


def qr_data_uri(uri: str) -> str:
    """The QR code as an SVG data: URI, so the page needs no script and the CSP stays strict."""
    return segno.make(uri, error="m").svg_data_uri(scale=6, border=2)


def _box(key: bytes) -> SecretBox:
    return SecretBox(hashlib.sha256(b"protect-totp-v1:" + key).digest())


def encrypt_secret(key: bytes, secret: str) -> str:
    return base64.b64encode(_box(key).encrypt(secret.encode())).decode()


def decrypt_secret(key: bytes, stored: str | None) -> str | None:
    if not stored:
        return None
    try:
        return _box(key).decrypt(base64.b64decode(stored)).decode()
    except (CryptoError, ValueError):
        return None


# --- Setup links ----------------------------------------------------------------------------


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def start_setup(user: User, now: datetime | None = None) -> str:
    """Clear the user's password and authenticator and issue a fresh setup token. Signs them
    out everywhere. Returns the token (shown once, never stored)."""
    token = secrets.token_urlsafe(32)
    user.password_hash = None
    user.totp_secret_enc = None
    user.totp_last_step = None
    user.failed_logins = 0
    user.locked_until = None
    user.setup_token_hash = token_hash(token)
    user.setup_expires_at = (now or utcnow()) + timedelta(hours=SETUP_LINK_HOURS)
    user.session_version = (user.session_version or 0) + 1
    return token


def setup_link(base_url: str, token: str) -> str:
    return f"{base_url.rstrip('/')}/setup/{token}"


def setup_token_matches(user: User, token: str, now: datetime | None = None) -> bool:
    if not user.setup_token_hash or user.setup_expires_at is None:
        return False
    if user.setup_expires_at < (now or utcnow()):
        return False
    return hmac.compare_digest(user.setup_token_hash, token_hash(token))


def is_locked(user: User, now: datetime | None = None) -> bool:
    return user.locked_until is not None and user.locked_until > (now or utcnow())


def record_failure(user: User, now: datetime | None = None) -> None:
    user.failed_logins = (user.failed_logins or 0) + 1
    if user.failed_logins >= MAX_FAILURES:
        user.locked_until = (now or utcnow()) + LOCKOUT
        user.failed_logins = 0
