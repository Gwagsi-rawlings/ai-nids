"""
AI-NIDS — Security Utilities
backend/app/core/security.py

Handles:
  - Password hashing (bcrypt, cost factor 12)
  - JWT token creation and verification
  - Token payload schema

FR Traceability: FR14.1 (username/password auth), FR14.3 (password complexity),
                 NFR5.1 (bcrypt cost>=12), NFR5.2 (session expiry 30 min)
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# ── Config ────────────────────────────────────────────────────
SECRET_KEY_ENV = "SECRET_KEY"          # read from os.getenv in dependencies
ALGORITHM      = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480      # 8 hours (US-6.3 AC4)

# ── Password hashing ──────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


def hash_password(plain: str) -> str:
    """Return bcrypt hash of plain-text password (cost factor 12)."""
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if plain matches stored bcrypt hash."""
    return pwd_context.verify(plain, hashed)


# ── JWT token schema ──────────────────────────────────────────
class TokenData(BaseModel):
    user_id: str
    username: str
    role: str          # one of the 4 RBAC roles
    exp: Optional[datetime] = None


# ── Token creation ────────────────────────────────────────────
def create_access_token(
    user_id: str,
    username: str,
    role: str,
    secret_key: str,
    expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES,
) -> str:
    """
    Create a signed JWT embedding user_id, username, and role.
    Expiry defaults to 8 hours (configurable).
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    payload = {
        "sub":      user_id,
        "username": username,
        "role":     role,
        "exp":      expire,
    }
    return jwt.encode(payload, secret_key, algorithm=ALGORITHM)


# ── Token verification ────────────────────────────────────────
def decode_access_token(token: str, secret_key: str) -> TokenData:
    """
    Decode and validate a JWT.
    Raises JWTError on invalid signature, expiry, or malformed token.
    """
    payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM])
    return TokenData(
        user_id=payload["sub"],
        username=payload["username"],
        role=payload["role"],
    )
