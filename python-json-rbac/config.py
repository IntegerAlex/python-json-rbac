"""
Centralised configuration – reads from environment variables or sane defaults.
"""
import os
from typing import Optional

# --- Secrets / Keys ----------------------------------------------------------
JWT_SECRET: str = os.getenv("JWT_SECRET", "")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is required")

PRIVATE_KEY_PATH: Optional[str] = os.getenv("JWT_PRIVATE_KEY_PATH")
PUBLIC_KEY_PATH: Optional[str] = os.getenv("JWT_PUBLIC_KEY_PATH")

# --- Algorithm & Signing -----------------------------------------------------
ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256").upper()
if ALGORITHM not in {"HS256", "RS256"}:
    raise ValueError("Only HS256 and RS256 are supported")

# --- Encryption toggle -------------------------------------------------------
ENABLE_JWE: bool = os.getenv("JWT_ENABLE_JWE", "false").lower() in {"1", "true", "yes"}

# --- Token lifetime ----------------------------------------------------------
try:
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "30"))
except ValueError:
    print("Warning: Invalid JWT_EXPIRE_MINUTES. Must be an integer. Using default 30.")
    ACCESS_TOKEN_EXPIRE_MINUTES = 30
