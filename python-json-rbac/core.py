"""
JWT / JWE creation and verification.
"""
import datetime
from typing import Any, Dict, Optional

from jose import jwt, JWTError, ExpiredSignatureError
from jose.exceptions import JWTClaimsError
from jose.utils import base64url_encode
from fastapi import HTTPException, status

from .config import (
    JWT_SECRET,
    PRIVATE_KEY_PATH,
    PUBLIC_KEY_PATH,
    ALGORITHM,
    ENABLE_JWE,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)

# --------------------------------------------------------------------------- #
#                               KEY HELPERS                                   #
# --------------------------------------------------------------------------- #
def _load_key(path: Optional[str], is_private: bool = False) -> str:
    """Load RSA key from file."""
    if not path or not os.path.exists(path):
        raise RuntimeError(f"Key file not found: {path}")
    with open(path, "rb") as f:
        return f.read().decode()

def _get_signing_key() -> str:
    if ALGORITHM == "HS256":
        return JWT_SECRET
    if ALGORITHM == "RS256":
        if not PRIVATE_KEY_PATH:
            raise RuntimeError("JWT_PRIVATE_KEY_PATH required for RS256")
        return _load_key(PRIVATE_KEY_PATH, is_private=True)
    raise NotImplementedError(ALGORITHM)

def _get_verify_key() -> str:
    if ALGORITHM == "HS256":
        return JWT_SECRET
    if ALGORITHM == "RS256":
        if not PUBLIC_KEY_PATH:
            raise RuntimeError("JWT_PUBLIC_KEY_PATH required for RS256")
        return _load_key(PUBLIC_KEY_PATH)
    raise NotImplementedError(ALGORITHM)

# --------------------------------------------------------------------------- #
#                          TOKEN CREATION (JWT / JWE)                         #
# --------------------------------------------------------------------------- #
def create_token(
    payload: Dict[str, Any],
    expires_delta: Optional[datetime.timedelta] = None,
) -> str:
    """
    Create a signed (and optionally encrypted) token.
    `payload` MUST contain at minimum: `sub` and `role`.
    """
    if "sub" not in payload or "role" not in payload:
        raise ValueError("payload must contain 'sub' and 'role' claims")

    now = datetime.datetime.utcnow()
    exp = now + (expires_delta or datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    claims = {
        "iat": now,
        "nbf": now,
        "exp": exp,
        "jti": base64url_encode(os.urandom(16)).decode(),  # 128-bit nonce
        **payload,
    }

    signing_key = _get_signing_key()
    jwt_token = jwt.encode(claims, signing_key, algorithm=ALGORITHM)

    if not ENABLE_JWE:
        return jwt_token

    # --- Optional JWE encryption (dir + A256GCM) -----------------------------
    from jose import jwe

    return jwe.encrypt(
        jwt_token,
        key=JWT_SECRET.encode(),  # direct symmetric key
        algorithm="dir",
        encryption="A256GCM",
    ).decode()

# --------------------------------------------------------------------------- #
#                             TOKEN VERIFICATION                              #
# --------------------------------------------------------------------------- #
def verify_token(token: str) -> Dict[str, Any]:
    """
    Verify signature, decrypt (if JWE), validate claims, and return payload.
    Raises 401 on any failure.
    """
    try:
        # --- Decrypt if JWE ----------------------------------------------------
        if ENABLE_JWE:
            from jose import jwe

            token = jwe.decrypt(token, key=JWT_SECRET.encode()).decode()

        # --- Verify signature & claims ----------------------------------------
        verify_key = _get_verify_key()
        payload = jwt.decode(
            token,
            verify_key,
            algorithms=[ALGORITHM],
            options={"verify_exp": True, "verify_nbf": True, "verify_iat": True},
        )

        # --- Enforce required claims ------------------------------------------
        if "sub" not in payload or "role" not in payload:
            raise JWTClaimsError("Missing required claims")

        return payload

    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except (JWTError, JWTClaimsError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
