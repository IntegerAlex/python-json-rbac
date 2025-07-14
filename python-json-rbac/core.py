"""
JWT / JWE creation and verification.
"""
import datetime
import os
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
    """
    Loads an RSA key from the specified file path.
    
    Parameters:
        path (Optional[str]): Path to the RSA key file.
        is_private (bool): Indicates whether the key is a private key.
    
    Returns:
        str: The contents of the RSA key file as a string.
    
    Raises:
        RuntimeError: If the key file does not exist or the path is not provided.
    """
    if not path or not os.path.exists(path):
        raise RuntimeError(f"Key file not found: {path}")
    with open(path, "rb") as f:
        return f.read().decode()

def _get_signing_key() -> str:
    """
    Return the signing key for JWT creation based on the configured algorithm.
    
    For HS256, returns the symmetric secret. For RS256, loads and returns the RSA private key from the configured file path. Raises a RuntimeError if the private key path is missing for RS256, or NotImplementedError for unsupported algorithms.
    """
    if ALGORITHM == "HS256":
        return JWT_SECRET
    if ALGORITHM == "RS256":
        if not PRIVATE_KEY_PATH:
            raise RuntimeError("JWT_PRIVATE_KEY_PATH required for RS256")
        return _load_key(PRIVATE_KEY_PATH, is_private=True)
    raise NotImplementedError(ALGORITHM)

def _get_verify_key() -> str:
    """
    Returns the key used to verify JWT signatures based on the configured algorithm.
    
    For HS256, returns the shared secret. For RS256, loads and returns the public key from the configured file path. Raises a RuntimeError if the public key path is missing for RS256, or NotImplementedError for unsupported algorithms.
    """
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
    Generate a signed JWT token from the provided payload, optionally encrypting it as a JWE.
    
    The payload must include the `sub` and `role` claims. Standard claims (`iat`, `nbf`, `exp`, `jti`) are added automatically. The token is signed using the configured algorithm and key. If JWE encryption is enabled, the signed JWT is encrypted using direct symmetric encryption (AES-256-GCM).
    
    Parameters:
        payload (Dict[str, Any]): Claims to include in the token. Must contain `sub` and `role`.
        expires_delta (Optional[datetime.timedelta]): Optional expiration interval. Defaults to a configured value if not provided.
    
    Returns:
        str: The signed (and optionally encrypted) token as a string.
    
    Raises:
        ValueError: If the payload does not contain both `sub` and `role` claims.
    """
    if "sub" not in payload or "role" not in payload:
        raise ValueError("payload must contain 'sub' and 'role' claims")

    now = datetime.datetime.now(datetime.timezone.utc)
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
    Verifies a JWT or JWE token, ensuring signature validity, claim integrity, and required claims, and returns the decoded payload.
    
    If the token is encrypted (JWE), it is decrypted before verification. The function checks for token expiration, not-before, issued-at, and the presence of mandatory claims ("sub" and "role"). Raises an HTTP 401 error if the token is expired, invalid, or missing required claims.
    
    Parameters:
        token (str): The JWT or JWE token string to verify.
    
    Returns:
        Dict[str, Any]: The decoded payload of the verified token.
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
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired") from None
    except (JWTError, JWTClaimsError, ValueError) as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from err
    except Exception as err:
        # Catch potential JWE decryption errors
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format") from err
