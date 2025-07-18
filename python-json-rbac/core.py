"""
JWT / JWE creation and verification with secure key rotation.
"""
import datetime
import os
import logging
from typing import Any, Dict, Optional, List, Tuple

from jose import jwt, JWTError, ExpiredSignatureError
from jose.exceptions import JWTClaimsError
from jose.utils import base64url_encode
from fastapi import HTTPException, status

from config import (
    JWT_SECRET,
    JWT_SECRET_PREVIOUS,
    JWT_SECRET_ID,
    JWT_SECRET_PREVIOUS_ID,
    PRIVATE_KEY_PATH,
    PUBLIC_KEY_PATH,
    ALGORITHM,
    ENABLE_JWE,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    KEY_ROTATION_ENABLED,
    KEY_ROTATION_GRACE_PERIOD_HOURS,
    STRICT_MODE,
    MAX_CLOCK_SKEW_SECONDS,
)

# Configure logging
logger = logging.getLogger(__name__)

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
    
    try:
        with open(path, "rb") as f:
            key_content = f.read().decode()
        
        # Basic validation for RSA key format
        if is_private and "PRIVATE KEY" not in key_content:
            raise RuntimeError(f"Invalid private key format in {path}")
        elif not is_private and "PUBLIC KEY" not in key_content:
            raise RuntimeError(f"Invalid public key format in {path}")
            
        return key_content
    except Exception as e:
        raise RuntimeError(f"Failed to load key from {path}: {e}")

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

def _get_verify_keys() -> List[Tuple[str, str]]:
    """
    Returns the keys used to verify JWT signatures with key rotation support.
    
    For HS256, returns the current secret and optionally the previous secret for rotation.
    For RS256, returns the public key. Returns a list of (key, key_id) tuples.
    """
    keys = []
    
    if ALGORITHM == "HS256":
        # Primary key
        keys.append((JWT_SECRET, JWT_SECRET_ID))
        
        # Previous key for rotation support
        if KEY_ROTATION_ENABLED and JWT_SECRET_PREVIOUS:
            keys.append((JWT_SECRET_PREVIOUS, JWT_SECRET_PREVIOUS_ID))
            
    elif ALGORITHM == "RS256":
        if not PUBLIC_KEY_PATH:
            raise RuntimeError("JWT_PUBLIC_KEY_PATH required for RS256")
        public_key = _load_key(PUBLIC_KEY_PATH)
        keys.append((public_key, "rsa-key"))
    else:
        raise NotImplementedError(ALGORITHM)
    
    return keys

def _get_verify_key() -> str:
    """
    Legacy method - returns the primary verify key for backward compatibility.
    """
    keys = _get_verify_keys()
    return keys[0][0] if keys else ""

# --------------------------------------------------------------------------- #
#                          TOKEN CREATION (JWT / JWE)                         #
# --------------------------------------------------------------------------- #
def create_token(
    payload: Dict[str, Any],
    expires_delta: Optional[datetime.timedelta] = None,
    key_id: Optional[str] = None,
) -> str:
    """
    Generate a signed JWT token from the provided payload, optionally encrypting it as a JWE.
    
    The payload must include the `sub` and `role` claims. Standard claims (`iat`, `nbf`, `exp`, `jti`) are added automatically. The token is signed using the configured algorithm and key. If JWE encryption is enabled, the signed JWT is encrypted using direct symmetric encryption (AES-256-GCM).
    
    Parameters:
        payload (Dict[str, Any]): Claims to include in the token. Must contain `sub` and `role`.
        expires_delta (Optional[datetime.timedelta]): Optional expiration interval. Defaults to a configured value if not provided.
        key_id (Optional[str]): Key ID for tracking which key was used for signing.
    
    Returns:
        str: The signed (and optionally encrypted) token as a string.
    
    Raises:
        ValueError: If the payload does not contain both `sub` and `role` claims.
    """
    if "sub" not in payload or "role" not in payload:
        raise ValueError("payload must contain 'sub' and 'role' claims")

    now = datetime.datetime.now(datetime.timezone.utc)
    exp = now + (expires_delta or datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    
    # Add standard claims
    claims = {
        "iat": now,
        "nbf": now,
        "exp": exp,
        "jti": base64url_encode(os.urandom(16)).decode(),  # 128-bit nonce
        **payload,
    }
    
    # Add key ID for rotation tracking if using HS256
    if ALGORITHM == "HS256":
        claims["kid"] = key_id or JWT_SECRET_ID

    signing_key = _get_signing_key()
    
    try:
        jwt_token = jwt.encode(claims, signing_key, algorithm=ALGORITHM)
    except Exception as e:
        logger.error(f"Failed to create JWT token: {e}")
        raise RuntimeError(f"Token creation failed: {e}")

    if not ENABLE_JWE:
        return jwt_token

    # --- Optional JWE encryption (dir + A256GCM) -----------------------------
    try:
        from jose import jwe

        encrypted_token = jwe.encrypt(
            jwt_token,
            key=JWT_SECRET.encode(),  # direct symmetric key
            algorithm="dir",
            encryption="A256GCM",
        ).decode()
        
        return encrypted_token
    except Exception as e:
        logger.error(f"Failed to encrypt token: {e}")
        raise RuntimeError(f"Token encryption failed: {e}")

# --------------------------------------------------------------------------- #
#                             TOKEN VERIFICATION                              #
# --------------------------------------------------------------------------- #
def verify_token(token: str) -> Dict[str, Any]:
    """
    Verifies a JWT or JWE token with key rotation support, ensuring signature validity, 
    claim integrity, and required claims, and returns the decoded payload.
    
    If the token is encrypted (JWE), it is decrypted before verification. The function 
    checks for token expiration, not-before, issued-at, and the presence of mandatory 
    claims ("sub" and "role"). Supports graceful key rotation by trying multiple keys.
    
    Parameters:
        token (str): The JWT or JWE token string to verify.
    
    Returns:
        Dict[str, Any]: The decoded payload of the verified token.
    """
    if not token or not token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Token is required"
        )

    try:
        # --- Decrypt if JWE ----------------------------------------------------
        decrypted_token = token
        if ENABLE_JWE:
            try:
                from jose import jwe
                decrypted_token = jwe.decrypt(token, key=JWT_SECRET.encode()).decode()
            except Exception as jwe_error:
                # Try with previous key if rotation is enabled
                if KEY_ROTATION_ENABLED and JWT_SECRET_PREVIOUS:
                    try:
                        decrypted_token = jwe.decrypt(token, key=JWT_SECRET_PREVIOUS.encode()).decode()
                        logger.info("Token decrypted with previous key during rotation")
                    except Exception:
                        logger.error(f"JWE decryption failed with both keys: {jwe_error}")
                        raise
                else:
                    raise

        # --- Verify signature & claims with key rotation support --------------
        verify_keys = _get_verify_keys()
        payload = None
        verification_errors = []
        
        for verify_key, key_id in verify_keys:
            try:
                # Enhanced JWT verification options
                options = {
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_signature": True,
                    "verify_aud": False,  # Audience verification disabled by default
                    "verify_iss": False,  # Issuer verification disabled by default
                }
                
                # Add clock skew tolerance
                if MAX_CLOCK_SKEW_SECONDS > 0:
                    options["leeway"] = MAX_CLOCK_SKEW_SECONDS
                
                payload = jwt.decode(
                    decrypted_token,
                    verify_key,
                    algorithms=[ALGORITHM],
                    options=options,
                )
                
                # Log successful verification with key rotation info
                token_key_id = payload.get("kid", "unknown")
                if key_id != JWT_SECRET_ID and KEY_ROTATION_ENABLED:
                    logger.info(f"Token verified with previous key (kid: {token_key_id})")
                
                break  # Successfully verified
                
            except (JWTError, JWTClaimsError) as e:
                verification_errors.append(f"Key {key_id}: {str(e)}")
                continue
        
        if payload is None:
            error_details = "; ".join(verification_errors)
            logger.warning(f"Token verification failed with all keys: {error_details}")
            raise JWTError("Token verification failed with all available keys")

        # --- Enhanced Claims Validation ---------------------------------------
        _validate_token_claims(payload)
        
        # --- Security Checks --------------------------------------------------
        if STRICT_MODE:
            _perform_security_checks(payload)

        return payload

    except ExpiredSignatureError:
        logger.warning("Token verification failed: token expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Token expired"
        ) from None
    except (JWTError, JWTClaimsError) as err:
        logger.warning(f"Token verification failed: {err}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token"
        ) from err
    except Exception as err:
        logger.error(f"Unexpected error during token verification: {err}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token format"
        ) from err

def _validate_token_claims(payload: Dict[str, Any]) -> None:
    """
    Validate required claims in the token payload.
    
    Args:
        payload: The decoded JWT payload
        
    Raises:
        JWTClaimsError: If required claims are missing or invalid
    """
    # Check required claims
    if "sub" not in payload or "role" not in payload:
        raise JWTClaimsError("Missing required claims: 'sub' and 'role' are mandatory")
    
    # Validate claim values
    if not payload["sub"] or not isinstance(payload["sub"], str):
        raise JWTClaimsError("Invalid 'sub' claim: must be a non-empty string")
    
    if not payload["role"] or not isinstance(payload["role"], str):
        raise JWTClaimsError("Invalid 'role' claim: must be a non-empty string")
    
    # Validate JTI if present
    if "jti" in payload and not payload["jti"]:
        raise JWTClaimsError("Invalid 'jti' claim: must be non-empty if present")

def _perform_security_checks(payload: Dict[str, Any]) -> None:
    """
    Perform additional security checks in strict mode.
    
    Args:
        payload: The decoded JWT payload
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    
    # Check for suspiciously old tokens
    if "iat" in payload:
        iat = datetime.datetime.fromtimestamp(payload["iat"], tz=datetime.timezone.utc)
        token_age = now - iat
        if token_age.total_seconds() > 86400:  # 24 hours
            logger.warning(f"Old token detected: issued {token_age} ago")
    
    # Validate key rotation grace period
    if KEY_ROTATION_ENABLED and "kid" in payload:
        token_kid = payload["kid"]
        if token_kid == JWT_SECRET_PREVIOUS_ID:
            # Check if we're still within grace period
            # Note: This is a simplified check. In production, you'd want to track rotation timestamps
            logger.info("Token using previous key within rotation grace period")

# --------------------------------------------------------------------------- #
#                           KEY ROTATION UTILITIES                            #
# --------------------------------------------------------------------------- #
def get_key_rotation_status() -> Dict[str, Any]:
    """
    Get the current key rotation status.
    
    Returns:
        Dict containing rotation status information
    """
    return {
        "rotation_enabled": KEY_ROTATION_ENABLED,
        "current_key_id": JWT_SECRET_ID,
        "previous_key_id": JWT_SECRET_PREVIOUS_ID,
        "grace_period_hours": KEY_ROTATION_GRACE_PERIOD_HOURS,
        "algorithm": ALGORITHM,
        "jwe_enabled": ENABLE_JWE,
    }

def create_token_with_rotation_metadata(
    payload: Dict[str, Any],
    expires_delta: Optional[datetime.timedelta] = None,
) -> Dict[str, Any]:
    """
    Create a token and return it with rotation metadata.
    
    Args:
        payload: Token payload
        expires_delta: Optional expiration time
        
    Returns:
        Dict containing token and metadata
    """
    token = create_token(payload, expires_delta)
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": (expires_delta or datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).total_seconds(),
        "key_id": JWT_SECRET_ID,
        "algorithm": ALGORITHM,
        "jwe_enabled": ENABLE_JWE,
    }
