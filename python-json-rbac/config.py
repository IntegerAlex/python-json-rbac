"""
Centralised configuration – reads from environment variables or sane defaults.
"""
import os
import re
import secrets
import hashlib
import logging
from typing import Optional, List

# Setup logging
logger = logging.getLogger(__name__)

# Add .env support
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # .env support is optional; recommend installing python-dotenv for local development

# --- Secret Validation Constants ---------------------------------------------
MIN_SECRET_LENGTH = 32  # Minimum 256 bits
MIN_SECRET_ENTROPY = 3.5  # Bits per character minimum
ALLOWED_SECRET_CHARS = re.compile(r'^[A-Za-z0-9+/=\-_]+$')  # Base64 + URL-safe chars

def _calculate_entropy(secret: str) -> float:
    """
    Estimate the Shannon entropy of a string, representing its average bits of information per character.
    
    Parameters:
        secret (str): The input string to analyze.
    
    Returns:
        float: The calculated entropy in bits per character.
    """
    if not secret:
        return 0.0
    
    # Count character frequencies
    char_counts = {}
    for char in secret:
        char_counts[char] = char_counts.get(char, 0) + 1
    
    # Calculate Shannon entropy
    import math
    length = len(secret)
    entropy = 0.0
    for count in char_counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy

def _validate_secret_strength(secret: str, min_length: int = MIN_SECRET_LENGTH) -> None:
    """
    Validates the strength and format of a JWT secret, enforcing minimum length, allowed characters, entropy, and resistance to common weak patterns.
    
    Raises:
        ValueError: If the secret is empty, too short, contains invalid characters, has insufficient entropy, matches a common weak value, or has excessive repeated characters.
    """
    if not secret:
        raise ValueError("JWT secret cannot be empty")
    
    if len(secret) < min_length:
        raise ValueError(f"JWT secret must be at least {min_length} characters long")
    
    if not ALLOWED_SECRET_CHARS.match(secret):
        raise ValueError("JWT secret contains invalid characters. Use base64/URL-safe characters only")
    
    entropy = _calculate_entropy(secret)
    if entropy < MIN_SECRET_ENTROPY:
        raise ValueError(f"JWT secret has insufficient entropy ({entropy:.2f} < {MIN_SECRET_ENTROPY})")
    
    # Check for common weak patterns
    if secret.lower() in {'test', 'secret', 'password', 'key', 'token'}:
        raise ValueError("JWT secret cannot be a common weak value")
    
    # Check for repeated patterns
    if len(set(secret)) < len(secret) * 0.5:  # Less than 50% unique characters
        raise ValueError("JWT secret has too many repeated characters")

def _generate_secure_secret(length: int = 64) -> str:
    """
    Generate a cryptographically secure, URL-safe secret string of the specified length.
    
    Parameters:
        length (int): Desired length of the generated secret in characters. Defaults to 64.
    
    Returns:
        str: A random, URL-safe secret string suitable for use as a JWT secret.
    """
    return secrets.token_urlsafe(length)

# --- Secrets / Keys ----------------------------------------------------------
JWT_SECRET: str = os.getenv("JWT_SECRET", "")
JWT_SECRET_PREVIOUS: str = os.getenv("JWT_SECRET_PREVIOUS", "")  # For key rotation

# Validate primary secret
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is required")

try:
    _validate_secret_strength(JWT_SECRET)
except ValueError as e:
    raise RuntimeError(f"JWT_SECRET validation failed: {e}")

# Validate previous secret if provided (for key rotation)
if JWT_SECRET_PREVIOUS:
    try:
        _validate_secret_strength(JWT_SECRET_PREVIOUS)
    except ValueError as e:
        raise RuntimeError(f"JWT_SECRET_PREVIOUS validation failed: {e}")

# Generate key IDs for rotation tracking
JWT_SECRET_ID: str = hashlib.sha256(JWT_SECRET.encode()).hexdigest()[:16]
JWT_SECRET_PREVIOUS_ID: str = (
    hashlib.sha256(JWT_SECRET_PREVIOUS.encode()).hexdigest()[:16] 
    if JWT_SECRET_PREVIOUS else ""
)

PRIVATE_KEY_PATH: Optional[str] = os.getenv("JWT_PRIVATE_KEY_PATH")
PUBLIC_KEY_PATH: Optional[str] = os.getenv("JWT_PUBLIC_KEY_PATH")

# --- Key Rotation Settings ---------------------------------------------------
KEY_ROTATION_ENABLED: bool = bool(JWT_SECRET_PREVIOUS)
KEY_ROTATION_GRACE_PERIOD_HOURS: int = int(os.getenv("JWT_KEY_ROTATION_GRACE_HOURS", "24"))

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
    logger.warning("Invalid JWT_EXPIRE_MINUTES. Must be an integer. Using default 30.")
    ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- Security Configuration --------------------------------------------------
# Enable strict mode for additional security checks
STRICT_MODE: bool = os.getenv("JWT_STRICT_MODE", "true").lower() in {"1", "true", "yes"}

# Maximum allowed clock skew in seconds
MAX_CLOCK_SKEW_SECONDS: int = int(os.getenv("JWT_MAX_CLOCK_SKEW", "300"))  # 5 minutes

# --- Runtime Security Validation ---------------------------------------------
def validate_runtime_security() -> None:
    """
    Performs runtime security checks on JWT configuration and logs warnings for insecure settings.
    
    Logs warnings if the JWT secret is too short for HS256, if JWE encryption is disabled, or if the access token expiration exceeds one hour, when strict mode is enabled.
    """
    if ALGORITHM == "HS256" and len(JWT_SECRET) < 64 and STRICT_MODE:
        logger.warning("For production use, consider using a longer JWT secret (64+ chars)")
    
    if not ENABLE_JWE and STRICT_MODE:
        logger.warning("JWE encryption is disabled. Consider enabling for sensitive data")
    
    if ACCESS_TOKEN_EXPIRE_MINUTES > 60 and STRICT_MODE:
        logger.warning("Token expiration is longer than 1 hour. Consider shorter lifetimes")

# Run runtime validation
validate_runtime_security()

# --- Utility Functions -------------------------------------------------------
def get_secret_info() -> dict:
    """
    Return non-sensitive metadata about the current JWT secret configuration.
    
    The returned dictionary includes secret identifiers, key rotation status, algorithm, encryption and strict mode flags, secret length, and an entropy estimate, but does not expose the actual secret values.
    
    Returns:
        dict: Dictionary containing metadata about the JWT secret configuration.
    """
    return {
        "primary_secret_id": JWT_SECRET_ID,
        "previous_secret_id": JWT_SECRET_PREVIOUS_ID,
        "key_rotation_enabled": KEY_ROTATION_ENABLED,
        "algorithm": ALGORITHM,
        "jwe_enabled": ENABLE_JWE,
        "strict_mode": STRICT_MODE,
        "secret_length": len(JWT_SECRET),
        "entropy_estimate": _calculate_entropy(JWT_SECRET)
    }

def generate_new_secret() -> str:
    """
    Generate a new cryptographically secure secret string suitable for JWT key rotation.
    
    Returns:
        str: A URL-safe, high-entropy secret string.
    """
    return _generate_secure_secret()

__all__ = [
    'JWT_SECRET', 'JWT_SECRET_PREVIOUS', 'JWT_SECRET_ID', 'JWT_SECRET_PREVIOUS_ID',
    'PRIVATE_KEY_PATH', 'PUBLIC_KEY_PATH', 'ALGORITHM', 'ENABLE_JWE',
    'ACCESS_TOKEN_EXPIRE_MINUTES', 'KEY_ROTATION_ENABLED', 'KEY_ROTATION_GRACE_PERIOD_HOURS',
    'STRICT_MODE', 'MAX_CLOCK_SKEW_SECONDS',
    'get_secret_info', 'generate_new_secret', 'validate_runtime_security'
]
