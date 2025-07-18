"""
Centralised configuration – reads from environment variables or sane defaults.
"""
import os
import re
import secrets
import hashlib
from typing import Optional, List

# --- Secret Validation Constants ---------------------------------------------
MIN_SECRET_LENGTH = 32  # Minimum 256 bits
MIN_SECRET_ENTROPY = 3.5  # Bits per character minimum
ALLOWED_SECRET_CHARS = re.compile(r'^[A-Za-z0-9+/=\-_]+$')  # Base64 + URL-safe chars

def _calculate_entropy(secret: str) -> float:
    """Calculate the entropy of a string in bits per character."""
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
    Validate JWT secret strength and format.
    
    Args:
        secret: The secret to validate
        min_length: Minimum required length in characters
        
    Raises:
        ValueError: If secret doesn't meet security requirements
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
    """Generate a cryptographically secure secret."""
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
    print("Warning: Invalid JWT_EXPIRE_MINUTES. Must be an integer. Using default 30.")
    ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- Security Configuration --------------------------------------------------
# Enable strict mode for additional security checks
STRICT_MODE: bool = os.getenv("JWT_STRICT_MODE", "true").lower() in {"1", "true", "yes"}

# Maximum allowed clock skew in seconds
MAX_CLOCK_SKEW_SECONDS: int = int(os.getenv("JWT_MAX_CLOCK_SKEW", "300"))  # 5 minutes

# --- Runtime Security Validation ---------------------------------------------
def validate_runtime_security() -> None:
    """Perform runtime security validations."""
    if ALGORITHM == "HS256" and len(JWT_SECRET) < 64 and STRICT_MODE:
        print("Warning: For production use, consider using a longer JWT secret (64+ chars)")
    
    if not ENABLE_JWE and STRICT_MODE:
        print("Warning: JWE encryption is disabled. Consider enabling for sensitive data")
    
    if ACCESS_TOKEN_EXPIRE_MINUTES > 60 and STRICT_MODE:
        print("Warning: Token expiration is longer than 1 hour. Consider shorter lifetimes")

# Run runtime validation
validate_runtime_security()

# --- Utility Functions -------------------------------------------------------
def get_secret_info() -> dict:
    """Get information about the current secret configuration (without exposing secrets)."""
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
    """Generate a new cryptographically secure secret for rotation."""
    return _generate_secure_secret()

__all__ = [
    'JWT_SECRET', 'JWT_SECRET_PREVIOUS', 'JWT_SECRET_ID', 'JWT_SECRET_PREVIOUS_ID',
    'PRIVATE_KEY_PATH', 'PUBLIC_KEY_PATH', 'ALGORITHM', 'ENABLE_JWE',
    'ACCESS_TOKEN_EXPIRE_MINUTES', 'KEY_ROTATION_ENABLED', 'KEY_ROTATION_GRACE_PERIOD_HOURS',
    'STRICT_MODE', 'MAX_CLOCK_SKEW_SECONDS',
    'get_secret_info', 'generate_new_secret', 'validate_runtime_security'
]
