"""
python-json-rbac – Minimal, standards-compliant JWT/JWE + RBAC for FastAPI.
"""

from .core import (
    create_token, 
    verify_token, 
    get_key_rotation_status,
    create_token_with_rotation_metadata,
)
from .auth import get_current_user
from .decorators import rbac_protect
from .key_manager import (
    get_key_manager,
    validate_current_secret,
    generate_secure_secret,
    create_rotation_plan,
    SecureKeyManager,
)
from .config import (
    get_secret_info,
    generate_new_secret,
    validate_runtime_security,
)

__all__ = [
    # Core JWT functionality
    "create_token", 
    "verify_token", 
    "get_current_user", 
    "rbac_protect",
    
    # Key rotation and management
    "get_key_rotation_status",
    "create_token_with_rotation_metadata",
    "get_key_manager",
    "SecureKeyManager",
    
    # Security utilities
    "validate_current_secret",
    "generate_secure_secret",
    "create_rotation_plan",
    "get_secret_info",
    "generate_new_secret",
    "validate_runtime_security",
]
