"""
FastAPI dependency for extracting the current user from the Bearer token.
"""
from typing import Dict, Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .core import verify_token

oauth2_scheme = HTTPBearer(auto_error=False)

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(oauth2_scheme),
) -> Dict[str, Any]:
    """
    Extracts and verifies the current user from a Bearer token in the Authorization header.
    
    Raises an HTTP 401 Unauthorized error if the token is missing, expired, or invalid.
    
    Returns:
        dict: The verified user payload extracted from the token.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return verify_token(credentials.credentials)
