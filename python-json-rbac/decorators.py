"""
FastAPI decorator for RBAC enforcement.
"""
import functools
from typing import Callable

from fastapi import Depends, HTTPException, status

from .auth import get_current_user

def rbac_protect(role: str) -> Callable:
    """
    Decorator factory that enforces `role` requirement.
    Usage:
        @app.get("/admin")
        @rbac_protect(role="admin")
        def admin_endpoint(user=Depends(get_current_user)): ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            user = kwargs.get("user") or (
                args[0] if args else None
            )  # FastAPI injects user via Depends
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="User not authenticated"
                )
            if user.get("role") != role:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient privileges (role '{role}' required)",
                )
            return await func(*args, **kwargs) if asyncio.iscoroutinefunction(func) else func(
                *args, **kwargs
            )

        # Ensure FastAPI dependency injection
        original_sig = inspect.signature(func)
        if "user" not in original_sig.parameters:
            wrapper.__signature__ = original_sig.replace(
                parameters=list(original_sig.parameters.values())
                + [
                    inspect.Parameter(
                        "user",
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                        annotation=dict,
                        default=Depends(get_current_user),
                    )
                ]
            )
        return wrapper

    return decorator


# Needed for decorator introspection
import inspect
import asyncio
