"""
FastAPI decorator for RBAC enforcement.
"""
import functools
from typing import Callable
import inspect
import asyncio

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
            # Try to find 'user' in kwargs, then in positional args by name
            user = kwargs.get("user")
            if not user:
                sig = inspect.signature(func)
                param_names = list(sig.parameters.keys())
                if "user" in param_names:
                    user_index = param_names.index("user")
                    if len(args) > user_index:
                        user = args[user_index]

            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="User not authenticated"
                )
            if user.get("role") != role:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient privileges (role '{role}' required)",
                )

            # Await async functions, call sync functions directly
            if asyncio.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            else:
                return func(*args, **kwargs)

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
