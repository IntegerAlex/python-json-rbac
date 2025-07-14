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
    Creates a decorator that restricts access to FastAPI endpoints based on the required user role.
    
    Parameters:
        role (str): The user role required to access the decorated endpoint.
    
    Returns:
        Callable: A decorator that enforces authentication and role-based access control, raising HTTP 401 if the user is unauthenticated and HTTP 403 if the user lacks the required role.
    """
    def decorator(func: Callable) -> Callable:
        """
        Wraps a FastAPI endpoint to enforce that the current user is authenticated and has the required role.
        
        Raises an HTTP 401 Unauthorized exception if the user is not authenticated, or an HTTP 403 Forbidden exception if the user lacks the specified role. Supports both synchronous and asynchronous endpoint functions, and ensures FastAPI injects the current user dependency if not already present.
        """
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
            user_roles = user.get("role")
            if isinstance(user_roles, str):
                user_roles = [user_roles]
            elif not isinstance(user_roles, list):
                user_roles = []
                
            if role not in user_roles:
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
