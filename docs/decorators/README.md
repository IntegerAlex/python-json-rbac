# RBAC Decorators (decorators.py)

## Overview

The `decorators.py` module provides the `@rbac_protect` decorator for enforcing role-based access control (RBAC) on FastAPI endpoints.

## API Reference

- `rbac_protect(role: str) -> Callable`: Decorator to restrict access to users with the specified role

## Example Usage

```python
from python_json_rbac.auth import get_current_user
from python_json_rbac.decorators import rbac_protect
from fastapi import FastAPI, Depends

app = FastAPI()

@app.get("/admin")
@rbac_protect(role="admin")
def admin_dashboard(user=Depends(get_current_user)):
    return {"message": f"Welcome, {user['sub']}!"}
```

## Advanced Usage

- Implement custom permission logic by extending the decorator
- Support multiple roles by passing a list and checking membership

## Security Notes

- Always use with authentication (get_current_user)
- Return minimal error info to avoid leaking role structure

## Troubleshooting

- **403 Forbidden**: User lacks required role
- **401 Unauthorized**: User not authenticated
