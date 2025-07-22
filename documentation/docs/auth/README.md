# Authentication Utilities (auth.py)

## Overview

The `auth.py` module provides FastAPI dependencies for extracting and verifying the current user from a JWT/JWE Bearer token.

## API Reference

- `get_current_user`: FastAPI dependency to extract and verify the user from the Authorization header

## Example Usage

```python
from python_json_rbac.auth import get_current_user
from fastapi import Depends

@app.get("/me")
def get_me(user=Depends(get_current_user)):
    return {"user": user}
```

## Security Notes

- Always use HTTPS in production
- Handle HTTP 401 errors for missing/invalid tokens

## Troubleshooting

- **401 Unauthorized**: Token missing, expired, or invalid
