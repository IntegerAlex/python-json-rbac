---
title: General Usage Guide
description: How to use python-json-rbac in your projects.
keywords: [usage, guide, python-json-rbac]
---

# Usage Guide

See the [Introduction](intro.md) for a quickstart.
See [Configuration](configuration/index.md) for all config options.

## Overview
`python-json-rbac` is a modular, production-grade library for JWT/JWE authentication and role-based access control (RBAC) in FastAPI and other Python web frameworks. It supports both symmetric (HS256) and asymmetric (RS256) JWTs, optional JWE encryption, and secure key rotation.

## Architecture
- **Config**: All settings are loaded from environment variables or a `.env` file (using `python-dotenv`).
- **Token Management**: Create and verify JWTs with `create_access_token` and `verify_token`.
- **RBAC Decorators**: Use `@rbac_protect(role=...)` to secure endpoints.
- **Key Management**: Built-in support for key rotation and secret validation.
- **Logging**: All warnings/errors use Python's `logging` module.

## Configuration & .env
Create a `.env` file in your project root:
```env
JWT_SECRET=your_super_secret_key
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=30
# For RS256:
# JWT_PRIVATE_KEY_PATH=path/to/private.pem
# JWT_PUBLIC_KEY_PATH=path/to/public.pem
```

## Basic Usage
### 1. Token Creation
```python
from python_json_rbac.auth import create_access_token

token = create_access_token(data={"sub": "user123", "role": ["admin"]})
```

### 2. FastAPI Integration & RBAC
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

### 3. Verifying Tokens
```python
from python_json_rbac.auth import verify_token

payload = verify_token(token)
print(payload)
```

## Advanced Features
### JWE Encryption
Enable with `.env`:
```
JWT_ENABLE_JWE=true
```
Tokens will be encrypted using AES-GCM.

### Key Rotation
Set `JWT_SECRET_PREVIOUS` in your `.env` to allow seamless key rotation:
```
JWT_SECRET_PREVIOUS=old_secret_value
```

### Custom Permissions
You can extend the RBAC decorator or implement your own permission logic by inspecting the user payload.

## Troubleshooting & FAQ
- **ImportError**: Ensure you use `pip install -e .` for local development and use correct import paths.
- **Token Invalid**: Check your secret, algorithm, and expiration settings.
- **Logging**: Adjust log level with `logging.basicConfig(level=logging.INFO)` in your app entrypoint.

## More
- See the [Introduction](intro.md) for a quickstart.
- See [Configuration](configuration/index.md) for all config options.
- API reference: docstrings in each module. 