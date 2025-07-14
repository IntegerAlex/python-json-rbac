# python-json-rbac

Minimal, secure JWT/JWE + RBAC for FastAPI. Provides decorators and utilities for secure, role-based access control in modern Python web APIs.

## Overview

`python-json-rbac` provides decorators and utilities for secure, role-based access control (RBAC) in modern Python web APIs. It supports JWT and JWE tokens, integrates with FastAPI, and is designed for modular, scalable, and secure backend architectures.

## Features
- JWT and optional JWE (encrypted JWT) support
- Role-based access control (RBAC) decorators
- FastAPI dependency integration
- Modular, service-oriented design
- Secure defaults and environment-based configuration
- Support for multiple user roles
- Extensible for custom permission logic

## Installation

```bash
pip install python-json-rbac
```

## Configuration

Set the following environment variables:
- `JWT_SECRET`: Secret key for signing JWTs (required)
- `JWT_ALGORITHM`: Algorithm for JWT signing (`HS256` or `RS256`, default: `HS256`)
- `JWT_PRIVATE_KEY_PATH`: Path to private key for RS256 (optional)
- `JWT_PUBLIC_KEY_PATH`: Path to public key for RS256 (optional)
- `JWT_ENABLE_JWE`: Enable JWE encryption (`true`/`false`, default: `false`)
- `JWT_EXPIRE_MINUTES`: Access token expiration in minutes (default: `30`)

## Usage Example

```python
from python_json_rbac.auth import create_access_token, verify_token
from python_json_rbac.core import RBAC
from python_json_rbac.decorators import rbac_protect

# Define roles and permissions
rules = {
    "admin": {"permissions": ["user:create", "user:read", "user:update", "user:delete"]},
    "editor": {"permissions": ["user:read", "user:update"]},
    "viewer": {"permissions": ["user:read"]}
}
rbac = RBAC(rules)

# Create a token
user_id = "user123"
roles = ["admin"]
token_data = {"sub": user_id, "role": roles}
access_token = create_access_token(data=token_data)

# Protect FastAPI endpoints
from fastapi import FastAPI, Depends
app = FastAPI()

@app.get("/admin")
@rbac_protect(role="admin")
def admin_dashboard(user=Depends(get_current_user)):
    return {"message": f"Welcome, {user['sub']}!"}
```

## Testing

To run tests:
```bash
pip install pytest
pytest
```

## Contributing

Contributions are welcome! Please open issues or submit pull requests on [GitHub](https://github.com/IntegerAlex/python-json-rbac).

## License

LGPL-2.1-only. See [LICENSE](LICENSE) for details. 