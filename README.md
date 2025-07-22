<p align="center">
  <img src="documentation/static/img/logo.png" alt="python-json-rbac Logo" height="120" />
</p>

# python-json-rbac

[![PyPI version](https://badge.fury.io/py/python-json-rbac.svg)](https://badge.fury.io/py/python-json-rbac)
[![PyPI Downloads](https://static.pepy.tech/badge/python-json-rbac)](https://pepy.tech/projects/python-json-rbac)
[![License: LGPL v2.1](https://img.shields.io/badge/License-LGPL%20v2.1-blue.svg)](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html)
[![Python Version](https://img.shields.io/pypi/pyversions/python-json-rbac.svg)](https://pypi.org/project/python-json-rbac/)
<a href="https://www.buymeacoffee.com/IntegerAlex" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 40px !important;width: 145px !important; vertical-align: middle; margin-left: 8px;" ></a>

Minimal, secure JWT/JWE + RBAC for FastAPI. Provides decorators and utilities for secure, role-based access control in modern Python web APIs.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quickstart](#quickstart)
- [Configuration & .env Support](#configuration--env-support)
- [Usage Example](#usage-example)
- [Advanced Usage & API](#advanced-usage--api)
- [Testing](#testing)
- [Security & Logging](#security--logging)
- [Contributing & Support](#contributing--support)
- [License](#license)

---

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
- .env support for easy configuration
- Production-grade logging

## Installation

```bash
pip install python-json-rbac
```

## Quickstart

1. **Add a `.env` file** to your project root:

   ```env
   JWT_SECRET=your_super_secret_key
   JWT_ALGORITHM=HS256
   JWT_EXPIRE_MINUTES=30
   ```

2. **Install dependencies** (if not already):

   ```bash
   pip install python-json-rbac
   ```

3. **Create a FastAPI app:**

```python
   from python_json_rbac.auth import create_access_token, get_current_user
   from python_json_rbac.decorators import rbac_protect
   from fastapi import FastAPI, Depends

   app = FastAPI()

   @app.get("/admin")
   @rbac_protect(role="admin")
   def admin_dashboard(user=Depends(get_current_user)):
       return {"message": f"Welcome, {user['sub']}!"}
   ```

## Configuration & .env Support

- All configuration can be set via environment variables or a `.env` file (recommended for development).
- Supported variables:
  - `JWT_SECRET` (required)
  - `JWT_ALGORITHM` (`HS256` or `RS256`)
  - `JWT_PRIVATE_KEY_PATH`, `JWT_PUBLIC_KEY_PATH` (for RS256)
  - `JWT_ENABLE_JWE` (optional, default: false)
  - `JWT_EXPIRE_MINUTES` (default: 30)
  - See [docs/configuration.md](docs/configuration.md) for full details.

## Usage Example

### Symmetric (HS256) Example

```python
from python_json_rbac.auth import create_access_token, get_current_user
from python_json_rbac.decorators import rbac_protect
from fastapi import FastAPI, Depends

app = FastAPI()

@app.get("/admin")
@rbac_protect(role="admin")
def admin_dashboard(user=Depends(get_current_user)):
    return {"message": f"Welcome, {user['sub']}!"}
```

### Asymmetric (RS256) Example

```python
# In your .env:
# JWT_ALGORITHM=RS256
# JWT_PRIVATE_KEY_PATH=path/to/private.pem
# JWT_PUBLIC_KEY_PATH=path/to/public.pem

from python_json_rbac.auth import create_access_token
# ...rest is the same as above
```

## Advanced Usage & API

- See the [docs/](docs/) directory for advanced RBAC, JWE, key rotation, and API reference.
- Example: [docs/usage.md](docs/usage.md)

## Testing

To run tests:

```bash
pip install pytest
pytest
```

## Security & Logging

- All warnings and errors use Python's `logging` module for production readiness.
- Secrets are validated for length and entropy.
- JWE encryption and key rotation are supported.
- See [docs/security.md](docs/security.md) for best practices.

## Contributing & Support

- Contributions are welcome! Please open issues or submit pull requests on [GitHub](https://github.com/IntegerAlex/python-json-rbac).
- For questions, use [GitHub Discussions](https://github.com/IntegerAlex/python-json-rbac/discussions) or [file an issue](https://github.com/IntegerAlex/python-json-rbac/issues).

## License

LGPL-2.1-only. See [LICENSE](LICENSE) for details.
