---
title: JWE Encryption
description: How to enable and use JWE (encrypted JWT) in python-json-rbac.
keywords: [jwe, encryption, jwt, python-json-rbac]
---

# JWE Encryption

Enable JWE by setting `JWT_ENABLE_JWE=true` in your `.env` file.

## Example
```python
from python_json_rbac.core import create_token
# With JWE enabled, tokens will be encrypted automatically.
``` 