---
title: Key Rotation
description: How to rotate JWT secrets and manage key rotation in python-json-rbac.
keywords: [key rotation, jwt, security, python-json-rbac]
---

# Key Rotation

## Rotating Secrets
- Set `JWT_SECRET_PREVIOUS` to the old secret
- Deploy new secret as `JWT_SECRET`
- After all tokens expire, remove the old secret

## Example
```python
from python_json_rbac.key_manager import get_key_manager

manager = get_key_manager()
manager.rotate_key()
``` 