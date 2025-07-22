---
title: JWT Tokens
description: How to create and verify JWT tokens with python-json-rbac.
keywords: [jwt, tokens, python-json-rbac]
---

# JWT Tokens

## Creating a JWT
```python
from python_json_rbac.core import create_token

token = create_token({"sub": "user123", "role": ["admin"]})
```

## Verifying a JWT
```python
from python_json_rbac.core import verify_token

payload = verify_token(token)
print(payload)
``` 