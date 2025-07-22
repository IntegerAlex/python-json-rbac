---
title: FastAPI Integration
description: How to use python-json-rbac authentication utilities with FastAPI.
keywords: [authentication, fastapi, python-json-rbac]
---

# FastAPI Integration

## Example Usage
```python
from python_json_rbac.auth import get_current_user
from fastapi import Depends

@app.get("/me")
def get_me(user=Depends(get_current_user)):
    return {"user": user}
``` 