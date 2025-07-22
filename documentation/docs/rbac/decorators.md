---
title: RBAC Decorators
description: How to use RBAC decorators to secure your FastAPI endpoints.
keywords: [rbac, decorators, fastapi, python-json-rbac]
---

# RBAC Decorators

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