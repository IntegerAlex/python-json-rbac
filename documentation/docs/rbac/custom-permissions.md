---
title: Custom Permissions
description: How to implement custom permission logic with python-json-rbac.
keywords: [rbac, custom permissions, python-json-rbac]
---

# Custom Permissions

You can extend the RBAC decorator or implement your own permission logic by inspecting the user payload.

## Example
```python
def custom_permission(user):
    return "admin" in user.get("role", []) or user.get("sub") == "superuser"

@app.get("/special")
def special_endpoint(user=Depends(get_current_user)):
    if not custom_permission(user):
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"message": "You have access!"}
``` 