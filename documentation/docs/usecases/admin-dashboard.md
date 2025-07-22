---
title: Securing an Admin Dashboard
description: How to secure an admin dashboard using RBAC decorators in python-json-rbac.
keywords: [use case, admin, dashboard, rbac, python-json-rbac]
---

# Securing an Admin Dashboard

Use `@rbac_protect(role="admin")` to restrict access to admin endpoints.

## Example
```python
@app.get("/admin")
@rbac_protect(role="admin")
def admin_dashboard(user=Depends(get_current_user)):
    return {"message": f"Welcome, {user['sub']}!"}
``` 