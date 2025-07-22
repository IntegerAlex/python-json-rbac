---
title: Multi-Tenant RBAC
description: How to implement multi-tenant RBAC with python-json-rbac.
keywords: [use case, multi-tenant, rbac, python-json-rbac]
---

# Multi-Tenant RBAC

Assign roles per tenant and check permissions dynamically in your endpoints.

## Example
```python
def has_tenant_role(user, tenant_id, role):
    return role in user.get("roles", {}).get(tenant_id, [])

@app.get("/tenant/{tenant_id}/resource")
def tenant_resource(tenant_id: str, user=Depends(get_current_user)):
    if not has_tenant_role(user, tenant_id, "editor"):
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"message": f"Access granted for tenant {tenant_id}"}
``` 