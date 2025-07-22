# Real-World Use Cases

## Securing an Admin Dashboard

Use `@rbac_protect(role="admin")` to restrict access to admin endpoints. Example:

```python
@app.get("/admin")
@rbac_protect(role="admin")
def admin_dashboard(user=Depends(get_current_user)):
    return {"message": f"Welcome, {user['sub']}!"}
```

## Multi-Tenant RBAC

Assign roles per tenant and check permissions dynamically in your endpoints.

## Rotating Secrets in Production

- Set `JWT_SECRET_PREVIOUS` to the old secret
- Deploy new secret as `JWT_SECRET`
- After all tokens expire, remove the old secret

## Using JWE for Sensitive Data

Enable `JWT_ENABLE_JWE=true` in your .env to encrypt tokens.

## Integrating with CI/CD for Secret Rotation

- Use the CLI to generate new secrets
- Store secrets in your CI/CD secrets manager
- Automate rotation and deployment

## Best Practices

- Always use HTTPS
- Rotate secrets regularly
- Use strong, random secrets
- Monitor and log key usage
