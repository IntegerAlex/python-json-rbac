---
title: Configuration Best Practices
description: Security and maintainability tips for configuring python-json-rbac.
keywords: [configuration, best practices, security]
---

- Use long, random secrets (64+ chars for HS256)
- Never commit secrets to version control
- Rotate secrets regularly
- Enable JWE for sensitive data
- Use environment variables or a .env file for all secrets 