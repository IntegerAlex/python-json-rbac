---
title: Authentication Troubleshooting
description: Common authentication issues and solutions for python-json-rbac.
keywords: [authentication, troubleshooting, python-json-rbac]
---

# Authentication Troubleshooting

- **401 Unauthorized**: Token missing, expired, or invalid
- **Check**: Is JWT_SECRET set? Is the token expired? Is the algorithm correct?
- **Tip**: Use HTTPS in production to protect tokens 