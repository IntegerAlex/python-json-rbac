---
title: Getting Started
description: Quickstart guide for python-json-rbac.
keywords: [quickstart, getting started, python-json-rbac]
---

# Getting Started

1. Install the package:
   ```bash
   pip install python-json-rbac
   ```
2. Add a `.env` file:
   ```env
   JWT_SECRET=your_super_secret_key
   JWT_ALGORITHM=HS256
   JWT_EXPIRE_MINUTES=30
   ```
3. Create a FastAPI app and secure endpoints with RBAC decorators.

See [Configuration](configuration/index.md) for all options. 