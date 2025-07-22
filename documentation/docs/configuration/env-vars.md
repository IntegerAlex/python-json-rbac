---
title: Environment Variables
description: All environment variables supported by python-json-rbac.
keywords: [env, configuration, python-json-rbac]
---

# Environment Variables

- `JWT_SECRET` (required): Main secret for signing JWTs
- `JWT_SECRET_PREVIOUS`: Previous secret for key rotation
- `JWT_ALGORITHM`: `HS256` (default) or `RS256`
- `JWT_PRIVATE_KEY_PATH`, `JWT_PUBLIC_KEY_PATH`: For RS256
- `JWT_ENABLE_JWE`: Enable JWE encryption (`true`/`false`)
- `JWT_EXPIRE_MINUTES`: Token lifetime (default: 30)
- `JWT_KEY_ROTATION_GRACE_HOURS`: Grace period for key rotation
- `JWT_STRICT_MODE`: Enable strict security checks
- `JWT_MAX_CLOCK_SKEW`: Allowed clock skew in seconds 