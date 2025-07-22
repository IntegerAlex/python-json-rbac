# Configuration (config.py)

## Overview

The `config.py` module centralizes all configuration for python-json-rbac. It loads settings from environment variables or a `.env` file (using python-dotenv). This ensures secure, flexible, and environment-specific configuration.

## Supported Environment Variables

- `JWT_SECRET` (required): Main secret for signing JWTs
- `JWT_SECRET_PREVIOUS`: Previous secret for key rotation
- `JWT_ALGORITHM`: `HS256` (default) or `RS256`
- `JWT_PRIVATE_KEY_PATH`, `JWT_PUBLIC_KEY_PATH`: For RS256
- `JWT_ENABLE_JWE`: Enable JWE encryption (`true`/`false`)
- `JWT_EXPIRE_MINUTES`: Token lifetime (default: 30)
- `JWT_KEY_ROTATION_GRACE_HOURS`: Grace period for key rotation
- `JWT_STRICT_MODE`: Enable strict security checks
- `JWT_MAX_CLOCK_SKEW`: Allowed clock skew in seconds

## .env Example

```env
JWT_SECRET=your_super_secret_key
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=30
```

## API Reference

- `JWT_SECRET`, `ALGORITHM`, ...: All config constants
- `validate_runtime_security()`: Run security checks at startup
- `get_secret_info()`: Get info about current secret (no secret value exposed)
- `generate_new_secret()`: Generate a new secure secret

## Security Best Practices

- Use long, random secrets (64+ chars for HS256)
- Never commit secrets to version control
- Rotate secrets regularly
- Enable JWE for sensitive data

## Troubleshooting

- **Missing JWT_SECRET**: Set in your .env or environment
- **Invalid algorithm**: Only HS256 and RS256 are supported
- **Low entropy warning**: Use a more random secret
