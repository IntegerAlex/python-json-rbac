# Token Management (core.py)

## Overview

The `core.py` module provides all JWT/JWE creation, verification, and claim validation logic. It supports both symmetric (HS256) and asymmetric (RS256) signing, optional JWE encryption, and key rotation.

## API Reference

- `create_token(payload, expires_delta=None, key_id=None) -> str`: Create a signed (and optionally encrypted) JWT/JWE
- `verify_token(token: str) -> dict`: Verify and decode a JWT/JWE, checking all claims
- `get_key_rotation_status() -> dict`: Get info about key rotation state
- `create_token_with_rotation_metadata(...)`: Create a token with extra rotation metadata

## Example: Creating and Verifying a JWT

```python
from python_json_rbac.core import create_token, verify_token

token = create_token({"sub": "user123", "role": ["admin"]})
payload = verify_token(token)
print(payload)
```

## Advanced Usage

- **JWE Encryption**: Enable with `JWT_ENABLE_JWE=true` in your .env
- **Key Rotation**: Use `JWT_SECRET_PREVIOUS` for seamless rotation
- **Custom Claims**: Add any extra fields to the payload

## Security Notes

- Always validate the output of `verify_token`
- Handle `ExpiredSignatureError` and other exceptions

## Troubleshooting

- **Token expired**: Check system clock and token lifetime
- **Invalid token**: Check secret, algorithm, and claims
