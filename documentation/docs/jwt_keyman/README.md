# JWT Key Management CLI (jwt_keyman.py)

## Overview

The `jwt_keyman.py` module provides a command-line interface (CLI) for managing JWT secrets, generating new keys, and performing key rotation.

## API Reference

- `generate`: Generate a new secret key
- `rotate`: Rotate to a new key
- `status`: Show current key status
- `cleanup`: Remove old keys

## Example Usage

```bash
python -m python_json_rbac.jwt_keyman generate
python -m python_json_rbac.jwt_keyman rotate
python -m python_json_rbac.jwt_keyman status
python -m python_json_rbac.jwt_keyman cleanup --dry-run
```

## Security Notes

- Store generated secrets securely
- Use dry-run before deleting keys

## Troubleshooting

- **Missing secret**: Set JWT_SECRET in your environment
- **File not found**: Check key storage path
