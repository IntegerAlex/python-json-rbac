# Key Management & Rotation (key_manager.py)

## Overview

The `key_manager.py` module provides secure key management, rotation, and metadata tracking for JWT secrets. It supports in-memory and file-based storage, thread safety, and dry-run cleanup.

## API Reference

- `SecureKeyManager(storage_path=None)`: Main class for managing keys
- `generate_key(algorithm, length)`: Generate a new key
- `activate_key(key_id)`: Activate a key
- `rotate_key(new_algorithm, new_length)`: Rotate to a new key
- `cleanup_old_keys(max_age_days, dry_run=False)`: Remove or preview old keys
- `get_rotation_status()`: Get rotation info
- `get_key_manager(storage_path=None)`: Thread-safe singleton accessor

## Example Usage

```python
from python_json_rbac.key_manager import get_key_manager

manager = get_key_manager(".jwt_keys.json")
secret, key_id = manager.generate_key()
manager.activate_key(key_id)
manager.rotate_key()
old_keys = manager.cleanup_old_keys(dry_run=True)
print("Would remove:", old_keys)
```

## Thread Safety & Persistence

- The global key manager is thread-safe using a lock
- Metadata can be persisted to disk or kept in memory

## Security Best Practices

- Rotate keys regularly
- Store key metadata securely
- Use dry_run before deleting keys

## Troubleshooting

- **Key not found**: Check key_id and storage path
- **No active key**: Always activate at least one key
