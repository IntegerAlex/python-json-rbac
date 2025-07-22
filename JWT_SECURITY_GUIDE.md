# JWT Security and Key Management Guide

This guide covers the enhanced JWT security features including secret validation, key rotation, and secure storage implemented in python-json-rbac.

## Table of Contents

1. [Secret Validation](#secret-validation)
2. [Key Rotation](#key-rotation)
3. [Environment Configuration](#environment-configuration)
4. [CLI Tools](#cli-tools)
5. [Security Best Practices](#security-best-practices)
6. [API Reference](#api-reference)

## Secret Validation

### Automatic Validation

The library now automatically validates JWT secrets on startup with the following requirements:

- **Minimum Length**: 32 characters (256 bits)
- **Character Set**: Base64/URL-safe characters only (`A-Za-z0-9+/=\-_`)
- **Entropy**: Minimum 3.5 bits per character
- **No Weak Patterns**: Rejects common weak values like "test", "secret", etc.
- **Character Diversity**: At least 50% unique characters

### Manual Validation

```python
from python_json_rbac import validate_current_secret

# Validate current configuration
result = validate_current_secret()
print(f"Valid: {result['valid']}")
print(f"Security Score: {result['security_score']}/100")
for rec in result['recommendations']:
    print(f"- {rec}")
```

## Key Rotation

### Environment-Based Rotation

Set these environment variables for key rotation:

```bash
# Current secret (required)
JWT_SECRET="your-current-64-char-secret-here"

# Previous secret for graceful rotation (optional)
JWT_SECRET_PREVIOUS="your-previous-secret-here"

# Grace period in hours (default: 24)
JWT_KEY_ROTATION_GRACE_HOURS=24
```

### Programmatic Rotation

```python
from python_json_rbac import get_key_manager

# Initialize key manager
manager = get_key_manager()

# Generate and rotate to a new key
new_secret, new_key_id = manager.rotate_key()

# Get rotation status
status = manager.get_rotation_status()
print(f"Active key: {status['active_key_id']}")
print(f"Key age: {status['active_key_age_hours']:.1f} hours")
```

### Token Creation with Rotation

```python
from python_json_rbac import create_token_with_rotation_metadata

# Create token with metadata
token_data = create_token_with_rotation_metadata({
    "sub": "user123",
    "role": "admin"
})

print(f"Token: {token_data['access_token']}")
print(f"Key ID: {token_data['key_id']}")
print(f"Expires in: {token_data['expires_in']} seconds")
```

## Environment Configuration

### Required Variables

```bash
# JWT secret (minimum 32 characters)
JWT_SECRET="your-cryptographically-secure-secret-here"
```

### Optional Security Variables

```bash
# Algorithm (HS256 or RS256)
JWT_ALGORITHM=HS256

# Token expiration in minutes
JWT_EXPIRE_MINUTES=30

# Enable JWE encryption
JWT_ENABLE_JWE=true

# Strict security mode
JWT_STRICT_MODE=true

# Maximum clock skew in seconds
JWT_MAX_CLOCK_SKEW=300

# Key rotation settings
JWT_SECRET_PREVIOUS="previous-secret-for-rotation"
JWT_KEY_ROTATION_GRACE_HOURS=24

# Key storage path for CLI tools
JWT_KEY_STORAGE_PATH=".jwt_keys.json"
```

### RSA Key Configuration

For RS256 algorithm:

```bash
JWT_ALGORITHM=RS256
JWT_PRIVATE_KEY_PATH="/path/to/private.pem"
JWT_PUBLIC_KEY_PATH="/path/to/public.pem"
```

## CLI Tools

The library includes a command-line tool for key management:

### Generate New Secret

```bash
# Generate a 64-character secret
python -m python_json_rbac.jwt_keyman generate --length 64

# Save to file
python -m python_json_rbac.jwt_keyman generate --output-file .env.new
```

### Validate Current Setup

```bash
# Basic validation
python -m python_json_rbac.jwt_keyman validate

# Detailed information
python -m python_json_rbac.jwt_keyman validate --verbose
```

### Key Rotation

```bash
# Dry run (see what would happen)
python -m python_json_rbac.jwt_keyman rotate --dry-run

# Perform rotation
python -m python_json_rbac.jwt_keyman rotate --output-file new_secret.txt
```

### Check Status

```bash
# Basic status
python -m python_json_rbac.jwt_keyman status

# Detailed status with all keys
python -m python_json_rbac.jwt_keyman status --verbose
```

### Cleanup Old Keys

```bash
# Clean up keys older than 30 days
python -m python_json_rbac.jwt_keyman cleanup --max-age-days 30
```

## Security Best Practices

### 1. Secret Generation

Always use cryptographically secure random generators:

```python
from python_json_rbac import generate_secure_secret

# Generate a 64-character URL-safe secret
secret = generate_secure_secret(64)
```

### 2. Regular Rotation

Implement regular key rotation:

```python
from python_json_rbac import create_rotation_plan

# Check if rotation is needed
plan = create_rotation_plan(rotation_interval_days=30)
if plan['action'] == 'rotate':
    print(f"Rotation needed: {plan['message']}")
```

### 3. Secure Storage

- Store secrets in environment variables, not in code
- Use secure secret management systems in production
- Enable JWE encryption for sensitive payloads
- Use strict mode for enhanced security checks

### 4. Monitoring

```python
from python_json_rbac import get_secret_info, get_key_rotation_status

# Monitor secret health
info = get_secret_info()
print(f"Secret entropy: {info['entropy_estimate']:.2f}")

# Monitor rotation status
status = get_key_rotation_status()
print(f"Rotation enabled: {status['rotation_enabled']}")
```

## API Reference

### Core Functions

#### `validate_current_secret() -> Dict[str, Any]`

Validates the current JWT secret configuration.

**Returns:**
- `valid`: Boolean indicating if configuration is valid
- `security_score`: Score from 0-100
- `recommendations`: List of improvement suggestions
- `secret_info`: Detailed information about the secret

#### `generate_secure_secret(length: int = 64) -> str`

Generates a cryptographically secure secret.

**Parameters:**
- `length`: Length in characters (default: 64)

**Returns:**
- URL-safe base64 encoded secret string

#### `create_rotation_plan(rotation_interval_days: int = 30, grace_period_days: int = 7) -> Dict[str, Any]`

Creates a key rotation plan based on current key age.

**Returns:**
- `action`: "rotate", "wait", or "initialize"
- `message`: Human-readable status message
- `urgency`: "low", "medium", or "high"

### Key Manager

#### `SecureKeyManager`

Main class for managing JWT keys with rotation support.

**Key Methods:**
- `generate_key(algorithm, length)`: Generate new key
- `rotate_key(new_algorithm, new_length)`: Perform rotation
- `get_rotation_status()`: Get current status
- `cleanup_old_keys(max_age_days)`: Remove old keys

### Configuration

#### `get_secret_info() -> Dict[str, Any]`

Returns information about current secret configuration without exposing the actual secret.

#### Environment Variables

All configuration is done through environment variables:

- `JWT_SECRET`: Primary secret (required)
- `JWT_SECRET_PREVIOUS`: Previous secret for rotation
- `JWT_ALGORITHM`: Signing algorithm (HS256/RS256)
- `JWT_ENABLE_JWE`: Enable encryption (true/false)
- `JWT_STRICT_MODE`: Enable strict security checks
- `JWT_EXPIRE_MINUTES`: Token expiration time
- `JWT_MAX_CLOCK_SKEW`: Maximum allowed clock skew
- `JWT_KEY_ROTATION_GRACE_HOURS`: Grace period for old keys

## Migration Guide

### From Basic Setup

If you're currently using basic JWT_SECRET:

1. **Validate your current secret:**
   ```bash
   python -m python_json_rbac.jwt_keyman validate
   ```

2. **If invalid, generate a new one:**
   ```bash
   python -m python_json_rbac.jwt_keyman generate --length 64
   ```

3. **Enable rotation:**
   ```bash
   # Set your old secret as previous
   export JWT_SECRET_PREVIOUS="$JWT_SECRET"
   export JWT_SECRET="new-generated-secret"
   ```

### To Production

1. Use a secure secret management system
2. Enable JWE encryption
3. Set up regular rotation schedule
4. Enable strict mode
5. Monitor key health and rotation status

## Troubleshooting

### Common Issues

1. **"JWT secret validation failed"**
   - Check minimum length (32+ characters)
   - Ensure proper character set
   - Verify entropy requirements

2. **"Token verification failed with all available keys"**
   - Check key rotation configuration
   - Verify JWT_SECRET_PREVIOUS is set correctly
   - Check grace period settings

3. **"Key file not found"**
   - Verify RSA key file paths
   - Check file permissions
   - Ensure proper key format

### Debug Mode

Enable debug mode for detailed error information:

```bash
export DEBUG=1
python -m python_json_rbac.jwt_keyman status
```

## Security Considerations

1. **Secret Exposure**: Never log or expose JWT secrets
2. **Rotation Timing**: Plan rotations during low-traffic periods
3. **Grace Periods**: Balance security with availability
4. **Key Storage**: Use proper secret management in production
5. **Monitoring**: Set up alerts for key rotation failures
6. **Backup**: Keep secure backups of rotation metadata
