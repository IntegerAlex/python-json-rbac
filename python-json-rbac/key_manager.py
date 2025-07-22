"""
Secure key management utilities for JWT secrets with rotation support.
"""
import os
import json
import secrets
import hashlib
import datetime
import logging
from pathlib import Path
from typing import Dict, Optional, Any, Tuple
from dataclasses import dataclass, asdict
import threading

from .config import (
    JWT_SECRET,
    JWT_SECRET_ID,
    _validate_secret_strength,
    _generate_secure_secret,
)

# Constants
MAGIC_UNIQUE_CHAR_RATIO = 0.5
SECONDS_PER_DAY = 86400

# Setup logging
logger = logging.getLogger(__name__)

# Thread lock for singleton
_key_manager_lock = threading.Lock()

@dataclass
class KeyMetadata:
    """Metadata for a JWT secret key."""
    key_id: str
    created_at: datetime.datetime
    algorithm: str
    key_length: int
    is_active: bool
    rotation_count: int = 0
    last_used: Optional[datetime.datetime] = None


class SecureKeyManager:
    """
    Secure key manager for JWT secrets with rotation capabilities.
    
    This class provides secure key generation, storage, rotation, and management
    for JWT secrets. It supports both in-memory and file-based key storage.
    """
    
    def __init__(self, storage_path: Optional[str] = None):
        """
        Initializes the SecureKeyManager, optionally loading key metadata from a specified storage path.
        
        Parameters:
            storage_path (Optional[str]): Path to persist key metadata. If not provided, metadata is managed in memory only.
        """
        self.storage_path = Path(storage_path) if storage_path else None
        self._keys: Dict[str, KeyMetadata] = {}
        self._load_metadata()
    
    def _load_metadata(self) -> None:
        """
        Loads key metadata from the storage file into the manager's internal state.
        
        If the storage file does not exist or is invalid, the method returns without modifying the current state. Warnings are logged for any errors encountered during loading or parsing.
        """
        if not self.storage_path or not self.storage_path.exists():
            return
        
        try:
            with open(self.storage_path, 'r') as f:
                data = json.load(f)
            
            for key_id, metadata in data.get('keys', {}).items():
                self._keys[key_id] = KeyMetadata(
                    key_id=metadata['key_id'],
                    created_at=datetime.datetime.fromisoformat(metadata['created_at']),
                    algorithm=metadata['algorithm'],
                    key_length=metadata['key_length'],
                    is_active=metadata['is_active'],
                    rotation_count=metadata.get('rotation_count', 0),
                    last_used=datetime.datetime.fromisoformat(metadata['last_used']) 
                              if metadata.get('last_used') else None,
                )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to load key metadata: {e}")
    
    def _save_metadata(self) -> None:
        """
        Persist the current key metadata to the configured storage path in JSON format.
        
        If the storage path is not set, the function does nothing. Creates parent directories as needed. Logs a warning if saving fails.
        """
        if not self.storage_path:
            return
        
        # Create directory if it doesn't exist
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            'keys': {
                key_id: {
                    **asdict(metadata),
                    'created_at': metadata.created_at.isoformat(),
                    'last_used': metadata.last_used.isoformat() if metadata.last_used else None,
                }
                for key_id, metadata in self._keys.items()
            }
        }
        
        try:
            with open(self.storage_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save key metadata: {e}")
    
    def generate_key(self, algorithm: str = "HS256", length: int = 64) -> Tuple[str, str]:
        """
        Generates a new cryptographically secure secret key and stores its metadata.
        
        Parameters:
        	algorithm (str): The JWT algorithm associated with the key.
        	length (int): The desired length of the generated key in characters.
        
        Returns:
        	tuple: A tuple containing the generated secret and its unique key ID.
        """
        secret = _generate_secure_secret(length)
        _validate_secret_strength(secret)
        
        key_id = hashlib.sha256(secret.encode()).hexdigest()[:16]
        
        metadata = KeyMetadata(
            key_id=key_id,
            created_at=datetime.datetime.now(datetime.timezone.utc),
            algorithm=algorithm,
            key_length=len(secret),
            is_active=False,  # Not active until explicitly set
        )
        
        self._keys[key_id] = metadata
        self._save_metadata()
        
        return secret, key_id
    
    def activate_key(self, key_id: str) -> None:
        """
        Activates the specified key by key ID and deactivates all others.
        
        Raises:
            ValueError: If the specified key ID does not exist.
        """
        if key_id not in self._keys:
            raise ValueError(f"Key {key_id} not found")
        try:
            # Deactivate all other keys
            for metadata in self._keys.values():
                metadata.is_active = False
            # Activate the specified key
            self._keys[key_id].is_active = True
            self._keys[key_id].last_used = datetime.datetime.now(datetime.timezone.utc)
        finally:
            # Ensure at least one key is active
            if not any(m.is_active for m in self._keys.values()):
                self._keys[key_id].is_active = True
            self._save_metadata()
    
    def get_active_key_id(self) -> Optional[str]:
        """
        Return the key ID of the currently active key, or None if no key is active.
        
        Returns:
            The key ID of the active key, or None if no active key exists.
        """
        for key_id, metadata in self._keys.items():
            if metadata.is_active:
                return key_id
        return None
    
    def get_key_metadata(self, key_id: str) -> Optional[KeyMetadata]:
        """
        Retrieve the metadata associated with a specific key ID.
        
        Parameters:
            key_id (str): The unique identifier of the key.
        
        Returns:
            Optional[KeyMetadata]: The metadata for the specified key, or None if the key does not exist.
        """
        return self._keys.get(key_id)
    
    def list_keys(self, include_inactive: bool = False) -> Dict[str, KeyMetadata]:
        """
        Returns a dictionary of key IDs to their metadata, optionally including inactive keys.
        
        Parameters:
            include_inactive (bool): If True, includes both active and inactive keys; otherwise, only active keys are returned.
        
        Returns:
            Dict[str, KeyMetadata]: Mapping of key IDs to their corresponding metadata.
        """
        if include_inactive:
            return self._keys.copy()
        
        return {
            key_id: metadata 
            for key_id, metadata in self._keys.items() 
            if metadata.is_active
        }
    
    def rotate_key(self, new_algorithm: str = "HS256", new_length: int = 64) -> Tuple[str, str]:
        """
        Generates and activates a new secret key, incrementing the rotation count of the previously active key.
        
        Parameters:
            new_algorithm (str): Algorithm to use for the new key.
            new_length (int): Length of the new key in bytes.
        
        Returns:
            Tuple[str, str]: The newly generated secret and its key ID.
        """
        # Generate new key
        new_secret, new_key_id = self.generate_key(new_algorithm, new_length)
        
        # Update rotation count for the previously active key
        current_active = self.get_active_key_id()
        if current_active and current_active in self._keys:
            self._keys[current_active].rotation_count += 1
        
        # Activate the new key
        self.activate_key(new_key_id)
        
        return new_secret, new_key_id
    
    def cleanup_old_keys(self, max_age_days: int = 30, dry_run: bool = False) -> Any:
        """
        Removes inactive keys older than the specified number of days, or previews keys eligible for removal if dry_run is True.
        
        Parameters:
            max_age_days (int): The maximum age in days for inactive keys to retain.
            dry_run (bool): If True, returns a list of keys that would be removed without deleting them.
        
        Returns:
            int or List[str]: The number of keys removed, or a list of key IDs that would be removed if dry_run is True.
        """
        cutoff_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=max_age_days)
        keys_to_remove = [key_id for key_id, metadata in self._keys.items()
                         if not metadata.is_active and metadata.created_at < cutoff_date]
        if dry_run:
            return keys_to_remove
        for key_id in keys_to_remove:
            del self._keys[key_id]
        if keys_to_remove:
            self._save_metadata()
        return len(keys_to_remove)
    
    def get_rotation_status(self) -> Dict[str, Any]:
        """
        Return detailed information about the current key rotation status.
        
        Returns:
            A dictionary containing the active key ID, age of the active key in hours, total number of keys, count of inactive keys, rotation count of the active key, and the last used timestamp of the active key.
        """
        active_key_id = self.get_active_key_id()
        active_metadata = self._keys.get(active_key_id) if active_key_id else None
        
        return {
            "active_key_id": active_key_id,
            "active_key_age_hours": (
                (datetime.datetime.now(datetime.timezone.utc) - active_metadata.created_at).total_seconds() / 3600
                if active_metadata else None
            ),
            "total_keys": len(self._keys),
            "inactive_keys": len([k for k in self._keys.values() if not k.is_active]),
            "rotation_count": active_metadata.rotation_count if active_metadata else 0,
            "last_used": active_metadata.last_used.isoformat() if active_metadata and active_metadata.last_used else None,
        }


# Global key manager instance (thread-safe)
_key_manager: Optional[SecureKeyManager] = None


def get_key_manager(storage_path: Optional[str] = None) -> SecureKeyManager:
    """
    Returns the singleton instance of the SecureKeyManager, initializing it with the given storage path if necessary.
    
    Parameters:
        storage_path (Optional[str]): Optional file path for persisting key metadata.
    
    Returns:
        SecureKeyManager: The global key manager instance.
    """
    global _key_manager
    with _key_manager_lock:
        if _key_manager is None:
            _key_manager = SecureKeyManager(storage_path)
    
    return _key_manager


def validate_current_secret() -> Dict[str, Any]:
    """
    Evaluates the current JWT secret's security properties and provides recommendations for improvement.
    
    Returns:
        dict: Contains validation status, a security score, actionable recommendations, and detailed secret information.
    """
    from .config import get_secret_info
    
    info = get_secret_info()
    
    recommendations = []
    security_score = 100
    
    # Check secret length
    if info["secret_length"] < 32:
        recommendations.append("Increase secret length to at least 32 characters")
        security_score -= 30
    elif info["secret_length"] < 64:
        recommendations.append("Consider using a longer secret (64+ characters) for enhanced security")
        security_score -= 10
    
    # Check entropy
    if info["entropy_estimate"] < 3.5:
        recommendations.append("Secret has low entropy - consider using a more random secret")
        security_score -= 25
    elif info["entropy_estimate"] < 4.0:
        recommendations.append("Secret entropy could be improved")
        security_score -= 10
    
    # Check rotation
    if not info["key_rotation_enabled"]:
        recommendations.append("Enable key rotation for improved security")
        security_score -= 15
    
    # Check JWE
    if not info["jwe_enabled"]:
        recommendations.append("Consider enabling JWE encryption for sensitive data")
        security_score -= 10
    
    return {
        "valid": len(recommendations) == 0,
        "security_score": max(0, security_score),
        "recommendations": recommendations,
        "secret_info": info,
    }


# Utility functions for easy access
def generate_secure_secret(length: int = 64) -> str:
    """
    Generate a cryptographically secure random secret string of the specified length.
    
    Parameters:
        length (int): The desired length of the generated secret.
    
    Returns:
        str: A securely generated secret string.
    """
    return _generate_secure_secret(length)


def create_rotation_plan(
    rotation_interval_days: int = 30,
    grace_period_days: int = 7,
) -> Dict[str, Any]:
    """
    Generate a rotation plan for JWT secret keys based on the specified rotation interval and grace period.
    
    Parameters:
        rotation_interval_days (int): Number of days after which a key should be rotated.
        grace_period_days (int): Additional days allowed before enforcing rotation.
    
    Returns:
        Dict[str, Any]: A dictionary describing the recommended action ("initialize", "rotate", or "wait"), an explanatory message, urgency level, and time until next rotation if applicable.
    """
    manager = get_key_manager()
    status = manager.get_rotation_status()
    
    if not status["active_key_id"]:
        return {
            "action": "initialize",
            "message": "No active key found. Initialize key management first.",
        }
    
    key_age_hours = status["active_key_age_hours"] or 0
    key_age_days = key_age_hours / 24
    
    if key_age_days >= rotation_interval_days:
        return {
            "action": "rotate",
            "message": f"Key is {key_age_days:.1f} days old. Rotation recommended.",
            "urgency": "high" if key_age_days > rotation_interval_days * 1.5 else "medium",
        }
    
    days_until_rotation = rotation_interval_days - key_age_days
    
    return {
        "action": "wait",
        "message": f"Key rotation scheduled in {days_until_rotation:.1f} days",
        "days_until_rotation": days_until_rotation,
        "urgency": "low",
    }
