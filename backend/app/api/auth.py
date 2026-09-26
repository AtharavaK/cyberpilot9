import secrets
import hashlib
from typing import Optional, Dict, Any
from fastapi import Header, HTTPException, Depends
from app.db import crud

API_KEY_PREFIX = "cpk_"
API_KEY_LENGTH = 32


def generate_api_key(name: str = "default") -> tuple[str, str]:
    """Generate a new API key and its hash.
    Returns: (plain_key, key_hash)"""
    random_part = secrets.token_urlsafe(API_KEY_LENGTH)
    plain_key = f"{API_KEY_PREFIX}{random_part}"
    key_hash = hashlib.sha256(plain_key.encode()).hexdigest()
    return plain_key, key_hash


def hash_api_key(plain_key: str) -> str:
    """Hash an API key for storage."""
    return hashlib.sha256(plain_key.encode()).hexdigest()


def verify_api_key(plain_key: str, key_hash: str) -> bool:
    """Verify an API key against its hash."""
    return hashlib.sha256(plain_key.encode()).hexdigest() == key_hash


async def get_api_key_optional(authorization: str = Header(None)) -> Optional[str]:
    """Extract API key from Authorization header, or return None if not provided."""
    if not authorization:
        return None

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    api_key = parts[1]
    if not api_key.startswith(API_KEY_PREFIX):
        return None

    return api_key


async def get_api_key_required(authorization: str = Header(None)) -> str:
    """Extract API key from Authorization header, raising 401 if missing/invalid."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid Authorization header format. Use: Bearer <api_key>")

    api_key = parts[1]
    if not api_key.startswith(API_KEY_PREFIX):
        raise HTTPException(status_code=401, detail="Invalid API key format")

    return api_key


async def validate_api_key(api_key: str = Depends(get_api_key_required)) -> Dict[str, Any]:
    """Validate API key against database."""
    key_hash = hash_api_key(api_key)
    key_data = await crud.get_api_key_by_hash(key_hash)

    if not key_data:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")

    if not key_data.get("is_active", True):
        raise HTTPException(status_code=401, detail="API key is disabled")

    # Update last_used timestamp
    await crud.update_api_key_last_used(key_data["id"])

    return key_data


async def optional_api_key(api_key: Optional[str] = Depends(get_api_key_optional)) -> Optional[Dict[str, Any]]:
    """Validate API key if provided, otherwise return None."""
    if not api_key:
        return None
    key_hash = hash_api_key(api_key)
    key_data = await crud.get_api_key_by_hash(key_hash)
    if not key_data or not key_data.get("is_active", True):
        return None
    return key_data


async def require_auth_or_bootstrap(api_key: Optional[Dict[str, Any]] = Depends(optional_api_key)):
    """Dependency that requires auth unless no ACTIVE API keys exist (bootstrap mode)."""
    keys = await crud.list_api_keys()
    active_keys = [k for k in keys if k.get("is_active", True)]
    if not active_keys:
        return None  # Allow bootstrap
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    return api_key