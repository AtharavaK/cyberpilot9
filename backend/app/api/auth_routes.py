from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
from app.api.auth import validate_api_key, require_auth_or_bootstrap, generate_api_key
from app.db import crud

router = APIRouter(prefix="/auth", tags=["authentication"])


class APIKeyCreateRequest(BaseModel):
    name: str = "default"


class APIKeyCreateResponse(BaseModel):
    id: int
    name: str
    key: str  # Only returned once!
    key_prefix: str
    created_at: str


class APIKeyResponse(BaseModel):
    id: int
    name: str
    key_prefix: str
    created_at: str
    last_used: Optional[str]
    is_active: bool


@router.post("/keys", response_model=APIKeyCreateResponse)
async def create_api_key_endpoint(
    request: APIKeyCreateRequest,
    current_user: Optional[dict] = Depends(require_auth_or_bootstrap)
):
    """Create a new API key. The plain key is only returned once.
    If no API keys exist, allows creation without authentication (bootstrap)."""
    plain_key, key_hash = generate_api_key(request.name)
    key_id = await crud.create_api_key(key_hash, plain_key[:8], request.name)

    key_data = await crud.get_api_key_by_id(key_id)

    return APIKeyCreateResponse(
        id=key_data["id"],
        name=key_data["name"],
        key=plain_key,  # Only returned on creation!
        key_prefix=key_data["key_prefix"],
        created_at=key_data["created_at"],
    )


@router.get("/keys", response_model=list[APIKeyResponse])
async def list_api_keys(current_user: dict = Depends(validate_api_key)):
    """List all API keys (without the full key)."""
    keys = await crud.list_api_keys()
    return [
        APIKeyResponse(
            id=k["id"],
            name=k["name"],
            key_prefix=k["key_prefix"],
            created_at=k["created_at"],
            last_used=k["last_used"],
            is_active=bool(k["is_active"]),
        )
        for k in keys
    ]


@router.get("/keys/{key_id}", response_model=APIKeyResponse)
async def get_api_key(key_id: int, current_user: dict = Depends(validate_api_key)):
    """Get a specific API key by ID."""
    key_data = await crud.get_api_key_by_id(key_id)
    if not key_data:
        raise HTTPException(status_code=404, detail="API key not found")

    return APIKeyResponse(
        id=key_data["id"],
        name=key_data["name"],
        key_prefix=key_data["key_prefix"],
        created_at=key_data["created_at"],
        last_used=key_data["last_used"],
        is_active=bool(key_data["is_active"]),
    )


@router.delete("/keys/{key_id}")
async def revoke_api_key(key_id: int, current_user: dict = Depends(validate_api_key)):
    """Revoke (disable) an API key."""
    success = await crud.revoke_api_key(key_id)
    if not success:
        raise HTTPException(status_code=404, detail="API key not found")
    return {"message": "API key revoked successfully"}