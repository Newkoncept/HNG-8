from fastapi import APIRouter, status, Depends, HTTPException
from typing import List
from datetime import datetime, timezone
from sqlalchemy import or_
from sqlalchemy.orm import Session
from app.features.api_keys.schemas.api_schema import (
    ApiKeyCreate, 
    ApiKeyRequest, 
    ApiKeyResponse,
    ApiKeyRollOver, 
    ApiKeyUserResponse
    
)
from app.database.db import get_db
from app.features.auth.utils.jwt_token import get_current_user
from app.features.api_keys.models.api_model import ApiKey
from app.features.api_keys.utils.api_util import(
    list_user_active_keys,
    create_new_api,
    verify_secret_hashes
)

from app.features.api_keys.utils.security import (hash_key, verify_key)


router = APIRouter(prefix="/keys", tags=["APIKeys"])

# @router.post("/", response_model="", status_code=status.HTTP_201_CREATED)
@router.post("/create", status_code=status.HTTP_201_CREATED)
def create_api_key(
    payload: ApiKeyRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    
    api_details = create_new_api(db, current_user, payload)

    api_key = api_details.get("api_key")
    generated_key = api_details.get("generated_key")

    # Return the secret key once (store hashed if needed)
    return ApiKeyResponse(
        api_key=f"sk_live_{generated_key.get('public_id')}_{generated_key.get('raw_key')}",
        expires_at=api_key.expires_at
    )

@router.get("/", response_model=List[ApiKeyUserResponse])
def list_user_keys(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    user_id = current_user.user_id
    keys = db.query(ApiKey).filter(ApiKey.user_id == user_id).all()

    return keys

@router.get("/active", response_model=List[ApiKeyUserResponse])
def list_active_keys(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    
    return list_user_active_keys(db, current_user)

@router.post("/{api_key}/revoke", status_code=status.HTTP_200_OK)
def revoke_key(
    api_key: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    db_api_key = verify_secret_hashes(api_key, current_user, db)
    
    db_api_key.is_revoked = True
    db.commit()
    return {
        "message" : f"{api_key.api_key} successfully revoked"
    }

@router.post("/rollover", response_model=ApiKeyResponse)
def rollover_expired_key(
    payload: ApiKeyRollOver,  # reuse to allow new ttl/permissions if desired
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    expired_key_id = payload.expired_key_id

    db_api_key = verify_secret_hashes(expired_key_id, current_user, db)
    now = datetime.now(timezone.utc)
    
    if db_api_key.expires_at is None or db_api_key.expires_at > now:
        raise HTTPException(status_code=400, detail="Key is still active; revoke or wait for expiry before rollover")
    
    api_details = create_new_api(db, current_user, db_api_key, payload.expiry)

    api_key = api_details.get("api_key")
    generated_key = api_details.get("generated_key")


    # Return the secret key once (store hashed if needed)
    return ApiKeyResponse(
        api_key=f"sk_live_{generated_key.get('public_id')}_{generated_key.get('raw_key')}",
        expires_at=api_key.expires_at
    )
