from typing import List
from pydantic import BaseModel, field_validator, Field
from app.features.api_keys.models.api_model import ALLOWED_PERMS
from datetime import datetime
import re

TTL_PATTERN = re.compile(r"^[1-9]\d*[HDMY]$", re.IGNORECASE)


class ApiKeyRequest(BaseModel):
    name: str
    permissions: list[str]
    expires_at : str | datetime

    @field_validator("permissions")
    def validate_permissions(cls, value):
        if not value or len(value) > 3:
            raise ValueError("1 to 3 permissions required")
        if len(set(value)) != len(value):
            raise ValueError("Duplicate permissions not allowed")
        
        bad = set(value) - ALLOWED_PERMS
        if bad:
            raise ValueError(f"Invalid permissions: {', '.join(bad)}")
        return value
    
    @field_validator("expires_at", mode="before")
    def validate_expires_at(cls, v):
        if isinstance(v, datetime):
            return v
        v = v.strip().upper()
        if not TTL_PATTERN.match(v):
            raise ValueError("expires_at must be <positive integer><H|D|M|Y> (e.g., 1H, 2D, 30M, 1Y)")
        return v

class ApiKeyCreate(ApiKeyRequest):
    api_key : str
    masked_key : str
    user_id : str
    public_api_id : str
    expires_at : datetime
    
    
class ApiKeyResponse(BaseModel):
    api_key : str
    expires_at : datetime

class ApiKeyUserResponse(BaseModel):
    api_key: str = Field(..., alias="masked_key")
    is_active: bool = Field(..., alias="is_revoked")
    expires_at : datetime
    name : str
    permissions : List["str"]

    model_config = {
        "from_attributes": True,  
        "populate_by_name": True,
    }

class ApiKeyRollOver(BaseModel):
    expired_key_id : str
    expiry : str
    
    @field_validator("expiry", mode="before")
    def validate_expires_at(cls, v):
        v = v.strip().upper()
        if not TTL_PATTERN.match(v):
            raise ValueError("expiry must be <positive integer><H|D|M|Y> (e.g., 1H, 2D, 30M, 1Y)")
        return v