from sqlalchemy import or_
import re, secrets
from datetime import datetime, timezone, timedelta
from dateutil.relativedelta import relativedelta
from app.features.api_keys.utils.security import hash_key, verify_key
from app.features.api_keys.models.api_model import ApiKey
from uuid import uuid4
from fastapi import HTTPException, status
from app.features.api_keys.schemas.api_schema import ApiKeyCreate, ApiKeyRequest

def parse_duration_to_utc(offset_str: str) -> datetime:
    """
    Convert strings like '1H', '1D', '1M', '1Y' into a UTC datetime.
    Returns: now_utc + offset
    """
    pattern = r"^(\d+)([HDMY])$"
    match = re.match(pattern, offset_str.upper().strip())
    
    if not match:
        raise ValueError(f"Invalid duration format: {offset_str}")
    
    value = int(match.group(1))
    unit = match.group(2)

    now = datetime.now(timezone.utc)

    if unit == "H":
        return now + timedelta(hours=value)
    elif unit == "D":
        return now + timedelta(days=value)
    elif unit == "M":
        return now + relativedelta(months=value)
    elif unit == "Y":
        return now + relativedelta(years=value)
    else:
        raise ValueError("Unsupported time unit")



def is_expired(expiry_dt: datetime) -> bool:
    """
    Returns True if expiry_dt is in the past (expired), False otherwise.
    Handles naive vs aware datetimes safely.
    """
    if expiry_dt is None:
        return True 
    
    # Ensure UTC-aware datetime
    if expiry_dt.tzinfo is None:
        expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    return now >= expiry_dt




def generate_secure_key():
    raw_key = secrets.token_urlsafe(32)
    hashed_key = hash_key(raw_key)
    public_id = uuid4().hex
    masked_key = f"sk_live_{public_id[:5]}_***{raw_key[-3:]}"
    return {
        "raw_key": raw_key,
        "hashed_key": hashed_key,
        "masked_key": masked_key,
        "public_id" : public_id
    }


def list_user_active_keys(db,current_user):
    user_id = current_user.user_id
    now = datetime.now(timezone.utc)
    keys = (
        db.query(ApiKey)
        .filter(
            ApiKey.user_id == user_id,
            ApiKey.is_revoked.is_(False),
            or_(ApiKey.expires_at.is_(None), ApiKey.expires_at > now),
        )
        .all()
    )
    return keys

def create_new_api(db, current_user, payload: ApiKeyRequest, expires = None):
    active_keys = len(list_user_active_keys(db, current_user))
    
    if active_keys >= 20:
        raise HTTPException(status_code= status.HTTP_409_CONFLICT, detail="Limit of 5 active keys reached")
    
    generated_key = generate_secure_key()
    if expires is None:
        expires_at = parse_duration_to_utc(payload.expires_at)
    else:
        expires_at = parse_duration_to_utc(expires)

    api_key_create = ApiKeyCreate(
            api_key = generated_key.get("hashed_key"),
            masked_key = generated_key.get("masked_key"),
            public_api_id = generated_key.get("public_id"),
            user_id=current_user.user_id,
            name = payload.name,
            permissions=payload.permissions,
            expires_at=expires_at
        )
    api_key = ApiKey(**api_key_create.model_dump())

    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    return {
        "api_key": api_key,
        "generated_key": generated_key
    }


def verify_secret_hashes(api_key, current_user, db):
    split_value = api_key.split("_") 
    public_key = split_value[2]
    secret_key = split_value[3]
    
    user_id = current_user.user_id
    api_key = (
        db.query(ApiKey).filter(
            ApiKey.user_id == user_id,
            ApiKey.public_api_id == public_key
            ).first()
    )
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    

    is_verified = verify_key(secret_key, api_key.api_key)

    if not is_verified:
        raise HTTPException(status_code=404, detail="API key not found")
    
    return api_key