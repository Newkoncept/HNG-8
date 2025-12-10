from datetime import datetime, timezone
from typing import Optional, List

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.features.auth.utils.jwt_token import get_current_user
from app.features.api_keys.models.api_model import ApiKey
from app.features.api_keys.utils.security import verify_key

bearer_scheme = HTTPBearer(auto_error=False)

class PrincipalType:
    USER = "user"
    SERVICE = "service"

class Principal:
    def __init__(self, type: str, user_id: str, permissions: Optional[List[str]] = None):
        self.type = type
        self.user_id = user_id
        self.permissions = permissions or []

def parse_api_key_header(raw: str) -> tuple[str, str, str]:
    """
    Expect: sk_live_<public_id>_<secret> or sk_test_<public_id>_<secret>
    """
    if not raw.startswith("sk_"):
        raise ValueError("Invalid API key format")
    parts = raw.split("_", 3)
    if len(parts) != 4:
        raise ValueError("Invalid API key format")
    prefix = f"{parts[0]}_{parts[1]}"  # sk_live / sk_test
    public_id = parts[2]
    secret = parts[3]
    return prefix, public_id, secret

async def get_principal(
    db: Session = Depends(get_db),
    bearer: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Principal:
    # 1. JWT preferred
    if bearer and bearer.scheme.lower() == "bearer":
        user = get_current_user(bearer.credentials)  # no await
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return Principal(type=PrincipalType.USER, user_id=user.user_id)

    # 2. API key
    if x_api_key:
        try:
            _prefix, public_id, secret = parse_api_key_header(x_api_key)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

        api_key: ApiKey = db.query(ApiKey).filter(ApiKey.public_api_id == public_id).first()
        if not api_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

        if not verify_key(secret, api_key.api_key):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

        if api_key.expires_at:
            now = datetime.now(timezone.utc)
            if api_key.expires_at.replace(tzinfo=timezone.utc) <= now:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key expired")

        if api_key.is_revoked:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key revoked")

        # permissions: handle list or comma-separated string
        perms_raw = api_key.permissions or []
        if isinstance(perms_raw, str):
            perms = [p.strip() for p in perms_raw.split(",") if p.strip()]
        else:
            perms = [p for p in perms_raw if p]
        return Principal(type=PrincipalType.SERVICE, user_id=api_key.user_id, permissions=perms)

    # 3. No auth
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

def require_permission(principal: Principal, permission: str):
    if principal.type == PrincipalType.USER:
        return
    if permission not in principal.permissions:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Missing permission: {permission}")
