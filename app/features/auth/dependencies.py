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
    Expect: sk_live_<public_id>_<secret>
    or     sk_test_<public_id>_<secret>
    """
    if not raw.startswith("sk_"):
        raise ValueError("Invalid API key format")

    parts = raw.split("_", 3)
    if len(parts) != 4:
        raise ValueError("Invalid API key format")

    # e.g. ["sk", "live", "<public_id>", "<secret>"]
    prefix = f"{parts[0]}_{parts[1]}"  # sk_live / sk_test if you need it
    public_id = parts[2]
    secret = parts[3]
    return prefix, public_id, secret


async def get_principal(
    db: Session = Depends(get_db),
    bearer: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Principal:
    # 1. JWT preferred if present
    if bearer and bearer.scheme.lower() == "bearer":
        # your get_current_user likely returns a User instance
        user = await get_current_user(bearer.credentials, db)  # adjust signature if needed
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )
        return Principal(type=PrincipalType.USER, user_id=user.user_id)

    # 2. API key
    if x_api_key:
        try:
            _prefix, public_id, secret = parse_api_key_header(x_api_key)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
            )

        api_key: ApiKey = (
            db.query(ApiKey)
            .filter(ApiKey.public_api_id == public_id)
            .first()
        )
        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
            )

        # verify secret against stored hash
        if not verify_key(secret, api_key.api_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
            )

        # check expiry & revoked
        now = datetime.now(timezone.utc)
        if api_key.expires_at.replace(tzinfo=timezone.utc) <= now:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key expired",
            )

        if api_key.is_revoked:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key revoked",
            )

        # permissions stored e.g. as "read,deposit,transfer"
        perms = [p.strip() for p in (api_key.permissions or "").split(",") if p.strip()]

        return Principal(
            type=PrincipalType.SERVICE,
            user_id=api_key.user_id,
            permissions=perms,
        )

    # 3. No auth
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
    )


def require_permission(principal: Principal, permission: str):
    # JWT users can do all wallet actions according to the spec
    if principal.type == PrincipalType.USER:
        return

    # For API keys, check permissions list
    if permission not in principal.permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing permission: {permission}",
        )
