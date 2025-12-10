import os
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2AuthorizationCodeBearer, HTTPBearer, HTTPAuthorizationCredentials
from app.features.auth.schemas.auth_schema import CurrentUser, TokenPayload
from jose import jwt, JWTError
from dotenv import load_dotenv

load_dotenv()



JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
JWT_EXPIRES_MINUTES = os.getenv("JWT_EXPIRES_MINUTES")


bearer_scheme = HTTPBearer(auto_error=True)


def create_access_token(data: dict):
    to_encode = data.copy()
    expiry_time = datetime.now(timezone.utc) + timedelta(minutes = int(JWT_EXPIRES_MINUTES))
    
    to_encode["exp"] =  int(expiry_time.timestamp())

    token_payload = TokenPayload(**to_encode)
    return jwt.encode(token_payload.model_dump(), JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> CurrentUser:
    try:
        payload = jwt.decode(token, 
                             JWT_SECRET_KEY, 
                             algorithms=[JWT_ALGORITHM]
                )
        
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
        return CurrentUser(**payload)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

def get_current_user(token_or_creds: HTTPAuthorizationCredentials | str = Depends(bearer_scheme),) -> CurrentUser:
    # Accept either HTTPAuthorizationCredentials or a raw token string
    token = token_or_creds.credentials if hasattr(token_or_creds, "credentials") else str(token_or_creds)
    return decode_access_token(token)