import os
from fastapi import APIRouter, HTTPException, Depends
from urllib.parse import urlencode
from dotenv import load_dotenv
import httpx
from sqlalchemy.orm import Session

from app.features.auth.schemas.auth_schema import TokenResponse
from app.features.auth.utils.jwt_token import create_access_token
from app.database.db import get_db
from app.features.auth.models.user_model import User
from app.features.wallet.routes.wallet_route import get_or_create_wallet


load_dotenv()
router = APIRouter(prefix='/auth/google', tags=["Authentication"])

GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

OAUTH_SCOPES = "openid email profile"

@router.get("/")
async def google_login():
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "scope": OAUTH_SCOPES,
        "access_type": "offline",
        "prompt": "consent",  
    }
    url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"

    return {
        "message": "Google sign in link created successfully",
        "data": {
            "url": url
        }
    }


@router.get("/callback")
async def callback(code: str | None = None, error: str | None = None, db: Session = Depends(get_db)):
    

    if error:
        raise HTTPException(status_code=400, detail=f"Google auth error: {error}")
    if not code:
        raise HTTPException(status_code=400, detail="Missing code from Google")

    
    async with httpx.AsyncClient() as client:
        token_data = {
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        }
        token_resp = await client.post(GOOGLE_TOKEN_URL, data=token_data)
        if token_resp.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch token from Google")
        tokens = token_resp.json()


        id_token = tokens.get("id_token")
        access_token = tokens.get("access_token")

        if not id_token:
            raise HTTPException(status_code=400, detail="No id_token in Google response")

        headers = {"Authorization": f"Bearer {access_token}"}
        userinfo_resp = await client.get(GOOGLE_USERINFO_URL, headers=headers)
        if userinfo_resp.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch userinfo from Google")
        userinfo = userinfo_resp.json()

        """
        Example userinfo:
        {
          "sub": "...",
          "email": "user@example.com",
          "email_verified": true,
          "name": "User Name",
          "picture": "https://...",
          "given_name": "...",
          "family_name": "..."
        }
        """

    provider_sub = userinfo.get("sub")


    user = db.query(User).filter_by(provider_sub=provider_sub).first()
    if not user:
        user = User(
            provider_sub=provider_sub,
            email=userinfo.get("email"),
            name=userinfo.get("name"),
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    get_or_create_wallet(db, user_id= user.user_id)

    access_jwt = create_access_token({"user_id":user.user_id})

    token_response = TokenResponse(access_token = access_jwt, token_type="bearer")

    return {
        "message": "User logged in successfully",
        "data": token_response.model_dump()
    }

