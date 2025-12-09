from pydantic import BaseModel
from datetime import datetime


class CurrentUser(BaseModel):
    user_id: str   

class TokenPayload(CurrentUser):
    exp: datetime

class TokenResponse(BaseModel):
    access_token: str
    token_type: str