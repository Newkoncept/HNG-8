import os
from fastapi import FastAPI

from app.features.auth.routers import auth_router
from app.features.api_keys.routes import api_route
from app.features.wallet.routes import wallet_route
from app.features.transaction.routes import transaction_route

from dotenv import load_dotenv

load_dotenv()

app = FastAPI()
app.include_router(auth_router.router)
app.include_router(api_route.router)
app.include_router(wallet_route.router)
# app.include_router(transaction_route.router)


app.get('/', tags=["default"])
def index():
    return {"data": "welcome"}




