from datetime import datetime
from pydantic import BaseModel, Field

class DepositRequest(BaseModel):
    amount: int = Field(gt=0)

class DepositResponse(BaseModel):
    reference: str
    authorization_url: str

class DepositStatusResponse(BaseModel):
    reference: str
    status: str
    amount: int

class TransferRequest(BaseModel):
    wallet_number: str
    amount: int = Field(gt=0)

class TransferResponse(BaseModel):
    status: str
    message: str

class BalanceResponse(BaseModel):
    wallet_number: str
    balance: int

class TransactionItem(BaseModel):
    type: str
    amount: int
    status: str
    created_at: datetime
