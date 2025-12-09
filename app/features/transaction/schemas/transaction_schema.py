from datetime import datetime
from pydantic import BaseModel

class TransactionOut(BaseModel):
    reference: str
    type: str
    status: str
    amount: int
    created_at: datetime
