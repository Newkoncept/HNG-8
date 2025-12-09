from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database.db import get_db
from app.features.auth.utils.jwt_token import get_current_user
from app.features.transaction.models.transaction_model import Transaction
from app.features.transaction.schemas.transaction_schema import TransactionOut
from app.features.wallet.models.wallet_model import Wallet

router = APIRouter(prefix="/transactions", tags=["transactions"])

@router.get("/", response_model=list[TransactionOut])
def list_transactions(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    wallet = db.query(Wallet).filter(Wallet.user_id == current_user.user_id).first()
    if not wallet:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Wallet not found")

    txs = (
        db.query(Transaction)
        .filter(Transaction.wallet_id == wallet.id)
        .order_by(Transaction.created_at.desc())
        .all()
    )
    return [
        TransactionOut(
            reference=tx.reference,
            type=tx.type.value,
            status=tx.status.value,
            amount=tx.amount,
            created_at=tx.created_at,
        )
        for tx in txs
    ]
