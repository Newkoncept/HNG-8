from fastapi import APIRouter, Depends, HTTPException, Request, Header, status
from sqlalchemy.orm import Session
from uuid import uuid4
import os
import hmac
import hashlib
import httpx

from app.database.db import get_db
from app.features.auth.dependencies import get_principal, require_permission, Principal
from app.features.wallet.models.wallet_model import Wallet
from app.features.transaction.models.transaction_model import (
    Transaction,
    TransactionType,
    TransactionStatus,
)
from app.features.auth.models.user_model import User 
from app.features.wallet.schemas.wallet_schema import (
    DepositRequest,
    DepositResponse,
    DepositStatusResponse,
    BalanceResponse,
    TransferRequest,
    TransferResponse,
    TransactionItem
)
from dotenv import load_dotenv


load_dotenv()

router = APIRouter(prefix="/wallet", tags=["wallet"])

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "replace_me")
PAYSTACK_BASE_URL = "https://api.paystack.co"


def get_or_create_wallet(db: Session, user_id: str) -> Wallet:
    wallet = db.query(Wallet).filter(Wallet.user_id == user_id).first()
    if wallet:
        return wallet
    wallet = Wallet(user_id=user_id, wallet_number=uuid4().hex, balance=0)
    db.add(wallet)
    db.commit()
    db.refresh(wallet)
    return wallet


@router.post("/deposit", response_model=DepositResponse)
async def create_deposit(
    body: DepositRequest,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    require_permission(principal, "deposit")

    if body.amount <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Amount must be positive",
        )

    wallet = get_or_create_wallet(db, principal.user_id)

    reference = f"dep_{uuid4().hex}"

    tx = Transaction(
        wallet_id=wallet.id,
        type=TransactionType.DEPOSIT,
        status=TransactionStatus.PENDING,
        amount=body.amount,
        reference=reference,
    )
    db.add(tx)
    db.commit()
    db.refresh(tx)

    # Call Paystack initialize
    PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "replace_me")
    PAYSTACK_BASE_URL = "https://api.paystack.co"

    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}
    user = db.query(User).filter(User.user_id == wallet.user_id).first()
    payload = {
        "amount": body.amount * 100,
        "email": user.email,
        "reference": reference,
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{PAYSTACK_BASE_URL}/transaction/initialize",
            json=payload,
            headers=headers,
            timeout=30,
        )

    if resp.status_code != 200:
        tx.status = TransactionStatus.FAILED
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to initialize Paystack transaction",
        )

    data = resp.json()
    if not data.get("status"):
        tx.status = TransactionStatus.FAILED
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Paystack error",
        )

    auth_url = data["data"]["authorization_url"]
    tx.metadata = data["data"]
    db.commit()

    return DepositResponse(reference=reference, authorization_url=auth_url)


def verify_paystack_signature(raw_body: bytes, signature: str) -> bool:
    secret = os.getenv("PAYSTACK_SECRET_KEY")
    expected = hmac.new(
        key=secret.encode("utf-8"),
        msg=raw_body,
        digestmod=hashlib.sha512,  # Confirm with Paystack docs
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


@router.post("/paystack/webhook")
async def paystack_webhook(
    request: Request,
    db: Session = Depends(get_db),
    x_paystack_signature: str = Header(None, alias="x-paystack-signature"),
):
    raw_body = await request.body()

    if not x_paystack_signature or not verify_paystack_signature(raw_body, x_paystack_signature):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid signature",
        )

    payload = await request.json()
    data = payload.get("data") or {}
    reference = data.get("reference")
    status_str = data.get("status")

    if not reference:
        return {"status": True}

    # Find transaction by reference
    tx = (
        db.query(Transaction)
        .filter(Transaction.reference == reference)
        .first()
    )
    if not tx:
        # Unknown reference, ignore for security
        return {"status": True}

    # Idempotency: if already success, do nothing
    if tx.status == TransactionStatus.SUCCESS:
        return {"status": True}

    tx.metadata = payload

    if status_str == "success":
        wallet = db.query(Wallet).filter(Wallet.id == tx.wallet_id).first()
        wallet.balance += tx.amount
        tx.status = TransactionStatus.SUCCESS
        db.commit()
    elif status_str in {"failed", "abandoned"}:
        tx.status = TransactionStatus.FAILED
        db.commit()
    else:
        db.commit()

    return {"status": True}
@router.get("/deposit/{reference}/status", response_model=DepositStatusResponse)
async def get_deposit_status(
    reference: str,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    require_permission(principal, "read")

    wallet = get_or_create_wallet(db, principal.user_id)

    tx = (
        db.query(Transaction)
        .filter(
            Transaction.reference == reference,
            Transaction.wallet_id == wallet.id,
            Transaction.type == TransactionType.DEPOSIT,
        )
        .first()
    )
    if not tx:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deposit not found",
        )

    return DepositStatusResponse(
        reference=tx.reference,
        status=tx.status.value,
        amount=tx.amount,
    )


@router.post("/transfer", response_model=TransferResponse)
async def transfer(
    body: TransferRequest,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    require_permission(principal, "transfer")

    if body.amount <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Amount must be positive",
        )

    sender_wallet = get_or_create_wallet(db, principal.user_id)

    if sender_wallet.wallet_number == body.wallet_number:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot transfer to same wallet",
        )

    recipient_wallet = (
        db.query(Wallet)
        .filter(Wallet.wallet_number == body.wallet_number)
        .first()
    )
    if not recipient_wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient wallet not found",
        )

    # Atomic transfer (simple version)
    if sender_wallet.balance < body.amount:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Insufficient balance",
        )

    sender_wallet.balance -= body.amount
    recipient_wallet.balance += body.amount

    out_tx = Transaction(
        wallet_id=sender_wallet.id,
        type=TransactionType.TRANSFER_OUT,
        status=TransactionStatus.SUCCESS,
        amount=body.amount,
        reference=f"tr_out_{uuid4().hex}",
        counterparty_wallet_id=recipient_wallet.id,
    )
    in_tx = Transaction(
        wallet_id=recipient_wallet.id,
        type=TransactionType.TRANSFER_IN,
        status=TransactionStatus.SUCCESS,
        amount=body.amount,
        reference=f"tr_in_{uuid4().hex}",
        counterparty_wallet_id=sender_wallet.id,
    )

    db.add(out_tx)
    db.add(in_tx)
    db.commit()

    return TransferResponse(status="success", message="Transfer completed")



@router.get("/balance", response_model=BalanceResponse)
async def get_wallet_balance(
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    require_permission(principal, "read")

    wallet = get_or_create_wallet(db, principal.user_id)
    return BalanceResponse(wallet_number=wallet.wallet_number, balance=wallet.balance)


@router.get("/transactions", response_model=list[TransactionItem])
async def get_transactions(
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    require_permission(principal, "read")

    wallet = get_or_create_wallet(db, principal.user_id)

    txs = (
        db.query(Transaction)
        .filter(Transaction.wallet_id == wallet.id)
        .order_by(Transaction.created_at.desc())
        .all()
    )

    return [
        TransactionItem(
            type=tx.type.value,
            amount=tx.amount,
            status=tx.status.value,
            created_at=tx.created_at,
        )
        for tx in txs
    ]
