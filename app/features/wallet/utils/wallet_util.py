import hmac
import hashlib
from app.features.wallet.models.wallet_model import Wallet
from sqlalchemy.orm import Session
from uuid import uuid4

def get_or_create_wallet(db: Session, user_id: str) -> Wallet:
    wallet = db.query(Wallet).filter(Wallet.user_id == user_id).first()
    if wallet:
        return wallet
    wallet = Wallet(user_id=user_id, wallet_number=uuid4().hex, balance=0)
    db.add(wallet)
    db.commit()
    db.refresh(wallet)
    return wallet


def verify_paystack_signature(raw_body: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(
        key=secret.encode("utf-8"),
        msg=raw_body,
        digestmod=hashlib.sha512,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def generate_reference_number() -> str:
    return f"dep_{uuid4().hex}"