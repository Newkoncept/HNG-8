from uuid import uuid4
from sqlalchemy import Column, Integer, String, ForeignKey
from app.database.db import Base

class Wallet(Base):
    __tablename__ = "wallets"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(50), ForeignKey("users.user_id"), unique=True, nullable=False)
    wallet_number = Column(String, unique=True, index=True, nullable=False)
    balance = Column(Integer, nullable=False, default=0) 