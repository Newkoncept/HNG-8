# models.py
from sqlalchemy import Column, String, Boolean, DateTime, func
from app.database.db import Base
from uuid import uuid4

class User(Base):
    __tablename__ = "users"

    user_id = Column(String(50), primary_key=True, index=True, default=lambda:str(uuid4()))
    provider_sub =  Column(String(50), unique=True, index=True)
    email = Column(String(50), unique=True, index=True, nullable=False)
    name = Column(String(70), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
