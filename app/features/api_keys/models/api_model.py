from sqlalchemy import Column, String, Boolean, DateTime, func, ForeignKey, Enum, JSON, CheckConstraint
from app.database.db import Base
from uuid import uuid4

ALLOWED_PERMS = {"deposit", "transfer", "read"}

class ApiKey(Base):
    __tablename__ = "api_keys"

    api_key = Column(String(200), primary_key=True, index=True) 
    public_api_id = Column(String(50), unique=True, index=True, default=lambda: str(uuid4()))
    user_id = Column(String(50), ForeignKey("users.user_id"), index=True, nullable=False)
    masked_key = Column(String(50), index=True, nullable=False)
    name = Column(String(100), nullable=False)
    permissions = Column(JSON, nullable=False)
    is_revoked = Column(Boolean, default=False, nullable=False)
    expires_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __table_args__ = (
        # basic length check that most DBs support; enforces 1–3 items
        CheckConstraint("json_array_length(permissions) BETWEEN 1 AND 3", name="ck_api_permissions_len"),
    )
