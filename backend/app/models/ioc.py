from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from app.db.session import Base

class IOC(Base):
    __tablename__ = "ioc"

    id = Column(Integer, primary_key=True, index=True)
    value = Column(String(512), unique=True, nullable=False, index=True)
    type = Column(String(32), nullable=False)
    reputation = Column(String(32), default="Unknown")
    risk_score = Column(Float, default=0)
    confidence = Column(Float, default=0)
    country = Column(String(128))
    asn = Column(String(128))
    organization = Column(String(256))
    ai_summary = Column(Text)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
