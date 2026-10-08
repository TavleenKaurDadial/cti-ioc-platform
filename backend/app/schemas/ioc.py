from pydantic import BaseModel, Field
from typing import Literal, Any
from datetime import datetime

IOCType = Literal["ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256"]

class IOCInvestigationRequest(BaseModel):
    value: str = Field(min_length=3, max_length=512)

class IOCResponse(BaseModel):
    id: int
    value: str
    type: str
    reputation: str
    risk_score: float
    confidence: float
    country: str | None = None
    asn: str | None = None
    organization: str | None = None
    ai_summary: str | None = None
    created_at: datetime | None = None

    model_config = {"from_attributes": True}

class InvestigationResponse(BaseModel):
    ioc: IOCResponse
    enrichment: dict[str, Any]
    correlations: dict[str, Any]
    analysis: dict[str, Any]
