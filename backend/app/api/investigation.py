from fastapi import APIRouter, Depends, HTTPException, Query
from datetime import datetime, timezone
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.ioc import IOC
from app.schemas.ioc import IOCInvestigationRequest, IOCResponse, InvestigationResponse
from app.services.enrichment import enrich_ioc
from app.services.ai_analysis import generate_analysis
from app.services.correlation import correlate
from app.services.ioc_parser import identify_ioc, normalize_ioc
from app.services.risk import calculate_risk

router = APIRouter(prefix="/api", tags=["IOC Investigation"])


@router.get("/investigations", response_model=list[IOCResponse])
def list_investigations(
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    investigated_at = func.coalesce(IOC.last_seen, IOC.created_at)
    return db.query(IOC).order_by(desc(investigated_at), desc(IOC.id)).limit(limit).all()


@router.post("/investigate", response_model=InvestigationResponse)
def investigate(payload: IOCInvestigationRequest, db: Session = Depends(get_db)):
    try:
        value = normalize_ioc(payload.value)
        ioc_type = identify_ioc(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    enrichment = enrich_ioc(value, ioc_type)
    risk_score, confidence, factors = calculate_risk(enrichment)
    correlations = correlate(enrichment)
    analysis = generate_analysis(value, ioc_type, enrichment, risk_score, confidence, factors, correlations)

    record = db.query(IOC).filter(IOC.value == value).first()
    now = datetime.now(timezone.utc)
    if not record:
        record = IOC(value=value, type=ioc_type, first_seen=now)
        db.add(record)
    record.type = ioc_type
    record.reputation = enrichment.get("reputation", "Unknown")
    record.risk_score = risk_score
    record.confidence = confidence
    record.country = enrichment.get("country")
    record.asn = enrichment.get("asn")
    record.organization = enrichment.get("organization")
    record.ai_summary = analysis["summary"]
    record.last_seen = now
    db.commit()
    db.refresh(record)

    return {
        "ioc": record,
        "enrichment": enrichment,
        "correlations": correlations,
        "analysis": analysis,
    }
