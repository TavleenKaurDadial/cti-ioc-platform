from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.db.session import Base, engine
from app.models import IOC
from app.api.investigation import router as investigation_router
from app.core.config import settings

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        with engine.begin() as connection:
            connection.execute(text("SELECT 1"))
            Base.metadata.create_all(bind=connection)
    except SQLAlchemyError as exc:
        logger.exception("Database connection or initialization failed during startup")
        raise RuntimeError(
            "Database initialization failed. Check DATABASE_URL and confirm PostgreSQL is running."
        ) from exc
    yield


app = FastAPI(title="CTI-Intel API", version="0.1.0", lifespan=lifespan)
frontend_origins = ["http://127.0.0.1:5173", "http://localhost:5173"]
if settings.frontend_origin and settings.frontend_origin not in frontend_origins:
    frontend_origins.append(settings.frontend_origin)
app.add_middleware(
    CORSMiddleware,
    allow_origins=frontend_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
app.include_router(investigation_router)

@app.get("/")
def root():
    return {"name": "CTI-Intel", "status": "running"}

@app.get("/health")
def health():
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError:
        logger.exception("Database health check failed")
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "api": "healthy", "database": "unavailable"},
        )

    return {"status": "healthy", "api": "healthy", "database": "healthy"}
