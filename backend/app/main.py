from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.endpoints import router as api_router
from app.api.auth_routes import router as auth_router
from app.db.database import init_db

app = FastAPI(
    title="CyberPilot API",
    description="Agentic AI Platform for Autonomous Security Assessment",
    version="1.0.0"
)

# CORS middleware for frontend integration
# Allowlisted origins — extend via APP_CORS_ORIGINS env var (comma-separated)
import os as _os
_raw_origins = _os.environ.get("APP_CORS_ORIGINS", 
    "http://localhost:5173,http://localhost:5174,http://localhost:5175,"
    "http://127.0.0.1:5173,http://127.0.0.1:5174,http://127.0.0.1:5175,"
    "http://localhost:3000,http://127.0.0.1:3000"
)
_ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    await init_db()

app.include_router(api_router, prefix="/api/v1")
app.include_router(auth_router, prefix="/api/v1")

@app.get("/")
def read_root():
    return {"message": "Welcome to the CyberPilot API Gateway"}
