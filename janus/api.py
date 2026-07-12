"""FastAPI backend for Janus.

Exposes the correlation engine, fused alerts, quantum-risk posture, per-session
explainability and the PQC artifact-vault demo. Also serves the static
dashboard.

NOTE: This prototype API is unauthenticated for demo simplicity. In production
it MUST sit behind authentication (OIDC/mTLS), RBAC and network controls — see
the Security Considerations section of the README.
"""

from __future__ import annotations

import json
import math
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from . import __version__, config, pipeline, pqc

# ---------------------------------------------------------------------------
# Security configuration
# ---------------------------------------------------------------------------
# API key required on all /api/* routes (except health). Defaults to a well-known
# prototype key; override via the JANUS_API_KEY environment variable in any real
# deployment.
API_KEY = os.getenv("JANUS_API_KEY", "demo-key-finspark-2026")
API_KEY_HEADER = "X-API-Key"
AUDIT_LOG_PATH = config.BASE_DIR / "audit.log"

# Paths that never require an API key.
_AUTH_EXEMPT_EXACT = {"/", "/api/health"}
_AUTH_EXEMPT_PREFIXES = ("/static",)


def _is_api_path(path: str) -> bool:
    return path.startswith("/api")


def _auth_required(request: Request) -> bool:
    """True when the request must carry a valid API key."""
    if request.method == "OPTIONS":  # allow CORS preflight
        return False
    path = request.url.path
    if path in _AUTH_EXEMPT_EXACT:
        return False
    if any(path.startswith(p) for p in _AUTH_EXEMPT_PREFIXES):
        return False
    return _is_api_path(path)


@asynccontextmanager
async def lifespan(app: FastAPI):
    pipeline.run()  # warm the cache so the first request is fast
    yield


app = FastAPI(
    title="Janus — Quantum-Aware Cyber-Fraud Fusion",
    version=__version__,
    description="Correlates cybersecurity telemetry with transactional behaviour, "
                "monitors quantum (HNDL) risk, and protects artefacts with PQC.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Rate limiting (slowapi): 60 requests / minute per client IP on /api/* routes.
# ---------------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


class ApiRateLimitMiddleware(SlowAPIMiddleware):
    """Applies the global rate limit only to /api/* routes (excluding health)."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if (
            request.method == "OPTIONS"
            or not _is_api_path(path)
            or path == "/api/health"
        ):
            return await call_next(request)
        return await super().dispatch(request, call_next)


async def _api_key_middleware(request: Request, call_next):
    """Reject /api/* requests that lack a valid X-API-Key header."""
    if _auth_required(request) and request.headers.get(API_KEY_HEADER) != API_KEY:
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid or missing API key"},
        )
    return await call_next(request)


async def _audit_middleware(request: Request, call_next):
    """Append a JSON line to audit.log for every /api request."""
    response = await call_next(request)
    if _is_api_path(request.url.path):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": request.method,
            "path": request.url.path,
            "ip": get_remote_address(request),
            "api_key_used": request.headers.get(API_KEY_HEADER) == API_KEY,
            "status_code": response.status_code,
        }
        try:
            with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError:
            pass  # never let audit logging break a response
    return response


# Middleware execution order (outermost first): audit -> api-key -> rate-limit
# -> CORS -> route. Added last = outermost, so audit wraps everything and always
# records the final status code (including 401 auth and 429 rate-limit rejects).
app.add_middleware(ApiRateLimitMiddleware)
app.add_middleware(BaseHTTPMiddleware, dispatch=_api_key_middleware)
app.add_middleware(BaseHTTPMiddleware, dispatch=_audit_middleware)


def _clean(obj):
    """Recursively replace NaN/inf so the response is valid JSON."""
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else None
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    return obj


@app.get("/api/health")
def health():
    return {"status": "ok", "version": __version__}


@app.get("/api/summary")
def summary():
    """Headline KPIs for the dashboard hero row."""
    st = pipeline.get_state()
    fused = st.metrics["fused"]
    return _clean({
        "total_sessions": st.metrics["total_sessions"],
        "true_threats": st.metrics["true_threats"],
        "alerts_actioned": fused["true_positives"] + fused["false_positives"],
        "precision": fused["precision"],
        "recall": fused["recall"],
        "f1": fused["f1"],
        "false_positives": fused["false_positives"],
        "false_positive_reduction_pct": st.metrics[
            "false_positive_reduction_pct_vs_best_single_signal"],
        "pqc_readiness_pct": st.quantum_summary["pqc_readiness_pct"],
        "high_hndl_exposure_sessions": st.quantum_summary["high_hndl_exposure_sessions"],
    })


@app.get("/api/metrics")
def metrics():
    """Full detection metrics incl. single-signal vs fused comparison."""
    return _clean(pipeline.get_state().metrics)


@app.get("/api/alerts")
def alerts(
    limit: int = Query(50, ge=1, le=800),
    min_score: float = Query(0.0, ge=0, le=100),
    threat_type: Optional[str] = None,
    band: Optional[str] = None,
):
    """List fused, explainable alerts, filterable and sorted by fused risk."""
    st = pipeline.get_state()
    df = st.alerts
    df = df[df["fused_score"] >= min_score]
    if threat_type:
        df = df[df["threat_type"] == threat_type]
    if band:
        df = df[df["risk_band"] == band.upper()]
    rows = df.head(limit).to_dict(orient="records")
    return _clean({"count": len(rows), "alerts": rows})


@app.get("/api/alerts/{session_id}")
def alert_detail(session_id: str):
    """Full case file for a single session (scores, reasons, narrative)."""
    st = pipeline.get_state()
    match = st.alerts[st.alerts["session_id"] == session_id]
    if match.empty:
        raise HTTPException(status_code=404, detail="session not found")
    alert = match.iloc[0].to_dict()

    # attach the raw correlated evidence (telemetry + transactions)
    sess = st.sessions[st.sessions["session_id"] == session_id].to_dict(orient="records")
    txns = st.transactions[st.transactions["session_id"] == session_id].to_dict(orient="records")
    return _clean({"alert": alert, "telemetry": sess[0] if sess else {}, "transactions": txns})


@app.get("/api/quantum")
def quantum():
    """Quantum / HNDL portfolio posture for the radar view."""
    st = pipeline.get_state()
    top = st.alerts[st.alerts["quantum_score"] >= 60].sort_values(
        "quantum_score", ascending=False).head(10)
    return _clean({
        "summary": st.quantum_summary,
        "pqc_module": pqc.status(),
        "top_exposed_sessions": top[[
            "session_id", "user_id", "quantum_score", "quantum_posture",
            "quantum_reasons"]].to_dict(orient="records"),
    })


@app.get("/api/threat-breakdown")
def threat_breakdown():
    """Counts of actioned alerts by threat type (for the donut chart)."""
    st = pipeline.get_state()
    actioned = st.alerts[st.alerts["fused_score"] >= pipeline.HIGH_RISK_THRESHOLD]
    return _clean(actioned["threat_type"].value_counts().to_dict())


@app.post("/api/protect-top-case")
def protect_top_case():
    """Demo: seal the highest-risk case file in the PQC artifact vault."""
    return _clean(pipeline.demo_protect_top_case())


@app.post("/api/reload")
def reload(seed: int = Query(config.DEFAULT_SEED)):
    """Re-run the pipeline (e.g. with a new seed) for live demos."""
    st = pipeline.run(seed=seed)
    return {"status": "reloaded", "sessions": len(st.sessions), "seed": seed}


# ---- static dashboard ----
app.mount("/static", StaticFiles(directory=str(config.STATIC_DIR)), name="static")


@app.get("/")
def index():
    return FileResponse(str(config.STATIC_DIR / "index.html"))
