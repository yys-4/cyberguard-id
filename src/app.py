"""
CyberGuard-ID — FastAPI entrypoint.

Phase 1 hardening applied:
  1.1  CORS: env-driven allow_origins, allow_credentials=False
  1.5  Rate limiting: slowapi, 30/min on /predict-v2, 60/min on /predict
  1.6  Input length guards: max_length on all user-supplied fields
  1.7  Structured JSON logging via python-json-logger (Log Analytics-friendly)
Phase 2 additions:
  2.1  Application Insights: opencensus FastAPI middleware (graceful fallback)
  2.2  blob_storage passed into HybridThreatAnalyzer for Blob-backed calibrator
  2.3  GET /health/drift endpoint with bearer-token auth
  2.4  model_version surfaced in /health/ready
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from pythonjsonlogger import jsonlogger
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from src.drift_monitor import DriftMonitor
from src.inference_engine import HybridThreatAnalyzer
from src.security import BlobStorageManager, KeyVaultSecretProvider, PredictionAuditLogger, SecuritySettings

# ---------------------------------------------------------------------------
# Structured JSON logging — stdout goes to Container Apps → Log Analytics
# ---------------------------------------------------------------------------

def _configure_logging() -> logging.Logger:
    """Replace basicConfig with JSON formatter for KQL-queryable stdout logs."""
    _logger = logging.getLogger("cyberguard.api")
    _logger.setLevel(logging.INFO)

    if not _logger.handlers:
        handler = logging.StreamHandler()
        formatter = jsonlogger.JsonFormatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
        handler.setFormatter(formatter)
        _logger.addHandler(handler)
        # Prevent duplicate logs from root logger propagation
        _logger.propagate = False

    return _logger


logger = _configure_logging()

# ---------------------------------------------------------------------------
# Rate limiter (slowapi — in-process, no Redis needed for scale-to-zero)
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address)

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CyberGuard-ID Phishing Detection API",
    description="API untuk mendeteksi apakah suatu pesan teks (SMS/WA/Email) merupakan Phishing atau Aman.",
    version="1.1.0",
)

# Phase 1.5 — attach slowapi state and exception handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ---------------------------------------------------------------------------
# CORS — Phase 1.1: env-driven origins, no wildcard with credentials
# ---------------------------------------------------------------------------

_raw_origins = os.getenv("CORS_ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS: List[str] = (
    [o.strip() for o in _raw_origins.split(",") if o.strip()]
    or ["http://localhost:5173"]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,  # wildcard + credentials is a browser-spec violation
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type"],
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

# ---------------------------------------------------------------------------
# Security / Azure bootstrap
# ---------------------------------------------------------------------------

security_settings = SecuritySettings.from_env()
secret_provider = KeyVaultSecretProvider.from_settings(security_settings, logger=logger)
loaded_secret_bindings = secret_provider.load_environment_secrets(security_settings.key_vault_secret_env_map)

if loaded_secret_bindings:
    logger.info(
        "Loaded %d runtime secret(s) from Key Vault into process environment.",
        len(loaded_secret_bindings),
    )

blob_storage = BlobStorageManager.from_settings(
    security_settings,
    secret_provider=secret_provider,
    logger=logger,
)
prediction_audit_logger = PredictionAuditLogger(
    settings=security_settings,
    blob_storage=blob_storage,
    logger=logger,
)

# ---------------------------------------------------------------------------
# Model & inference engine
# ---------------------------------------------------------------------------

MODEL_PATH = os.getenv("MODEL_PATH", os.path.join("models", "xgboost_no_platform.joblib"))
model = joblib.load(MODEL_PATH)
# Phase 2.2: pass blob_storage so calibrator can sync from Blob on cold start
hybrid_analyzer = HybridThreatAnalyzer(MODEL_PATH, logger=logger, blob_storage=blob_storage)

# ---------------------------------------------------------------------------
# Phase 2.1 — Application Insights (opencensus) — graceful fallback if not configured
# ---------------------------------------------------------------------------

_appinsights_connstr = os.getenv("APPLICATIONINSIGHTS_CONNECTION_STRING", "")
if _appinsights_connstr:
    try:
        from opencensus.ext.azure import metrics_exporter
        from opencensus.ext.azure.log_exporter import AzureLogHandler
        from opencensus.ext.azure.trace_exporter import AzureExporter
        from opencensus.ext.fastapi.fastapi_middleware import FastAPIMiddleware
        from opencensus.trace.samplers import ProbabilitySampler

        app.add_middleware(
            FastAPIMiddleware,
            exporter=AzureExporter(connection_string=_appinsights_connstr),
            sampler=ProbabilitySampler(1.0),
        )
        _az_handler = AzureLogHandler(connection_string=_appinsights_connstr)
        logging.getLogger("cyberguard.api").addHandler(_az_handler)
        logger.info("Application Insights telemetry active.")
    except Exception as _ai_exc:  # pragma: no cover — only active in Azure
        logger.warning("Application Insights middleware could not be loaded: %s", _ai_exc)
else:
    logger.info("APPLICATIONINSIGHTS_CONNECTION_STRING not set — App Insights disabled (local dev mode).")

# ---------------------------------------------------------------------------
# Phase 2.3 — Drift monitor
# ---------------------------------------------------------------------------

_drift_monitor = DriftMonitor(
    blob_storage=blob_storage,
    logs_prefix=os.getenv("BLOB_LOGS_PREFIX", "logs") + "/predictions",
    logger=logger,
)
_drift_bearer_token = os.getenv("DRIFT_MONITOR_BEARER_TOKEN", "")

# ---------------------------------------------------------------------------
# Phase 2.4 — Model metadata (version surfaced in /health/ready)
# ---------------------------------------------------------------------------

_model_metadata: Dict[str, Any] = {}
_metadata_path = os.path.join("models", "model_metadata.json")
if os.path.exists(_metadata_path):
    try:
        with open(_metadata_path, encoding="utf-8") as _f:
            _model_metadata = json.load(_f)
    except Exception as _meta_exc:
        logger.warning("Could not load model_metadata.json: %s", _meta_exc)

# ---------------------------------------------------------------------------
# Static files (legacy — Phase 3.1 will remove this)
# ---------------------------------------------------------------------------

if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# ---------------------------------------------------------------------------
# Pydantic models — Phase 1.6: input length guards
# ---------------------------------------------------------------------------


class PredictionRequest(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="Teks pesan yang ingin diuji (tidak boleh kosong, maks 5000 karakter)",
    )


class PredictionResponse(BaseModel):
    is_phishing: bool
    confidence: float
    message: str
    reasoning: List[str] = []
    mitigation_tip: str = ""


class PredictionRequestV2(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="Teks pesan yang ingin diuji (tidak boleh kosong, maks 5000 karakter)",
    )
    source: Optional[str] = Field(
        default=None,
        max_length=50,
        description="Sumber pesan opsional untuk konteks (contoh: SMS, WhatsApp, Email)",
    )
    sensitivity: Optional[str] = Field(
        default=None,
        max_length=20,
        description="Sensitivitas kebijakan threshold: low, balanced, high, atau auto (berbasis kanal)",
    )


class TopContributor(BaseModel):
    feature: str
    raw_feature: str
    contribution: float
    impact: str
    value: float


class CalibrationInfo(BaseModel):
    applied: bool
    method: str
    raw_probability: float
    calibrated_probability: float
    channel_adjusted_probability: float


class ThresholdPolicyInfo(BaseModel):
    sensitivity: str
    mode: str
    channel: str
    base_threshold: float
    channel_offset: float
    decision_threshold: float
    uncertainty_margin: float


class ChannelAnalysisInfo(BaseModel):
    channel: str
    token_count: int
    expected_token_mean: float
    expected_token_std: float
    token_z_score: float
    baseline_link_rate: float
    baseline_urgency_rate: float
    channel_sample_size: int
    prior_global: float
    prior_channel: float
    prior_adjustment_applied: bool
    prior_odds_ratio: float
    prior_min_sample: int
    prior_smoothing: float
    smoothed_prior_channel: float
    channel_prior_weight: float


class PredictionResponseV2(BaseModel):
    is_phishing: bool
    confidence: float = Field(..., description="Probabilitas ancaman phishing dalam persen (0-100)")
    message: str
    reasoning: List[str] = Field(default_factory=list)
    mitigation_tip: str = ""
    xai_method: str
    top_contributors: List[TopContributor] = Field(default_factory=list)
    uncertainty_flag: bool
    calibration: CalibrationInfo
    threshold_policy: ThresholdPolicyInfo
    channel_analysis: ChannelAnalysisInfo


# ---------------------------------------------------------------------------
# Phase 3.3 — LRU cache for deterministic inference (saves redundant SHAP compute)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=512)
def _cached_analyze(text: str, source: Optional[str], sensitivity: Optional[str]) -> str:
    """
    Cache key: (text, source, sensitivity) — all deterministic inputs.
    Returns JSON-serialisable dict as a frozen string; caller re-parses.
    We cache the raw dict repr because lru_cache requires hashable return types.
    """
    import json
    result = hybrid_analyzer.analyze_text(text, source=source, sensitivity=sensitivity, top_k=5)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def extract_features(text: str) -> Dict[str, List[Any]]:
    """Legacy feature extractor used only by the /predict (v1) endpoint."""
    text_lower = text.lower()

    dangerous_domains = ["http", "www", "bit.ly", ".com", ".id", ".xyz", ".info", ".net", ".org", "wa.me"]
    has_link = 1 if any(domain in text_lower for domain in dangerous_domains) else 0

    urgency_keywords = ["segera", "hari ini", "batas waktu", "kadaluarsa", "blokir", "dihapus", "menang", "selamat", "diblokir"]
    has_urgency = 1 if any(kw in text_lower for kw in urgency_keywords) else 0

    return {
        "processed_text": [text],
        "has_dangerous_link": [has_link],
        "contains_urgency": [has_urgency],
    }


def audit_prediction_event(
    endpoint: str,
    text: str,
    source: Optional[str],
    is_phishing: bool,
    confidence: float,
    xai_method: Optional[str],
) -> None:
    try:
        prediction_audit_logger.log_prediction(
            endpoint=endpoint,
            text=text,
            source=source,
            is_phishing=is_phishing,
            confidence=confidence,
            xai_method=xai_method,
        )
    except Exception as exc:  # pragma: no cover — defensive guard
        logger.warning("Prediction audit logging failed: %s", exc)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/")
def read_root() -> Dict[str, str]:
    return {"message": "Welcome to CyberGuard-ID Phishing Detection API"}


@app.get("/dashboard")
def serve_dashboard() -> FileResponse:
    dashboard_file = os.path.join(STATIC_DIR, "dashboard.html")
    if not os.path.exists(dashboard_file):
        raise HTTPException(status_code=404, detail="Dashboard tidak ditemukan.")
    return FileResponse(dashboard_file)


@app.post("/predict", response_model=PredictionResponse)
@limiter.limit("60/minute")
def predict_phishing(request: PredictionRequest, http_request: Request) -> PredictionResponse:  # noqa: ARG001
    if not request.text or not request.text.strip():
        raise HTTPException(status_code=400, detail="Input teks tidak valid. Pesan tidak boleh hanya berisi whitespace.")

    features = extract_features(request.text)
    df_features = pd.DataFrame(features)

    prediction = model.predict(df_features)[0]
    probabilities = model.predict_proba(df_features)[0]

    confidence = float(probabilities[1]) if prediction == 1 else float(probabilities[0])

    is_phishing = bool(prediction == 1)
    message = "Pesan ini terdeteksi sebagai PHISHING." if is_phishing else "Pesan ini terdeteksi AMAN."

    reasoning: List[str] = []
    mitigation_tip = "Tetap waspada dan jangan pernah membagikan OTP atau mengklik tautan dari pengirim yang tidak dikenal."

    if is_phishing:
        text_lower = request.text.lower()
        if ".apk" in text_lower:
            reasoning.append("Ditemukan tautan aplikasi (.apk) yang berpotensi bahaya.")
            mitigation_tip = "Jangan pernah mengunduh atau menginstal file .apk dari sumber yang tidak resmi untuk mencegah infeksi malware."
        elif features["has_dangerous_link"][0] == 1:
            reasoning.append("Ditemukan tautan yang mencurigakan atau berbahaya.")
            mitigation_tip = "Hindari mengklik tautan dari pengirim yang tidak Anda kenal. Lakukan verifikasi terlebih dahulu jika ragu."

        if features["contains_urgency"][0] == 1:
            reasoning.append("Menggunakan kata-kata yang mendesak atau menuntut korban untuk bertindak cepat.")
            if ".apk" not in text_lower:
                mitigation_tip = "Penipu sering menggunakan taktik desakan agar Anda panik. Selalu tenang dan verifikasi informasi melalui kontak resmi."
    else:
        mitigation_tip = "Pesan terlihat aman, namun tetaplah waspada dan jangan berikan informasi pribadi jika tidak diperlukan."

    confidence_percent = round(confidence * 100, 2)

    audit_prediction_event(
        endpoint="/predict",
        text=request.text,
        source=None,
        is_phishing=is_phishing,
        confidence=confidence_percent,
        xai_method="model_probability",
    )

    if is_phishing:
        logger.info("PHISHING DETECTED | Confidence: %.2f | Text: %s", confidence_percent, request.text.strip())

    return PredictionResponse(
        is_phishing=is_phishing,
        confidence=confidence_percent,
        message=message,
        reasoning=reasoning,
        mitigation_tip=mitigation_tip,
    )


@app.post("/predict-v2", response_model=PredictionResponseV2)
@limiter.limit("30/minute")
def predict_phishing_v2(request: PredictionRequestV2, http_request: Request) -> PredictionResponseV2:  # noqa: ARG001
    if not request.text or not request.text.strip():
        raise HTTPException(status_code=400, detail="Input teks tidak valid. Pesan tidak boleh hanya berisi whitespace.")

    import json

    text_clean = request.text.strip()
    try:
        result_json = _cached_analyze(text_clean, request.source, request.sensitivity)
        result: Dict[str, Any] = json.loads(result_json)
    except Exception as exc:
        logger.exception("Analisis /predict-v2 gagal: %s", exc)
        raise HTTPException(status_code=500, detail="Terjadi kegagalan internal saat menganalisis pesan.") from exc

    audit_prediction_event(
        endpoint="/predict-v2",
        text=request.text,
        source=request.source,
        is_phishing=result["is_phishing"],
        confidence=result["confidence"],
        xai_method=result["xai_method"],
    )

    if result["is_phishing"]:
        logger.info(
            "PHISHING DETECTED V2 | ThreatProb: %.2f | XAI: %s | Text: %s",
            result["confidence"],
            result["xai_method"],
            text_clean[:500],
        )

    return PredictionResponseV2(
        is_phishing=result["is_phishing"],
        confidence=result["confidence"],
        message=result["message"],
        reasoning=result["reasoning"],
        mitigation_tip=result["mitigation_tip"],
        xai_method=result["xai_method"],
        top_contributors=result["top_contributors"],
        uncertainty_flag=result["uncertainty_flag"],
        calibration=result["calibration"],
        threshold_policy=result["threshold_policy"],
        channel_analysis=result["channel_analysis"],
    )


@app.get("/health/live")
def health_live() -> Dict[str, str]:
    return {"status": "ok", "service": "cyberguard-id"}


@app.get("/health/ready")
def health_ready() -> Dict[str, Any]:
    status = hybrid_analyzer.get_runtime_status()
    if not status.get("model_loaded", False):
        raise HTTPException(status_code=503, detail={"status": "not_ready", "checks": status})
    # Phase 2.4: surface model version from model_metadata.json
    response: Dict[str, Any] = {"status": "ready", "checks": status}
    if _model_metadata:
        response["model_version"] = _model_metadata.get("model_version", "unknown")
        response["model_trained_at"] = _model_metadata.get("trained_at", "unknown")
    return response


@app.get("/health/drift")
def health_drift(http_request: Request) -> Dict[str, Any]:
    """Phase 2.3 — Model drift stats (bearer-token protected)."""
    if _drift_bearer_token:
        auth_header = http_request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer ") or auth_header[7:] != _drift_bearer_token:
            raise HTTPException(status_code=401, detail="Invalid or missing bearer token.")
    return _drift_monitor.compute()
