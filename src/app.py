from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import List, Optional
import joblib
import pandas as pd
import os
import logging

from src.inference_engine import HybridThreatAnalyzer
from src.security import BlobStorageManager, KeyVaultSecretProvider, PredictionAuditLogger, SecuritySettings

app = FastAPI(
    title="CyberGuard-ID Phishing Detection API",
    description="API untuk mendeteksi apakah suatu pesan teks (SMS/WA/Email) merupakan Phishing atau Aman.",
    version="1.0.0"
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(message)s"
)

logger = logging.getLogger("cyberguard.api")

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

MODEL_PATH = os.getenv("MODEL_PATH", os.path.join("models", "xgboost_no_platform.joblib"))
model = joblib.load(MODEL_PATH)
hybrid_analyzer = HybridThreatAnalyzer(MODEL_PATH, logger=logger)

if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

class PredictionRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Teks pesan yang ingin diuji (tidak boleh kosong)")

class PredictionResponse(BaseModel):
    is_phishing: bool
    confidence: float
    message: str
    reasoning: List[str] = []
    mitigation_tip: str = ""


class PredictionRequestV2(BaseModel):
    text: str = Field(..., min_length=1, description="Teks pesan yang ingin diuji (tidak boleh kosong)")
    source: Optional[str] = Field(
        default=None,
        description="Sumber pesan opsional untuk konteks (contoh: SMS, WhatsApp, Email)",
    )
    sensitivity: Optional[str] = Field(
        default=None,
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


def extract_features(text: str):
    text_lower = text.lower()

    dangerous_domains = ['http', 'www', 'bit.ly', '.com', '.id', '.xyz', '.info', '.net', '.org', 'wa.me']
    has_link = 1 if any(domain in text_lower for domain in dangerous_domains) else 0

    urgency_keywords = ['segera', 'hari ini', 'batas waktu', 'kadaluarsa', 'blokir', 'dihapus', 'menang', 'selamat', 'diblokir']
    has_urgency = 1 if any(kw in text_lower for kw in urgency_keywords) else 0

    return {
        "processed_text": [text],
        "has_dangerous_link": [has_link],
        "contains_urgency": [has_urgency]
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
    except Exception as exc:  # pragma: no cover - defensive guard
        logger.warning("Prediction audit logging failed: %s", exc)

@app.get("/")
def read_root():
    return {"message": "Welcome to CyberGuard-ID Phishing Detection API"}


@app.get("/dashboard")
def serve_dashboard():
    dashboard_file = os.path.join(STATIC_DIR, "dashboard.html")
    if not os.path.exists(dashboard_file):
        raise HTTPException(status_code=404, detail="Dashboard tidak ditemukan.")
    return FileResponse(dashboard_file)

@app.post("/predict", response_model=PredictionResponse)
def predict_phishing(request: PredictionRequest):
    if not request.text or not request.text.strip():
        raise HTTPException(status_code=400, detail="Input teks tidak valid. Pesan tidak boleh hanya berisi whitespace.")

    features = extract_features(request.text)
    df_features = pd.DataFrame(features)

    prediction = model.predict(df_features)[0]
    probabilities = model.predict_proba(df_features)[0]

    confidence = float(probabilities[1]) if prediction == 1 else float(probabilities[0])

    is_phishing = bool(prediction == 1)
    message = "Pesan ini terdeteksi sebagai PHISHING." if is_phishing else "Pesan ini terdeteksi AMAN."

    reasoning = []
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
        mitigation_tip=mitigation_tip
    )


@app.post("/predict-v2", response_model=PredictionResponseV2)
def predict_phishing_v2(request: PredictionRequestV2):
    if not request.text or not request.text.strip():
        raise HTTPException(status_code=400, detail="Input teks tidak valid. Pesan tidak boleh hanya berisi whitespace.")

    try:
        result = hybrid_analyzer.analyze_text(
            request.text.strip(),
            source=request.source,
            sensitivity=request.sensitivity,
            top_k=5,
        )
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
            request.text.strip()[:500],
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
def health_live():
    return {"status": "ok", "service": "cyberguard-id"}


@app.get("/health/ready")
def health_ready():
    status = hybrid_analyzer.get_runtime_status()
    if not status.get("model_loaded", False):
        raise HTTPException(status_code=503, detail={"status": "not_ready", "checks": status})
    return {"status": "ready", "checks": status}
