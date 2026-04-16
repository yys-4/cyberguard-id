import pandas as pd
from fastapi.testclient import TestClient

from src.app import app, hybrid_analyzer
from src.inference_engine import extract_inference_features

client = TestClient(app)


def test_predict_v2_rejects_whitespace_input():
    response = client.post("/predict-v2", json={"text": "   "})

    assert response.status_code == 400
    assert "whitespace" in response.json()["detail"].lower()


def test_predict_v2_phishing_like_payload_schema():
    response = client.post(
        "/predict-v2",
        json={
            "text": "PERINGATAN! Akun Anda diblokir, segera verifikasi di bit.ly/cek-akun sekarang juga.",
            "source": "SMS",
        },
    )

    assert response.status_code == 200
    body = response.json()

    assert isinstance(body["is_phishing"], bool)
    assert 0.0 <= body["confidence"] <= 100.0
    assert body["xai_method"] in {"shap", "heuristic_fallback"}
    assert isinstance(body["reasoning"], list)
    assert len(body["reasoning"]) >= 1
    assert isinstance(body["top_contributors"], list)
    assert "calibration" in body
    assert "threshold_policy" in body
    assert "channel_analysis" in body
    assert 0.0 <= body["calibration"]["raw_probability"] <= 100.0
    assert 0.0 <= body["calibration"]["calibrated_probability"] <= 100.0
    assert 0.0 <= body["calibration"]["channel_adjusted_probability"] <= 100.0
    assert body["threshold_policy"]["sensitivity"] in {"low", "balanced", "high"}
    assert body["threshold_policy"]["mode"] in {"auto_channel", "user_override"}
    assert body["threshold_policy"]["channel"] in {"sms", "whatsapp", "email", "unknown"}
    assert 0.0 <= body["threshold_policy"]["decision_threshold"] <= 100.0
    assert body["channel_analysis"]["channel"] == "sms"
    assert isinstance(body["channel_analysis"]["token_count"], int)
    assert isinstance(body["channel_analysis"]["prior_min_sample"], int)
    assert isinstance(body["channel_analysis"]["prior_smoothing"], (int, float))
    assert any("sms" in item.lower() for item in body["reasoning"])


def test_predict_v2_non_phishing_like_payload_schema():
    response = client.post(
        "/predict-v2",
        json={
            "text": "Halo, meeting dipindah ke jam 3 sore di ruang utama. Terima kasih.",
            "source": "WhatsApp",
        },
    )

    assert response.status_code == 200
    body = response.json()

    assert isinstance(body["is_phishing"], bool)
    assert 0.0 <= body["confidence"] <= 100.0
    assert body["xai_method"] in {"shap", "heuristic_fallback"}
    assert isinstance(body["uncertainty_flag"], bool)
    assert isinstance(body["mitigation_tip"], str)
    assert len(body["mitigation_tip"]) > 0
    assert isinstance(body["calibration"]["applied"], bool)
    assert body["calibration"]["method"] in {"none", "platt_sigmoid"}
    assert body["threshold_policy"]["channel"] == "whatsapp"
    assert body["channel_analysis"]["channel"] == "whatsapp"


def test_predict_v2_sensitivity_changes_threshold_policy():
    payload = {
        "text": "Pemberitahuan akun, segera cek status anda sekarang.",
        "source": "SMS",
    }

    response_low = client.post("/predict-v2", json={**payload, "sensitivity": "low"})
    response_high = client.post("/predict-v2", json={**payload, "sensitivity": "high"})

    assert response_low.status_code == 200
    assert response_high.status_code == 200

    body_low = response_low.json()
    body_high = response_high.json()

    assert body_low["threshold_policy"]["sensitivity"] == "low"
    assert body_high["threshold_policy"]["sensitivity"] == "high"
    assert body_low["threshold_policy"]["mode"] == "user_override"
    assert body_high["threshold_policy"]["mode"] == "user_override"
    assert body_low["threshold_policy"]["decision_threshold"] > body_high["threshold_policy"]["decision_threshold"]


def test_predict_v2_auto_channel_policy_mode():
    response = client.post(
        "/predict-v2",
        json={
            "text": "Pesan verifikasi akun via tautan segera.",
            "source": "Email",
            "sensitivity": "auto",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["threshold_policy"]["mode"] == "auto_channel"
    assert body["threshold_policy"]["channel"] == "email"
    assert body["threshold_policy"]["sensitivity"] in {"low", "balanced", "high"}


def test_predict_v2_falls_back_when_shap_fails(monkeypatch):
    monkeypatch.setattr(hybrid_analyzer, "shap_available", True)

    def _raise_shap_error(*args, **kwargs):
        raise RuntimeError("forced shap failure for test")

    monkeypatch.setattr(hybrid_analyzer, "_explain_with_shap", _raise_shap_error)

    response = client.post(
        "/predict-v2",
        json={"text": "Klik bit.ly/cek-sekarang untuk klaim hadiah", "source": "Email"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["xai_method"] == "heuristic_fallback"
    assert len(body["reasoning"]) >= 1


def test_inference_feature_schema_matches_no_platform_model():
    payload = extract_inference_features("Ini pesan uji sederhana")
    assert list(payload.keys()) == ["processed_text", "has_dangerous_link", "contains_urgency"]

    df_features = pd.DataFrame(payload)
    prediction = hybrid_analyzer.model.predict(df_features)
    probabilities = hybrid_analyzer.model.predict_proba(df_features)

    assert len(prediction) == 1
    assert probabilities.shape[0] == 1


def test_health_endpoints_are_available():
    live = client.get("/health/live")
    ready = client.get("/health/ready")

    assert live.status_code == 200
    assert live.json()["status"] == "ok"

    assert ready.status_code == 200
    ready_body = ready.json()
    assert ready_body["status"] == "ready"
    assert ready_body["checks"]["model_loaded"] is True
    assert "channel_segmentation" in ready_body["checks"]
    assert "profiles" in ready_body["checks"]["channel_segmentation"]


def test_dashboard_route_and_static_assets_are_available():
    dashboard = client.get("/dashboard")
    asset = client.get("/static/dashboard.js")

    assert dashboard.status_code == 200
    assert "text/html" in dashboard.headers["content-type"].lower()

    assert asset.status_code == 200
    assert "javascript" in asset.headers["content-type"].lower()
