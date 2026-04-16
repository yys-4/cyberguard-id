# CyberGuard-ID

CyberGuard-ID adalah platform deteksi phishing berbahasa Indonesia berbasis FastAPI + XGBoost dengan output yang bisa dijelaskan (Explainable AI).

Fokus utamanya bukan hanya akurasi deteksi, tetapi juga keputusan yang bisa diaudit: skor risiko, alasan prediksi, konteks kanal, dan kebijakan sensitivitas yang dapat dikendalikan.

## Kenapa CyberGuard-ID

- **Deteksi real-time** untuk SMS, WhatsApp, dan Email.
- **Explainable AI** dengan SHAP + fallback heuristik agar hasil tidak black-box.
- **Channel-aware scoring** untuk menangkap perbedaan pola bahasa tiap kanal.
- **Dynamic threshold policy** untuk mengontrol tradeoff false positive vs detection rate.
- **Siap integrasi** melalui REST API, dashboard interaktif, health endpoints, dan Docker.

## Highlight Fitur

### 1) Intelligent Inference Engine

- Prediksi phishing/non-phishing dengan skor confidence.
- Confidence calibration (Platt sigmoid) untuk probabilitas yang lebih stabil.
- Penyesuaian prior berbasis kanal untuk konteks lokal Indonesia.

### 2) Explainable AI

- Top contributors dari SHAP untuk transparansi fitur yang paling berpengaruh.
- Reasoning kontekstual kanal, contoh:
  - "Link ini sangat tidak lazim ditemukan di protokol SMS (...)".

### 3) Thresholding yang Bisa Diatur

- `low`: lebih konservatif, cocok saat target utama menekan false positive.
- `balanced`: mode default yang seimbang.
- `high`: lebih agresif mendeteksi ancaman.
- `auto`: sistem memilih sensitivitas berdasarkan kanal.

### 4) Developer Experience

- Swagger docs langsung aktif.
- Health endpoints untuk liveness/readiness.
- Script dev stack untuk menjalankan backend + frontend tanpa bentrok port.

## Arsitektur Singkat

1. Input teks masuk via `POST /predict-v2`.
2. Engine melakukan preprocessing dan ekstraksi fitur.
3. Model XGBoost menghasilkan probabilitas risiko.
4. Confidence dikalibrasi, lalu disesuaikan dengan konteks kanal.
5. Decision threshold diterapkan sesuai sensitivity policy.
6. API mengembalikan label, confidence, reasoning, dan metadata kebijakan.

## Quick Start

### Prasyarat

- Python 3.9+
- Node.js 22.12+ (untuk frontend dashboard)
- npm

### Instalasi Backend

```bash
pip install -r requirements.txt
```

### Jalankan Backend (Local)

```bash
uvicorn src.app:app --reload
```

Endpoint utama:

- API base: `http://localhost:8000`
- Swagger: `http://localhost:8000/docs`
- Dashboard server-side: `http://localhost:8000/dashboard`

## Frontend Dashboard (React + Vite)

Jika tim ingin iterasi UI terpisah dari FastAPI:

```bash
cd frontend-dashboard
npm install
cp .env.example .env
npm run dev
```

Frontend aktif di `http://localhost:5173`.

Catatan:

- Pastikan backend aktif di `http://localhost:8000`.
- Set `VITE_API_BASE_URL` di file `.env` frontend.

## Dev Workflow Tanpa Bentrok Port

### Jalankan Backend + Frontend Sekaligus

```bash
bash scripts/dev-stack.sh
```

Script ini otomatis:

- memakai backend yang sudah aktif jika sehat,
- mencari port kosong bila `8000` atau `5173` sedang terpakai,
- menyinkronkan `VITE_API_BASE_URL` untuk frontend.

### Smoke Test End-to-End

```bash
bash scripts/smoke-e2e.sh
```

Verifikasi yang dijalankan:

- backend health endpoint responsif,
- frontend dev server responsif,
- alur frontend ke `POST /predict-v2` berjalan dengan schema valid.

## API Reference

### Legacy Endpoint

- `POST /predict`

Dipertahankan untuk backward compatibility.

### Intelligent Endpoint (Recommended)

- `POST /predict-v2`

Request body:

```json
{
  "text": "PERINGATAN! Akun Anda diblokir, segera verifikasi di bit.ly/cek-akun sekarang juga.",
  "source": "SMS",
  "sensitivity": "auto"
}
```

Parameter:

- `text` (required): pesan yang dianalisis.
- `source` (optional): kanal sumber (`SMS`, `WhatsApp`, `Email`).
- `sensitivity` (optional): `low | balanced | high | auto`.

Contoh response:

```json
{
  "is_phishing": true,
  "confidence": 96.42,
  "message": "Pesan ini terdeteksi berisiko PHISHING.",
  "reasoning": [
    "Indikator tautan berbahaya meningkatkan skor risiko pesan ini.",
    "Indikator bahasa mendesak meningkatkan skor risiko pesan ini.",
    "Link ini sangat tidak lazim ditemukan di protokol SMS (...)"
  ],
  "mitigation_tip": "Jangan klik tautan yang dikirim pengirim tidak dikenal. Verifikasi lewat kanal resmi terlebih dahulu.",
  "xai_method": "shap",
  "top_contributors": [
    {
      "feature": "indikator tautan berbahaya",
      "raw_feature": "num__has_dangerous_link",
      "contribution": 0.812345,
      "impact": "increase_risk",
      "value": 1.0
    }
  ],
  "uncertainty_flag": false,
  "calibration": {
    "applied": true,
    "method": "platt_sigmoid",
    "raw_probability": 94.87,
    "calibrated_probability": 96.42,
    "channel_adjusted_probability": 97.10
  },
  "threshold_policy": {
    "sensitivity": "balanced",
    "mode": "auto_channel",
    "channel": "sms",
    "base_threshold": 60.0,
    "channel_offset": 0.0,
    "decision_threshold": 60.0,
    "uncertainty_margin": 5.0
  },
  "channel_analysis": {
    "channel": "sms",
    "token_count": 14,
    "expected_token_mean": 16.2,
    "expected_token_std": 7.9,
    "token_z_score": -0.278,
    "baseline_link_rate": 21.7,
    "baseline_urgency_rate": 18.4,
    "channel_sample_size": 3520,
    "prior_global": 51.2,
    "prior_channel": 57.9,
    "prior_adjustment_applied": true,
    "prior_odds_ratio": 1.31,
    "prior_min_sample": 200,
    "prior_smoothing": 200.0,
    "smoothed_prior_channel": 55.1,
    "channel_prior_weight": 1.0
  }
}
```

## Health Endpoints

- `GET /health/live` → liveness probe.
- `GET /health/ready` → readiness probe + runtime checks.

Contoh:

```bash
curl -X GET http://localhost:8000/health/live
curl -X GET http://localhost:8000/health/ready
```

## Quick API Smoke Test

Phishing-like:

```bash
curl -X POST http://localhost:8000/predict-v2 \
  -H "Content-Type: application/json" \
  -d '{"text":"PERINGATAN! Akun diblokir, verifikasi di bit.ly/cek sekarang","source":"SMS","sensitivity":"high"}'
```

Non-phishing-like:

```bash
curl -X POST http://localhost:8000/predict-v2 \
  -H "Content-Type: application/json" \
  -d '{"text":"Halo, rapat dipindah ke jam 15.00 di ruang utama","source":"WhatsApp","sensitivity":"low"}'
```

## Menjalankan dengan Docker Compose

```bash
docker compose up --build
```

Service URL:

- API: `http://localhost:8000`
- Swagger: `http://localhost:8000/docs`

## Testing

```bash
pytest -q
```

## Environment Variables (Hardening)

Calibration:

- `ENABLE_CONFIDENCE_CALIBRATION=true|false`
- `CALIBRATION_DATA_PATH` (default: `data/processed/processed_cyber_data.csv`)

Threshold policy:

- `DEFAULT_SENSITIVITY=low|balanced|high`
- `THRESHOLD_LOW` (default: `0.75`)
- `THRESHOLD_BALANCED` (default: `0.60`)
- `THRESHOLD_HIGH` (default: `0.45`)
- `THRESHOLD_UNCERTAINTY_MARGIN` (default: `0.05`)

Channel auto policy:

- `AUTO_SENSITIVITY_SMS` (default: `low`)
- `AUTO_SENSITIVITY_WHATSAPP` (default: `balanced`)
- `AUTO_SENSITIVITY_EMAIL` (default: `balanced`)
- `THRESHOLD_OFFSET_SMS` (default: `0.00`)
- `THRESHOLD_OFFSET_WHATSAPP` (default: `0.00`)
- `THRESHOLD_OFFSET_EMAIL` (default: `0.00`)

Channel prior guardrails:

- `CHANNEL_PRIOR_WEIGHT` (default: `1.00`)
- `CHANNEL_PRIOR_MIN_SAMPLE` (default: `200`)
- `CHANNEL_PRIOR_SMOOTHING` (default: `200.0`)
- `CHANNEL_PRIOR_MAX_ODDS_RATIO` (default: `3.0`)

## Catatan Interpretasi

- Output reasoning membantu investigasi, tetapi bukan kebenaran absolut.
- Untuk `uncertainty_flag=true`, lakukan verifikasi manual tambahan sebelum tindakan final.

## Status Produk

CyberGuard-ID saat ini siap untuk:

- demo produk,
- integrasi internal,
- baseline production pilot dengan observability dasar.

Untuk scale production penuh, disarankan menambahkan monitoring metrik model, drift detection, dan audit log pipeline.
