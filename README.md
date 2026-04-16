# CyberGuard-ID

Backend deteksi phishing berbasis FastAPI + XGBoost dengan explainability hybrid (SHAP + fallback heuristik).

## Instalasi dependencies
```bash
pip install -r requirements.txt
```

## Jalankan API Server (Local)
Untuk menjalankan API menggunakan FastAPI:
```bash
uvicorn src.app:app --reload
```

Akses dokumentasi Swagger di:

`http://localhost:8000/docs`

## Interactive Web Dashboard (The Interface)

CyberGuard-ID sekarang menyediakan dashboard web interaktif untuk simulasi dan edukasi keamanan siber publik.

Akses di:

`http://localhost:8000/dashboard`

Fitur utama:

- Simulasi analisis pesan phishing secara real-time melalui endpoint `POST /predict-v2`.
- Visualisasi skor risiko, alasan deteksi (XAI), kontributor fitur, dan tip mitigasi.
- Checklist red flags otomatis (link mencurigakan, bahasa mendesak, permintaan OTP/data sensitif, iming-iming hadiah).
- Mini kuis edukasi dan statistik sesi untuk penguatan awareness pengguna.

## Frontend Package Terpisah (React + Vite)

Untuk workflow tim Frontend & UI/UX yang ingin iterasi UI secara independen dari FastAPI, tersedia paket frontend terpisah di folder `frontend-dashboard/`.

Jalankan:

```bash
cd frontend-dashboard
npm install
cp .env.example .env
npm run dev
```

Frontend akan berjalan di:

- `http://localhost:5173`

Catatan:

- Pastikan backend API aktif di `http://localhost:8000`.
- Konfigurasi API frontend diatur lewat environment variable `VITE_API_BASE_URL`.
- Gunakan Node.js versi `22.12+` (disarankan pakai `.nvmrc` di root repo).

### Jalankan Backend + Frontend Tanpa Bentrok Port

Gunakan orkestrasi dev stack otomatis:

```bash
bash scripts/dev-stack.sh
```

Script ini akan:

- Memakai backend yang sudah aktif jika health endpoint tersedia.
- Menemukan port kosong otomatis jika `8000` atau `5173` sudah terpakai.
- Menjalankan frontend dengan `VITE_API_BASE_URL` yang sinkron ke backend aktif.

### Smoke Test End-to-End Frontend -> Predict-v2

Saat backend dan frontend sudah aktif, jalankan:

```bash
bash scripts/smoke-e2e.sh
```

Script ini memverifikasi:

- Backend health endpoint aktif.
- Frontend dev server merespons.
- Request simulasi dari konteks frontend ke `POST /predict-v2` berhasil dan schema penting tersedia.

## Endpoint

### 1) Endpoint Legacy

`POST /predict`

Tetap dipertahankan untuk backward compatibility.

### 2) Endpoint Intelligent Backend (v2)

`POST /predict-v2`

Request body:

```json
{
	"text": "PERINGATAN! Akun Anda diblokir, segera verifikasi di bit.ly/cek-akun sekarang juga.",
	"source": "SMS",
	"sensitivity": "auto"
}
```

- `text` wajib.
- `source` opsional (SMS/WhatsApp/Email) sebagai konteks segmentasi kanal (bukan fitur utama classifier XGBoost).
- `sensitivity` opsional untuk mengatur ambang deteksi:
  - `low`: lebih konservatif (menekan false positive).
  - `balanced`: default seimbang.
  - `high`: lebih sensitif mendeteksi ancaman (berpotensi menaikkan false positive).
  - `auto`: sistem memilih sensitivitas berdasarkan kanal yang dianalisis.

Response body (contoh):

```json
{
	"is_phishing": true,
	"confidence": 96.42,
	"message": "Pesan ini terdeteksi berisiko PHISHING.",
	"reasoning": [
		"Indikator tautan berbahaya meningkatkan skor risiko pesan ini.",
		"Indikator bahasa mendesak meningkatkan skor risiko pesan ini."
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
		"calibrated_probability": 96.42
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

Keterangan field utama:

- `confidence`: probabilitas ancaman phishing (0-100).
- `calibration`: metadata kalibrasi confidence.
  - `raw_probability`: skor asli model sebelum kalibrasi.
  - `calibrated_probability`: skor setelah calibration model.
	- `channel_adjusted_probability`: skor akhir setelah penyesuaian prior berbasis kanal.
- `threshold_policy`: metadata kebijakan keputusan.
	- `mode`: `user_override` atau `auto_channel`.
	- `channel`: kanal yang dipakai dalam kebijakan threshold.
	- `base_threshold`: threshold dasar dari sensitivity level.
	- `channel_offset`: penyesuaian threshold khusus kanal.
  - `decision_threshold`: ambang persen untuk menentukan phishing/non-phishing.
  - `sensitivity`: level sensitivitas yang dipakai untuk keputusan.
- `channel_analysis`: ringkasan segmentasi kanal (profil token, baseline link/urgency, prior kanal).
- `xai_method`:
	- `shap`: penjelasan berbasis kontribusi fitur model.
	- `heuristic_fallback`: fallback jika SHAP gagal/timeout.
- `uncertainty_flag`: `true` jika confidence berada di area borderline.

## Segmentasi Kanal

Lapisan segmentasi kanal menambahkan konteks distribusi kata per kanal:

- SMS cenderung singkat.
- WhatsApp cenderung lebih naratif.
- Email punya pola campuran formal + tautan.

Sistem membandingkan token input terhadap baseline kanal (`channel_analysis`) agar keputusan lebih kontekstual dan false positive lebih terkendali.

## Confidence Calibration Dan Threshold Policy

Hardening ini menambahkan dua lapisan kontrol:

1. Confidence calibration dengan metode Platt sigmoid untuk menstabilkan probabilitas model.
2. Threshold policy berbasis sensitivitas agar tradeoff false positive vs detection rate bisa diatur.
3. Dynamic thresholding berbasis kanal ketika `sensitivity=auto`.
4. Channel prior adjustment untuk menyesuaikan skor dengan distribusi ancaman tiap kanal.

Default threshold:

- `low`: 75%
- `balanced`: 60%
- `high`: 45%

Makna praktis:

- Jika tim ingin mengurangi false positive, pilih `sensitivity=low`.
- Jika tim ingin deteksi agresif, pilih `sensitivity=high`.
- Jika tim ingin sistem menyesuaikan otomatis per kanal, pilih `sensitivity=auto`.

## XAI Berbasis Konteks Kanal

Selain SHAP top contributors, reasoning sekarang menyertakan konteks kanal. Contoh untuk SMS:

- "Link ini sangat tidak lazim ditemukan di protokol SMS (...)".

Dengan ini, penjelasan tidak hanya berkata "ada link", tetapi juga menjelaskan kenapa indikator tersebut abnormal pada kanal yang sedang dianalisis.

## Health Endpoints

- `GET /health/live`: liveness probe cepat.
- `GET /health/ready`: readiness probe berisi status model, calibration, dan threshold policy runtime.

## Quick Smoke Test

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

Health check:

```bash
curl -X GET http://localhost:8000/health/live
curl -X GET http://localhost:8000/health/ready
```

## Jalankan Dengan Docker Compose

```bash
docker compose up --build
```

Service akan berjalan di:

- API: `http://localhost:8000`
- Swagger: `http://localhost:8000/docs`

## Menjalankan Test

```bash
pytest -q
```

## Environment Variables Hardening

- `ENABLE_CONFIDENCE_CALIBRATION=true|false`
- `CALIBRATION_DATA_PATH` default: `data/processed/processed_cyber_data.csv`
- `DEFAULT_SENSITIVITY=low|balanced|high`
- `AUTO_SENSITIVITY_SMS` default: `low`
- `AUTO_SENSITIVITY_WHATSAPP` default: `balanced`
- `AUTO_SENSITIVITY_EMAIL` default: `balanced`
- `THRESHOLD_LOW` default: `0.75`
- `THRESHOLD_BALANCED` default: `0.60`
- `THRESHOLD_HIGH` default: `0.45`
- `THRESHOLD_UNCERTAINTY_MARGIN` default: `0.05`
- `THRESHOLD_OFFSET_SMS` default: `0.00`
- `THRESHOLD_OFFSET_WHATSAPP` default: `0.00`
- `THRESHOLD_OFFSET_EMAIL` default: `0.00`
- `CHANNEL_PRIOR_WEIGHT` default: `1.00`
- `CHANNEL_PRIOR_MIN_SAMPLE` default: `200`
- `CHANNEL_PRIOR_SMOOTHING` default: `200.0`
- `CHANNEL_PRIOR_MAX_ODDS_RATIO` default: `3.0`

## Catatan Interpretasi XAI

- Penjelasan model (`reasoning` dan `top_contributors`) membantu interpretasi keputusan, namun bukan kebenaran absolut.
- Untuk pesan dengan `uncertainty_flag=true`, lakukan verifikasi manual tambahan sebelum mengambil keputusan keamanan.
