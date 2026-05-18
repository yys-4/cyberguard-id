"""
stress_test_and_retrain.py — Validation stress test + XGBoost retrain pipeline.

Phase 1.2 addition: persist calibrator to disk after retraining.
Phase 2.4 addition: write model_metadata.json alongside each trained model,
  upload to Blob at processed/models/<version>/.
"""

from __future__ import annotations

import json
import os
import subprocess
import logging
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier

from src.security import BlobStorageManager, KeyVaultSecretProvider, SecuritySettings

DATA_PATH = "data/processed/processed_cyber_data.csv"
MODEL_DIR = "models"
OLD_MODEL_PATH = os.path.join(MODEL_DIR, "xgboost_baseline.joblib")
NEW_MODEL_PATH = os.path.join(MODEL_DIR, "xgboost_no_platform.joblib")
CALIBRATOR_PATH = os.getenv("CALIBRATOR_PATH", os.path.join(MODEL_DIR, "probability_calibrator.joblib"))

logger = logging.getLogger("cyberguard.retrain")
security_settings = SecuritySettings.from_env()
secret_provider = KeyVaultSecretProvider.from_settings(security_settings, logger=logger)
blob_storage = BlobStorageManager.from_settings(security_settings, secret_provider=secret_provider, logger=logger)


def maybe_download_blob_input(local_path: str, blob_path: str) -> None:
    if os.path.exists(local_path):
        return
    if not blob_storage.enabled:
        return
    if blob_storage.download_file(blob_path=blob_path, local_path=local_path, overwrite=False):
        print(f"Downloaded missing input from blob path: {blob_path}")


def maybe_upload_blob_output(local_path: str, blob_path: str) -> None:
    if not blob_storage.enabled:
        return
    if blob_storage.upload_file(local_path=local_path, blob_path=blob_path, overwrite=True):
        print(f"Uploaded to blob path: {blob_path}")


def _get_git_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], text=True).strip()
    except Exception:
        return "unknown"


def _persist_calibrator(pipeline: Pipeline, calibrator_path: str) -> None:
    """
    Phase 1.2: Fit Platt sigmoid on retrained model and persist to disk.
    This ensures the calibrator file is always in sync with the newly trained model.
    """
    print(f"\n=== Menyimpan calibrator ke {calibrator_path} ===")
    try:
        df = pd.read_csv(DATA_PATH)
        df = df.dropna(subset=["processed_text", "label"])
        df["processed_text"] = df["processed_text"].fillna("")
        df["has_dangerous_link"] = df["has_dangerous_link"].fillna(0)
        df["contains_urgency"] = df["contains_urgency"].fillna(0)

        features = df[["processed_text", "has_dangerous_link", "contains_urgency"]]
        labels = df["label"].astype(int)

        raw_probs = pipeline.predict_proba(features)[:, 1].reshape(-1, 1)
        raw_probs = np.clip(raw_probs, 1e-6, 1.0 - 1e-6)

        calibrator = LogisticRegression(max_iter=1000, random_state=42, solver="liblinear")
        calibrator.fit(raw_probs, labels)

        os.makedirs(os.path.dirname(calibrator_path) or ".", exist_ok=True)
        payload = {"method": "platt_sigmoid", "model": calibrator}
        joblib.dump(payload, calibrator_path)
        print(f"Calibrator (Platt sigmoid) disimpan ke {calibrator_path}")

        maybe_upload_blob_output(
            calibrator_path,
            security_settings.processed_blob_path("models/probability_calibrator.joblib"),
        )
    except Exception as exc:
        print(f"PERINGATAN: Gagal menyimpan calibrator: {exc}")


def _write_model_metadata(
    version: str,
    metrics: dict,
    model_dir: str,
) -> None:
    """
    Phase 2.4: Write model_metadata.json alongside the trained model artifact.
    Uploads to Blob at processed/models/<version>/.
    """
    metadata = {
        "model_version": version,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "metrics": metrics,
        "git_commit": _get_git_commit(),
        "ci_run_id": os.getenv("GITHUB_RUN_ID", "local"),
    }

    metadata_path = os.path.join(model_dir, "model_metadata.json")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"\nModel metadata ditulis ke {metadata_path}:")
    print(json.dumps(metadata, indent=2))

    blob_version_path = f"models/{version}/model_metadata.json"
    maybe_upload_blob_output(metadata_path, security_settings.processed_blob_path(blob_version_path))
    blob_model_path = f"models/{version}/xgboost_no_platform.joblib"
    maybe_upload_blob_output(NEW_MODEL_PATH, security_settings.processed_blob_path(blob_model_path))


# 10 Phishing Texts for Stress Test
stress_test_data = [
    "PERHATIAN! Rekening BCA Anda telah diblokir karena aktivitas mencurigakan. Klik link berikut untuk verifikasi data Anda segera: http://bca-pemulihan.com",
    "Selamat! Nomor Anda terpilih memenangkan undian Rp 50 Juta dari Shopee. Hubungi nomor M-Kios ini untuk klaim hadiah: +62812345678",
    "Akun Instagram Anda terdeteksi melanggar hak cipta. Tolong konfirmasi identitas Anda di link ini atau akun akan dihapus dalam 24 jam: https://ig-security-check.info",
    "Paket Anda dari J&T Express tertahan di gudang karena alamat tidak lengkap. Mohon update detail pengiriman di: bit.ly/jnt-update-resi",
    "Promo Spesial Telkomsel! Dapatkan kuota 100GB hanya dengan Rp 10.000. Promo terbatas hari ini saja, aktifkan di www.telkomsel-kuota-murah.xyz",
    "Pemberitahuan dari Whatsapp: Layanan Anda akan kadaluarsa. Upgrade ke Whatsapp Premium secara gratis melalui tautan ini: http://wa-premium-update.com",
    "DANA: Ada percobaan login dari perangkat tidak dikenal. Jika ini bukan Anda, amankan akun Anda segera klik link batalkan login: http://dana-care.com/secure",
    "Kami dari kepolisian RI memberitahukan bahwa Anda terlibat kasus pencucian uang. Segera bayar denda ke rekening Virtual Account ini atau petugas akan menjemput Anda.",
    "PENGUMUMAN! Anda berhak mendapatkan bantuan sosial tunai (BST) Rp 600.000 dari pemerintah. Daftarkan KTP Anda di: https://bansos-pemerintah-2026.id",
    "Tagihan PLN Anda bulan ini membengkak Rp 2.500.000. Untuk rincian pemakaian, silakan download slip di link berikut: http://pln-tagihan.com/apk",
]


def map_features(text: str) -> tuple:
    has_link = 1 if "http" in text or "www" in text or "bit.ly" in text or ".com" in text or ".id" in text or ".xyz" in text or ".info" in text else 0
    urgency_keywords = ["segera", "hari ini", "batas waktu", "kadaluarsa", "blokir", "dihapus"]
    has_urgency = 1 if any(kw in text.lower() for kw in urgency_keywords) else 0
    return text, has_link, has_urgency


def main() -> None:
    print("=== TAHAP 1: STRESS TEST MODEL LAMA (dengan asumsi platform = SMS) ===")
    maybe_download_blob_input(OLD_MODEL_PATH, security_settings.processed_blob_path("models/xgboost_baseline.joblib"))
    old_model = joblib.load(OLD_MODEL_PATH)

    test_rows = []
    for txt in stress_test_data:
        _, link_flag, urg_flag = map_features(txt)
        test_rows.append({
            "processed_text": txt,
            "platform": "SMS",  # Dummy platform for old model
            "has_dangerous_link": link_flag,
            "contains_urgency": urg_flag,
        })
    df_stress = pd.DataFrame(test_rows)
    preds = old_model.predict(df_stress)

    print(f"Hasil Prediksi (1=Phishing, 0=Normal): {preds}")
    print(f"Akurasi Stress Test (Model Lama): {sum(preds)}/10 Phishing terdeteksi.\n")

    print("=== TAHAP 2: RETRAIN TANPA FITUR PLATFORM ===")
    maybe_download_blob_input(DATA_PATH, security_settings.processed_blob_path("datasets/processed_cyber_data.csv"))
    df = pd.read_csv(DATA_PATH)
    df = df.dropna(subset=["processed_text", "label"])
    df["processed_text"] = df["processed_text"].fillna("")
    df["has_dangerous_link"] = df["has_dangerous_link"].fillna(0)
    df["contains_urgency"] = df["contains_urgency"].fillna(0)

    X = df[["processed_text", "has_dangerous_link", "contains_urgency"]]
    y = df["label"]

    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.15, stratify=y, random_state=42
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=0.17647, stratify=y_train_val, random_state=42
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("text", TfidfVectorizer(max_features=3000), "processed_text"),
            ("num", "passthrough", ["has_dangerous_link", "contains_urgency"]),
        ]
    )

    xgb_model = XGBClassifier(
        n_estimators=100,
        random_state=42,
        eval_metric="logloss",
        use_label_encoder=False,
    )

    pipeline = Pipeline(steps=[
        ("preprocessor", preprocessor),
        ("classifier", xgb_model),
    ])

    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)

    f1 = f1_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)

    print("\n--- METRIK TEST SET (TANPA PLATFORM) ---")
    print(f"Precision: {prec:.4f}")
    print(f"Recall: {rec:.4f}")
    print(f"F1-Score: {f1:.4f}")

    if f1 > 0.90:
        print(f"\nModel stabil (F1 > 0.90) tanpa fitur platform. Menyimpan model ke {NEW_MODEL_PATH}...")
        joblib.dump(pipeline, NEW_MODEL_PATH)
        maybe_upload_blob_output(NEW_MODEL_PATH, security_settings.processed_blob_path("models/xgboost_no_platform.joblib"))

        # Phase 2.4: write and upload model metadata
        model_version = f"v1.{datetime.now(timezone.utc).strftime('%Y%m%d')}"
        _write_model_metadata(
            version=model_version,
            metrics={"test_f1": round(f1, 4), "test_precision": round(prec, 4), "test_recall": round(rec, 4)},
            model_dir=MODEL_DIR,
        )

        # Phase 1.2: persist calibrator in sync with newly trained model
        _persist_calibrator(pipeline, CALIBRATOR_PATH)

        # Stress test the new model
        print("\n=== Menguji 10 Teks Stress Test ke Model Baru ===")
        df_stress_new = df_stress[["processed_text", "has_dangerous_link", "contains_urgency"]]
        preds_new = pipeline.predict(df_stress_new)
        print(f"Hasil Prediksi Model Baru: {preds_new}")
        print(f"Akurasi Stress Test (Model Baru): {sum(preds_new)}/10 Phishing terdeteksi.\n")
    else:
        print("\nPERINGATAN: Performa model turun drastis di bawah 0.90 tanpa fitur platform.")


if __name__ == "__main__":
    main()
