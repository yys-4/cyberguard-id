import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import f1_score, precision_score, recall_score, classification_report
from xgboost import XGBClassifier
import os

DATA_PATH = "data/processed/processed_cyber_data.csv"
MODEL_DIR = "models"
OLD_MODEL_PATH = os.path.join(MODEL_DIR, "xgboost_baseline.joblib")
NEW_MODEL_PATH = os.path.join(MODEL_DIR, "xgboost_no_platform.joblib")

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
    "Tagihan PLN Anda bulan ini membengkak Rp 2.500.000. Untuk rincian pemakaian, silakan download slip di link berikut: http://pln-tagihan.com/apk"
]

def map_features(text):
    has_link = 1 if 'http' in text or 'www' in text or 'bit.ly' in text or '.com' in text or '.id' in text or '.xyz' in text or '.info' in text else 0
    urgency_keywords = ['segera', 'hari ini', 'batas waktu', 'kadaluarsa', 'blokir', 'dihapus']
    has_urgency = 1 if any(kw in text.lower() for kw in urgency_keywords) else 0
    return text, has_link, has_urgency

def main():
    print("=== TAHAP 1: STRESS TEST MODEL LAMA (dengan asumsi platform = SMS) ===")
    old_model = joblib.load(OLD_MODEL_PATH)
    
    test_rows = []
    for txt in stress_test_data:
        _, link_flag, urg_flag = map_features(txt)
        test_rows.append({
            'processed_text': txt,
            'platform': 'SMS', # Dummy platform for old model
            'has_dangerous_link': link_flag,
            'contains_urgency': urg_flag
        })
    df_stress = pd.DataFrame(test_rows)
    preds = old_model.predict(df_stress)
    
    print(f"Hasil Prediksi (1=Phishing, 0=Normal): {preds}")
    print(f"Akurasi Stress Test (Model Lama): {sum(preds)}/10 Phishing terdeteksi.\n")

    print("=== TAHAP 2: RETRAIN TANPA FITUR PLATFORM ===")
    df = pd.read_csv(DATA_PATH)
    df = df.dropna(subset=['processed_text', 'label'])
    df['processed_text'] = df['processed_text'].fillna('')
    df['has_dangerous_link'] = df['has_dangerous_link'].fillna(0)
    df['contains_urgency'] = df['contains_urgency'].fillna(0)
    
    # Drop platform
    X = df[['processed_text', 'has_dangerous_link', 'contains_urgency']]
    y = df['label']
    
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.15, stratify=y, random_state=42
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=0.17647, stratify=y_train_val, random_state=42
    )
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('text', TfidfVectorizer(max_features=3000), 'processed_text'),
            ('num', 'passthrough', ['has_dangerous_link', 'contains_urgency'])
        ]
    )
    
    model = XGBClassifier(
        n_estimators=100,
        random_state=42,
        eval_metric='logloss',
        use_label_encoder=False
    )
    
    pipeline = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('classifier', model)
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
        
        # Stress test the new model
        print("\n=== Menguji 10 Teks Stress Test ke Model Baru ===")
        df_stress_new = df_stress[['processed_text', 'has_dangerous_link', 'contains_urgency']]
        preds_new = pipeline.predict(df_stress_new)
        print(f"Hasil Prediksi Model Baru: {preds_new}")
        print(f"Akurasi Stress Test (Model Baru): {sum(preds_new)}/10 Phishing terdeteksi.\n")
    else:
        print("\nPERINGATAN: Performa model turun drastis di bawah 0.90 tanpa fitur platform.")

if __name__ == "__main__":
    main()
