import pandas as pd
import re
import matplotlib.pyplot as plt
import os
import logging

from src.security import BlobStorageManager, KeyVaultSecretProvider, SecuritySettings

logger = logging.getLogger("cyberguard.preprocessing")
security_settings = SecuritySettings.from_env()
secret_provider = KeyVaultSecretProvider.from_settings(security_settings, logger=logger)
blob_storage = BlobStorageManager.from_settings(security_settings, secret_provider=secret_provider, logger=logger)


def maybe_download_blob_input(local_path, blob_path):
    if os.path.exists(local_path):
        return
    if not blob_storage.enabled:
        return

    if blob_storage.download_file(blob_path=blob_path, local_path=local_path, overwrite=False):
        print(f"Downloaded missing dataset from blob path: {blob_path}")


def maybe_upload_blob_output(local_path, blob_path):
    if not blob_storage.enabled:
        return

    if blob_storage.upload_file(local_path=local_path, blob_path=blob_path, overwrite=True):
        print(f"Uploaded artifact to blob path: {blob_path}")

# 1. Load Data
db_raw_path = "data/raw/sms_spam_indo.csv"
db_syn_path = "data/external/synthetic_phishing_data.csv"

maybe_download_blob_input(db_raw_path, security_settings.raw_blob_path("datasets/sms_spam_indo.csv"))
maybe_download_blob_input(db_syn_path, security_settings.raw_blob_path("datasets/synthetic_phishing_data.csv"))

# Kaggle dataset
df_raw = pd.read_csv(db_raw_path)
# Rename and map labels (Spam/Promo/Fraud -> 1, Normal/Ham -> 0)
# Assuming 'Kategori' might contain 'spam', 'promo', 'penipuan', 'ham', 'normal'
label_map = {'spam': 1, 'promo': 1, 'penipuan': 1, 'ham': 0, 'normal': 0}
df_raw['label'] = df_raw['Kategori'].str.lower().map(label_map).fillna(0).astype(int)
df_raw = df_raw.rename(columns={'Pesan': 'text'})
df_raw = df_raw[['text', 'label']]
df_raw['platform'] = 'SMS' # Assuming Kaggle SMS dataset

# Synthetic dataset
df_syn = pd.read_csv(db_syn_path)

# News Datasets (Fake & Real News)
news_dir = "data/raw/Dataset Cleaned"
news_files = [
    ("Cleaned_Antaranews_v1.csv", "News_Antara"),
    ("Cleaned_Detik_v2.csv", "News_Detik"),
    ("Cleaned_Kompas_v2.csv", "News_Kompas"),
    ("Cleaned_TurnBackHoax_v3.csv", "News_Hoax")
]

news_dfs = []
for file, platform_name in news_files:
    file_path = os.path.join(news_dir, file)
    if not os.path.exists(file_path):
        maybe_download_blob_input(file_path, security_settings.raw_blob_path(f"datasets/news/{file}"))
    if os.path.exists(file_path):
        df_news = pd.read_csv(file_path)
        # Using clean_text or narasi. fallback to judul if needed
        # We will use 'clean_text' if it exists, otherwise 'narasi'
        text_col = 'clean_text' if 'clean_text' in df_news.columns else 'narasi'
        df_n = pd.DataFrame()
        df_n['text'] = df_news[text_col].astype(str).fillna(df_news['judul'].astype(str))
        df_n['label'] = df_news['label'].fillna(0).astype(int)
        df_n['platform'] = platform_name
        news_dfs.append(df_n)

# Merge and Deduplicate
df_combined = pd.concat([df_raw, df_syn] + news_dfs, ignore_index=True)
initial_len = len(df_combined)
df_combined = df_combined.drop_duplicates(subset=['text']).reset_index(drop=True)
print(f"Removed {initial_len - len(df_combined)} duplicate rows.")

# 2. Text Normalization
slang_dict = {
    'sgera': 'segera', 'mw': 'mau', 'sldo': 'saldo', 'krna': 'karena', 'blm': 'belum',
    'klo': 'kalau', 'yg': 'yang', 'dgn': 'dengan', 'utk': 'untuk', 'bs': 'bisa',
    'udh': 'sudah', 'bner': 'benar', 'ga': 'tidak', 'gak': 'tidak', 'tp': 'tapi',
    'almt': 'alamat', 'krng': 'kurang', 'dsni': 'disini', 'mhn': 'mohon', 'mksihh': 'terima kasih',
    'yach': 'ya', 'temen2': 'teman-teman', 'teman2': 'teman-teman', 'bnyk': 'banyak',
    'd': 'di', 'dr': 'dari', 'kmi': 'kami', 'kmbali': 'kembali', 'tnpa': 'tanpa',
    'kntor': 'kantor', 'prgkat': 'perangkat', 'smntara': 'sementara'
}

def normalize_text(text):
    if not isinstance(text, str): return ""
    # Lowercase for dictionary mapping flexibility, though we keep uppercase for urgency if needed
    words = text.split()
    normalized = " ".join([slang_dict.get(word.lower(), word) for word in words])
    return normalized

df_combined['text_norm'] = df_combined['text'].apply(normalize_text)

# 3. Feature Extraction
# has_dangerous_link
dangerous_patterns = r'(\.apk|\.top|\.xyz|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|s\.id|bit\.ly|tinyurl)'
df_combined['has_dangerous_link'] = df_combined['text_norm'].str.contains(dangerous_patterns, flags=re.IGNORECASE, regex=True).astype(int)

# contains_urgency
urgency_keywords = r'(dibekukan|blokir|pajak|hadiah|segera|tutup|hangus|peringatan|terlambat|denda|terpotong)'
df_combined['contains_urgency'] = df_combined['text_norm'].str.contains(urgency_keywords, flags=re.IGNORECASE, regex=True).astype(int)

# 4. Cleaning & Tokenization
def clean_and_tokenize(text):
    # Keep alphanumeric, exclamation marks, and whitespace
    text = re.sub(r'[^a-zA-Z0-9\s!]', ' ', text)
    # Replace multiple spaces with single space
    text = re.sub(r'\s+', ' ', text).strip()
    # Simple tokenization by splitting, though we keep it returning the joined text or list depending on the model need
    # Here we return a list of tokens (as string representation)
    tokens = re.findall(r'\b\w+\b|!', text)
    return " ".join(tokens)

df_combined['processed_text'] = df_combined['text_norm'].apply(clean_and_tokenize)

# 5. Visualization
counts = df_combined['label'].value_counts()
plt.figure(figsize=(6, 4))
bars = plt.bar(counts.index.astype(str).map({'0': 'Normal (0)', '1': 'Phishing (1)'}), counts.values, color=['#1f77b4', '#d62728'])
plt.title('Class Distribution after Merging (Kaggle + Synthetic)')
plt.ylabel('Count')
plt.xlabel('Label')

for bar in bars:
    yval = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2, yval + 10, int(yval), ha='center', va='bottom')

os.makedirs('reports', exist_ok=True)
plt.savefig('reports/class_distribution.png')
print("Saved visualization to reports/class_distribution.png")
maybe_upload_blob_output(
    local_path='reports/class_distribution.png',
    blob_path=security_settings.processed_blob_path('reports/class_distribution.png'),
)

# 6. Output to CSV
os.makedirs('data/processed', exist_ok=True)
output_path = 'data/processed/processed_cyber_data.csv'
final_cols = ['processed_text', 'label', 'platform', 'has_dangerous_link', 'contains_urgency']
df_combined[final_cols].to_csv(output_path, index=False, encoding='utf-8')
print(f"Processed dataset saved to {output_path}")
maybe_upload_blob_output(
    local_path=output_path,
    blob_path=security_settings.processed_blob_path('datasets/processed_cyber_data.csv'),
)

print("\n--- Top 5 Processed Rows ---")
print(df_combined[final_cols].head())
