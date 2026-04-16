import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix, classification_report
from xgboost import XGBClassifier
import os

# Configs
DATA_PATH = "data/processed/processed_cyber_data.csv"
MODEL_DIR = "models"
REPORT_DIR = "reports"
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

def main():
    print("Loading data...")
    df = pd.read_csv(DATA_PATH)
    # Ensure no entirely null rows for text or label
    df = df.dropna(subset=['processed_text', 'label'])
    
    # Fill any null values in numeric/text columns
    df['processed_text'] = df['processed_text'].fillna('')
    df['has_dangerous_link'] = df['has_dangerous_link'].fillna(0)
    df['contains_urgency'] = df['contains_urgency'].fillna(0)
    
    X = df[['processed_text', 'platform', 'has_dangerous_link', 'contains_urgency']]
    y = df['label']
    
    # 70:15:15 split with stratification
    print("Splitting data into 70% Train, 15% Validation, 15% Test...")
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.15, stratify=y, random_state=42
    )
    
    # 15% of total is ~17.65% of the remaining 85%
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=0.17647, stratify=y_train_val, random_state=42
    )
    
    print(f"Train size: {len(X_train)} | Val size: {len(X_val)} | Test size: {len(X_test)}")
    
    # 1. Preprocessing Setup
    # TfidfVectorizer outputs sparse matrix. XGBoost can handle sparse.
    preprocessor = ColumnTransformer(
        transformers=[
            ('text', TfidfVectorizer(max_features=3000), 'processed_text'),
            ('cat', OneHotEncoder(handle_unknown='ignore'), ['platform']),
            ('num', 'passthrough', ['has_dangerous_link', 'contains_urgency'])
        ]
    )
    
    # 2. Baseline Model (XGBoost) setup
    # Lightweight for mobile/web deployment
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
    
    # robustness: Cross-Validation (K-Fold)
    print("\nRobustness Check: Running 5-Fold Cross Validation on Train Data (F1-score)...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(pipeline, X_train, y_train, cv=cv, scoring='f1')
    print(f"CV F1-Score: {np.mean(cv_scores):.4f} (+/- {np.std(cv_scores):.4f})")
    
    # Train the exact same pipeline on the full training data
    print("\nTraining Baseline XGBoost model...")
    pipeline.fit(X_train, y_train)
    
    # 3. Evaluation on Validation Set (optional check) & Test Set (main metric reporting)
    print("Evaluating model...")
    y_pred = pipeline.predict(X_test)
    
    f1 = f1_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    
    print("\n--- TEST SET METRICS ---")
    print(f"Precision (Menghindari FP): {prec:.4f}")
    print(f"Recall (Deteksi as banyak mungkin): {rec:.4f}")
    print(f"F1-Score (Fokus Utama Data Imbalance/Cyber): {f1:.4f}")
    
    print("\nClassification Report:\n", classification_report(y_test, y_pred))
    
    # Confusion Matrix Visualization
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(6,5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False)
    plt.title("Confusion Matrix - XGBoost (Test Set)")
    plt.ylabel("True Label")
    plt.xlabel("Predicted Label")
    plt.tight_layout()
    plt.savefig(os.path.join(REPORT_DIR, "xgboost_confusion_matrix.png"), dpi=300)
    plt.close()
    print(f"Confusion Matrix disimpan ke: {REPORT_DIR}/xgboost_confusion_matrix.png")
    
    # 4. Feature Importance Visualization (Explainability)
    # Extract feature names from preprocessing steps
    text_features = preprocessor.named_transformers_['text'].get_feature_names_out()
    cat_features = preprocessor.named_transformers_['cat'].get_feature_names_out(['platform'])
    num_features = ['has_dangerous_link', 'contains_urgency']
    
    all_features = np.concatenate([text_features, cat_features, num_features])
    importances = pipeline.named_steps['classifier'].feature_importances_
    
    feature_imp_df = pd.DataFrame({'Feature': all_features, 'Importance': importances})
    feature_imp_df = feature_imp_df.sort_values(by='Importance', ascending=False)
    
    top_10 = feature_imp_df.head(10)
    print("\nTop 10 Feature Importances:")
    print(top_10)
    
    plt.figure(figsize=(10,6))
    # We use barplot to show importance cleanly
    sns.barplot(data=top_10, x='Importance', y='Feature', palette='viridis')
    plt.title("Top 10 Feature Importances - XGBoost")
    plt.tight_layout()
    plt.savefig(os.path.join(REPORT_DIR, "top10_feature_importances_xgboost.png"), dpi=300)
    plt.close()
    print(f"Feature Importance Chart disimpan ke: {REPORT_DIR}/top10_feature_importances_xgboost.png")
    
    # 5. Model Export
    model_path = os.path.join(MODEL_DIR, "xgboost_baseline.joblib")
    joblib.dump(pipeline, model_path)
    print(f"\nModel Exported successfully: Deployment-ready model saved as {model_path}")

if __name__ == "__main__":
    main()
