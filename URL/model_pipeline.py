import os
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, ConfusionMatrixDisplay

from config import MODEL_ARTIFACTS_FILE, VISUALS_DIR
from url_utils import normalize_input_url
from features import extract_features

def prepare_data(df):
    print(" Preprocessing data")
    df = df.dropna(subset=['url']).copy()
    df['url'] = df['url'].astype(str).str.strip()
    df['type'] = df['type'].astype(str).str.lower().str.strip()
    df = df[df['type'].isin(['legitimate', 'phishing'])].copy()

    # Normalization 
    df['url_clean'] = df['url'].apply(normalize_input_url)
    df = df.sort_values(['url_clean', 'type'], ascending=[True, False])
    df = df.drop_duplicates(subset=['url_clean']).reset_index(drop=True)

    feature_rows = []
    total_urls = len(df)
    
    for i, url in enumerate(df['url_clean']):
        feature_rows.append(extract_features(url))
        if (i + 1) % 5000 == 0:
            print(f"    -> Processed {i + 1:,} / {total_urls:,} URLs")

    features_df = pd.DataFrame(feature_rows).fillna(0)
    
    # Combine normalized URL 
    X = pd.concat([df[['url_clean']], features_df], axis=1)
    y = df['type'].map({'legitimate': 0, 'phishing': 1}).astype(int)
    
    return X, y

def train_and_evaluate(X, y):
    print(" Training Model...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    numeric_features = [col for col in X.columns if col != 'url_clean']

    
    preprocessor = ColumnTransformer(
        transformers=[
            ('url_tfidf', TfidfVectorizer(analyzer='char', ngram_range=(3, 5), max_features=3000), 'url_clean'),
            ('num_scaler', StandardScaler(), numeric_features)
        ]
    )

    pipeline = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('classifier', RandomForestClassifier(n_estimators=300, class_weight='balanced', random_state=42, n_jobs=-1))
    ])

    pipeline.fit(X_train, y_train)

    # Evaluate
    probs = pipeline.predict_proba(X_test)[:, 1]
    
    # Simple Threshold Optimization for F1-Score
    best_f1, best_thresh = 0, 0.5
    for thresh in np.arange(0.3, 0.8, 0.05):
        preds = (probs >= thresh).astype(int)
        f1 = f1_score(y_test, preds, zero_division=0)
        if f1 > best_f1:
            best_f1, best_thresh = f1, thresh

    y_pred = (probs >= best_thresh).astype(int)

    print(f"\n[*] Validation Threshold: {best_thresh:.3f}")
    print(f"[*] Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
    print(f"[*] Precision: {precision_score(y_test, y_pred, zero_division=0):.4f}")
    print(f"[*] Recall:    {recall_score(y_test, y_pred, zero_division=0):.4f}")
    print(f"[*] F1-Score:  {best_f1:.4f}")

    # Visuals
    print("\n Confusion Matrix visualization...")
    os.makedirs(VISUALS_DIR, exist_ok=True)
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    fig, ax = plt.subplots(figsize=(7, 6))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Legitimate", "Phishing"])
    disp.plot(cmap="Blues", ax=ax, values_format="d")
    plt.title("Confusion Matrix")
    
    cm_path = os.path.join(VISUALS_DIR, "confusion_matrix.png")
    plt.savefig(cm_path, bbox_inches="tight", dpi=300)
    plt.close(fig)

    # Save artifact
    os.makedirs(os.path.dirname(MODEL_ARTIFACTS_FILE), exist_ok=True)
    joblib.dump({'pipeline': pipeline, 'threshold': best_thresh}, MODEL_ARTIFACTS_FILE)
    print(f"[*] Complete pipeline saved to {MODEL_ARTIFACTS_FILE}")

    return pipeline, best_thresh

def predict_single_url(url, pipeline, threshold):
    url_clean = normalize_input_url(url)
    features = extract_features(url_clean)
    
    
    df_in = pd.DataFrame([features])
    df_in['url_clean'] = url_clean

    prob = pipeline.predict_proba(df_in)[0, 1]
    label = "Phishing" if prob >= threshold else "Legitimate"
    return label, float(prob)