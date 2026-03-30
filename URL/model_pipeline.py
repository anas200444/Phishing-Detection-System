import os
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, HistGradientBoostingClassifier, VotingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, matthews_corrcoef, confusion_matrix, ConfusionMatrixDisplay

from config import MODEL_ARTIFACTS_FILE, VISUALS_DIR, ABSOLUTE_TRUSTED
from url_utils import normalize_input_url, parse_url_parts, get_sld_tld, get_precomputed_pop_domains
from features import extract_features

def prepare_data(df):
    print("[*] Extracting enhanced features from dataset... This might take a moment.")
    df = df.dropna(subset=['url']).copy()
    df['url'] = df['url'].astype(str).str.strip()
    df['type'] = df['type'].astype(str).str.lower().str.strip()
    df = df[df['type'].isin(['legitimate', 'phishing'])].copy()

    # Create the normalization key
    df['url_norm_key'] = df['url'].astype(str).map(lambda x: normalize_input_url(x).lower().strip())
    
    # --- OPTIMIZED DEDUPLICATION ---
    # Sort by URL ascending, and 'type' descending ('phishing' > 'legitimate' alphabetically)
    # This ensures that if a URL has both labels, 'phishing' is placed first.
    df = df.sort_values(['url_norm_key', 'type'], ascending=[True, False])
    # Drop duplicates keeping the first occurrence
    df = df.drop_duplicates(subset=['url_norm_key'], keep='first').reset_index(drop=True)
    # -------------------------------

    feature_rows = []
    urls = df['url'].tolist()
    get_precomputed_pop_domains()

    total_urls = len(urls)
    for i, url in enumerate(urls):
        feature_rows.append(extract_features(url))
        if (i + 1) % 2000 == 0:
            print(f"    -> Processed {i + 1:,} / {total_urls:,} URLs")

    features_df = pd.DataFrame(feature_rows).fillna(0)
    y = df['type'].map({'legitimate': 0, 'phishing': 1}).astype(int)
    return features_df, y
def compute_threshold_stats(y_true, probs, threshold):
    y_pred = (probs >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        'threshold': round(float(threshold), 2),
        'y_pred': y_pred,
        'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp),
        'precision': precision_score(y_true, y_pred, zero_division=0),
        'recall': recall_score(y_true, y_pred, zero_division=0),
        'f1': f1_score(y_true, y_pred, zero_division=0)
    }

def choose_best_threshold(y_true, probs):
    best_stats, best_score = None, -1e18
    for threshold in np.arange(0.15, 0.85, 0.01):
        stats = compute_threshold_stats(y_true, probs, threshold)
        if stats['recall'] < 0.90: continue
        mcc = matthews_corrcoef(y_true, stats['y_pred'])
        score = (mcc * 0.6) + (stats['f1'] * 0.4) 
        if best_stats is None or score > best_score:
            best_stats, best_score = stats, score
    return best_stats

def build_model():
    rf = RandomForestClassifier(n_estimators=450, max_depth=None, min_samples_split=4, min_samples_leaf=2, class_weight='balanced', random_state=42, n_jobs=-1)
    hgb = HistGradientBoostingClassifier(max_iter=350, learning_rate=0.06, max_leaf_nodes=41, early_stopping=True, validation_fraction=0.1, random_state=42)
    et = ExtraTreesClassifier(n_estimators=300, min_samples_split=4, class_weight='balanced', random_state=42, n_jobs=-1)
    return VotingClassifier(estimators=[('rf', rf), ('hgb', hgb), ('et', et)], voting='soft')

def train_and_evaluate(X, y):
    feature_columns = X.columns.tolist()
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled  = scaler.transform(X_test)

    print("[*] Training Phishing Detection Model (Voting Ensemble)...")
    model = build_model()
    model.fit(X_train_scaled, y_train.values)

    cal_model = CalibratedClassifierCV(model, method='isotonic', cv=3)
    cal_model.fit(X_train_scaled, y_train.values)

    test_probs = cal_model.predict_proba(X_test_scaled)[:, 1]
    best_stats = choose_best_threshold(y_test.values, test_probs)
    best_threshold = best_stats['threshold']

    print(f"\n[*] Validation threshold : {best_threshold:.3f}")
    print(f"[*] Validation FP: {best_stats['fp']:,}  | FN: {best_stats['fn']:,}")
    print(f"[*] Accuracy:  {accuracy_score(y_test, best_stats['y_pred']):.4f}")
    print(f"[*] Precision: {best_stats['precision']:.4f}")
    print(f"[*] Recall:    {best_stats['recall']:.4f}")
    print(f"[*] F1-Score:  {best_stats['f1']:.4f}")

    print("\n[*] Generating Confusion Matrix visualization...")
    os.makedirs(VISUALS_DIR, exist_ok=True)
    cm = confusion_matrix(y_test, best_stats['y_pred'], labels=[0, 1])
    fig, ax = plt.subplots(figsize=(7, 6))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Legitimate", "Phishing"])
    disp.plot(cmap="Blues", ax=ax, values_format="d")
    plt.title("Confusion Matrix - Validation Set")
    
    cm_path = os.path.join(VISUALS_DIR, "confusion_matrix.png")
    plt.savefig(cm_path, bbox_inches="tight", dpi=300)
    plt.close(fig)
    print(f"[*] Confusion matrix saved to {cm_path}")

    print("\n[*] Saving trained model to disk...")
    # Ensuring Desktop path exists 
    os.makedirs(os.path.dirname(MODEL_ARTIFACTS_FILE), exist_ok=True)
    joblib.dump({
        'model': cal_model,
        'scaler': scaler,
        'threshold': best_threshold,
        'feature_columns': feature_columns
    }, MODEL_ARTIFACTS_FILE)
    print(f"[*] Artifacts successfully saved to {MODEL_ARTIFACTS_FILE}")

    return cal_model, scaler, best_threshold, feature_columns

def apply_post_rules(url, features, probabilities):
    phishing_prob = float(probabilities[1])
    legit_prob    = float(probabilities[0])
    _, domain, path, query = parse_url_parts(url)
    sld, tld = get_sld_tld(domain)

    if domain in ABSOLUTE_TRUSTED: return "Legitimate", max(legit_prob, 0.99)
    if features.get('is_free_hosting', 0) == 1 and phishing_prob > 0.40: return "Phishing", max(phishing_prob, 0.95)
    if features.get('is_dynamic_dns', 0) == 1 and phishing_prob > 0.40: return "Phishing", max(phishing_prob, 0.95)
    if features.get('uses_https', 0) == 0 and features.get('is_suspicious_tld', 0) == 1 and len(path) > 1: return "Phishing", max(phishing_prob, 0.96)
    if features.get('is_url_shortener', 0) == 1 and (features.get('has_hex_hash_path', 0) == 1 or features.get('uses_https', 0) == 0): return "Phishing", max(phishing_prob, 0.97)
    if features.get('is_suspicious_tld', 0) == 1 and features.get('login_keyword_in_path', 0) == 1: return "Phishing", max(phishing_prob, 0.96)
    if features.get('is_typosquatting_attempt', 0) == 1: return "Phishing", max(phishing_prob, 0.98)
    
    if features.get('is_url_shortener', 0) == 1 and (features.get('has_suspicious_keyword', 0) == 1 or features.get('brand_in_path_untrusted', 0) == 1): return "Phishing", max(phishing_prob, 0.975)
    if features.get('has_compromised_cms', 0) == 1 and features.get('has_suspicious_keyword', 0) == 1: return "Phishing", max(phishing_prob, 0.985)
    if features.get('has_url_in_path', 0) == 1: return "Phishing", max(phishing_prob, 0.985)
    
    if features.get('is_cloud_abuse', 0) == 1 and (features.get('brand_in_path_untrusted', 0) == 1 or features.get('brand_in_query_untrusted', 0) == 1 or features.get('has_suspicious_keyword', 0) == 1): return "Phishing", max(phishing_prob, 0.98)
    if features.get('brand_plus_suspicious_keyword', 0) == 1: return "Phishing", max(phishing_prob, 0.975)
    if features.get('brand_in_subdomain_mismatch', 0) == 1: return "Phishing", max(phishing_prob, 0.97)
    if features.get('edit_distance_brand_attack', 0) == 1 and features.get('has_suspicious_keyword', 0) == 1: return "Phishing", max(phishing_prob, 0.97)
    if features.get('contains_brand_on_untrusted', 0) == 1 and features.get('is_suspicious_tld', 0) == 1: return "Phishing", max(phishing_prob, 0.965)
    
    if features.get('has_punycode_domain', 0) == 1 and (features.get('high_similarity_brand_attack', 0) == 1 or features.get('contains_brand_on_untrusted', 0) == 1): return "Phishing", max(phishing_prob, 0.97)
    if features.get('excessive_subdomains', 0) == 1 and (features.get('login_keyword_in_path', 0) == 1 or features.get('contains_brand_on_untrusted', 0) == 1): return "Phishing", max(phishing_prob, 0.955)
    if domain.endswith('microsoftonline.com') and domain.startswith('login.'): return "Legitimate", max(legit_prob, 0.90)

    if features.get('is_likely_portal', 0) == 1 and phishing_prob < 0.72:
        if features.get('suspicious_signal_count', 0) <= 4 and features.get('email_in_url', 0) == 0: return "Legitimate", max(legit_prob, 0.85)
    if features.get('email_in_url', 0) == 1 and not features.get('is_trusted_brand', 0): return "Phishing", max(phishing_prob, 0.96)

    return None, None

def predict_single_url(url, model, scaler, threshold, feature_columns):
    url = normalize_input_url(url)
    features = extract_features(url)
    feat_df = pd.DataFrame([features]).fillna(0)

    for col in feature_columns:
        if col not in feat_df.columns:
            feat_df[col] = 0

    feat_sc = scaler.transform(feat_df[feature_columns])
    probs = model.predict_proba(feat_sc)[0]

    rule_label, rule_conf = apply_post_rules(url, features, probs)
    if rule_label is not None:
        return rule_label, rule_conf

    phishing_prob = float(probs[1])

    if phishing_prob >= threshold: return "Phishing", phishing_prob

    if (phishing_prob >= max(0.20, threshold - 0.10) and (
        features.get('is_typosquatting_attempt', 0) == 1 or
        features.get('brand_in_subdomain_mismatch', 0) == 1 or
        features.get('brand_plus_suspicious_keyword', 0) == 1 or
        features.get('suspicious_signal_count', 0) >= 6
    )):
        return "Phishing", max(phishing_prob, 0.90)

    return "Legitimate", float(probs[0])