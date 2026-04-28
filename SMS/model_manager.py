import os
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split, cross_validate
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from preprocessing import preprocess_text

def load_and_clean_data():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    local_file_path = os.path.join(script_dir, "Combined-Labeled-Dataset.csv")
    
    try:
        df = pd.read_csv(local_file_path)
    except Exception as e:
        print(f"Error loading data: {e}. Ensure dataset exists.")
        exit()

    df = df[['message', 'smishing label']].dropna().drop_duplicates()
    df = df[df['smishing label'].isin([0, 1, '0', '1'])]
    df['smishing label'] = df['smishing label'].astype(int)
    return df

def train_and_evaluate(df):
    df['clean_message'] = df['message'].apply(preprocess_text)
    df = df[df['clean_message'].str.strip() != '']

    X_train, X_test, y_train, y_test = train_test_split(
        df['clean_message'], df['smishing label'], test_size=0.20, random_state=42
    )

    vectorizer = TfidfVectorizer(max_features=10000, ngram_range=(1, 2), sublinear_tf=True)
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)

    model = LogisticRegression(C=5.0, solver='lbfgs', max_iter=1000, class_weight={0: 1, 1: 2}, n_jobs=-1)

    # Cross Validation
    cv_results = cross_validate(model, X_train_tfidf, y_train, cv=5, scoring=['accuracy', 'precision', 'recall', 'f1'])
    print(f"\nCV Accuracy: {cv_results['test_accuracy'].mean():.4f} | F1-Score: {cv_results['test_f1'].mean():.4f}")

    # Final Train & Evaluate
    model.fit(X_train_tfidf, y_train)
    y_prob = model.predict_proba(X_test_tfidf)[:, 1]
    y_pred = (y_prob >= 0.60).astype(int)

    print(f"Holdout Accuracy: {accuracy_score(y_test, y_pred):.4f} | Precision: {precision_score(y_test, y_pred):.4f}")
    
    # RESTORED: Confusion Matrix
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("-" * 50)
    
    return model, vectorizer

def load_or_train_model():
    """Automatically loads existing artifacts or trains a new model if they don't exist."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(script_dir, 'smishing_model.pkl')
    vectorizer_path = os.path.join(script_dir, 'tfidf_vectorizer.pkl')

    if os.path.exists(model_path) and os.path.exists(vectorizer_path):
        print("[*] Loading existing ML model and vectorizer...")
        return joblib.load(model_path), joblib.load(vectorizer_path)
    
    print("[!] Saved model not found. Automatically initiating training pipeline...")
    dataset = load_and_clean_data()
    model, vectorizer = train_and_evaluate(dataset)
    
    joblib.dump(model, model_path)
    joblib.dump(vectorizer, vectorizer_path)
    print("[*] Model trained and artifacts saved successfully.")
    
    return model, vectorizer

def predict_sms_ml(raw_message, saved_model, saved_vectorizer):
    """Evaluates the text and returns only the classification label."""
    cleaned_text = preprocess_text(raw_message)
    vectorized_text = saved_vectorizer.transform([cleaned_text])
    probability = saved_model.predict_proba(vectorized_text)[0][1]
    
    return "Phishing" if probability >= 0.60 else "Legitimate"