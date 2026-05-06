import os
import joblib
import pandas as pd
from urllib.parse import urlparse

from url_utils import ensure_url_scheme, is_valid_url_format
from model_pipeline import train_and_evaluate, prepare_data
from check_url import evaluate_url
from config import MODEL_ARTIFACTS_FILE, DATASET_FILE


def display_result(result: dict) -> None:
    """Pretty print the evaluation result from evaluate_url()."""
    print("\n" + "=" * 60)
    print(f"  FINAL VERDICT: {result['status']}")
    print("=" * 60)
    print("\n[ Details ]")
    for line in result.get("details", []):
        print(f"  • {line}")

    if result.get("screenshot_url"):
        print("\n[ Screenshot ]")
        print(f"  {result['screenshot_url']}")


def process_user_input(pipeline, threshold) -> None:
    print("\n" + "=" * 54)
    print("  Phishing URL Detection System (API + ML Fallback)")
    print("=" * 54)

    while True:
        raw_url = input("\nEnter the URL to check (or type 'exit' to quit): ").strip()
        if raw_url.lower() == "exit":
            print("Exiting. Stay secure!")
            break
        if not raw_url:
            print("  [!] URL cannot be empty.")
            continue

        url = ensure_url_scheme(raw_url)
        if not is_valid_url_format(url):
            print("  [!] Error: Please enter a valid URL.")
            print("  [i] Example: https://www.google.com or http://example.org")
            continue

    
        result = evaluate_url(url)
        display_result(result)

        pass


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    # Check if we have a pre‑trained model
    if os.path.exists(MODEL_ARTIFACTS_FILE):
        use_saved = input(f"[*] Found existing model '{MODEL_ARTIFACTS_FILE}'. Load it? (y/n): ").strip().lower()
        if use_saved == 'y':
            print("[*] Loading saved model pipeline...")
            data = joblib.load(MODEL_ARTIFACTS_FILE)
            process_user_input(data['pipeline'], data['threshold'])
            return

    # Otherwise train from dataset
    if not os.path.exists(DATASET_FILE):
        print(f"[!] Error: Training dataset '{DATASET_FILE}' not found.")
        return

    try:
        df = pd.read_csv(DATASET_FILE)
        if 'url' not in df.columns or 'type' not in df.columns:
            df = pd.read_csv(DATASET_FILE, header=None, names=['url', 'type'])
        print(f"[*] Loaded dataset: {len(df):,} records.")
    except Exception as exc:
        print(f"Error loading dataset: {exc}")
        return

    X, y = prepare_data(df)
    pipeline, threshold = train_and_evaluate(X, y)
    process_user_input(pipeline, threshold)


if __name__ == "__main__":
    main()