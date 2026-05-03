import os
import joblib
import pandas as pd
from url_utils import is_valid_url_format, ensure_url_scheme
from model_pipeline import train_and_evaluate, prepare_data, predict_single_url
from api_services import check_virustotal, submit_and_poll_urlscan, api_has_usable_result, display_report
from config import MODEL_ARTIFACTS_FILE, DATASET_FILE

def analyze_url_api_first_then_ml(target_url: str, pipeline, threshold):
    print(f"\n[+] Starting analysis for: {target_url}")
    vt_results = check_virustotal(target_url)
    urlscan_data, scan_uuid = submit_and_poll_urlscan(target_url)

    if api_has_usable_result(vt_results, urlscan_data):
        print("\n[+] API returned a result. Skipping ML model.")
        display_report(urlscan_data, scan_uuid, vt_results, target_url)
        return

    print("\n[-] No usable API result found. Falling back to ML model...")
    label, prob = predict_single_url(target_url, pipeline, threshold)
    print(f"\n  ML Result -> [{label}]  confidence: {prob * 100:.2f}%")

def process_user_input(pipeline, threshold):
    print("\n" + "=" * 48)
    print("  Advanced Phishing URL Detection System")
    print("=" * 48)
    
    while True:
    
        url = input("\nEnter the URL to check (or type 'exit' to quit): ").strip()
        
        if url.lower() == 'exit':
            print("Exiting. Stay secure!")
            break

        if not url:
            print("  [!] URL cannot be empty.")
            continue
            
        url = ensure_url_scheme(url)
        if not is_valid_url_format(url):
            # Updated error message and example as requested
            print("  [!] Error: Please enter a valid URL.")
            print("  [i] Example: https://www.google.com or http://example.org")
            continue
            
        analyze_url_api_first_then_ml(url, pipeline, threshold)

def main():

    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    # --------------------------------------------------------------------------------

    if os.path.exists(MODEL_ARTIFACTS_FILE):
        ans = input(f"[*] Found existing model '{MODEL_ARTIFACTS_FILE}'. Load it? (y/n): ").strip().lower()
        if ans == 'y':
            print("[*] Loading saved model pipeline...")
            data = joblib.load(MODEL_ARTIFACTS_FILE)
            # Use the new pipeline keys
            process_user_input(data['pipeline'], data['threshold'])
            return

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
    # Unpack the new return values from train_and_evaluate
    pipeline, threshold = train_and_evaluate(X, y)
    process_user_input(pipeline, threshold)

if __name__ == "__main__":
    main()