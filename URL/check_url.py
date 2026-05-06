import os
import joblib
import urllib.parse
from url_utils import is_valid_url_format, ensure_url_scheme
from api_services import check_virustotal, check_google_safe_browsing, get_url_intelligence, api_has_usable_result
from model_pipeline import predict_single_url

def evaluate_url(target_url: str) -> dict:
    """
    Evaluates a URL using Threat Intel APIs and constructs HTML-safe result strings.
    """
    target_url = ensure_url_scheme(target_url)
    if not is_valid_url_format(target_url):
        return {
            "is_safe": False,
            "status": "Please enter a valid URL",
            "details": ["Please enter a valid URL or domain (e.g., example.com)"]
        }

    details = []
    is_safe = True
    screenshot_url = None  # Will hold the plain URL for the front-end

    # Primary API Checks
    vt_results = check_virustotal(target_url)
    gsb_results = check_google_safe_browsing(target_url)
    
    # Microlink Screenshot URL (direct image URL via embed parameter)
    encoded_url = urllib.parse.quote(target_url, safe='')
    screenshot_url = f"https://api.microlink.io/?url={encoded_url}&screenshot=true&meta=false&embed=screenshot.url"

    if api_has_usable_result(vt_results, gsb_results):
        details.append("Analysis completed via Threat Intelligence APIs.")
        
        # Google Safe Browsing Result
        if "error" not in gsb_results:
            if gsb_results.get("is_malicious"):
                is_safe = False
                details.append("Google Safe Browsing: Flagged as Malicious/Phishing.")
            else:
                details.append("Google Safe Browsing: Clean.")
        
        # VirusTotal Result
        if "error" not in vt_results:
            stats = vt_results.get('stats', {})
            malicious_count = stats.get('malicious', 0)
            if malicious_count > 0 or vt_results.get('reputation', 0) < 0:
                is_safe = False
                details.append(f"VirusTotal: Flagged as Malicious ({malicious_count} detections).")
            else:
                details.append("VirusTotal: Clean (No malicious signatures found).")

        # Metadata Enrichment
        intel = get_url_intelligence(target_url)
        details.append(f"Resolved IP: {intel.get('ip')}")
        details.append(f"Hosting Location: {intel.get('country')}")
        details.append(f"ISP / Provider: {intel.get('isp')}")
        details.append(f"Domain Registered On: {intel.get('created')}")

    else:
        # ML Fallback
        details.append("API results unavailable. Analyzing via local ML model.")
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            model_path = os.path.join(current_dir, "Phishing_URL_pipeline.pkl")
            
            if os.path.exists(model_path):
                data = joblib.load(model_path)
                label, _ = predict_single_url(target_url, data['pipeline'], data['threshold'])
                
                if label.lower() == "phishing":
                    is_safe = False
                    details.append("ML Model Verdict: Detected high-risk")
                else:
                    details.append("ML Model Verdict: URL appears legitimate.")
            else:
                return {"is_safe": False, "status": "ANALYSIS FAILED", "details": ["Model artifacts missing."]}
        except Exception as e:
            return {"is_safe": False, "status": "ERROR", "details": [f"ML failed: {str(e)}"]}

    return {
        "is_safe": is_safe,
        "status": "LEGITIMATE / SAFE" if is_safe else "PHISHING / MALICIOUS",
        "details": details,
        "screenshot_url": screenshot_url if api_has_usable_result(vt_results, gsb_results) else None
    }