import os
import joblib
from .url_utils import is_valid_url_format, ensure_url_scheme
from .api_services import check_virustotal, submit_and_poll_urlscan, api_has_usable_result
from .model_pipeline import predict_single_url

def evaluate_url(target_url: str) -> dict:
    """
    Evaluates a URL using Threat Intel APIs first, falling back to ML.
    """
    # 1. Validation
    target_url = ensure_url_scheme(target_url)
    if not is_valid_url_format(target_url):
        return {
            "is_safe": False,
            "status": "Please enter a valid URL",
            "details": ["Please enter a valid URL or domain (e.g., example.com)"]
        }

    details = []
    is_safe = True

    
    vt_results = check_virustotal(target_url)
    urlscan_data, scan_uuid = submit_and_poll_urlscan(target_url)

    if api_has_usable_result(vt_results, urlscan_data):
        details.append("Analysis completed via Threat Intelligence APIs.")
        
        
        if "error" not in vt_results:
            stats = vt_results.get('stats', {})
            malicious_count = stats.get('malicious', 0)
            if malicious_count > 0 or vt_results.get('reputation', 0) < 0:
                is_safe = False
                details.append(f"VirusTotal : Flagged as Malicious (Detections: {malicious_count}).")
            else:
                details.append("VirusTotal : Clean (No malicious signatures found).")

        
        if urlscan_data:
            overall = urlscan_data.get('verdicts', {}).get('overall', {})
            if overall.get('malicious', False):
                is_safe = False
                details.append("urlscan.io: Categorized as Malicious.")
            else:
                details.append("urlscan.io : No direct threats found.")

            # Extract useful server/network information
            page_data = urlscan_data.get('page', {})
            ip_addr = page_data.get('ip', 'N/A')
            country = page_data.get('country', 'N/A')
            server = page_data.get('server', 'N/A')
            asn = page_data.get('asnname', 'Unknown')
            
            # Append the extracted info to the details list
            details.append(f"Hosted IP Address: {ip_addr}")
            details.append(f"Server Location (Country): {country}")
            details.append(f"Server Name: {server}")
            details.append(f"ISP / ASN: {asn}")

            
            if scan_uuid:
                screenshot_url = f"https://urlscan.io/screenshots/{scan_uuid}.png"
                
                link_html = f"<a href='{screenshot_url}' target='_blank' style='color: var(--primary-color, #4facfe); text-decoration: underline;'>View Sandbox Screenshot</a>"
                details.append(f"Live Capture: {link_html}")

    else:
        # 3. ML Fallback (No APIs available)
        details.append("API results unavailable. Analyzing via local ML model.")
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            model_path = os.path.join(current_dir, "Phishing_URL_pipeline.pkl")
            
            if os.path.exists(model_path):
                data = joblib.load(model_path)
                label, _ = predict_single_url(target_url, data['pipeline'], data['threshold'])
                
                if label.lower() == "phishing":
                    is_safe = False
                    details.append("ML Model Verdict: Detected high-risk ")
                else:
                    details.append("ML Model Verdict: URL appears legitimate.")
            else:
                return {
                    "is_safe": False, 
                    "status": "ANALYSIS FAILED", 
                    "details": ["ML Model artifacts not found on the server."]
                }
        except Exception as e:
            return {
                "is_safe": False, 
                "status": "ERROR", 
                "details": [f"ML analysis failed: {str(e)}"]
            }

    # 4. Final Output Formatting
    return {
        "is_safe": is_safe,
        "status": "LEGITIMATE / SAFE" if is_safe else "PHISHING / MALICIOUS",
        "details": details
    }