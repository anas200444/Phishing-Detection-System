import os
import sys
import re
from pathlib import Path


current_dir = Path(__file__).resolve().parent
parent_dir = current_dir.parent


if str(current_dir) not in sys.path: sys.path.insert(0, str(current_dir))
if str(parent_dir) not in sys.path: sys.path.insert(0, str(parent_dir))

#  discover all subdirectories in the parent folder
# (e.g., "URL", "IP Address", "Email", "Phone", or variations like "IP_check")
for root, dirs, files in os.walk(parent_dir):
  
    if any(part.startswith('.') or part == '__pycache__' for part in Path(root).parts):
        continue
    if root not in sys.path:
        sys.path.insert(0, root)



URL_MODEL_DATA = None

def load_url_model():
    global URL_MODEL_DATA
    if URL_MODEL_DATA is None:
        try:
            import joblib
            import config  
            if os.path.exists(config.MODEL_ARTIFACTS_FILE):
                URL_MODEL_DATA = joblib.load(config.MODEL_ARTIFACTS_FILE)
            else:
                URL_MODEL_DATA = False 
        except Exception:
            URL_MODEL_DATA = False
    return URL_MODEL_DATA

def check_phone_integration(phone_num):
    try:
        import check_phone
        result = check_phone.check_phone_number(phone_num)
        return not result.get("is_safe", True)
    except Exception as e:
        print(f"  [!] Phone integration error: {e}")
        return False

def check_email_integration(email_addr):
    try:
        import check_email
        result = check_email.evaluate_email(email_addr)
        return not result.get("is_safe", True)
    except Exception as e:
        print(f"  [!] Email integration error: {e}")
        return False

def check_ip_integration(ip_addr):
    try:
        import IP_check
        result = IP_check.evaluate_ip(ip_addr)
        return not result.get("is_safe", True)
    except Exception as e:
        print(f"  [!] IP integration error: {e}")
        return False

def check_url_integration(url):
    try:
        import api_services
        vt_results = api_services.check_virustotal(url)
        if "error" not in vt_results:
            stats = vt_results.get('stats', {})
            reputation = vt_results.get('reputation', 0)
            if stats.get('malicious', 0) > 0 or reputation < 0:
                return True
        
        model_data = load_url_model()
        if model_data:
            import model_pipeline
            label, _ = model_pipeline.predict_single_url(
                url, model_data['model'], model_data['scaler'], 
                model_data['threshold'], model_data['feature_columns']
            )
            if label == "Phishing": 
                return True
        return False
    except Exception as e:
        print(f"  [!] URL integration error: {e}")
        return False

def extract_elements(text):
    email_pattern = r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}'
    emails = re.findall(email_pattern, text)
    
    ip_pattern = r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
    ips = re.findall(ip_pattern, text)
    
   
    url_pattern = r'(?i)(?:https?://|www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[-a-zA-Z0-9()@:%_+.~#?&//=]*)?'
    raw_urls = re.findall(url_pattern, text)
    
    clean_urls = []
    for u in raw_urls:
        u = u.rstrip('.,;!?')
        if not any(u in email for email in emails) and not any(u in ip for ip in ips):
            if '.' in u and len(u) > 3: 
                clean_urls.append(u)
    
    phone_pattern = r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
    phones = re.findall(phone_pattern, text)

    return {
        "emails": list(set(emails)),
        "ips": list(set(ips)),
        "urls": list(set(clean_urls)),
        "phones": list(set(phones))
    }

def analyze_rule_based(sms_text):
    """Executes rule-based extraction. Prints elements and returns (is_phishing, flagged_element)."""
    elements = extract_elements(sms_text)
    
    found_any = any(len(v) > 0 for v in elements.values())
    if not found_any:
        print("  [*] No extractable entities (URL, IP, Email, Phone) found.")
        return False, None

    print("  [+] Extracted Entities:")
    for key, values in elements.items():
        if values:
            print(f"      - {key.capitalize()}: {values}")

    print("\n  [-] Analyzing extracted entities...")
    
    for ip in elements['ips']:
        if check_ip_integration(ip): return True, f"IP: {ip}"
    for url in elements['urls']:
        if check_url_integration(url): return True, f"URL: {url}"
    for email in elements['emails']:
        if check_email_integration(email): return True, f"Email: {email}"
    for phone in elements['phones']:
        if check_phone_integration(phone): return True, f"Phone: {phone}"

    return False, None