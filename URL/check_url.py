import os
import sys
import concurrent.futures

current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
if root_dir not in sys.path: sys.path.insert(0, root_dir)

try:
    from ollama_analyzer import get_ai_analysis
except ImportError:
    def get_ai_analysis(*args, **kwargs): return {"impact_analysis": [], "countermeasures": []}

from url_utils import (ensure_url_scheme, is_valid_url_format, load_threat_lists, 
                       is_tranco_whitelisted, URLHAUS_SET, detect_typosquatting_and_homograph)
from url_apis import check_virustotal, check_google_safe_browsing, check_otx_url, get_url_intelligence, get_valid_screenshot
from url_scoring import calculate_url_threat_metrics

def evaluate_url(target_url):
    target_url = ensure_url_scheme(target_url)
    if not is_valid_url_format(target_url):
        return {"status": "ERROR", "is_safe": False, "details": ["Please enter a valid URL (e.g., example.com)"], "screenshot_url": None}

    load_threat_lists()
    details = []

    # Parallel lookups (Added screenshot API here)
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        f_vt = executor.submit(check_virustotal, target_url)
        f_gsb = executor.submit(check_google_safe_browsing, target_url)
        f_otx = executor.submit(check_otx_url, target_url)
        f_intel = executor.submit(get_url_intelligence, target_url)
        f_screen = executor.submit(get_valid_screenshot, target_url)

        vt_result = f_vt.result()
        gsb_result = f_gsb.result()
        otx_result = f_otx.result()
        intel = f_intel.result()
        screenshot_url = f_screen.result()

    is_whitelisted, tranco_domain = is_tranco_whitelisted(target_url)
    urlhaus_malicious = target_url in URLHAUS_SET
    brand_result = detect_typosquatting_and_homograph(target_url)

    # 1. Evaluate Metrics
    threat_score, tc_lvl, ph_lvl, risk_label, base_status, evidence_conf = calculate_url_threat_metrics(
        vt_result, gsb_result, otx_result, urlhaus_malicious, brand_result, is_whitelisted
    )

    # 2. Status Output Formatting
    status_msg = f"{base_status} / {risk_label.upper()} RISK"
    is_safe = (base_status == "LEGITIMATE")

    # 3. Assemble Details (Does not skip layers; applies whitelist note if found)
    if is_whitelisted:
        details.append(f"Top 1 Million Whitelist: Root domain '{tranco_domain}' found (Classified as Legitimate).")

    vt_mal = vt_result.get("stats", {}).get("malicious", 0)
    if vt_mal > 0:
        msg = f"VirusTotal flagged as Malicious ({vt_mal} engines)."
        if is_whitelisted: msg += " (Ignored due to exact whitelist presence)"
        details.append(msg)
    elif not vt_result.get("error"):
        details.append("VirusTotal: Clean.")
        
    if gsb_result.get("is_malicious"): 
        msg = "Google Safe Browsing flagged as Malicious/Phishing."
        if is_whitelisted: msg += " (Ignored due to exact whitelist presence)"
        details.append(msg)
    else: 
        details.append("Google Safe Browsing: Clean.")

    if otx_result.get("found"): 
        msg = f"AlienVault OTX flagged URL in {otx_result['pulse_count']} threat intelligence pulse(s)."
        if is_whitelisted: msg += " (Ignored due to exact whitelist presence)"
        details.append(msg)
    else: 
        details.append("AlienVault OTX: Clear.")

    if urlhaus_malicious: 
        msg = "URLhaus Database: URL actively flagged as malware distribution."
        if is_whitelisted: msg += " (Ignored due to exact whitelist presence)"
        details.append(msg)
        
    b = brand_result.get("matched_brand")
    b_txt = f" Matched brand: {b}." if b else ""
    if brand_result.get("homograph_risk") == 1:
        details.append(f"Homograph Attack: Domain uses deceiving characters to mimic trusted domain.{b_txt}")
    if brand_result.get("typosquat_risk") == 1:
        details.append(f"Typosquatting: Domain closely imitates a trusted domain.{b_txt}")

    # Append Intelligence
    details.append("--- Domain Intelligence ---")
    details.append(f"Resolved IP: {intel['ip']}")
    details.append(f"Hosting Location: {intel['country']}")
    details.append(f"ISP / Provider: {intel['isp']}")
    details.append(f"Registrant / Org: {intel['org']}")
    if intel['age_days'] >= 0:
        details.append(f"Domain Registered On: {intel['created']} (Age: {intel['age_days']} days)")
    else:
        details.append(f"Domain Registered On: {intel['created']}")

    # 4. Trigger AI
    ai_data = get_ai_analysis(target_url, "URL", threat_score, details)

    return {
        "status": status_msg,
        "is_safe": is_safe,
        "threat_score": threat_score,
        "threat_confidence": tc_lvl,
        "potential_harm": ph_lvl,
        "likelihood": tc_lvl,
        "impact": ph_lvl,
        "risk_label": risk_label,
        "severity": risk_label,
        "ai_impact": ai_data.get("impact_analysis", []),
        "ai_countermeasures": ai_data.get("countermeasures", []),
        "details": details,
        "screenshot_url": screenshot_url
    }