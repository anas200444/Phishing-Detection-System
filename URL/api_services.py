import base64
import socket
import requests
import whois
from datetime import datetime
from config import VT_HEADERS, GSB_API_KEY
from url_utils import extract_domain   # changed from .url_utils

def check_virustotal(target_url: str) -> dict:
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    vt_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:
        response = requests.get(vt_endpoint, headers=VT_HEADERS, timeout=15)
        if response.status_code == 200:
            attributes = response.json().get('data', {}).get('attributes', {})
            return {
                "stats": attributes.get('last_analysis_stats', {}),
                "reputation": attributes.get('reputation', 0)
            }
        return {"error": "No previous scan found or API error."}
    except Exception as e:
        return {"error": str(e)}

def check_google_safe_browsing(target_url: str) -> dict:
    if not GSB_API_KEY or GSB_API_KEY == 'AIzaSyDwjly0Y_EpTNYtxg9qNc_gTgvXT1HS3eU':
         return {"is_malicious": False, "error": "GSB API Key not configured."}

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
    payload = {
        "client": {"clientId": "phish-detector", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": target_url}]
        }
    }
    try:
        response = requests.post(endpoint, json=payload, timeout=10)
        result = response.json()
        return {"is_malicious": "matches" in result, "details": result.get("matches", [])}
    except Exception:
        return {"is_malicious": False, "error": "GSB Lookup Failed"}

def get_url_intelligence(target_url: str) -> dict:
    """Enhanced intelligence using socket, multiple geolocation APIs, and whois."""
    domain = extract_domain(target_url)
    intel = {
        "domain": domain, 
        "ip": "N/A", 
        "country": "Unknown", 
        "isp": "Unknown", 
        "created": "N/A",
        "org": "N/A"
    }

    # 1. Local IP Resolution (Using Python Socket - No API)
    try:
        intel["ip"] = socket.gethostbyname(domain)
    except:
        pass

    # 2. Geolocation – try multiple free APIs (no API key needed)
    ip = intel["ip"]
    if ip != "N/A":
        # Primary: ipapi.co
        country = "Unknown"
        isp = "Unknown"
        try:
            geo = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5).json()
            if not geo.get("error"):
                country = geo.get("country_name", "Unknown")
                isp = geo.get("org", "Unknown")
        except:
            pass

        # Fallback: ip-api.com if still unknown
        if country == "Unknown" or isp == "Unknown":
            try:
                geo2 = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
                if geo2.get("status") == "success":
                    country = geo2.get("country", country)
                    isp = geo2.get("isp", isp) or geo2.get("org", isp)
            except:
                pass

        intel["country"] = country or "Unknown"
        intel["isp"] = isp or "Unknown"

    # 3. Domain Registration via python-whois (No API Key required)
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            intel["created"] = creation_date.strftime("%Y-%m-%d")
        intel["org"] = w.org or "Private"
    except:
        pass

    return intel

def api_has_usable_result(vt_results: dict, gsb_results: dict) -> bool:
    vt_ok = isinstance(vt_results, dict) and "error" not in vt_results
    gsb_ok = isinstance(gsb_results, dict) and "error" not in gsb_results
    return vt_ok or gsb_ok