import base64
import socket
import urllib.parse
import time
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from url_utils import normalize_url_for_vt, ensure_url_scheme, extract_domain, get_base_domain

try: import whois
except: whois = None

VT_API_KEY = "fb9ed8979176bc743716b6736bba75ddce368e7fd06f129517ff8b10e452bd9c"
GSB_API_KEY = "AIzaSyDwjly0YEpTNYtxg9qNcgTgvXT1HS3eU"
OTX_API_KEY = "a8d8b1329ba8afe42374251d6932540ecf6efe15b97b1b2e52bb5b68c1b54c93"

VT_HEADERS = {"accept": "application/json", "x-apikey": VT_API_KEY}
OTX_HEADERS = {"X-OTX-API-KEY": OTX_API_KEY, "Accept": "application/json"}
VT_SCAN_POLL_SECONDS, VT_SCAN_POLL_INTERVAL = 15, 3

def check_virustotal(target_url):
    if not VT_API_KEY: return {"error": "VirusTotal API key not configured."}
    
    parsed = urlparse(ensure_url_scheme(target_url))
    variants = list(dict.fromkeys(filter(None, [
        target_url.strip(), normalize_url_for_vt(target_url),
        f"{parsed.scheme.lower()}://{parsed.netloc.lower()}" if not parsed.query and not parsed.params else None
    ])))

    for variant in variants:
        endpoint = f"https://www.virustotal.com/api/v3/urls/{base64.urlsafe_b64encode(variant.encode()).decode().strip('=')}"
        try:
            resp = requests.get(endpoint, headers=VT_HEADERS, timeout=15)
            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                return {"stats": attrs.get("last_analysis_stats", {}), "reputation": attrs.get("reputation", 0), "source": "existing", "checked_url": variant}
        except: pass

    scan_url = normalize_url_for_vt(target_url)
    try:
        sub = requests.post("https://www.virustotal.com/api/v3/urls", headers={"accept": "application/json", "x-apikey": VT_API_KEY, "content-type": "application/x-www-form-urlencoded"}, data={"url": scan_url}, timeout=15)
        if sub.status_code in (200, 201):
            aid = sub.json().get("data", {}).get("id")
            deadline = time.time() + VT_SCAN_POLL_SECONDS
            while time.time() <= deadline:
                resp = requests.get(f"https://www.virustotal.com/api/v3/analyses/{aid}", headers=VT_HEADERS, timeout=15)
                if resp.status_code == 200 and resp.json().get("data", {}).get("attributes", {}).get("status") == "completed":
                    return {"stats": resp.json().get("data", {}).get("attributes", {}).get("stats", {}), "reputation": 0, "source": "new_scan", "checked_url": scan_url}
                time.sleep(VT_SCAN_POLL_INTERVAL)
        return {"error": "Scan submitted but pending."}
    except Exception as e: return {"error": str(e)}

def check_otx_url(target_url):
    if not OTX_API_KEY or OTX_API_KEY == "PUT_YOUR_OTX_API_KEY_HERE": return {"error": "OTX API key missing."}
    variants = [target_url, normalize_url_for_vt(target_url)]
    for v in variants:
        try:
            resp = requests.get(f"https://otx.alienvault.com/api/v1/indicators/url/{urllib.parse.quote(v, safe='')}/general", headers=OTX_HEADERS, timeout=4)
            if resp.status_code == 200:
                count = resp.json().get("pulse_info", {}).get("count", 0)
                if count > 0: return {"found": True, "pulse_count": count, "checked_url": v}
        except: pass
    return {"found": False, "pulse_count": 0}

def check_google_safe_browsing(target_url):
    if not GSB_API_KEY: return {"is_malicious": False}
    try:
        res = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}", json={"client": {"clientId": "phish", "clientVersion": "1.0"}, "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": target_url}]}}, timeout=5).json()
        return {"is_malicious": "matches" in res}
    except: return {"is_malicious": False}

def get_url_intelligence(target_url):
    domain = extract_domain(target_url).split(":")[0]
    base_domain = get_base_domain(domain)
    intel = {"domain": domain, "ip": "N/A", "country": "Unknown", "isp": "Unknown", "created": "Unknown", "org": "Private / Unknown", "age_days": -1}
    
    try: intel["ip"] = socket.gethostbyname(domain)
    except: pass
    
    if intel["ip"] != "N/A":
        try:
            geo = requests.get(f"https://ipapi.co/{intel['ip']}/json/", timeout=4).json()
            intel["country"], intel["isp"] = geo.get("country_name", "Unknown"), geo.get("org", "Unknown")
        except: pass
        
    if whois:
        try:
            w = whois.whois(base_domain)
            created = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            if created:
                intel["created"] = created.strftime("%Y-%m-%d")
                intel["age_days"] = (datetime.now() - created).days
            intel["org"] = w.org or w.registrar or intel["org"]
        except: pass
    return intel

def get_valid_screenshot(target_url):
    encoded = urllib.parse.quote(target_url, safe="")
    api_url = f"https://api.microlink.io/?url={encoded}&screenshot=true&meta=false"
    try:
        result = requests.get(api_url, timeout=10).json()
        if result.get("status") == "success":
            return result.get("data", {}).get("screenshot", {}).get("url")
    except Exception:
        pass
    return None