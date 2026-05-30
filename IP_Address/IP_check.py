import os
import sys
import ipaddress
import socket
import requests
import concurrent.futures
from urllib.parse import quote
from dotenv import load_dotenv

current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)

if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

load_dotenv(os.path.join(root_dir, ".env"))

try:
    from ollama_analyzer import get_ai_analysis
except ImportError:
    def get_ai_analysis(*args, **kwargs): return {"impact_analysis": [], "countermeasures": []}

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
FINDIP_API_KEY = os.getenv("FINDIP_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")

def validate_ip(ip_string):
    try:
        return ipaddress.ip_address(str(ip_string).strip())
    except ValueError:
        return None

def check_reverse_dns(ip):
    try:
        hostnames = socket.gethostbyaddr(ip)
        return True, hostnames[0]
    except Exception as e:
        return False, str(e)

def check_virustotal(ip, session):
    if not VIRUSTOTAL_API_KEY:
        return {"malicious": 0, "suspicious": 0, "total": 0, "status": "VirusTotal API key missing"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = session.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            attrs = response.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "total": sum(stats.values()),
                "network": attrs.get("network", "Unknown"),
                "asn": attrs.get("asn", "Unknown"),
                "as_owner": attrs.get("as_owner", "Unknown"),
                "continent": attrs.get("continent", "Unknown"),
                "status": "Success"
            }
        return {"malicious": 0, "suspicious": 0, "total": 0, "status": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"malicious": 0, "suspicious": 0, "total": 0, "status": str(e)}

def get_findip_info(ip, session):
    if not FINDIP_API_KEY:
        return None

    url = f"https://api.findip.net/{ip}/?token={FINDIP_API_KEY}"
    try:
        response = session.get(url, timeout=5)
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass
    return None

def check_stopforumspam(ip, session):
    url = f"https://api.stopforumspam.org/api?ip={ip}&json&confidence"
    try:
        response = session.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json().get("ip", {})
            return {
                "appears": data.get("appears", 0) == 1,
                "frequency": data.get("frequency", 0),
                "confidence": data.get("confidence", 0),
                "lastseen": data.get("lastseen", "Never")
            }
    except Exception:
        pass
    return {"appears": False, "frequency": 0, "confidence": 0, "lastseen": "Never"}

def check_otx_ip(ip, session):
    if not OTX_API_KEY:
        return {"found": False, "pulse_count": 0}

    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    try:
        response = session.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            return {"found": pulse_count > 0, "pulse_count": pulse_count}
    except Exception:
        pass
    return {"found": False, "pulse_count": 0}

def calculate_threat_metrics(vt_data, sfs_data, otx_data):
    vt_mal = vt_data.get("malicious", 0)
    vt_sus = vt_data.get("suspicious", 0)
    sfs_conf = sfs_data.get("confidence", 0)
    sfs_freq = sfs_data.get("frequency", 0)
    otx_pulses = otx_data.get("pulse_count", 0)
    vt_score = (vt_mal * 15) + (vt_sus * 5)
    sfs_score = (sfs_conf / 100.0) * (sfs_freq * 2)
    otx_score = otx_pulses * 0.9
    threat_score = min(99, max(5, int(vt_score + sfs_score + otx_score)))

    matrix = [
        (24, "LEGITIMATE", "Low", 1, 1),
        (49, "SUSPICIOUS", "Medium", 2, 2),
        (74, "MALICIOUS", "High", 3, 3),
        (100, "MALICIOUS", "Critical", 3, 3)
    ]

    base_status, risk_label, threat_confidence_level, potential_harm_level = next(
        (status, label, conf, harm) for threshold, status, label, conf, harm in matrix if threat_score <= threshold
    )

    evidence_confidence = 30
    evidence_confidence += 40 if (vt_mal + vt_sus) > 0 else 0
    evidence_confidence += 20 if (sfs_conf + sfs_freq) > 0 else 0
    evidence_confidence += 10 if otx_pulses > 0 else 0

    evidence_confidence = min(99, evidence_confidence)

    return (
        threat_score,
        threat_confidence_level,
        potential_harm_level,
        risk_label,
        base_status,
        evidence_confidence
    )

def evaluate_ip(ip_input):
    ip_obj = validate_ip(ip_input)

    if not ip_obj:
        return {"status": "Invalid IP Format", "is_safe": False, "details": ["The provided input is not a valid IP address."]}

    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified:
        return {"status": "Private/Internal IP", "is_safe": False, "details": ["Private or internal network addresses cannot be scanned externally."]}

    valid_ip = str(ip_obj)
    details = []

    with requests.Session() as session:
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_rdns = executor.submit(check_reverse_dns, valid_ip)
            future_vt = executor.submit(check_virustotal, valid_ip, session)
            future_sfs = executor.submit(check_stopforumspam, valid_ip, session)
            future_otx = executor.submit(check_otx_ip, valid_ip, session)
            future_ipinfo = executor.submit(get_findip_info, valid_ip, session)

            rdns_found, rdns_hostname = future_rdns.result()
            vt_data = future_vt.result()
            sfs_data = future_sfs.result()
            otx_data = future_otx.result()
            ip_info = future_ipinfo.result()

    threat_score, threat_confidence, potential_harm, risk_label, base_status, evidence_confidence = calculate_threat_metrics(vt_data, sfs_data, otx_data)

    status_msg = f"{base_status} / {risk_label.upper()} RISK"
    is_safe = (base_status == "LEGITIMATE")

    details.append(f"Target Public IP: {valid_ip}")

    if ip_info:
        try:
            country = ip_info.get('country', {}).get('names', {}).get('en', 'Unknown')
            city = ip_info.get('city', {}).get('names', {}).get('en', 'Unknown')
            traits = ip_info.get('traits', {})
            location = ip_info.get('location', {})

            isp = traits.get('isp', 'Unknown ISP')
            org = traits.get('organization', 'Unknown Organization')
            conn_type = traits.get('connection_type', 'Unknown Type')
            user_type = traits.get('user_type', 'Unknown Profile')

            tz = location.get('time_zone', 'N/A')

            details.append(f"Geolocation: {city}, {country}")
            details.append(f"Timezone: {tz}")
            details.append(f"Network ISP: {isp}")
            if org and org != isp:
                details.append(f"Organization: {org}")
            details.append(f"Connection Type : {conn_type}")
            details.append(f"User Identity : {user_type}")
        except Exception:pass

    details.append(f"Reverse DNS: {rdns_hostname if rdns_found else 'No domain attached ( indicates dynamic allocation)'}")

    net_block = vt_data.get('network', 'Unknown Block')
    asn = vt_data.get('asn', 'Unknown ASN')
    as_owner = vt_data.get('as_owner', 'Unknown Owner')
    details.append(f"Subnet & Topology: Block {net_block} routed via AS{asn} ({as_owner})")

    vt_total = vt_data.get("total", 0)
    vt_mal = vt_data.get("malicious", 0)
    vt_sus = vt_data.get("suspicious", 0)

    if vt_total > 0:
        if vt_mal > 0 or vt_sus > 0:
            details.append(f"VirusTotal: Flagged {vt_mal} Malicious, {vt_sus} Suspicious (across {vt_total} security engines).")
        else:
            details.append(f"VirusTotal: Categorized Clean across {vt_total} security engines.")
    else:
        details.append(f"VirusTotal: Request failed or yielded 0 engines ({vt_data.get('status')}).")

    if otx_data.get("found"):
        details.append(f"AlienVault OTX: Flagged IP in {otx_data['pulse_count']} threat intelligence pulse(s).")
    else:
        details.append("AlienVault OTX: Clear.")

    if sfs_data.get("appears"):
        details.append(f"Flagged in global spammer DBs with {sfs_data['confidence']}% spam confidence.")
        details.append(f"Historical Activity: Reported {sfs_data['frequency']} times.")
        details.append(f"Most recent activity: {sfs_data['lastseen']}")

    try:
        ai_data = get_ai_analysis(valid_ip, "IP Address", threat_score, details)
        if not isinstance(ai_data, dict):
            ai_data = {"impact_analysis": [], "countermeasures": []}
    except Exception:pass

    return {
        "status": status_msg,
        "is_safe": is_safe,
        "threat_score": threat_score,
        "threat_confidence": threat_confidence,
        "potential_harm": potential_harm,
        "likelihood": threat_confidence,
        "impact": potential_harm,
        "risk_label": risk_label,
        "severity": risk_label,
        "ai_impact": ai_data.get("impact_analysis", []),
        "ai_countermeasures": ai_data.get("countermeasures", []),
        "details": details
    }