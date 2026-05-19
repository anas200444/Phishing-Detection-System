import os
import sys
import ipaddress
import socket
import requests
import concurrent.futures

current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

try:
    from ollama_analyzer import get_ai_analysis
except ImportError:
    print("Warning: ollama_analyzer.py not found in root. AI insights disabled.")
    def get_ai_analysis(*args, **kwargs): return {"impact_analysis": [], "countermeasures": []}

VIRUSTOTAL_API_KEY = "fb9ed8979176bc743716b6736bba75ddce368e7fd06f129517ff8b10e452bd9c"
FINDIP_API_KEY = "5527a178dd01467cb70b6236595645ef"

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

def calculate_threat_metrics(vt_data, sfs_data):
    vt_mal = vt_data.get("malicious", 0)
    vt_sus = vt_data.get("suspicious", 0)
    vt_total = vt_data.get("total", 0)
    sfs_conf = sfs_data.get("confidence", 0)
    sfs_freq = sfs_data.get("frequency", 0)

    # This project is a phishing/threat-intelligence detection system.
    # We should NOT pretend that we know true OWASP Likelihood and Impact,
    # because we do not know the victim organization's assets or business context.
    # Instead, we use an OWASP-derived matrix:
    #     Final Severity = Threat Confidence x Potential Harm
    # Same 0-9 scoring idea and Low/Medium/High mapping, but the factors are
    # suitable for detection/reputation data.

    vt_ratio = 0.0
    if vt_total > 0:
        vt_ratio = (vt_mal + (vt_sus * 0.5)) / vt_total

    # 1. Threat Confidence score, 0-9.
    # Meaning: how confident the system is that this indicator is actually abusive.
    threat_confidence_score = 0.0
    threat_confidence_score += vt_ratio * 4.0
    threat_confidence_score += min(2.4, vt_mal * 0.8)
    threat_confidence_score += min(1.0, vt_sus * 0.25)
    threat_confidence_score += (sfs_conf / 100.0) * 1.8
    threat_confidence_score += min(1.2, sfs_freq / 25.0)

    if vt_mal >= 2:
        threat_confidence_score += 0.8
    if vt_mal >= 5:
        threat_confidence_score += 0.8
    if vt_total == 0 and sfs_conf == 0 and sfs_freq == 0:
        threat_confidence_score = 0.5

    threat_confidence_score = min(9.0, threat_confidence_score)

    # 2. Potential Harm score, 0-9.
    # Meaning: generic harm if the indicator is malicious.
    # This is NOT organization-specific business impact.
    if vt_mal >= 5 or (vt_mal >= 2 and sfs_conf >= 50) or (sfs_conf >= 90 and sfs_freq >= 50):
        potential_harm_score = 7.5
    elif vt_mal >= 2 or sfs_conf >= 70 or sfs_freq >= 50:
        potential_harm_score = 6.0
    elif vt_mal == 1 or vt_sus > 0 or sfs_conf > 0 or sfs_freq > 0:
        potential_harm_score = 4.0
    else:
        potential_harm_score = 2.0

    # OWASP threshold style: 0-<3 Low, 3-<6 Medium, 6-9 High.
    def scale_level(score):
        if score < 3:
            return 1
        if score < 6:
            return 2
        return 3

    threat_confidence_level = scale_level(threat_confidence_score)
    potential_harm_level = scale_level(potential_harm_score)

    # OWASP-derived severity matrix.
    # Format: (Threat Confidence, Potential Harm)
    # 1 = Low, 2 = Medium, 3 = High
    risk_matrix = {
        (3, 3): "Critical",
        (3, 2): "High",
        (3, 1): "Medium",
        (2, 3): "High",
        (2, 2): "Medium",
        (2, 1): "Low",
        (1, 3): "Medium",
        (1, 2): "Low",
        (1, 1): "Note"
    }

    risk_label = risk_matrix.get((threat_confidence_level, potential_harm_level), "Note")

    # 0-100 UI score derived from the two matrix inputs.
    threat_score = min(100, int(((threat_confidence_score + potential_harm_score) / 18.0) * 100))

    # Evidence quality/confidence: how much data the engine had to make the decision.
    evidence_confidence = 20
    if vt_total > 0:
        evidence_confidence += min(45, int((vt_total / 90.0) * 45))
    if vt_mal > 0 or vt_sus > 0:
        evidence_confidence += 15
    if sfs_conf > 0:
        evidence_confidence += min(15, int(sfs_conf * 0.15))
    if sfs_freq > 0:
        evidence_confidence += min(5, int(sfs_freq / 10))
    evidence_confidence = min(100, evidence_confidence)

    # Final detection status.
    if risk_label in ["Critical", "High"] or vt_mal >= 2 or sfs_conf >= 70:
        base_status = "MALICIOUS"
    elif risk_label == "Medium" or vt_mal == 1 or vt_sus > 0 or sfs_conf > 0 or sfs_freq > 0:
        base_status = "SUSPICIOUS"
    else:
        base_status = "LEGITIMATE"

    return threat_score, threat_confidence_level, potential_harm_level, risk_label, base_status, evidence_confidence

def evaluate_ip(ip_input):
    ip_obj = validate_ip(ip_input)
    
    if not ip_obj:
        return {"status": "Invalid IP Format", "is_safe": False, "details": ["The provided input is not a valid IPv4/IPv6 address."]}
        
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified:
        return {"status": "Private/Internal IP", "is_safe": False, "details": ["Private or internal network addresses cannot be scanned externally."]}
    
    valid_ip = str(ip_obj)
    details = []
    
    with requests.Session() as session:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            future_rdns = executor.submit(check_reverse_dns, valid_ip)
            future_vt = executor.submit(check_virustotal, valid_ip, session)
            future_sfs = executor.submit(check_stopforumspam, valid_ip, session)
            future_ipinfo = executor.submit(get_findip_info, valid_ip, session)
            
            rdns_found, rdns_hostname = future_rdns.result()
            vt_data = future_vt.result()
            sfs_data = future_sfs.result()
            ip_info = future_ipinfo.result()
            
    threat_score, threat_confidence, potential_harm, risk_label, base_status, evidence_confidence = calculate_threat_metrics(vt_data, sfs_data)
    
    status_msg = f"{base_status} / {risk_label.upper()} RISK"
    is_safe = (base_status == "LEGITIMATE")

    details.append(f"Target Public IP: {valid_ip}")
    # Removed the "Risk Model:" line as requested
    
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
            
            lat = location.get('latitude', 'N/A')
            lon = location.get('longitude', 'N/A')
            tz = location.get('time_zone', 'N/A')
            
            # Geolocation line without coordinates
            details.append(f"Geolocation: {city}, {country}")
            details.append(f"Timezone: {tz}")
            details.append(f"Network ISP: {isp}")
            if org and org != isp:
                details.append(f"Organization: {org}")
            # Split Routing Profile into two lines
            details.append(f"Connection Type : {conn_type}")
            details.append(f"User Identity : {user_type}")
        except Exception:
            details.append("Network Intelligence: Could not parse deep geographic profile.")
    
    details.append(f"Reverse DNS: {rdns_hostname if rdns_found else 'No domain attached (Often indicates dynamic or botnet allocation)'}")

    net_block = vt_data.get('network', 'Unknown Block')
    asn = vt_data.get('asn', 'Unknown ASN')
    as_owner = vt_data.get('as_owner', 'Unknown Owner')
    details.append(f"Subnet & Topology: Block {net_block} routed via AS{asn} ({as_owner})")

    vt_total = vt_data.get("total", 0)
    vt_mal = vt_data.get("malicious", 0)
    vt_sus = vt_data.get("suspicious", 0)

    if vt_total > 0:
        if vt_mal > 0 or vt_sus > 0:
            details.append(f"VirusTotal Consensus: Flagged {vt_mal} Malicious, {vt_sus} Suspicious (across {vt_total} security engines).")
        else:
            details.append(f"VirusTotal Consensus: Categorized Clean across {vt_total} security engines.")
    else:
        details.append(f"VirusTotal Consensus: Request failed or yielded 0 engines ({vt_data.get('status')}).")

    if sfs_data.get("appears"):
        details.append(f"Threat Intelligence: Flagged in global spammer DBs with {sfs_data['confidence']}% spam confidence.")
        # Historical Activity split into two lines
        details.append(f"Historical Activity: Reported {sfs_data['frequency']} times across threat forums.")
        details.append(f"Most recent activity: {sfs_data['lastseen']}")

    ai_data = get_ai_analysis(valid_ip, "IP Address", threat_score, details)

    return {
        "status": status_msg, 
        "is_safe": is_safe,
        "threat_score": threat_score,
        "threat_confidence": threat_confidence,
        "potential_harm": potential_harm,
        "likelihood": threat_confidence,  # kept for old frontend compatibility
        "impact": potential_harm,        # kept for old frontend compatibility
        "risk_label": risk_label,
        "severity": risk_label,
        # Removed the "confidence" field to exclude Evidence Confidence from Analysis Status
        "ai_impact": ai_data.get("impact_analysis", []),
        "ai_countermeasures": ai_data.get("countermeasures", []),
        "details": details
    }