import os
import sys
import ipaddress
import socket
import requests
import json

# Add root directory to path to import central Ollama module
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

try:
    from ollama_analyzer import get_ai_analysis
except ImportError:
    print("Warning: ollama_analyzer.py not found in root. AI insights disabled.")
    def get_ai_analysis(*args, **kwargs): return {"impact_analysis": [], "countermeasures": []}

# Configuration 
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

def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            clean = stats.get("clean", 0)
            unrated = stats.get("unrated", 0)
            timeout = stats.get("timeout", 0)
            
            total_engines = malicious + suspicious + undetected + unrated + clean + timeout
            
            return (malicious > 0 or suspicious > 0), malicious, suspicious, total_engines, "Success"
        return False, 0, 0, 0, f"Error {response.status_code}"
    except Exception as e:
        return False, 0, 0, 0, f"Error: {e}"

def get_findip_info(ip):
    url = f"https://api.findip.net/{ip}/?token={FINDIP_API_KEY}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass
    return None

def check_stopforumspam(ip):
    """Checks IP against StopForumSpam database for blacklist status"""
    url = f"https://api.stopforumspam.org/api?ip={ip}&json&confidence"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json().get("ip", {})
            return {
                "appears": data.get("appears", 0) == 1,
                "frequency": data.get("frequency", 0),
                "confidence": data.get("confidence", 0),
                "lastseen": data.get("lastseen", "Never"),
                "asn": data.get("asn", "N/A"),
                "country": data.get("country", "N/A"),
                "delegated": data.get("delegated", "N/A")
            }
    except Exception:
        pass
    return None

def calculate_threat_metrics(vt_malicious, vt_suspicious, vt_total, sfs_confidence):
    vt_score = 0
    if vt_total > 0:
        vt_base = (vt_malicious * 15) + (vt_suspicious * 5)
        vt_ratio = ((vt_malicious + (vt_suspicious * 0.5)) / vt_total) * 100
        vt_score = min(100.0, (vt_base * 0.6) + (vt_ratio * 0.4))
        
    combined_score = vt_score + sfs_confidence - ((vt_score * sfs_confidence) / 100)
    score = min(max(int(combined_score), 0), 100)
    
    if score < 30:       
        likelihood = 1
        impact = 1
    elif score < 70:     
        likelihood = 2
        impact = 2
    else:                
        likelihood = 3
        impact = 3
        
    return score, likelihood, impact

def evaluate_ip(ip_input):
    ip_obj = validate_ip(ip_input)
    
    if not ip_obj:
        return {
            "status": "Please enter a valid IP", 
            "is_safe": False, 
            "details": ["The provided input is invalid."]
        }
        
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified:
        return {
            "status": "Private/Internal IP",
            "is_safe": False,
            "details": ["The provided input is a private/internal network address and cannot be scanned externally."]
        }
    
    valid_ip = str(ip_obj)
    details = [f"Analyzing Public IP: {valid_ip}"]
    
    rdns_found, rdns_hostname = check_reverse_dns(valid_ip)
    is_malicious, vt_mal, vt_sus, vt_total, vt_status = check_virustotal(valid_ip)
    sfs_data = check_stopforumspam(valid_ip)
    ip_info = get_findip_info(valid_ip)
    
    sfs_confidence = sfs_data.get("confidence", 0) if sfs_data else 0
    threat_score, likelihood, impact = calculate_threat_metrics(vt_mal, vt_sus, vt_total, sfs_confidence)

    if threat_score >= 70:
        status = "MALICIOUS / PHISHING"
        is_safe = False
    elif threat_score >= 30:
        status = "SUSPICIOUS"
        is_safe = False
    else:
        status = "LEGITIMATE / SAFE"
        is_safe = True

    if vt_total > 0:
        if vt_mal > 0 or vt_sus > 0:
            details.append(f"VirusTotal Alert: {vt_mal} Malicious, {vt_sus} Suspicious (out of {vt_total} engines).")
        else:
            details.append(f"VirusTotal: Clean across {vt_total} security engines.")
    else:
        details.append(f"VirusTotal: Check failed or returned 0 engines ({vt_status}).")

    if sfs_data:
        if sfs_data["appears"]:
            details.append(f"StopForumSpam Alert: Flagged with {sfs_data['confidence']}% Confidence.")
            details.append(f"Frequency: Reported {sfs_data['frequency']} times across threat forums.")
            details.append(f"Last Reported Activity: {sfs_data['lastseen']}")
        else:
            details.append("StopForumSpam: IP not found in global spammer databases.")

    if rdns_found:
        details.append(f"Reverse DNS: Resolved to {rdns_hostname}")
    else:
        details.append("Reverse DNS: No hostname configured (Common in dynamic or botnet IPs).")

    if ip_info:
        try:
            continent = ip_info.get('continent', {}).get('names', {}).get('en')
            country = ip_info.get('country', {}).get('names', {}).get('en')
            city = ip_info.get('city', {}).get('names', {}).get('en')
            
            location = ip_info.get('location', {})
            accuracy_radius = location.get('accuracy_radius')
            
            traits = ip_info.get('traits', {})
            isp = traits.get('isp')
            org = traits.get('organization')
            asn = traits.get('autonomous_system_number')
            conn_type = traits.get('connection_type')

            if country: details.append(f"Location: {city if city else 'Unknown City'}, {country} ({continent})")
            if accuracy_radius: details.append(f"Accuracy Radius: {accuracy_radius}km")
            if isp: details.append(f"ISP: {isp}")
            if org and org != isp: details.append(f"Organization: {org}")
            if asn: details.append(f"ASN: AS{asn}")
            if conn_type: details.append(f"Connection Type: {conn_type}")

        except Exception:
            details.append("Note: Could not parse full geographic/network profile.")
    else:
        details.append("Network Intelligence: Could not fetch geographic or ISP data.")

    # Call Centralized Ollama Script
    ai_data = get_ai_analysis(valid_ip, "IP Address", threat_score, details)

    return {
        "status": status, 
        "is_safe": is_safe,
        "threat_score": threat_score,
        "likelihood": likelihood,
        "impact": impact,
        "ai_impact": ai_data.get("impact_analysis", []),
        "ai_countermeasures": ai_data.get("countermeasures", []),
        "details": details
    }