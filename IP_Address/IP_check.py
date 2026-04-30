import ipaddress
import socket
import requests

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
            return (malicious > 0 or suspicious > 0), malicious, suspicious, "Success"
        return False, 0, 0, f"Error {response.status_code}"
    except Exception as e:
        return False, 0, 0, f"Error: {e}"

def get_findip_info(ip):
    url = f"https://api.findip.net/{ip}/?token={FINDIP_API_KEY}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass
    return None

def evaluate_ip(ip_input):
    ip_obj = validate_ip(ip_input)
    
    if not ip_obj:
        return {
            "status": "Please enter a valid IP", 
            "is_safe": False, 
            "details": ["The provided input is invalid "]
        }
        
    
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified:
        return {
            "status": "This is a private IP address and cannot be used for detection.",
            "is_safe": False,
            "details": ["The provided input is a private/internal network address."]
        }
    
    
    valid_ip = str(ip_obj)
        
    details = [f"Analyzing Public IP: {valid_ip}"]
        
    
    rdns_found, rdns_hostname = check_reverse_dns(valid_ip)
    is_malicious, vt_mal, vt_sus, vt_status = check_virustotal(valid_ip)
    ip_info = get_findip_info(valid_ip)

    
    if is_malicious:
        status = " MALICIOUS / PHISHING"
        is_safe = False
        details.append(f"Flagged by VirusTotal ({vt_mal} malicious and {vt_sus} suspicious engines).")
    elif not rdns_found:
        status = "SUSPICIOUS"
        is_safe = False
        details.append("No Reverse DNS configured. Potentially dynamic, botnet, or unassigned IP.")
    else:
        status = "LEGITIMATE / SAFE"
        is_safe = True
        details.append("Clean across VirusTotal engines.")

    
    if rdns_found: 
        details.append(f"Reverse DNS Hostname: {rdns_hostname}")
    else:
        details.append("Reverse DNS Hostname: None (Resolution Failed)")

    if ip_info:
        try:
            
            continent = ip_info.get('continent', {}).get('names', {}).get('en')
            country = ip_info.get('country', {}).get('names', {}).get('en')
            city = ip_info.get('city', {}).get('names', {}).get('en')
            
            
            subdivisions = ip_info.get('subdivisions', [])
            state = subdivisions[0].get('names', {}).get('en') if subdivisions else None

            
            location = ip_info.get('location', {})
            time_zone = location.get('time_zone')
            accuracy_radius = location.get('accuracy_radius')
            
            
            traits = ip_info.get('traits', {})
            isp = traits.get('isp')
            org = traits.get('organization')
            asn = traits.get('autonomous_system_number')
            asn_org = traits.get('autonomous_system_organization')
            conn_type = traits.get('connection_type')
            user_type = traits.get('user_type')

            
            if continent: details.append(f"Continent: {continent}")
            if country: details.append(f"Country: {country}")
            if state: details.append(f"State/Province: {state}")
            if city: details.append(f"City: {city}")
            if time_zone: details.append(f"Time Zone: {time_zone}")
            if accuracy_radius: details.append(f"Location Accuracy Radius: {accuracy_radius}km")

            
            if isp: details.append(f"ISP (Internet Service Provider): {isp}")
            if org and org != isp: details.append(f"Organization: {org}")
            if asn: details.append(f"ASN: AS{asn} ({asn_org})")
            if conn_type: details.append(f"Connection Type: {conn_type}")
            if user_type: details.append(f"Network User Type: {user_type.capitalize()}")

        except Exception:
            details.append("Note: Could not parse full geographic/network profile.")
    else:
        details.append("Network Intelligence: Could not fetch geographic or ISP data.")

    return {
        "status": status, 
        "is_safe": is_safe, 
        "details": details
    }