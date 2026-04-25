import os
import sys
import ipaddress
import socket
import requests

#API keys
VIRUSTOTAL_API_KEY = "fb9ed8979176bc743716b6736bba75ddce368e7fd06f129517ff8b10e452bd9c"
FINDIP_API_KEY = "5527a178dd01467cb70b6236595645ef"

def validate_ip(ip_string):
    """Validates if the provided string is a valid, public IP address."""
    try:
        ip = ipaddress.ip_address(ip_string)
        if ip.is_private or ip.is_loopback:
            print(f"[-] {ip_string} is a private or loopback IP address.")
            return None
        return str(ip)
    except ValueError:
        return None

def check_reverse_dns(ip):
    """Infrastructure Check (Reverse DNS / PTR Record)."""
    try:
        hostnames = socket.gethostbyaddr(ip)
        return True, hostnames[0]
    except socket.herror:
        return False, None
    except Exception as e:
        return False, str(e)

def check_virustotal(ip):
    """Global Threat Intelligence Check via VirusTotal API."""
    if VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        return False, 0, 0, "Skipped (No API Key)"

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            
            is_flagged = (malicious > 0 or suspicious > 0)
            return is_flagged, malicious, suspicious, "Success"
            
        elif response.status_code == 401:
            return False, 0, 0, "Invalid API Key"
        else:
            return False, 0, 0, f"HTTP Error {response.status_code}"
    except requests.exceptions.RequestException as e:
        return False, 0, 0, f"Network Error: {e}"
    except ValueError:
        return False, 0, 0, "Parse Error"

def get_findip_info(ip):
    """General IP Enrichment (Location, ISP, Network Traits) via FindIP.net."""
    if FINDIP_API_KEY == "YOUR_FINDIP_API_KEY":
        print("    [!] FindIP API key not set. Skipping general info check.")
        return None

    url = f"https://api.findip.net/{ip}/?token={FINDIP_API_KEY}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            
            # Location Extraction
            continent = data.get('continent', {}).get('names', {}).get('en', 'Unknown')
            country = data.get('country', {}).get('names', {}).get('en', 'Unknown')
            iso_code = data.get('country', {}).get('iso_code', 'Unknown')
            city = data.get('city', {}).get('names', {}).get('en', 'Unknown')
            postal = data.get('postal', {}).get('code', 'Unknown')
            lat = data.get('location', {}).get('latitude', 'Unknown')
            lon = data.get('location', {}).get('longitude', 'Unknown')
            tz = data.get('location', {}).get('time_zone', 'Unknown')
            
            # Network Traits Extraction
            traits = data.get('traits', {})
            isp = traits.get('isp', 'Unknown')
            asn = traits.get('autonomous_system_number', 'Unknown')
            aso = traits.get('autonomous_system_organization', 'Unknown')
            user_type = traits.get('user_type', 'Unknown')
            conn_type = traits.get('connection_type', 'Unknown')

            print(f"    -> Continent:       {continent}")
            print(f"    -> Country:         {country} ({iso_code})")
            print(f"    -> City:            {city}")
            print(f"    -> Postal Code:     {postal}")
            print(f"    -> Coordinates:     {lat}, {lon}")
            print(f"    -> Timezone:        {tz}")
            print(f"    -> ISP:             {isp}")
            print(f"    -> ASN:             {asn}")
            print(f"    -> AS Organization: {aso}")
            print(f"    -> User Type:       {user_type}")
            print(f"    -> Connection Type: {conn_type}")
            
            return data
        else:
            print(f"    [-] FindIP API failed. HTTP Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"    [-] FindIP network error: {e}")
    return None

def evaluate_ip(ip_input):
    """Master pipeline execution for IP Address analysis."""
    print(f"\n[+] Target Acquired: {ip_input}")
    
    valid_ip = validate_ip(ip_input)
    if not valid_ip:
        print("\n*** VERDICT: Invalid Data Format or Private IP ***\n" + "-"*40)
        return

    print("    [*] Analyzing IP in the background...")
    
    
    rdns_found, rdns_hostname = check_reverse_dns(valid_ip)
    is_malicious, vt_mal, vt_sus, vt_status = check_virustotal(valid_ip)
    
    # Calculate Verdict
    if is_malicious:
        verdict = "MALICIOUS (Flagged in VirusTotal Threat DB)"
    elif not rdns_found:
        verdict = "SUSPICIOUS (No Reverse DNS configured, potentially dynamic/botnet IP)"
    else:
        verdict = "LEGITIMATE / CLEAN"

    
    print(f"\n" + "="*50)
    print(f"*** VERDICT: {verdict} ***")
    print("="*50)

    
    print("\n[+] General IP Information:")
    get_findip_info(valid_ip)

    
    print("\n[+] Technical & Threat Details:")
    print(f"    -> Reverse DNS: {rdns_hostname if rdns_found else 'Not Found'}")
    
    if vt_status == "Success":
        if is_malicious:
            print(f"    [!] VirusTotal Alert: {vt_mal} Malicious | {vt_sus} Suspicious flags")
        else:
            print(f"    -> VirusTotal Status: Clean (0 flags)")
    else:
        print(f"    -> VirusTotal Check: {vt_status}")
    
    print("-" * 50)

if __name__ == "__main__":
    try:
       
        user_input = input("\nEnter target IP address for analysis: ").strip()
        if user_input:
            evaluate_ip(user_input)
    except KeyboardInterrupt:
        print("\nExecution terminated.")
        sys.exit(0)