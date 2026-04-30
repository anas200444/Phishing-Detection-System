import os
import sys
import dns.resolver
import requests

script_dir = os.path.dirname(os.path.abspath(__file__))
BLOCKLIST_FILE = os.path.join(script_dir, "disposable_email_blocklist.txt")

def get_domain_from_email(email):
    try:
        return email.split('@')[1].strip().lower()
    except IndexError:
        return None

def check_blocklist(domain):
    """Analysis against disposable blocklist."""
    if not os.path.exists(BLOCKLIST_FILE):
        return False

    with open(BLOCKLIST_FILE, 'r', encoding='utf-8') as file:
        blocklist = set()
        for line in file:
            clean_line = line.strip().lower()
            if clean_line:
                blocklist.add(clean_line)
    
    return domain in blocklist

def check_dns_records(domain):
    spf_found = False
    dmarc_found = False
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if 'v=spf1' in rdata.to_text():
                spf_found = True
                break
    except Exception:
        pass 
    
    try:
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for rdata in answers:
            if 'v=DMARC1' in rdata.to_text():
                dmarc_found = True
                break
    except Exception:
        pass

    return spf_found, dmarc_found

def check_stopforumspam(email):
    url = f"https://api.stopforumspam.org/api?email={email}&json"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    result = {
        "is_flagged": False,
        "appears": 0,
        "frequency": 0,
        "confidence": 0,
        "error": None
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get("success") == 1:
                email_data = data.get("email", {})
                appears = email_data.get("appears", 0)
                
                result["appears"] = appears
                if appears > 0:
                    result["is_flagged"] = True
                    result["frequency"] = email_data.get("frequency", 0)
                    result["confidence"] = email_data.get("confidence", 0)
        else:
            result["error"] = f"API HTTP Error: {response.status_code}"
            
    except requests.exceptions.RequestException as e:
        result["error"] = "Network connection failed."
    except ValueError:
        result["error"] = "Failed to response."
        
    return result

def evaluate_email(email):
    domain = get_domain_from_email(email)
    
    if not domain:
        return {
            "status": "Please Enter a valid Email",
            "is_safe": False,
            "details": ["Invalid email format."]
        }

    is_disposable = check_blocklist(domain)
    spf, dmarc = check_dns_records(domain)
    sfs_data = check_stopforumspam(email)

    details = [
        f"Target Email: {email}",
        f"Extracted Domain: {domain}"
    ]
    
    is_safe = True

    if is_disposable:
        is_safe = False
        details.append("Domain matches a known temporary email provider.")
    
    # 2. DNS Authentication Check
    if spf and dmarc:
        details.append("DNS Authentication: (Both SPF and DMARC records found).")
    elif spf:
        details.append("DNS Authentication: (SPF found, DMARC missing).")
    elif dmarc:
        details.append("DNS Authentication: (DMARC found, SPF missing).")
    else:
        is_safe = False
        details.append("DNS Authentication Failure: Domain lacks proper SPF or DMARC records.")

    
    if sfs_data.get("is_flagged"):
        is_safe = False
        details.append(f"Flagged maliciously by Threat Database.")
        details.append(f"Database Appearances: {sfs_data.get('frequency')}")
        details.append(f"Threat Confidence: {sfs_data.get('confidence')}%")
    else:
        if sfs_data.get("error"):
            details.append(f"Could not verify ({sfs_data.get('error')}).")
        else:
            details.append("Clear (No known threats).")

    # Final Status Verdict
    status = "LEGITIMATE / SAFE" if is_safe else "PHISHING / MALICIOUS"

    return {
        "status": status,
        "is_safe": is_safe,
        "details": details
    }

if __name__ == "__main__":
    try:
        user_input = input("\nEnter target email for analysis: ").strip()
        if user_input:
            result = evaluate_email(user_input)
            print(f"\n*** VERDICT: {result['status']} ***")
            for detail in result['details']:
                print(f"- {detail}")
            print("-" * 40)
    except KeyboardInterrupt:
        print("\nExecution terminated.")
        sys.exit(0)

#Resourses 
##https://github.com/disposable-email-domains