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

def check_local_blocklist(domain):
    """ Static Local Analysis against disposable blocklist."""
    if not os.path.exists(BLOCKLIST_FILE):
        print(f"[-] Error: Could not find blocklist at: {BLOCKLIST_FILE}")
        return False

    with open(BLOCKLIST_FILE, 'r', encoding='utf-8') as file:
        blocklist = set()
        for line in file:
            clean_line = line.strip().lower()
            if clean_line:
                blocklist.add(clean_line)
    
    return domain in blocklist

def check_dns_records(domain):
    """Authentication Check (SPF/DMARC)."""
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
    """Global Threat Intelligence Check (Specific Email Address)."""
    url = f"https://api.stopforumspam.org/api?email={email}&json"
    
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("success") == 1:
                email_data = data.get("email", {})
                
                # 'appears' > 0 means the email is logged in their threat database
                appears = email_data.get("appears", 0)
                if appears > 0:
                    frequency = email_data.get("frequency", "unknown")
                    confidence = email_data.get("confidence", "unknown")
                    print(f"    [!] ALERT: Email specifically flagged by StopForumSpam!")
                    print(f"        -> Database appearances: {frequency}")
                    print(f"        -> Threat Confidence: {confidence}%")
                    return True
            return False
        else:
            print(f"[-] API connection failed. HTTP Status: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"[-] Network error while connecting to threat database: {e}")
        return False
    except ValueError:
        print("[-] Error parsing API response.")
        return False

def evaluate_email(email):
    """Master pipeline execution."""
    print(f"\n[+] Target Acquired: {email}")
    domain = get_domain_from_email(email)
    
    if not domain:
        return "Invalid Data Format"

  
    print(" Initiating Blocklist Check...")
    if check_local_blocklist(domain):
        return "Phishing / Disposable "

    print("Verifying SPF/DMARC Signatures...")
    spf, dmarc = check_dns_records(domain)
    
    if not spf and not dmarc:
        return "Phishing / Suspicious (Authentication Failed: No SPF or DMARC)"

   
    print("Querying Global Email Threat Intelligence...")
    if check_stopforumspam(email):
        return "Phishing / Malicious (Exact Email Match in Threat DB)"

    return "Legitimate"

if __name__ == "__main__":
    try:
        
        user_input = input("\nEnter target email for analysis: ").strip()
        if user_input:
            result = evaluate_email(user_input)
            print(f"\n*** VERDICT: {result} ***\n" + "-"*40)
    except KeyboardInterrupt:
        print("\nExecution terminated.")
        sys.exit(0)

#Resourses 
##https://github.com/disposable-email-domains