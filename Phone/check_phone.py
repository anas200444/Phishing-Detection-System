import os
import sys
import requests
import re
import phonenumbers
import json
from phonenumbers import geocoder
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException

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

# --- Constants & Config ---
TWILIO_ACCOUNT_SID = 'ACf6798286da9976d744abfe90e6c43883'
TWILIO_AUTH_TOKEN = 'e3f3b8526b36580e16b614ca2371adfe'
DISPOSABLE_DB_URL = "https://raw.githubusercontent.com/iP1SMS/disposable-phone-numbers/refs/heads/master/number-list.json"

def get_dynamic_country_iso():
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    try:
        res = requests.get("http://ip-api.com/json/", headers=headers, timeout=3)
        if res.status_code == 200: return res.json().get("countryCode")
    except Exception: pass
        
    try:
        res = requests.get("https://ipapi.co/json/", headers=headers, timeout=3)
        if res.status_code == 200: return res.json().get("country_code")
    except Exception: pass
        
    try:
        res = requests.get("https://ipinfo.io/json", headers=headers, timeout=3)
        if res.status_code == 200: return res.json().get("country")
    except Exception: pass
        
    return None

def parse_number(raw_number, dynamic_region):
    clean_number = str(raw_number).strip()
    if clean_number.startswith('00'):
        clean_number = '+' + clean_number[2:]
        
    if clean_number.startswith('+'):
        try:
            parsed = phonenumbers.parse(clean_number, None)
            if phonenumbers.is_valid_number(parsed): return parsed
        except phonenumbers.phonenumberutil.NumberParseException: pass
            
    if dynamic_region:
        try:
            parsed = phonenumbers.parse(clean_number, dynamic_region)
            if phonenumbers.is_valid_number(parsed): return parsed
        except phonenumbers.phonenumberutil.NumberParseException: pass
            
    try:
        parsed = phonenumbers.parse(clean_number, "US")
        if phonenumbers.is_valid_number(parsed): return parsed
    except phonenumbers.phonenumberutil.NumberParseException: pass
        
    digits_only = re.sub(r'\D', '', clean_number)
    if digits_only:
        try:
            parsed = phonenumbers.parse('+' + digits_only, None)
            if phonenumbers.is_valid_number(parsed): return parsed
        except phonenumbers.phonenumberutil.NumberParseException: pass
            
    return None

def check_disposable_status(phone_number):
    try:
        response = requests.get(DISPOSABLE_DB_URL, timeout=5)
        if response.status_code == 200:
            disposable_dict = response.json()
            digits_only = phone_number.lstrip('+')
            if digits_only in disposable_dict or phone_number in disposable_dict:
                return True
    except Exception:
        pass
    return False

def check_secondary_spam_database(phone_number):
    try:
        risk_url = f"https://raw.githubusercontent.com/mrcasals/spam-numbers/master/spam_numbers.txt"
        res = requests.get(risk_url, timeout=5)
        if res.status_code == 200:
            if phone_number in res.text or phone_number.lstrip('+') in res.text:
                return True
    except Exception:
        pass
    return False

def calculate_threat_metrics(is_disposable, is_skip_spam, is_osint_spam, is_voip, twilio_score):
    score = 0
    impact = 1 
    
    if is_disposable:
        score += 65
        impact = 3
    if is_skip_spam:
        score += 75
        impact = 3
    if is_osint_spam:
        score += 55
        impact = max(impact, 2)
    if is_voip:
        score += 30
        impact = max(impact, 2)
        
    score += twilio_score 
    
    score = min(max(int(score), 1), 100) 
    
    if score < 30:
        likelihood = 1 
    elif score < 70:
        likelihood = 2 
    else:
        likelihood = 3 
        
    return score, likelihood, impact

def check_phone_number(raw_phone_number):
    details = []
    dynamic_region = get_dynamic_country_iso()
    parsed_number = parse_number(raw_phone_number, dynamic_region)
    
    if not parsed_number:
        return {
            "status": "Please Enter a Valid Phone number",
            "is_safe": False,
            "details": ["Country Code Missing or Invalid", "Please include the country code (e.g., +962)"]
        }
    
    phone_number = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
    country_name = geocoder.description_for_number(parsed_number, "en")
    if country_name:
        details.append(f"Detected Country: {country_name}")
    details.insert(0, f"Analyzing formatted number: {phone_number}")
    
    is_safe = True
    status = "LEGITIMATE / SAFE"

    is_disposable = False
    is_skip_spam = False
    is_osint_spam = False
    is_voip = False
    twilio_risk = 0

    if check_disposable_status(phone_number):
        is_safe = False
        is_disposable = True
        status = "SUSPICIOUS / DISPOSABLE"
        details.append("Alert: This is a known TEMPORARY/DISPOSABLE number.")
    else:
        details.append("Clean (Not found in known disposable lists).")

    try:
        skip_url = f"https://spam.skipcalls.app/check/{phone_number}"
        skip_response = requests.get(skip_url, timeout=5)
        if skip_response.status_code == 200 and skip_response.json().get("is_spam") == True:
            is_safe = False
            is_skip_spam = True
            status = "PHISHING / SPAM"
            details.append("Number is flagged in SkipCalls spam database.")
        else:
            details.append("SkipCalls: Clean (No spam records found).")
    except Exception:
        details.append("SkipCalls API connection bypassed.")

    if check_secondary_spam_database(phone_number):
        is_safe = False
        is_osint_spam = True
        if status == "LEGITIMATE / SAFE":
            status = "SUSPICIOUS / BLACKLISTED"
        details.append("Number found in secondary OSINT blacklist.")

    try:
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        lookup = client.lookups.v2.phone_numbers(phone_number).fetch(fields=['line_type_intelligence', 'sms_pumping_risk'])
        
        if hasattr(lookup, 'valid') and lookup.valid is False:
             return {
                "status": "Validation Failed",
                "is_safe": False,
                "details": ["Number failed network validation checks, Ensure the number is active and formatted correctly."]
             }
            
        if hasattr(lookup, 'national_format') and lookup.national_format:
            details.append(f"National Format: {lookup.national_format}")
            
        if lookup.line_type_intelligence:
            line_type = lookup.line_type_intelligence.get('type')
            carrier = lookup.line_type_intelligence.get('carrier_name')
            
            if carrier:
                details.append(f"Carrier: {carrier}")
                
            if line_type:
                details.append(f"Line Type: {line_type.capitalize()}")
                if line_type.lower() in ["nonfixedvoip", "voip"]:
                    is_safe = False
                    is_voip = True
                    if status == "LEGITIMATE / SAFE":
                        status = "SUSPICIOUS / PHISHING"
                    details.append("Suspected non-fixed VoIP number (commonly used to mask identity).")
                    
        if lookup.sms_pumping_risk:
            twilio_risk = lookup.sms_pumping_risk.get('risk_score', 0)
            if twilio_risk > 70: 
                is_safe = False
                if status == "LEGITIMATE / SAFE":
                    status = "PHISHING / FRAUD RISK"
                details.append(f"Alert: High Fraud Risk Score ({twilio_risk}/100).")
            else:
                details.append(f"Fraud Risk Score: {twilio_risk}/100 (Acceptable).")
                
    except TwilioRestException as e:
        if e.status == 404:
            return {
                "status": "Invalid Phone Number",
                "is_safe": False,
                "details": ["Number not found or invalid in telecom records."]
            }
        details.append("Telecom API check bypassed")
    except Exception:
        details.append("Telecom API check bypassed.")

    if is_safe:
        details.append("No high-risk telecom indicators found.")

    threat_score, likelihood, impact = calculate_threat_metrics(is_disposable, is_skip_spam, is_osint_spam, is_voip, twilio_risk)
    
    # Call Centralized Ollama Script
    ai_data = get_ai_analysis(phone_number, "Phone Number", threat_score, details)

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