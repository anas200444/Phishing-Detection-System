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

def calculate_threat_metrics(is_skip_spam, is_voip, twilio_risk):
    # 1. Threat Confidence score, 0-9.
    threat_confidence_score = 0.0
    threat_confidence_score += (twilio_risk / 100.0) * 5.0
    
    if is_skip_spam:
        threat_confidence_score += 3.0
    if is_voip:
        threat_confidence_score += 1.5
        
    threat_confidence_score = min(9.0, threat_confidence_score)

    # 2. Potential Harm score, 0-9.
    if twilio_risk >= 70 or is_skip_spam:
        potential_harm_score = 7.5
    elif twilio_risk >= 40 or is_voip:
        potential_harm_score = 6.0
    elif twilio_risk > 10:
        potential_harm_score = 4.0
    else:
        potential_harm_score = 2.0

    # OWASP threshold style: 0-<3 Low, 3-<6 Medium, 6-9 High.
    def scale_level(score):
        if score < 3: return 1
        if score < 6: return 2
        return 3

    threat_confidence_level = scale_level(threat_confidence_score)
    potential_harm_level = scale_level(potential_harm_score)

    # Risk matrix: (Threat Confidence, Potential Harm)
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

    # Final detection status based on matching the IP script's severity threshold logic
    if risk_label in ["Critical", "High"] or is_skip_spam:
        base_status = "MALICIOUS"
    elif risk_label == "Medium" or is_voip or twilio_risk >= 30:
        base_status = "SUSPICIOUS"
    else:
        base_status = "LEGITIMATE"

    return threat_score, threat_confidence_level, potential_harm_level, risk_label, base_status

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

    is_skip_spam = False
    is_voip = False
    twilio_risk = 0

    try:
        skip_url = f"https://spam.skipcalls.app/check/{phone_number}"
        skip_response = requests.get(skip_url, timeout=5)
        if skip_response.status_code == 200 and skip_response.json().get("is_spam") == True:
            is_skip_spam = True
            details.append("Number is flagged in SkipCalls spam database.")
        else:
            details.append("SkipCalls: Clean (No spam records found).")
    except Exception:
        details.append("SkipCalls API connection bypassed.")

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
                    is_voip = True
                    details.append("Suspected non-fixed VoIP number (commonly used to mask identity).")
                    
        if lookup.sms_pumping_risk:
            twilio_risk = lookup.sms_pumping_risk.get('risk_score', 0)
            if twilio_risk > 70: 
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

    if not is_skip_spam and twilio_risk < 30 and not is_voip:
        details.append("No high-risk telecom indicators found.")

    threat_score, threat_confidence, potential_harm, risk_label, base_status = calculate_threat_metrics(is_skip_spam, is_voip, twilio_risk)
    
    status_msg = f"{base_status} / {risk_label.upper()} RISK"
    is_safe = (base_status == "LEGITIMATE")

    # Call Centralized Ollama Script
    ai_data = get_ai_analysis(phone_number, "Phone Number", threat_score, details)

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