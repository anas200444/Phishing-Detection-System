import requests
import re
import phonenumbers
from phonenumbers import geocoder
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException

TWILIO_ACCOUNT_SID = 'ACf6798286da9976d744abfe90e6c43883'
TWILIO_AUTH_TOKEN = 'e3f3b8526b36580e16b614ca2371adfe'

def get_dynamic_country_iso():
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    
    try:
        res = requests.get("http://ip-api.com/json/", headers=headers, timeout=3)
        if res.status_code == 200:
            return res.json().get("countryCode")
    except Exception:
        pass
        
    try:
        res = requests.get("https://ipapi.co/json/", headers=headers, timeout=3)
        if res.status_code == 200:
            return res.json().get("country_code")
    except Exception:
        pass
        
    try:
        res = requests.get("https://ipinfo.io/json", headers=headers, timeout=3)
        if res.status_code == 200:
            return res.json().get("country")
    except Exception:
        pass
        
    return None

def parse_number(raw_number, dynamic_region):
    
    clean_number = str(raw_number).strip()
    
    
    if clean_number.startswith('00'):
        clean_number = '+' + clean_number[2:]
        
    
    if clean_number.startswith('+'):
        try:
            parsed = phonenumbers.parse(clean_number, None)
            if phonenumbers.is_valid_number(parsed):
                return parsed
        except phonenumbers.phonenumberutil.NumberParseException:
            pass
            
    if dynamic_region:
        try:
            parsed = phonenumbers.parse(clean_number, dynamic_region)
            if phonenumbers.is_valid_number(parsed):
                return parsed
        except phonenumbers.phonenumberutil.NumberParseException:
            pass
            
    #   "US" standard ((XXX) XXX-XXXX format globally)
    try:
        parsed = phonenumbers.parse(clean_number, "US")
        if phonenumbers.is_valid_number(parsed):
            return parsed
    except phonenumbers.phonenumberutil.NumberParseException:
        pass
        
    
    digits_only = re.sub(r'\D', '', clean_number)
    if digits_only:
        try:
            parsed = phonenumbers.parse('+' + digits_only, None)
            if phonenumbers.is_valid_number(parsed):
                return parsed
        except phonenumbers.phonenumberutil.NumberParseException:
            pass
            
    return None

def check_phone_number(raw_phone_number):
    details = []
    
    dynamic_region = get_dynamic_country_iso()
    parsed_number = parse_number(raw_phone_number, dynamic_region)
    
    if not parsed_number:
        return {
            "status": "Please Enter a Valid Phone number",
            "is_safe": False,
            "details": [
                "Country Code Missing or Invalid",
                "Please include the country code (e.g., +962) "
            ]
        }

    
    phone_number = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
    
    
    country_name = geocoder.description_for_number(parsed_number, "en")
    if country_name:
        details.append(f"Detected Country: {country_name}")

    details.insert(0, f"Analyzing formatted number: {phone_number}")
    is_safe = True
    status = "LEGITIMATE / SAFE"

    #  Spam Database Check
    try:
        skip_url = f"https://spam.skipcalls.app/check/{phone_number}"
        skip_response = requests.get(skip_url, timeout=5)
        if skip_response.status_code == 200 and skip_response.json().get("is_spam") == True:
            is_safe = False
            status = "PHISHING / SPAM"
            details.append("Number is flagged in a spam database.")
        else:
            details.append("Clean (No spam records found).")
    except Exception:
        details.append("Spam database connection bypassed.")

    # Telecom Carrier Lookup
    try:
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        lookup = client.lookups.v2.phone_numbers(phone_number).fetch(fields=['line_type_intelligence', 'sms_pumping_risk'])

        if hasattr(lookup, 'valid') and lookup.valid is False:
             return {
                "status": "Validation Failed",
                "is_safe": False,
                "details": ["Number failed network validation checks,Ensure the number is active and formatted correctly."]
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
                    if status == "LEGITIMATE / SAFE":
                        status = "SUSPICIOUS / PHISHING"
                    details.append("Suspected non-fixed VoIP number (commonly used to mask identity).")

        if lookup.sms_pumping_risk:
            risk_score = lookup.sms_pumping_risk.get('risk_score', 0)
            if risk_score > 70: 
                is_safe = False
                if status == "LEGITIMATE / SAFE":
                    status = "PHISHING / FRAUD RISK"
                details.append(f"Alert: High Fraud Risk Score ({risk_score}/100).")
            else:
                details.append(f"Fraud Risk Score: {risk_score}/100 (Acceptable).")

    except TwilioRestException as e:
        if e.status == 404:
            return {
                "status": "Please enter a valid phone number",
                "is_safe": False,
                "details": ["Number not found or invalid in telecom records."]
            }
        details.append("Telecom API check bypassed")
    except Exception:
        details.append("Telecom API check bypassed.")

    if is_safe:
        details.append("No high-risk telecom indicators found.")

    return {
        "status": status,
        "is_safe": is_safe,
        "details": details
    }