import os
import sys
import requests
import re
import phonenumbers
from phonenumbers import geocoder
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
from dotenv import load_dotenv

current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)

if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

load_dotenv(os.path.join(root_dir, ".env"))

try:
    from ollama_analyzer import get_ai_analysis
except ImportError:
    def get_ai_analysis(*args, **kwargs):
        return {"impact_analysis": [], "countermeasures": []}

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")


def parse_number(raw_number, dynamic_region=None):
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

    digits_only = re.sub(r'\D', '', clean_number)

    if digits_only:
        try:
            parsed = phonenumbers.parse('+' + digits_only, None)
            if phonenumbers.is_valid_number(parsed):
                return parsed
        except phonenumbers.phonenumberutil.NumberParseException:
            pass

        for region in phonenumbers.SUPPORTED_REGIONS:
            try:
                parsed = phonenumbers.parse(clean_number, region)
                if phonenumbers.is_valid_number(parsed):
                    return parsed
            except phonenumbers.phonenumberutil.NumberParseException:
                continue

    return None


def calculate_threat_metrics(is_skip_spam, is_voip):
    threat_confidence_score = 0

    if is_skip_spam:
        threat_confidence_score += 6

    if is_voip:
        threat_confidence_score += 2

    threat_confidence_score = min(9, threat_confidence_score)

    if is_skip_spam and is_voip:
        potential_harm_score = 8
    elif is_skip_spam:
        potential_harm_score = 7
    elif is_voip:
        potential_harm_score = 5
    else:
        potential_harm_score = 2

    def scale_level(score):
        if score <= 2:
            return 1
        if score <= 5:
            return 2
        return 3

    threat_confidence_level = scale_level(threat_confidence_score)
    potential_harm_level = scale_level(potential_harm_score)

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

    risk_label = risk_matrix.get(
        (threat_confidence_level, potential_harm_level),
        "Note"
    )

    raw_score = int(
        ((threat_confidence_score + potential_harm_score) / 18) * 100
    )

    severity_min_score = {
        "Note": 0,
        "Low": 25,
        "Medium": 50,
        "High": 70,
        "Critical": 85
    }

    threat_score = max(raw_score, severity_min_score[risk_label])
    threat_score = min(100, threat_score)

    if risk_label == "Critical" and is_skip_spam:
        base_status = "MALICIOUS"
    elif risk_label in ["High", "Critical"] and is_skip_spam:
        base_status = "MALICIOUS"
    elif risk_label in ["Medium", "High"] or is_voip:
        base_status = "SUSPICIOUS"
    else:
        base_status = "LEGITIMATE"

    return threat_score, threat_confidence_level, potential_harm_level, risk_label, base_status


def check_phone_number(raw_phone_number):
    details = []

    parsed_number = parse_number(raw_phone_number)

    if not parsed_number:
        return {
            "status": "Please Enter a Valid Phone number",
            "is_safe": False,
            "details": [
                "Invalid phone number format",
                "Please enter a valid number with country code when possible, such as +962xxxxxxxxx or +966xxxxxxxxx"
            ]
        }

    phone_number = phonenumbers.format_number(
        parsed_number,
        phonenumbers.PhoneNumberFormat.E164
    )

    country_name = geocoder.description_for_number(parsed_number, "en")

    if country_name:
        details.append(f"Detected Country: {country_name}")

    details.insert(0, f"Analyzing formatted number: {phone_number}")

    is_skip_spam = False
    is_voip = False

    skip_url = f"https://spam.skipcalls.app/check/{phone_number}"

    try:
        skip_response = requests.get(skip_url, timeout=5)

        if skip_response.status_code == 200 and skip_response.json().get("is_spam") == True:
            is_skip_spam = True
            details.append("Number is flagged in SkipCalls spam database.")
        else:
            details.append("SkipCalls: Clean (No spam records found).")

    except Exception:
        details.append("SkipCalls: Unable to check spam database.")

    try:
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

        lookup = client.lookups.v2.phone_numbers(phone_number).fetch(
            fields=['line_type_intelligence']
        )

        if hasattr(lookup, 'national_format') and lookup.national_format:
            details.append(f"National Format: {lookup.national_format}")

        if lookup.line_type_intelligence:
            line_type = lookup.line_type_intelligence.get('type')
            carrier = lookup.line_type_intelligence.get('carrier_name')

            if carrier:
                details.append(f"Carrier: {carrier}")

            if line_type:
                details.append(f"Line Type: {line_type}")

                if line_type.lower() in ["nonfixedvoip", "voip"]:
                    is_voip = True
                    details.append("Suspected non-fixed VoIP number")

    except TwilioRestException as e:
        if e.status == 404:
            return {
                "status": "Invalid Phone Number",
                "is_safe": False,
                "details": ["Number not found or invalid in telecom records."]
            }

    except Exception:
        pass

    if not is_skip_spam and not is_voip:
        details.append("No high-risk telecom indicators found.")

    threat_score, threat_confidence, potential_harm, risk_label, base_status = calculate_threat_metrics(
        is_skip_spam,
        is_voip
    )

    status_msg = f"{base_status} / {risk_label.upper()} RISK"
    is_safe = base_status == "LEGITIMATE"

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