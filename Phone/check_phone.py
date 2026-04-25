import requests
import re
from twilio.rest import Client


TWILIO_ACCOUNT_SID = 'ACf6798286da9976d744abfe90e6c43883'
TWILIO_AUTH_TOKEN = 'e3f3b8526b36580e16b614ca2371adfe'

def format_phone_number(raw_number):

    
    cleaned_number = re.sub(r'[^\d+]', '', raw_number)
    return cleaned_number

def check_phone_number(raw_phone_number):
    """
    Analyzes a phone number and classifies it as 'Phishing' or 'Legitimate'.
    Checks SkipCalls first, then Twilio.
    """
    
    phone_number = format_phone_number(raw_phone_number)
    print(f"\n[+] Starting analysis for: {phone_number}")

   
    print("[-] Step 1: Checking SkipCalls database...")
    try:
        skip_url = f"https://spam.skipcalls.app/check/{phone_number}"
        skip_response = requests.get(skip_url, timeout=5)
        
        if skip_response.status_code == 200:
            data = skip_response.json()
            
           
            if data.get("is_spam") == True:
                return "Phishing (Reason: Flagged in SkipCalls spam database)"
            else:
                print("    -> Number is clean on SkipCalls.")
    except Exception as e:
        print(f"    -> SkipCalls connection failed: {e}. Moving to next layer.")

  
    print("[-] Step 2: Checking Twilio for telecom risk signals...")
    try:
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        
   
        if not phone_number.startswith('+'):
            print("    -> Warning: Twilio works best with a '+' and country code (E.164 format).")

        lookup = client.lookups.v2.phone_numbers(phone_number).fetch(
            fields=['line_type_intelligence', 'sms_pumping_risk']
        )

        
        if lookup.line_type_intelligence:
            line_type = lookup.line_type_intelligence.get('type')
            if line_type == "nonFixedVoip":
                return "Phishing (Reason: Suspected non-fixed VoIP number)"

       
        if lookup.sms_pumping_risk:
            risk_score = lookup.sms_pumping_risk.get('risk_score', 0)
            if risk_score > 70: 
                return f"Phishing (Reason: High Twilio Fraud Risk Score: {risk_score})"
                
        print("    -> Twilio analysis complete. No high-risk indicators found.")

    except Exception as e:
        print(f"    -> Twilio check failed. Error: {e}")


    
    return "Legitimate"


if __name__ == "__main__":
    print("========================================")
    print("  Phishing Number Classifier Module     ")
    print("========================================")
    
    
    user_input = input("Enter the phone number to analyze (e.g., +1 (325) 244-7821): ")
    
    if user_input.strip():
        result = check_phone_number(user_input)
        print("\n========================================")
        print(f" FINAL RESULT: {result}")
        print("========================================\n")
    else:
        print("No number entered. Exiting.")