# =========================================================
# MODULE: URL Analyzer ( ML, and API)
# =========================================================
# STEP 1: Import necessary libraries
# STEP 2: Configuration & API Keys
# Store your VirusTotal or Google Safe Browsing API keys here
# ---------------------------------------------------------
# PATH ONE: Machine Learning (ML) Approach
# ---------------------------------------------------------
# TODO: Load the Phishing URL Dataset 
# TODO: Feature Extraction 
# (Extract features like: URL length, number of dots, presence of '@', etc.)
# TODO: Train/Load the ML Model (e.g., Random Forest or Logistic Regression)
# TODO: Define a function to predict if a URL is 'Malicious' or 'Benign'
# ---------------------------------------------------------
# PATH TWO:API Approach
# ---------------------------------------------------------
# TODO: Define a function to send the URL to VirusTotal API
# TODO: Parse the JSON response to see how many engines flagged it
# TODO: Handle API errors (e.g., rate limits or network issues)
# ---------------------------------------------------------
# CORE LOGIC: Heuristic Analysis (Structural Anomalies)
# ---------------------------------------------------------
# TODO: Check for Typosquatting (e.g., 'g00gle.com' instead of 'google.com')
# TODO: Check for IP-based hosting (
# TODO: Check for unusual TLDs (.xyz, .top, .loan)
# ---------------------------------------------------------
# FINAL AGGREGATION: Unified Risk Score
# ---------------------------------------------------------
# TODO: Combine results from ML, API, and Heuristics
# TODO: Assign weights 
# TODO: Return a final Risk Score (0 to 100) and a Recommendation

# PATH TWO:API Approach (Done)
import requests
import base64

def get_virustotal_reputation(target_url, api_key):
    #Encode the URL to Base64 (Required for VT API v3)

    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    
    #  Set up the API endpoint 
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    try:
        # Send the request
        response = requests.get(endpoint, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            
            #  Parse the 'last_analysis_stats'
            stats = data['data']['attributes']['last_analysis_stats']
            
            malicious_count = stats.get('malicious', 0)
            # Sum all stats 
            # to get the total engine count
            total_engines = sum(stats.values())
            
            # Final output format:
            return f"{malicious_count}/{total_engines}"
            
        elif response.status_code == 404:
            return "URL not found in VirusTotal database. Try submitting it for a scan first."
        else:
            return f"Error: {response.status_code}"

    except Exception as e:
        return f"An error occurred: {e}"

# --- Usage ---
API_KEY = "fb9ed8979176bc743716b6736bba75ddce368e7fd06f129517ff8b10e452bd9c"
user_url = input("Enter the URL to analyze: ")
result = get_virustotal_reputation(user_url, API_KEY)

print(f"Reputation Result: {result}")