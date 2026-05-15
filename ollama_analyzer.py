import requests
import json

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3" 

def get_ai_analysis(target_value, threat_type, threat_score, details):
    """
    Centralized function to query local Ollama model for impact and countermeasures.
    """
    prompt = f"""
     {threat_type} on {target_value} (Score: {threat_score}/100).
    Indicators: {', '.join(details)}.
    
    Provide exactly 3 clear impacts and 3 direct countermeasures for a general user. 
    Use absolute, definitive language. Never use ambiguous words like "unclear", "maybe", or "possibly".
    
    Output strictly as JSON:
    {{
        "impact_analysis": ["Impact 1", "Impact 2", "Impact 3"],
        "countermeasures": ["Action 1", "Action 2", "Action 3"]
    }}
    """
    
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "format": "json",
        "stream": False
    }
    
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=45)
        if response.status_code == 200:
            data = response.json()
            text_response = data.get("response", "").strip()
            return json.loads(text_response)
        else:
            print(f"Ollama API Error: {response.status_code} - {response.text}")
            return {"impact_analysis": [], "countermeasures": []}
    except Exception as e:
        print(f"Ollama Connection Error (Is Ollama running?): {e}")
        return {"impact_analysis": [], "countermeasures": []}