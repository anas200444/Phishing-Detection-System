import os
from .extraction import analyze_rule_based
from .model_manager import load_or_train_model, predict_sms_ml

def evaluate_sms(text: str) -> dict:
    if not isinstance(text, str) or not text.strip() or len(text.split()) < 1:
        return {
            "is_safe": False,
            "status": "INVALID FORMAT",
            "details": ["Please enter a valid SMS message."]
        }
    
    details = []
    is_safe = True
    
    details.append("Entity Extraction...")
    is_rule_phishing, flagged_element = analyze_rule_based(text)
    
    if is_rule_phishing:
        is_safe = False
        details.append(f"Malicious entity detected within message: {flagged_element}")
    else:
        details.append("No malicious links, IPs, emails, or phones extracted.")
        
    # Stage 2: Machine Learning Validation
    details.append("Machine Learning Validation...")
    try:
        trained_model, trained_vectorizer = load_or_train_model()
        ml_verdict = predict_sms_ml(text, trained_model, trained_vectorizer)
        
        if ml_verdict.lower() == "phishing":
            is_safe = False
            details.append("ML Model classified the text context as Phishing/Smishing.")
        else:
            
            if is_rule_phishing:
                details.append("ML Model classified the text context as Legitimate, but the extracted element in the message is malicious (Phishing).")
            else:
                details.append(" ML Model classified the text context as Legitimate.")
                
    except Exception as e:
        details.append(f"ML Analysis Error: {str(e)}")
        
    status = "LEGITIMATE / SAFE" if is_safe else "PHISHING / MALICIOUS"
    
    return {
        "is_safe": is_safe,
        "status": status,
        "details": details
    }
#resourses : https://github.com/shaghayegh-hp/Smishing_Dataset#combined-labeled-smishing-dataset