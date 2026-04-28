from extraction import analyze_rule_based
from model_manager import load_or_train_model, predict_sms_ml

def is_valid_sms(text):
    if not isinstance(text, str) or not text.strip(): return False
    return len(text.split()) >= 1

if __name__ == "__main__":
    print("======================================================")
    print("  Multi-Vector Smishing Detection System Initializing ")
    print("======================================================")
    
    trained_model, trained_vectorizer = load_or_train_model()

    print("\nSystem ready! The interface is running.")
    print("======================================================")

    while True:
        try:
            target_sms = input("\nEnter SMS message for analysis: ").strip()
            
            if not target_sms:
                continue
                
            if not is_valid_sms(target_sms):
                print("Error: Invalid SMS message format provided.")
                continue

            print("\n" + "-"*50)
            print("  Stage 1: Rule-Based Entity Extraction")
            print("-"*50)
            
            # Unpack both the boolean result and the specific element that caused the flag
            is_rule_phishing, flagged_element = analyze_rule_based(target_sms)
            
            print("\n  >>> STAGE 1 SUMMARY <<<")
            if is_rule_phishing:
                print(f"  [!] The extracted element ({flagged_element}) is MALICIOUS / PHISHING.")
            else:
                print("  [*] The extracted elements are LEGITIMATE (or none were found).")

            print("\n" + "-"*50)
            print("  Stage 2: Machine Learning Validation")
            print("-"*50)
            
            # Catching only the single text verdict now
            ml_verdict = predict_sms_ml(target_sms, trained_model, trained_vectorizer)
            print(f"  [*] ML Verdict: {ml_verdict.upper()}")

            print("\n" + "="*50)
            
            final_status = "PHISHING" if (is_rule_phishing or ml_verdict == "Phishing") else "LEGITIMATE"
            print(f"  FINAL SYSTEM VERDICT: {final_status}")
            print("="*50)
            
        except KeyboardInterrupt:
            print("\nShutting down system")
            break