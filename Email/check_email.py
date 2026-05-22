import os
import sys
import concurrent.futures
from urllib.parse import quote, unquote

import dns.resolver
import requests

try:
    from OTXv2 import OTXv2, InvalidAPIKey, NotFound, BadRequest, RetryError
    OTX_AVAILABLE = True
    OTX_IMPORT_ERROR = None
except Exception as error:
    OTX_AVAILABLE = False
    OTX_IMPORT_ERROR = str(error)

    class InvalidAPIKey(Exception):
        pass

    class NotFound(Exception):
        pass

    class BadRequest(Exception):
        pass

    class RetryError(Exception):
        pass


# ============================================================
# API KEY - plaintext as requested
# ============================================================
OTX_API_KEY = "a8d8b1329ba8afe42374251d6932540ecf6efe15b97b1b2e52bb5b68c1b54c93"


# ============================================================
# Paths / AI Analyzer
# ============================================================
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)

if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

BLOCKLIST_FILE = os.path.join(current_dir, "disposable_email_blocklist.txt")

try:
    from ollama_analyzer import get_ai_analysis as real_get_ai_analysis
except Exception:
    real_get_ai_analysis = None


def safe_get_ai_analysis(target, target_type, threat_score, details):
    if real_get_ai_analysis is None:
        return {"impact_analysis": [], "countermeasures": []}

    try:
        data = real_get_ai_analysis(target, target_type, threat_score, details)
        if not isinstance(data, dict):
            return {"impact_analysis": [], "countermeasures": []}

        return {
            "impact_analysis": data.get("impact_analysis", []) or [],
            "countermeasures": data.get("countermeasures", []) or []
        }
    except Exception:
        return {"impact_analysis": [], "countermeasures": []}


# ============================================================
# Email Helpers
# ============================================================
def normalize_email_input(email):
    if not email:
        return ""

    email = unquote(str(email).strip())

    if email.lower().startswith("mailto:"):
        email = email[7:]

    email = email.strip().strip("<>").strip()

    if "@" not in email:
        return email

    local_part, domain = email.rsplit("@", 1)
    return f"{local_part.strip()}@{domain.strip().lower()}"


def is_valid_email(email):
    email = normalize_email_input(email)

    if not email or "@" not in email or " " in email:
        return False

    try:
        local_part, domain = email.rsplit("@", 1)
    except ValueError:
        return False

    if not local_part or not domain or "." not in domain:
        return False

    if domain.startswith(".") or domain.endswith("."):
        return False

    return True


def get_domain_from_email(email):
    try:
        email = normalize_email_input(email)
        local_part, domain = email.rsplit("@", 1)

        if not local_part or not domain or "." not in domain:
            return None

        return domain.lower()
    except ValueError:
        return None


def same_email(value, target):
    return normalize_email_input(value).lower() == normalize_email_input(target).lower()


# ============================================================
# Disposable Email Check
# ============================================================
def check_blocklist(domain):
    if not domain or not os.path.exists(BLOCKLIST_FILE):
        return False

    try:
        with open(BLOCKLIST_FILE, "r", encoding="utf-8") as file:
            return domain.lower() in {
                line.strip().lower()
                for line in file
                if line.strip()
            }
    except Exception:
        return False


# ============================================================
# SPF / DMARC Check
# ============================================================
def make_dns_resolver():
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 4
    return resolver


def check_dns_records(domain):
    spf_found = False
    dmarc_found = False
    resolver = make_dns_resolver()

    try:
        for record in resolver.resolve(domain, "TXT"):
            if "v=spf1" in record.to_text().lower():
                spf_found = True
                break
    except Exception:
        pass

    try:
        for record in resolver.resolve(f"_dmarc.{domain}", "TXT"):
            if "v=dmarc1" in record.to_text().lower():
                dmarc_found = True
                break
    except Exception:
        pass

    return spf_found, dmarc_found


# ============================================================
# StopForumSpam Exact Email Check
# ============================================================
def check_stopforumspam(email, session=None):
    result = {
        "is_flagged": False,
        "appears": 0,
        "frequency": 0,
        "confidence": 0,
        "lastseen": "Never",
        "error": None
    }

    try:
        http = session or requests
        response = http.get(
            "https://api.stopforumspam.org/api",
            params={"email": email, "json": "", "confidence": ""},
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=5
        )

        if response.status_code != 200:
            result["error"] = f"API HTTP Error: {response.status_code}"
            return result

        data = response.json()

        if data.get("success") != 1:
            result["error"] = "StopForumSpam returned unsuccessful response."
            return result

        email_data = data.get("email", {}) or {}
        appears = int(email_data.get("appears", 0) or 0)

        result["appears"] = appears

        if appears > 0:
            result["is_flagged"] = True
            result["frequency"] = int(email_data.get("frequency", 0) or 0)
            result["confidence"] = int(float(email_data.get("confidence", 0) or 0))
            result["lastseen"] = email_data.get("lastseen", "Unknown") or "Unknown"

    except requests.exceptions.RequestException:
        result["error"] = "Network connection failed."
    except ValueError:
        result["error"] = "Failed to parse StopForumSpam response."
    except Exception as error:
        result["error"] = f"StopForumSpam check failed: {error}"

    return result


# ============================================================
# AlienVault OTX Exact Email Check
# ============================================================
def make_otx_result(error=None):
    return {
        "is_flagged": False,
        "pulse_count": 0,
        "pulses": [],
        "error": error
    }


def get_pulse_id(pulse):
    if not isinstance(pulse, dict):
        return ""

    return pulse.get("id") or pulse.get("_id") or pulse.get("pulse_id") or ""


def get_pulse_name(pulse):
    if not isinstance(pulse, dict):
        return "Unknown Pulse"

    return pulse.get("name") or pulse.get("title") or "Unknown Pulse"


def add_pulse(result, pulse):
    pulse_id = get_pulse_id(pulse)
    pulse_name = get_pulse_name(pulse)

    if not pulse_id:
        pulse_id = pulse_name

    for existing in result["pulses"]:
        if existing["id"] == pulse_id:
            return

    result["pulses"].append({
        "id": pulse_id,
        "name": pulse_name
    })


def parse_direct_otx_response(data, result):
    if not isinstance(data, dict):
        return 0

    pulse_info = data.get("pulse_info", {}) or {}
    pulses = pulse_info.get("pulses", []) or []

    for pulse in pulses:
        add_pulse(result, pulse)

    try:
        return int(pulse_info.get("count", len(pulses)) or 0)
    except Exception:
        return len(pulses)


def search_results_to_list(data):
    if isinstance(data, dict):
        results = data.get("results", [])
        return results if isinstance(results, list) else []

    return data if isinstance(data, list) else []


def indicators_to_list(data):
    if isinstance(data, dict):
        results = data.get("results", [])
        return results if isinstance(results, list) else []

    return data if isinstance(data, list) else []


def indicator_is_exact_email(indicator, email):
    if not isinstance(indicator, dict):
        return False

    value = indicator.get("indicator") or indicator.get("value") or indicator.get("ioc") or ""
    indicator_type = str(indicator.get("type", "")).lower().strip()

    email_types = {"email", "email_address", "email-address", "e-mail", "mail"}

    if indicator_type and indicator_type not in email_types:
        return False

    return same_email(value, email)


def pulse_has_email(otx, pulse, email):
    for indicator in pulse.get("indicators", []) or []:
        if indicator_is_exact_email(indicator, email):
            return True

    pulse_id = get_pulse_id(pulse)

    if not pulse_id:
        return False

    try:
        indicators_data = otx.get_pulse_indicators(
            pulse_id,
            include_inactive=True,
            limit=1000
        )

        for indicator in indicators_to_list(indicators_data):
            if indicator_is_exact_email(indicator, email):
                return True
    except Exception:
        return False

    return False


def check_alienvault_otx_exact_email(email):
    if not OTX_AVAILABLE:
        return make_otx_result(f"OTXv2 library is not available: {OTX_IMPORT_ERROR}")

    if not OTX_API_KEY or OTX_API_KEY == "PASTE_YOUR_ALIENVAULT_OTX_API_KEY_HERE":
        return make_otx_result("AlienVault OTX API key is not configured.")

    result = make_otx_result()

    try:
        otx = OTXv2(OTX_API_KEY.strip())

        # Fast path: direct exact email indicator lookup.
        try:
            encoded_email = quote(email, safe="")
            data = otx.get(f"/api/v1/indicators/email/{encoded_email}/general")
            direct_count = parse_direct_otx_response(data, result)

            if direct_count > 0:
                result["pulse_count"] = max(direct_count, len(result["pulses"]))
                result["is_flagged"] = True
                return result

        except (NotFound, BadRequest):
            pass

        # Fallback path: search pulses once, then confirm exact email.
        search_data = otx.search_pulses(email, max_results=50)

        for pulse in search_results_to_list(search_data):
            if pulse_has_email(otx, pulse, email):
                add_pulse(result, pulse)

        result["pulse_count"] = len(result["pulses"])
        result["is_flagged"] = result["pulse_count"] > 0
        return result

    except InvalidAPIKey:
        return make_otx_result("Invalid AlienVault OTX API key.")
    except RetryError:
        return make_otx_result("AlienVault OTX retry limit exceeded. Try again later.")
    except requests.exceptions.RequestException:
        return make_otx_result("AlienVault OTX network connection failed.")
    except Exception as error:
        return make_otx_result(f"AlienVault OTX lookup failed: {error}")


# ============================================================
# IP-System-Style Threat Metrics for Email
# ============================================================
def calculate_threat_metrics(is_disposable, spf, dmarc, sfs_data, otx_data):
    otx_pulses = int(otx_data.get("pulse_count", 0) or 0)
    sfs_conf = int(sfs_data.get("confidence", 0) or 0)
    sfs_freq = int(sfs_data.get("frequency", 0) or 0)
    missing_spf = not spf
    missing_dmarc = not dmarc

    # This email module now follows the same OWASP-derived structure used
    # by the IP module:
    #     Final Severity = Threat Confidence x Potential Harm
    # The factors are adapted for email reputation/authentication evidence.

    otx_ratio = min(1.0, otx_pulses / 5.0)

    # 1. Threat Confidence score, 0-9.
    # Meaning: how confident the system is that this email sender is abusive.
    threat_confidence_score = 0.0
    threat_confidence_score += otx_ratio * 4.0
    threat_confidence_score += min(2.4, otx_pulses * 0.8)
    threat_confidence_score += (sfs_conf / 100.0) * 1.8
    threat_confidence_score += min(1.2, sfs_freq / 25.0)

    if is_disposable:
        threat_confidence_score += 1.2
    if missing_spf:
        threat_confidence_score += 0.4
    if missing_dmarc:
        threat_confidence_score += 0.4
    if otx_pulses >= 2:
        threat_confidence_score += 0.8
    if otx_pulses >= 5:
        threat_confidence_score += 0.8

    if (
        otx_pulses == 0
        and sfs_conf == 0
        and sfs_freq == 0
        and not is_disposable
        and spf
        and dmarc
    ):
        threat_confidence_score = 0.5

    threat_confidence_score = min(9.0, threat_confidence_score)

    # 2. Potential Harm score, 0-9.
    # Meaning: generic harm if this email sender is malicious.
    # This is not organization-specific business impact.
    if (
        otx_pulses >= 5
        or (otx_pulses >= 2 and sfs_conf >= 50)
        or (sfs_conf >= 90 and sfs_freq >= 50)
        or (is_disposable and (missing_spf or missing_dmarc) and sfs_conf >= 50)
    ):
        potential_harm_score = 7.5
    elif otx_pulses >= 2 or sfs_conf >= 70 or sfs_freq >= 50 or is_disposable:
        potential_harm_score = 6.0
    elif otx_pulses == 1 or sfs_conf > 0 or sfs_freq > 0 or missing_spf or missing_dmarc:
        potential_harm_score = 4.0
    else:
        potential_harm_score = 2.0

    # OWASP threshold style: 0-<3 Low, 3-<6 Medium, 6-9 High.
    def scale_level(score):
        if score < 3:
            return 1
        if score < 6:
            return 2
        return 3

    threat_confidence_level = scale_level(threat_confidence_score)
    potential_harm_level = scale_level(potential_harm_score)

    # OWASP-derived severity matrix.
    # Format: (Threat Confidence, Potential Harm)
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

    risk_label = risk_matrix.get(
        (threat_confidence_level, potential_harm_level),
        "Note"
    )

    # 0-100 UI score derived from the two matrix inputs.
    threat_score = min(
        100,
        int(((threat_confidence_score + potential_harm_score) / 18.0) * 100)
    )

    # Evidence quality/confidence: how much data the engine had to decide.
    evidence_confidence = 20
    if spf or dmarc:
        evidence_confidence += 15
    if spf and dmarc:
        evidence_confidence += 10
    if otx_data.get("error") is None:
        evidence_confidence += 20
    if otx_pulses > 0:
        evidence_confidence += min(20, 10 + otx_pulses * 2)
    if sfs_data.get("error") is None:
        evidence_confidence += 15
    if sfs_conf > 0:
        evidence_confidence += min(15, int(sfs_conf * 0.15))
    if sfs_freq > 0:
        evidence_confidence += min(5, int(sfs_freq / 10))

    evidence_confidence = min(100, evidence_confidence)

    # Final detection status.
    if risk_label in ["Critical", "High"] or otx_pulses >= 2 or sfs_conf >= 70:
        base_status = "MALICIOUS"
    elif (
        risk_label == "Medium"
        or otx_pulses == 1
        or sfs_conf > 0
        or sfs_freq > 0
        or is_disposable
        or missing_spf
        or missing_dmarc
    ):
        base_status = "SUSPICIOUS"
    else:
        base_status = "LEGITIMATE"

    return (
        threat_score,
        threat_confidence_level,
        potential_harm_level,
        risk_label,
        base_status,
        evidence_confidence
    )


# ============================================================
# Main Email Evaluation
# ============================================================
def evaluate_email(email):
    email = normalize_email_input(email)

    if not is_valid_email(email):
        return {
            "status": "Invalid Email Format",
            "is_safe": False,
            "threat_score": 100,
            "threat_confidence": 3,
            "potential_harm": 3,
            "likelihood": 3,
            "impact": 3,
            "risk_label": "High",
            "severity": "High",
            "otx_pulse_count": 0,
            "ai_impact": [],
            "ai_countermeasures": [],
            "details": ["The provided input is not a valid email address."]
        }

    domain = get_domain_from_email(email)
    details = [
        f"Target Email: {email}",
        f"Extracted Domain: {domain}"
    ]

    with requests.Session() as session:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            future_disposable = executor.submit(check_blocklist, domain)
            future_dns = executor.submit(check_dns_records, domain)
            future_sfs = executor.submit(check_stopforumspam, email, session)
            future_otx = executor.submit(check_alienvault_otx_exact_email, email)

            is_disposable = future_disposable.result()
            spf, dmarc = future_dns.result()
            sfs_data = future_sfs.result()
            otx_data = future_otx.result()

    (
        threat_score,
        threat_confidence,
        potential_harm,
        risk_label,
        base_status,
        evidence_confidence
    ) = calculate_threat_metrics(
        is_disposable,
        spf,
        dmarc,
        sfs_data,
        otx_data
    )

    status_msg = f"{base_status} / {risk_label.upper()} RISK"
    is_safe = (base_status == "LEGITIMATE")

    if is_disposable:
        details.append("Disposable Email Check: Domain matches a known temporary email provider.")
    else:
        details.append("Disposable Email Check: Clear.")

    if spf and dmarc:
        details.append("DNS Authentication: Both SPF and DMARC records found.")
    elif spf:
        details.append("DNS Authentication: SPF found, DMARC missing.")
    elif dmarc:
        details.append("DNS Authentication: DMARC found, SPF missing.")
    else:
        details.append("DNS Authentication Failure: Domain lacks proper SPF and DMARC records.")

    if sfs_data.get("is_flagged"):
        details.append(
            f"StopForumSpam: Flagged in global spammer DBs with {sfs_data.get('confidence', 0)}% spam confidence."
        )
        details.append(
            f"Historical Activity: Reported {sfs_data.get('frequency', 0)} times across threat forums."
        )
        details.append(f"Most recent activity: {sfs_data.get('lastseen', 'Unknown')}")
    elif sfs_data.get("error"):
        details.append(f"StopForumSpam: Could not verify ({sfs_data.get('error')}).")
    else:
        details.append("StopForumSpam: Clear (No known threats found).")

    otx_count = int(otx_data.get("pulse_count", 0) or 0)

    if otx_count > 0:
        details.append(f"AlienVault OTX Exact Email: Flagged in {otx_count} confirmed pulse(s).")

        pulse_names = [
            pulse["name"]
            for pulse in otx_data.get("pulses", [])
            if pulse.get("name")
        ]

        if pulse_names:
            details.append("AlienVault OTX Pulse Names: " + " | ".join(pulse_names[:5]))

    elif otx_data.get("error"):
        details.append(f"AlienVault OTX Exact Email: Could not verify ({otx_data.get('error')}).")
    else:
        details.append("AlienVault OTX Exact Email: Clear (0 confirmed pulses found).")

    ai_data = safe_get_ai_analysis(email, "Email Address", threat_score, details)

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
        "evidence_confidence": evidence_confidence,
        "otx_pulse_count": otx_count,
        "ai_impact": ai_data.get("impact_analysis", []),
        "ai_countermeasures": ai_data.get("countermeasures", []),
        "details": details
    }