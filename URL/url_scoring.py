def calculate_url_threat_metrics(vt_data, gsb_data, otx_data, urlhaus_flag, brand_result, is_whitelisted):
    vt_mal = vt_data.get("stats", {}).get("malicious", 0)
    vt_sus = vt_data.get("stats", {}).get("suspicious", 0)
    vt_total = sum(vt_data.get("stats", {}).values())
    gsb_flag = gsb_data.get("is_malicious", False)
    otx_pulses = otx_data.get("pulse_count", 0)
    
    typo_risk = brand_result.get("typosquat_risk", 0) == 1
    homo_risk = brand_result.get("homograph_risk", 0) == 1

    vt_ratio = 0.0
    if vt_total > 0:
        vt_ratio = (vt_mal + (vt_sus * 0.5)) / vt_total

    # 1. Threat Confidence score, 0-9
    threat_confidence_score = 0.0
    threat_confidence_score += vt_ratio * 4.0
    threat_confidence_score += min(2.4, vt_mal * 0.8)
    threat_confidence_score += min(1.0, vt_sus * 0.25)
    
    if urlhaus_flag: threat_confidence_score += 5.0
    if gsb_flag: threat_confidence_score += 5.0
    threat_confidence_score += min(2.0, otx_pulses * 0.5)
    if typo_risk or homo_risk: threat_confidence_score += 3.0

    if vt_mal >= 2: threat_confidence_score += 0.8
    if vt_mal >= 5: threat_confidence_score += 0.8
    if vt_total == 0 and not urlhaus_flag and not gsb_flag and otx_pulses == 0 and not typo_risk and not homo_risk:
        threat_confidence_score = 0.5

    threat_confidence_score = min(9.0, threat_confidence_score)

    # 2. Potential Harm score, 0-9
    if vt_mal >= 5 or urlhaus_flag or gsb_flag:
        potential_harm_score = 7.5
    elif vt_mal >= 2 or otx_pulses >= 3 or typo_risk or homo_risk:
        potential_harm_score = 6.0
    elif vt_mal == 1 or vt_sus > 0 or otx_pulses > 0:
        potential_harm_score = 4.0
    else:
        potential_harm_score = 2.0

    def scale_level(score):
        if score < 3: return 1
        if score < 6: return 2
        return 3

    threat_confidence_level = scale_level(threat_confidence_score)
    potential_harm_level = scale_level(potential_harm_score)

    # Risk Matrix matches IP module exactly
    risk_matrix = {
        (3, 3): "Critical", (3, 2): "High", (3, 1): "Medium",
        (2, 3): "High", (2, 2): "Medium", (2, 1): "Low",
        (1, 3): "Medium", (1, 2): "Low", (1, 1): "Note"
    }
    risk_label = risk_matrix.get((threat_confidence_level, potential_harm_level), "Note")

    # Final 0-100 Score
    threat_score = min(100, int(((threat_confidence_score + potential_harm_score) / 18.0) * 100))

    # Evidence confidence logic 
    evidence_confidence = 20
    if vt_total > 0: evidence_confidence += min(45, int((vt_total / 90.0) * 45))
    if vt_mal > 0 or vt_sus > 0: evidence_confidence += 15
    if urlhaus_flag or gsb_flag: evidence_confidence += 20
    if otx_pulses > 0: evidence_confidence += min(15, otx_pulses * 5)
    evidence_confidence = min(100, evidence_confidence)

    # Status Determination
    if risk_label in ["Critical", "High"] or vt_mal >= 2 or urlhaus_flag or gsb_flag:
        base_status = "MALICIOUS"
    elif risk_label == "Medium" or vt_mal == 1 or vt_sus > 0 or otx_pulses > 0 or typo_risk or homo_risk:
        base_status = "SUSPICIOUS"
    else:
        base_status = "LEGITIMATE"

    # Whitelist Override: Does not skip calculations, but ensures final matrix is clean
    if is_whitelisted:
        threat_score = 0
        threat_confidence_level = 1
        potential_harm_level = 1
        risk_label = "Note"
        base_status = "LEGITIMATE"

    return threat_score, threat_confidence_level, potential_harm_level, risk_label, base_status, evidence_confidence