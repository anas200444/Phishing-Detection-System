import re
import pandas as pd
from config import TYPOSQUAT_LIST
from url_utils import parse_url_parts, calculate_entropy, unicode_skeleton, levenshtein_distance

def extract_features(url):
    original_url = str(url) if not pd.isna(url) else ""
    url_clean, domain, path, query = parse_url_parts(original_url)
    
    domain_skeleton = unicode_skeleton(domain)
    sld = domain.split('.')[0] if '.' in domain else domain

    features = {
        'url_len': len(url_clean),
        'domain_len': len(domain),
        'path_len': len(path),
        'num_digits_url': sum(c.isdigit() for c in url_clean),
        'num_digits_domain': sum(c.isdigit() for c in domain),
        'num_hyphens_domain': domain.count('-'),
        'subdomain_count': max(0, len(domain.split('.')) - 2),
        'domain_entropy': calculate_entropy(domain),
        'path_depth': path.count('/'),
        'has_ip': 1 if re.match(r'^(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])$', domain) else 0,
        'has_at': 1 if '@' in url_clean else 0,
        'uses_https': 1 if original_url.lower().startswith('https') else 0,
        'typosquat_risk': 0
    }

    # Evaluate against the  essential typosquat list
    for brand in TYPOSQUAT_LIST:
        if brand in domain_skeleton and brand != sld:
            features['typosquat_risk'] = 1
            break
        if 1 <= levenshtein_distance(sld, brand) <= 2:
            features['typosquat_risk'] = 1
            break

    return features