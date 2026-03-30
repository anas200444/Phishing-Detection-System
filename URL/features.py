import itertools
import difflib
import pandas as pd
from config import *
from url_utils import *

def extract_brand_matches(domain, path, query):
    domain_str = " ".join(tokenize_for_brand_checks(domain.replace('.', ' ').replace('-', ' ')))
    path_str   = " ".join(tokenize_for_brand_checks(path))
    query_str  = " ".join(tokenize_for_brand_checks(query))

    brands_in_domain, brands_in_path, brands_in_query = set(), set(), set()
    for brand, aliases in BRAND_ALIASES.items():
        if any(a in domain_str for a in aliases): brands_in_domain.add(brand)
        if any(a in path_str for a in aliases): brands_in_path.add(brand)
        if any(a in query_str for a in aliases): brands_in_query.add(brand)
    return brands_in_domain, brands_in_path, brands_in_query

def is_exact_trusted_domain(domain):
    if not domain: return 0
    trusted_pool = POPULAR_DOMAINS + EXTRA_TRUSTED_DOMAINS
    return 1 if any(domain == d or domain.endswith('.' + d) for d in trusted_pool) else 0

def get_brand_similarity_signals(domain):
    labels = get_domain_labels(domain)
    if not labels: return "", 99, 0.0, 0, 0

    sld, tld = get_sld_tld(domain)
    sub_labels = get_subdomain_labels(domain)

    label_candidates = set()
    for label in labels:
        for v in advanced_unleet_variants(label):
            label_candidates.add(v)

    joined_candidates = set()
    for label in labels: joined_candidates.add(label)
    joined_candidates.add("".join(labels))
    joined_candidates.add("".join(sub_labels))
    joined_candidates.add(sld)
    joined_candidates.add(sld.replace('-', ''))

    for jc in list(joined_candidates):
        for v in advanced_unleet_variants(jc):
            joined_candidates.add(v)

    best_brand, best_distance, best_ratio = "", 99, 0.0
    has_embedded_brand, deceptive_subdomain_brand = 0, 0

    all_candidates = list(itertools.chain(label_candidates, joined_candidates))
    subdomain_vars_list = [advanced_unleet_variants(sub) for sub in sub_labels]

    for pop_domain, pop_sld, pop_norm, pop_vars in get_precomputed_pop_domains():
        for cand in all_candidates:
            if not cand: continue
            if len(pop_sld) >= 4 and pop_sld in cand and cand != pop_sld:
                has_embedded_brand = 1

            for pv in pop_vars:
                if not pv: continue
                dist = damerau_levenshtein_distance(cand, pv, max_dist=3)

                if dist < best_distance:
                    best_distance = dist
                    best_brand = pop_sld
                    best_ratio = difflib.SequenceMatcher(None, cand, pv).ratio()
                elif dist == best_distance and dist <= 3:
                    ratio = difflib.SequenceMatcher(None, cand, pv).ratio()
                    if ratio > best_ratio:
                        best_brand = pop_sld
                        best_ratio = ratio

        for sv_list in subdomain_vars_list:
            if any((pv in sv or sv == pv) for sv in sv_list for pv in pop_vars):
                if sld != pop_sld and not domain.endswith("." + pop_domain) and domain != pop_domain:
                    deceptive_subdomain_brand = 1

    return best_brand, best_distance, best_ratio, has_embedded_brand, deceptive_subdomain_brand

def is_typosquatting(domain):
    if not domain or is_exact_trusted_domain(domain): return 0
    sld, tld = get_sld_tld(domain)
    sld_norm = unicode_skeleton(sld)
    best_brand, best_distance, best_ratio, has_embedded_brand, deceptive_subdomain_brand = get_brand_similarity_signals(domain)

    has_punycode = int('xn--' in domain)
    mixed_script_like = int(any(ord(ch) > 127 for ch in domain))
    sld_vars = advanced_unleet_variants(sld_norm)
    
    for pop_domain, pop_sld, pop_norm, pop_vars in get_precomputed_pop_domains():
        for var in sld_vars:
            if var == pop_norm and domain != pop_domain and sld != pop_sld: return 1

    if len(best_brand) >= 4:
        if best_distance <= 1: return 1
        if best_distance == 2 and best_ratio >= 0.74: return 1
        if best_ratio >= 0.85 and sld != best_brand: return 1
    else:
        if best_distance == 1 and best_ratio >= 0.85 and len(sld_norm) <= len(best_brand) + 2: return 1

    dedup_sld = re.sub(r'(.)\1+', r'\1', sld_norm)
    for pop_domain, pop_sld, pop_norm, pop_vars in get_precomputed_pop_domains():
        dedup_brand = re.sub(r'(.)\1+', r'\1', pop_norm)
        if (dedup_sld == pop_norm or dedup_sld == dedup_brand) and sld != pop_sld: return 1

    if has_embedded_brand == 1 and len(best_brand) >= 4: return 1
    if deceptive_subdomain_brand == 1: return 1
    if (has_punycode or mixed_script_like) and best_ratio >= 0.2: return 1

    return 0

def suspicious_signals_score(features):
    SIGNAL_WEIGHTS = {
        'is_free_hosting': 2, 'is_dynamic_dns': 3, 'has_compromised_cms': 2, 'has_at_symbol': 3, 'email_in_url': 4,
        'has_double_slash_path': 1, 'has_https_token_in_domain': 2, 'has_ip_address': 2, 'has_suspicious_keyword': 2,
        'login_keyword_in_path': 2, 'is_typosquatting_attempt': 5, 'contains_brand_on_untrusted': 4,
        'brand_in_domain_and_path_untrusted': 3, 'has_php_in_path': 1, 'redirect_like_path': 2,
        'has_suspicious_file_ext': 2, 'is_url_shortener': 3, 'hex_pattern_domain': 2, 'brand_in_path_untrusted': 2,
        'is_blog_platform_phishing': 2, 'is_dga_like': 2, 'has_url_in_path': 4, 'has_hex_hash_path': 4,
        'has_random_alphanum_path': 2, 'is_suspicious_tld': 3, 'has_tilde_in_path': 2, 'brand_plus_suspicious_keyword': 4,
        'excessive_subdomains': 2, 'excessive_hyphens': 2, 'has_punycode_domain': 3, 'has_unicode_domain': 2,
        'brand_in_subdomain_mismatch': 4, 'edit_distance_brand_attack': 4, 'high_similarity_brand_attack': 3,
        'embedded_brand_attack': 3, 'brand_query_path_combo': 2, 'domain_keyword_combo': 2
    }
    return int(sum(int(features.get(k, 0)) * w for k, w in SIGNAL_WEIGHTS.items()))

def extract_features(url):
    features = {}
    original_url = str(url) if not pd.isna(url) else ""
    url_clean, domain, path, query = parse_url_parts(url)

    domain_parts = get_domain_labels(domain)
    sld, tld = get_sld_tld(domain)
    sld_norm = unicode_skeleton(sld)

    brands_in_domain, brands_in_path, brands_in_query = extract_brand_matches(domain, path, query)
    is_trusted = is_exact_trusted_domain(domain)
    features['is_trusted_brand'] = is_trusted

    best_brand, best_distance, best_ratio, has_embedded_brand, deceptive_subdomain_brand = get_brand_similarity_signals(domain)

    features['has_punycode_domain'] = int('xn--' in normalize_url(url))
    features['has_unicode_domain'] = int(any(ord(ch) > 127 for ch in domain))
    features['best_brand_distance'] = 0 if best_distance == 99 else best_distance
    features['best_brand_similarity'] = round(float(best_ratio), 4)
    features['embedded_brand_attack'] = int(has_embedded_brand)
    features['brand_in_subdomain_mismatch'] = int(deceptive_subdomain_brand)
    features['edit_distance_brand_attack'] = int((best_distance <= 2) and (best_ratio >= 0.74) and not is_trusted and len(best_brand) >= 4)
    features['high_similarity_brand_attack'] = int((best_ratio >= 0.88) and not is_trusted and sld_norm != best_brand)

    features['is_likely_portal'] = int(any(k in domain for k in PORTAL_KEYWORDS) and not is_trusted)
    features['brand_domain_count'] = len(brands_in_domain)
    features['contains_brand_on_untrusted'] = int((not is_trusted) and len(brands_in_domain) > 0)
    features['brand_in_path_untrusted'] = int((not is_trusted) and len(brands_in_path) > 0)
    features['brand_in_query_untrusted'] = int((not is_trusted) and len(brands_in_query) > 0)
    features['brand_in_domain_and_path_untrusted'] = int((not is_trusted) and len(brands_in_domain) > 0 and len(brands_in_path) > 0)
    features['brand_query_path_combo'] = int((not is_trusted) and ((len(brands_in_path) > 0 and len(brands_in_query) > 0) or (len(brands_in_domain) > 0 and len(brands_in_query) > 0)))

    features['is_cloud_abuse'] = int(any(domain == h or domain.endswith('.' + h) for h in ABUSED_CLOUD_HOSTS) and (len(brands_in_path) > 0 or len(brands_in_query) > 0))
    features['is_dynamic_dns'] = 1 if any(domain == d or domain.endswith('.' + d) for d in DYNAMIC_DNS_PROVIDERS) else 0
    features['is_free_hosting'] = 1 if any(domain == h or domain.endswith('.' + h) for h in FREE_HOSTING) else 0
    features['is_url_shortener'] = 1 if any(domain == s or domain.endswith('.' + s) for s in URL_SHORTENERS) else 0
    features['has_compromised_cms'] = 1 if any(k in path for k in CMS_TOKENS) else 0
    features['uses_https'] = 1 if original_url.lower().startswith('https') else 0
    features['is_suspicious_tld'] = 1 if tld in SUSPICIOUS_TLDS else 0

    features['url_length'] = len(url_clean)
    features['path_depth'] = path.count('/')
    features['num_digits_url'] = sum(c.isdigit() for c in url_clean)
    features['num_digits_domain'] = sum(c.isdigit() for c in domain)
    features['dash_count_domain'] = domain.count('-')
    features['subdomain_count'] = max(0, len(domain_parts) - 2)
    features['excessive_subdomains'] = 1 if features['subdomain_count'] >= 3 else 0
    features['excessive_hyphens'] = 1 if features['dash_count_domain'] >= 3 else 0

    features['email_in_url'] = has_email_in_url(original_url)
    features['has_at_symbol'] = 1 if '@' in url_clean else 0
    features['has_ip_address'] = is_ip_address(domain)
    features['has_https_token_in_domain'] = int('https' in domain or 'http' in domain)
    features['hex_pattern_domain'] = int(bool(re.search(r'[a-f0-9]{12,}', sld)))
    features['has_double_slash_path'] = int('//' in path)

    features['domain_entropy'] = calculate_entropy(domain)
    features['sld_entropy'] = calculate_entropy(sld)
    features['is_dga_like'] = is_dga_like(sld)

    features['has_url_in_path'] = 1 if re.search(r'(http|https|ftp)://|https?//', path + query, re.IGNORECASE) else 0
    features['has_hex_hash_path'] = 1 if re.search(r'/[0-9a-fA-F]{8,}', path) else 0
    features['has_random_alphanum_path'] = 1 if re.search(r'/[a-zA-Z0-9]{15,}', path) and not features['has_hex_hash_path'] else 0
    features['has_tilde_in_path'] = 1 if '~' in path else 0
    features['has_suspicious_file_ext'] = int(any(path.lower().endswith(ext) for ext in SUSPICIOUS_FILE_EXTENSIONS))
    features['redirect_like_path'] = 1 if any(tok in path for tok in REDIRECT_TOKENS) else 0
    features['has_php_in_path'] = 1 if '.php' in path else 0

    combined_string = unicode_skeleton(domain + path + query)
    domain_tokens = set(tokenize_for_brand_checks(domain))
    features['domain_keyword_combo'] = int(any(tok in domain_tokens for tok in HIGH_RISK_COMBO_WORDS) and (len(brands_in_domain) > 0 or features['high_similarity_brand_attack'] == 1))

    if features['is_likely_portal'] == 1:
        features['has_suspicious_keyword'] = int(any(kw in combined_string for kw in SUSPICIOUS_KEYWORDS))
        features['login_keyword_in_path'] = 0
    else:
        features['has_suspicious_keyword'] = int(any(kw in combined_string for kw in SUSPICIOUS_KEYWORDS + ['login']))
        features['login_keyword_in_path'] = 1 if any(k in path for k in LOGIN_PATH_TOKENS) else 0

    features['brand_plus_suspicious_keyword'] = 1 if ((features['contains_brand_on_untrusted'] == 1 or features['edit_distance_brand_attack'] == 1 or features['brand_in_subdomain_mismatch'] == 1) and features['has_suspicious_keyword'] == 1) else 0

    features['is_blog_platform_phishing'] = int(any(domain == h or domain.endswith('.' + h) for h in BLOG_PLATFORMS) and (len(brands_in_path) > 0 or len(brands_in_query) > 0 or features['has_suspicious_keyword'] == 1))

    features['is_typosquatting_attempt'] = is_typosquatting(domain)
    features['suspicious_signal_count'] = suspicious_signals_score(features)

    features['phishing_risk_score'] = (
        features['suspicious_signal_count'] * 0.35 + features['is_typosquatting_attempt'] * 5.0 +
        features['contains_brand_on_untrusted'] * 3.5 + features['brand_plus_suspicious_keyword'] * 4.5 +
        features['is_cloud_abuse'] * 4.2 + features['is_dga_like'] * 2.5 + features['is_dynamic_dns'] * 3.5 +
        features['brand_in_subdomain_mismatch'] * 4.2 + features['edit_distance_brand_attack'] * 4.0 +
        features['high_similarity_brand_attack'] * 3.5 + features['has_punycode_domain'] * 2.5
    )
    return features