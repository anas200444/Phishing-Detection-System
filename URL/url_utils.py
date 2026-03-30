import re
import math
import unicodedata
import pandas as pd
from urllib.parse import urlparse
from config import *
from config import _RANDOM_DOMAIN_VOWEL_THRESHOLD, _RANDOM_DOMAIN_CONSONANT_RUN

_PRECOMPUTED_POP_DOMAINS = []

def extract_domain(url: str) -> str:
    parsed_url = urlparse(url)
    return parsed_url.netloc or parsed_url.path

def is_valid_url_format(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme in ("http", "https") and parsed.netloc)
    except Exception:
        return False

def ensure_url_scheme(url: str) -> str:
    url = str(url).strip()
    if not url: return url
    if not url.startswith(("http://", "https://")): return "http://" + url
    return url

def normalize_input_url(url: str) -> str:
    url = str(url).strip()
    if not url: return url
    url = re.sub(r'^(?:https?://|hxxps?://|h?ttps?://|tx+ps?://)', '', url, flags=re.IGNORECASE)
    return 'https://' + url

def normalize_url(url):
    if pd.isna(url): return ""
    url = str(url).lower().strip()
    return url.replace('[.]', '.').replace('hxxps', 'https').replace('hxxp', 'http')

def safe_idna_decode(domain: str) -> str:
    if not domain: return ""
    try:
        return domain.encode('ascii', errors='ignore').decode('idna')
    except Exception:
        return domain

def unicode_skeleton(text: str) -> str:
    if not text: return ""
    text = re.sub(r'[\u200b\u200c\u200d\ufeff]', '', text)
    text = unicodedata.normalize("NFKC", text.lower())
    chars = [HOMOGLYPH_CHAR_MAP.get(ch, ch) for ch in text]
    text = "".join(chars)
    text = text.replace('rn', 'm').replace('vv', 'w').replace('cl', 'd').replace('nn', 'm')
    return text

def parse_url_parts(url):
    url = normalize_url(url)
    url_clean = re.sub(r'^\s+', '', url)
    url_clean = re.sub(r'^(?:https?://|hxxps?://|h?ttps?://|tx+ps?://)', '', url_clean)
    url_clean = re.sub(r'^www\.', '', url_clean)
    try:
        parsed = urlparse('http://' + url_clean)
        domain = parsed.netloc.split(':')[0].strip('.').lower()
        domain = safe_idna_decode(domain)
        path   = parsed.path  or ""
        query  = parsed.query or ""
    except ValueError:
        domain = url_clean.split('/')[0].strip('.').lower()
        domain = safe_idna_decode(domain)
        path, query = "", ""
    return url_clean, domain, path, query

def get_sld_tld(domain):
    parts = [p for p in domain.split('.') if p]
    if len(parts) >= 2: return parts[-2], parts[-1]
    if len(parts) == 1: return parts[0], ""
    return "", ""

def get_domain_labels(domain):
    return [p for p in domain.split('.') if p]

def get_subdomain_labels(domain):
    labels = get_domain_labels(domain)
    return [] if len(labels) <= 2 else labels[:-2]

def is_ip_address(domain):
    pat = r'^(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])$'
    return 1 if re.match(pat, domain) else 0

def has_email_in_url(url: str) -> int:
    if not url: return 0
    if re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', url): return 1
    if re.search(r'[a-zA-Z0-9._%+-]+%40[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', url, re.IGNORECASE): return 1
    return 0

def calculate_entropy(text):
    if not text: return 0.0
    probs = [float(text.count(c)) / len(text) for c in dict.fromkeys(text)]
    return -sum(p * math.log2(p) for p in probs if p > 0)

def vowel_ratio(text):
    letters = [c for c in text.lower() if c.isalpha()]
    return sum(1 for c in letters if c in VOWELS) / len(letters) if letters else 0.5

def max_consonant_run(text):
    if not text: return 0
    best, cur = 0, 0
    for ch in text.lower():
        if ch in CONSONANTS:
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best

def is_dga_like(sld: str) -> int:
    if len(sld) < 5: return 0
    if vowel_ratio(sld) < _RANDOM_DOMAIN_VOWEL_THRESHOLD and len(sld) >= 8: return 1
    if max_consonant_run(sld) >= _RANDOM_DOMAIN_CONSONANT_RUN: return 1
    return 0

def advanced_unleet_variants(text: str):
    text = unicode_skeleton(text)
    base_maps = [
        {'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g'},
        {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g'},
        {'0': 'o', '1': 'i', '2': 'z', '3': 'e', '4': 'a', '5': 's', '6': 'g', '7': 't', '8': 'b', '9': 'g'},
    ]
    variants = {text}
    for m in base_maps:
        variants.add("".join(m.get(ch, ch) for ch in text))
    more = set()
    for v in variants:
        more.add(v.replace('-', '').replace('_', '').replace('.', ''))
    variants |= more
    return list(variants)

def get_precomputed_pop_domains():
    global _PRECOMPUTED_POP_DOMAINS
    if not _PRECOMPUTED_POP_DOMAINS:
        for pop_domain in POPULAR_DOMAINS:
            pop_sld, pop_tld = get_sld_tld(pop_domain)
            pop_norm = unicode_skeleton(pop_sld)
            pop_vars = set([pop_sld])
            for v in advanced_unleet_variants(pop_sld):
                pop_vars.add(v)
            _PRECOMPUTED_POP_DOMAINS.append((pop_domain, pop_sld, pop_norm, pop_vars))
    return _PRECOMPUTED_POP_DOMAINS

def tokenize_for_brand_checks(text):
    if not text: return []
    text = unicode_skeleton(text)
    text = re.sub(r'[^a-z0-9]+', ' ', text.lower())
    split_tokens = []
    for tok in [t for t in text.split() if t]:
        split_tokens.append(tok)
        for var in advanced_unleet_variants(tok):
            split_tokens.append(var)
    return list(set(split_tokens))

def damerau_levenshtein_distance(s1: str, s2: str, max_dist: int = 3) -> int:
    if s1 == s2: return 0
    len1, len2 = len(s1), len(s2)
    if abs(len1 - len2) > max_dist: return max_dist + 1

    d = [[0] * (len2 + 1) for _ in range(len1 + 1)]
    for i in range(len1 + 1): d[i][0] = i
    for j in range(len2 + 1): d[0][j] = j

    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and s1[i - 1] == s2[j - 2] and s1[i - 2] == s2[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + cost)
    return d[len1][len2]