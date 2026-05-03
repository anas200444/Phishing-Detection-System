import re
import math
import unicodedata
from urllib.parse import urlparse
from config import HOMOGLYPH_CHAR_MAP

def extract_domain(url: str) -> str:
    parsed_url = urlparse(url)
    return parsed_url.netloc or parsed_url.path

def is_valid_url_format(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme in ("http", "https") and parsed.netloc and '.' in parsed.netloc)
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

def unicode_skeleton(text: str) -> str:
    if not text: return ""
    text = re.sub(r'[\u200b\u200c\u200d\ufeff]', '', text)
    text = unicodedata.normalize("NFKC", text.lower())
    chars = [HOMOGLYPH_CHAR_MAP.get(ch, ch) for ch in text]
    return "".join(chars).replace('rn', 'm').replace('vv', 'w').replace('cl', 'd').replace('nn', 'm')

def parse_url_parts(url):
    url = normalize_input_url(url).lower()
    url_clean = re.sub(r'^https?://', '', url)
    url_clean = re.sub(r'^www\.', '', url_clean)
    
    try:
        parsed = urlparse('http://' + url_clean)
        domain = parsed.netloc.split(':')[0].strip('.')
        path   = parsed.path  or ""
        query  = parsed.query or ""
    except ValueError:
        domain = url_clean.split('/')[0].strip('.')
        path, query = "", ""
        
    return url_clean, domain, path, query

def calculate_entropy(text):
    if not text: return 0.0
    probs = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probs if p > 0)

def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]