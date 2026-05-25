import os
import io
import re
import csv
import time
import zipfile
import requests
import unicodedata
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_FILE = os.path.join(PROJECT_DIR, "tranco.csv")
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/text_online/"
URLHAUS_FILE = os.path.join(PROJECT_DIR, "urlhaus.txt")

CACHE_MAX_AGE_SECONDS = 24 * 60 * 60
REQUEST_TIMEOUT = 20
BRAND_SOURCE_LIMIT = 100_000
MIN_BRAND_LEN = 5
MAX_BRAND_LEN = 30
TYPO_RANK_LIMIT = 30_000
EXACT_COMBO_RANK_LIMIT = 5_000

HTTP_HEADERS = {
    "User-Agent": "Mozilla/5.0 Phishing-Detection-System/1.0",
    "Accept": "*/*",
    "Connection": "close",
}

HOMOGLYPH_CHAR_MAP = {
    "а": "a", "ɑ": "a", "α": "a", "ａ": "a", "@": "a", "4": "a", "ä": "a", "á": "a", "à": "a", "â": "a", "ã": "a", "å": "a", "ą": "a",
    "е": "e", "ε": "e", "ｅ": "e", "3": "e", "é": "e", "è": "e", "ê": "e", "ë": "e", "ę": "e", "ė": "e",
    "і": "i", "í": "i", "ì": "i", "ï": "i", "ı": "i", "ｉ": "i", "1": "i", "!": "i", "î": "i", "į": "i", "|": "i",
    "ο": "o", "о": "o", "0": "o", "ｏ": "o", "ö": "o", "ó": "o", "ò": "o", "ô": "o", "õ": "o", "ø": "o", "ѳ": "o",
    "р": "p", "ρ": "p", "ｐ": "p", "þ": "p", "ѕ": "s", "ｓ": "s", "$": "s", "5": "s", "š": "s", "ş": "s",
    "ԁ": "d", "ď": "d", "ｄ": "d", "đ": "d", "с": "c", "ϲ": "c", "ｃ": "c", "ç": "c", "ć": "c", "č": "c",
    "х": "x", "χ": "x", "ｘ": "x", "у": "y", "γ": "y", "ｙ": "y", "ý": "y", "ÿ": "y", "ν": "v", "ⅴ": "v", "ｖ": "v",
    "ｍ": "m", "rn": "m", "nn": "m", "ｎ": "n", "ñ": "n", "ń": "n", "ｇ": "g", "ԍ": "g", "9": "g", "ğ": "g", "ģ": "g",
    "ｌ": "l", "ⅼ": "l", "I": "l", "ł": "l", "ĺ": "l", "ľ": "l", "ｂ": "b", "ß": "b", "8": "b", "в": "b",
    "ｔ": "t", "7": "t", "ț": "t", "ť": "t", "ｋ": "k", "κ": "k", "ķ": "k", "ｗ": "w", "vv": "w", "ŵ": "w",
    "ｕ": "u", "μ": "u", "ú": "u", "ù": "u", "û": "u", "ü": "u", "ų": "u", "ū": "u",
}

TRANCO_SET = set()
URLHAUS_SET = set()
BRAND_SET = set()
BRAND_RANK = {}
BRAND_BY_LENGTH = {}
LISTS_LOADED = False

def cache_is_fresh(path):
    return (os.path.exists(path) and os.path.getsize(path) > 0 and time.time() - os.path.getmtime(path) < CACHE_MAX_AGE_SECONDS)

def read_text(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as file: return file.read()

def atomic_write(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as file: file.write(text)
    os.replace(tmp, path)

def load_tranco(force_refresh=False):
    try:
        if not force_refresh and cache_is_fresh(TRANCO_FILE):
            return [clean_host(r[1]) for r in csv.reader(io.StringIO(read_text(TRANCO_FILE))) if len(r) > 1 and clean_host(r[1])]
        response = requests.get(TRANCO_URL, headers=HTTP_HEADERS, timeout=REQUEST_TIMEOUT)
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            csv_name = next(n for n in z.namelist() if n.lower().endswith(".csv"))
            text = z.read(csv_name).decode("utf-8", errors="ignore")
            atomic_write(TRANCO_FILE, text)
            return [clean_host(r[1]) for r in csv.reader(io.StringIO(text)) if len(r) > 1 and clean_host(r[1])]
    except Exception:
        return []

def load_urlhaus(force_refresh=False):
    try:
        if not force_refresh and cache_is_fresh(URLHAUS_FILE):
            return {l.strip() for l in read_text(URLHAUS_FILE).splitlines() if l.strip() and not l.startswith("#")}
        text = requests.get(URLHAUS_URL, headers=HTTP_HEADERS, timeout=REQUEST_TIMEOUT).text
        atomic_write(URLHAUS_FILE, text)
        return {l.strip() for l in text.splitlines() if l.strip() and not l.startswith("#")}
    except Exception:
        return set()

def build_brand_data(domains):
    brands, rank_map, by_length = set(), {}, {}
    for rank, domain in enumerate(domains[:BRAND_SOURCE_LIMIT], start=1):
        brand = extract_brand_from_domain(domain)
        if brand and MIN_BRAND_LEN <= len(brand) <= MAX_BRAND_LEN and not brand.isdigit() and re.fullmatch(r"[a-z0-9]+", brand):
            brands.add(brand)
            rank_map[brand] = min(rank_map.get(brand, rank), rank)
            by_length.setdefault(len(brand), set()).add(brand)
    return brands, rank_map, by_length

def load_threat_lists(force_refresh=False):
    global LISTS_LOADED, TRANCO_SET, URLHAUS_SET, BRAND_SET, BRAND_RANK, BRAND_BY_LENGTH
    if LISTS_LOADED and not force_refresh: return
    with ThreadPoolExecutor(max_workers=2) as executor:
        tranco_domains = executor.submit(load_tranco, force_refresh).result()
        URLHAUS_SET = executor.submit(load_urlhaus, force_refresh).result()
    TRANCO_SET = set(tranco_domains)
    BRAND_SET, BRAND_RANK, BRAND_BY_LENGTH = build_brand_data(tranco_domains)
    LISTS_LOADED = True

# --- URL Helpers ---
def ensure_url_scheme(url): return url if not url or str(url).strip().startswith(("http://", "https://")) else "http://" + str(url).strip()
def is_valid_url_format(url):
    try: return urlparse(url).scheme in ("http", "https") and bool(urlparse(url).netloc) and "." in urlparse(url).netloc
    except: return False
def clean_host(host):
    h = str(host).lower().split("@")[-1].split(":")[0].strip(".")
    return h[4:] if h.startswith("www.") else h
def get_sld(domain):
    parts = clean_host(domain).split(".")
    if len(parts) > 2 and len(parts[-2]) <= 3 and len(parts[-1]) <= 3: return parts[-3]
    return parts[-2] if len(parts) >= 2 else domain
def extract_domain(url): return urlparse(url).netloc or urlparse(url).path
def get_base_domain(domain):
    parts = clean_host(domain).split(".")
    if len(parts) < 2: return domain
    return ".".join(parts[-3:]) if len(parts) > 2 and len(parts[-2]) <= 3 and len(parts[-1]) <= 3 else ".".join(parts[-2:])
def decode_punycode(domain):
    try: return domain.encode("ascii").decode("idna") if "xn--" in domain.lower() else domain
    except: return domain
def unicode_skeleton(text):
    if not text: return ""
    text = unicodedata.normalize("NFKC", re.sub(r"[\u200b\u200c\u200d\ufeff]", "", text).lower())
    text = "".join(HOMOGLYPH_CHAR_MAP.get(ch, ch) for ch in text)
    return text.replace("rn", "m").replace("vv", "w").replace("cl", "d").replace("nn", "m")
def extract_brand_from_domain(domain): return re.sub(r"[^a-z0-9]", "", unicode_skeleton(decode_punycode(get_sld(domain))))
def normalize_url_for_vt(url):
    parsed = urlparse(str(url).strip())
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path or '/'}" + (f";{parsed.params}" if parsed.params else "") + (f"?{parsed.query}" if parsed.query else "") + (f"#{parsed.fragment}" if parsed.fragment else "")

# --- Spoofing & Whitelisting ---
def is_tranco_whitelisted(url):
    parsed = urlparse(url)
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.params: return False, None
    host = clean_host(parsed.netloc)
    return (True, host) if host in TRANCO_SET else (False, None)

def levenshtein_distance(a, b):
    if len(a) < len(b): return levenshtein_distance(b, a)
    if not b: return len(a)
    prev = range(len(b) + 1)
    for i, c1 in enumerate(a):
        curr = [i + 1]
        for j, c2 in enumerate(b): curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]

def detect_typosquatting_and_homograph(url):
    raw_domain = re.sub(r"^www\.", "", re.sub(r"^https?://", "", str(url).strip().lower())).split("/")[0].strip(".")
    skel_domain = unicode_skeleton(decode_punycode(raw_domain))
    raw_sld = re.sub(r"[^a-z0-9]", "", get_sld(decode_punycode(raw_domain)).lower())
    skel_sld = re.sub(r"[^a-z0-9]", "", get_sld(skel_domain).lower())
    result = {"typosquat_risk": 0, "homograph_risk": 0, "matched_brand": None}
    
    if not raw_sld or not skel_sld: return result
    if raw_sld != skel_sld and skel_sld in BRAND_SET and BRAND_RANK.get(skel_sld, 999999) <= TYPO_RANK_LIMIT:
        result.update({"homograph_risk": 1, "matched_brand": skel_sld})
        return result
    if raw_sld == skel_sld and skel_sld in BRAND_SET: return result
    
    # Check typo distance
    for length in range(max(MIN_BRAND_LEN, len(skel_sld) - 2), min(MAX_BRAND_LEN, len(skel_sld) + 2) + 1):
        for brand in BRAND_BY_LENGTH.get(length, []):
            if BRAND_RANK.get(brand, 999999) <= TYPO_RANK_LIMIT:
                dist = levenshtein_distance(skel_sld, brand)
                if brand != skel_sld and 1 <= dist <= (1 if len(brand) <= 8 else (2 if len(brand) >= 6 else 0)):
                    result.update({"typosquat_risk": 1, "matched_brand": brand})
                    return result
    return result