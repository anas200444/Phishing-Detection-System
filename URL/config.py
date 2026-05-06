import os

# --- API KEYS ---
VT_API_KEY = 'fb9ed8979176bc743716b6736bba75ddce368e7fd06f129517ff8b10e452bd9c'
GSB_API_KEY = 'AIzaSyDwjly0Y_EpTNYtxg9qNc_gTgvXT1HS3eU'

VT_HEADERS = {"accept": "application/json", "x-apikey": VT_API_KEY}

# --- ML Configuration ---
DATASET_FILE = "URL dataset.csv"
VISUALS_DIR  = "visualizations"
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_ARTIFACTS_FILE = os.path.join(PROJECT_DIR, "Phishing_URL_pipeline.pkl")

# --- TYPOSQUATTING LIST ---
TYPOSQUAT_LIST = [
    'google', 'microsoft', 'apple', 'amazon', 'github', 'dropbox', 
    'slack', 'adobe', 'yahoo', 'outlook', 'docusign', 'oracle',
    'facebook', 'linkedin', 'instagram', 'twitter', 'tiktok', 
    'whatsapp', 'snapchat', 'discord', 'telegram', 'zoom',
    'paypal', 'chase', 'bankofamerica', 'wellsfargo', 'capitalone', 
    'citibank', 'barclays', 'hsbc', 'visa', 'mastercard', 'americanexpress',
    'binance', 'coinbase', 'kraken', 'metamask', 'trustwallet',
    'netflix', 'ebay', 'steam', 'roblox', 'spotify', 'walmart', 'target',
    'fedex', 'dhl', 'ups', 'usps'
]

# --- HOMOGLYPH CHARACTER MAPPING ---
HOMOGLYPH_CHAR_MAP = {
    'а': 'a', 'ɑ': 'a', 'α': 'a', 'ａ': 'a', '@': 'a', '4': 'a', 'ä': 'a', 'á': 'a', 'à': 'a', 'â': 'a', 'ã': 'a', 'å': 'a', 'ą': 'a',
    'е': 'e', 'ε': 'e', 'ｅ': 'e', '3': 'e', 'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e', 'ę': 'e', 'ė': 'e',
    'і': 'i', 'í': 'i', 'ì': 'i', 'ï': 'i', 'ı': 'i', 'ｉ': 'i', '1': 'i', '!': 'i', 'î': 'i', 'į': 'i', '|': 'i',
    'ο': 'o', 'о': 'o', '0': 'o', 'ｏ': 'o', 'ö': 'o', 'ó': 'o', 'ò': 'o', 'ô': 'o', 'õ': 'o', 'ø': 'o', 'ѳ': 'o',
    'р': 'p', 'ρ': 'p', 'ｐ': 'p', 'þ': 'p', 'ѕ': 's', 'ｓ': 's', '$': 's', '5': 's', 'š': 's', 'ş': 's',
    'ԁ': 'd', 'ď': 'd', 'ｄ': 'd', 'đ': 'd', 'с': 'c', 'ϲ': 'c', 'ｃ': 'c', 'ç': 'c', 'ć': 'c', 'č': 'c',
    'х': 'x', 'χ': 'x', 'ｘ': 'x', 'у': 'y', 'γ': 'y', 'ｙ': 'y', 'ý': 'y', 'ÿ': 'y', 'ν': 'v', 'ⅴ': 'v', 'ｖ': 'v',
    'ｍ': 'm', 'rn': 'm', 'nn': 'm', 'ｎ': 'n', 'ñ': 'n', 'ń': 'n', 'ｇ': 'g', 'ԍ': 'g', '9': 'g', 'ğ': 'g', 'ģ': 'g',
    'ｌ': 'l', 'ⅼ': 'l', 'I': 'l', 'ł': 'l', 'ĺ': 'l', 'ľ': 'l', 'ｂ': 'b', 'ß': 'b', '8': 'b', 'в': 'b',
    'ｔ': 't', '7': 't', 'ț': 't', 'ť': 't', 'ｋ': 'k', 'κ': 'k', 'ķ': 'k', 'ｗ': 'w', 'vv': 'w', 'ŵ': 'w',
    'ｕ': 'u', 'μ': 'u', 'ú': 'u', 'ù': 'u', 'û': 'u', 'ü': 'u', 'ų': 'u', 'ū': 'u'
}