import os

# API CONFIGURATION
URLSCAN_API_KEY = '019d1a04-6286-73c5-8053-b19f5f9e0985'
VT_API_KEY = 'fb9ed8979176bc743716b6736bba75ddce368e7fd06f129517ff8b10e452bd9c'

URLSCAN_HEADERS = {'API-Key': URLSCAN_API_KEY, 'Content-Type': 'application/json'}
VT_HEADERS = {"accept": "application/json", "x-apikey": VT_API_KEY}

# ML CONFIGURATION
DATASET_FILE = "URL dataset.csv"
VISUALS_DIR  = "visualizations"

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_ARTIFACTS_FILE = os.path.join(PROJECT_DIR, "Phishing_URL_model.pkl")

# CONSTANTS & LISTS
SUSPICIOUS_KEYWORDS = [
    'verify', 'secure', 'bank', 'update', 'account', 'signin', 'support', 'auth', 'billing', 'confirm', 'password', 'recovery',
    'free', 'wallet', 'admin', 'webscr', 'bonus', 'claim', 'unlock', 'webmail', 'ticket', 'refund', 'invoice', 'payment',
    'reset', 'validate', 'alert', 'service', 'suspended', 'security', 'gift', 'prize', 'pending', 'limited', 'important', 'activation',
    'verification', 'restore', 'reactivate', 'notification', 'manage', 'credential', 'authenticate', 'helpdesk', 'checkout', 'pki-validation',
]
LOGIN_PATH_TOKENS = ['login', 'signin', 'auth', 'authenticate', 'cs', 'admin']
PORTAL_KEYWORDS = ['exam', 'student', 'univ', 'college', 'academy', 'learn', 'course', 'study', 'insti', 'portal', 'school', 'educat', 'campus', 'scholar']
ABUSED_CLOUD_HOSTS = ['googleusercontent.com', 'amazonaws.com', 'storage.googleapis.com', 'azurewebsites.net', 'cloudfront.net', 'github.io', 'pages.dev', 'vercel.app', 'netlify.app', 'onrender.com', 's3.amazonaws.com']
DYNAMIC_DNS_PROVIDERS = ['ddns.net', 'ddns.info', 'no-ip.org', 'duckdns.org', 'hopto.org', 'zapto.org', 'sytes.net', 'freeddns.org', 'myddns.me']
POPULAR_DOMAINS = [
    'google.com', 'gmail.com', 'youtube.com', 'facebook.com', 'instagram.com', 'whatsapp.com', 'microsoft.com', 'microsoftonline.com', 'slack.com',
    'apple.com', 'icloud.com', 'amazon.com', 'paypal.com', 'netflix.com', 'roblox.com', 'discord.com', 'steamcommunity.com', 'steampowered.com',
    'steam.com', 'github.com', 'linkedin.com', 'dropbox.com', 'adobe.com', 'x.com', 'twitter.com', 'tiktok.com', 'snapchat.com',
    'yahoo.com', 'outlook.com', 'hotmail.com', 'office.com', 'live.com', 'chase.com', 'wellsfargo.com', 'bankofamerica.com',
    'capitalone.com', 'visa.com', 'mastercard.com', 'ebay.com', 'bcp.com.pe', 'zoom.us', 'cnn.com', 'bbc.com', 'foxnews.com', 'nytimes.com', 'wsj.com'
]
ABSOLUTE_TRUSTED = {
    'google.com', 'gmail.com', 'youtube.com', 'facebook.com', 'microsoft.com', 'apple.com', 'amazon.com', 'paypal.com', 'netflix.com', 'linkedin.com',
    'github.com', 'ebay.com', 'steam.com', 'whatsapp.com', 'docs.google.com', 'drive.google.com', 'slack.com', 'microsoftonline.com', 'cnn.com', 'bbc.com',
    'foxnews.com', 'nytimes.com', 'wsj.com'
}
EXTRA_TRUSTED_DOMAINS = ['docs.google.com', 'drive.google.com', 'sites.google.com', 'stackoverflow.com', 'stackexchange.com', 'wikimedia.org', 'wikipedia.org', 'wordpress.com', 'tumblr.com', 'blogspot.com', 'weebly.com', 'wixsite.com']
FREE_HOSTING = ['000webhostapp.com', '123formbuilder.com', 'hyperphp.com', 'cloudaccess.host', 'freeiz.com', 'site44.com', 'bravesites.com', 'page.tl', 'hostfree.pw', 'free.fr', 'pagedemo.co']
BLOG_PLATFORMS = ['blogspot.com', 'blogspot.ru', 'blogspot.co.uk', 'weebly.com', 'wixsite.com', 'tumblr.com', 'appspot.com', 'firebaseapp.com']
SUSPICIOUS_TLDS = {'xyz', 'top', 'click', 'gq', 'ml', 'cf', 'ga', 'tk', 'work', 'support', 'buzz', 'country', 'stream', 'download', 'xin', 'kim', 'men', 'loan', 'mom', 'zip', 'review', 'monster', 'cyou', 'surf', 'bar', 'cfd', 'digital', 'live', 'icu', 'me', 'cc', 'cn', 'pw', 'nl', 'email', 'is', 'info', 'ru', 'su'}
URL_SHORTENERS = {'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'tiny.cc', 'cutt.ly', 'rebrand.ly', 'short.io', 'shorte.st', 'trib.al', 'soo.gd', 'bc.vc', 'x.co', '1drv.ms', 'kekk.is', 'v.gd', 'shorturl.at', 'rb.gy', 't.ly'}
SUSPICIOUS_FILE_EXTENSIONS = ['.exe', '.zip', '.rar', '.scr', '.js', '.apk', '.bat', '.cmd', '.xml']
REDIRECT_TOKENS = ['/redirect', '/redir', '/out', '/url', '/go']
CMS_TOKENS = ['wp-admin', 'wp-content', 'wp-includes', 'com_user', 'drupal']
CONSONANTS = set('bcdfghjklmnpqrstvwxyz')
VOWELS = set('aeiou')

BRAND_ALIASES = {
    'google': ['google', 'gmail', 'gdrive', 'googledrive'], 'microsoft': ['microsoft', 'office', 'office365', 'outlook', 'hotmail', 'live', 'onedrive', '1drive'],
    'apple': ['apple', 'icloud', 'itunes', 'appleid', 'appleld'], 'amazon': ['amazon', 'aws', 'prime'], 'paypal': ['paypal', 'paypa', 'paypa1', 'paypai', 'paypal1'],
    'netflix': ['netflix'], 'roblox': ['roblox'], 'discord': ['discord'], 'steam': ['steam', 'steampowered'], 'github': ['github'], 'linkedin': ['linkedin'],
    'facebook': ['facebook', 'fb', 'meta'], 'instagram': ['instagram'], 'whatsapp': ['whatsapp'], 'adobe': ['adobe', 'acrobat'], 'yahoo': ['yahoo', 'yahoomass'],
    'bankofamerica': ['bankofamerica', 'boa'], 'wellsfargo': ['wellsfargo'], 'chase': ['chase'], 'dropbox': ['dropbox'], 'tiktok': ['tiktok'],
    'snapchat': ['snapchat'], 'twitter': ['twitter', 'x'], 'spotify': ['spotify'], 'ebay': ['ebay'], 'slack': ['slack'], 'zoom': ['zoom'],
    'bcp': ['bcp', 'bancodecredito'], 'cnn': ['cnn'], 'bbc': ['bbc']
}

BRAND_KEYWORDS = sorted({alias for aliases in BRAND_ALIASES.values() for alias in aliases})

_RANDOM_DOMAIN_VOWEL_THRESHOLD = 0.18
_RANDOM_DOMAIN_CONSONANT_RUN = 5

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

HIGH_RISK_COMBO_WORDS = {
    'secure', 'login', 'signin', 'verify', 'update', 'account', 'auth', 'wallet', 'billing', 'support', 'payment', 'recover', 'recovery',
    'password', 'confirm', 'webmail', 'portal', 'verification'
}