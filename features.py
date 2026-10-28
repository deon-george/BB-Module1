"""Feature extractor mirroring PhishingDataset schema (30 features)."""
import re

FEATURE_NAMES = [
    'having_IP_Address','URL_Length','Shortining_Service','having_At_Symbol',
    'double_slash_redirecting','Prefix_Suffix','having_Sub_Domain','SSLfinal_State',
    'Domain_registeration_length','Favicon','port','HTTPS_token','Request_URL',
    'URL_of_Anchor','Links_in_tags','SFH','Submitting_to_email','Abnormal_URL',
    'Redirect','on_mouseover','RightClick','popUpWidnow','Iframe','age_of_domain',
    'DNSRecord','web_traffic','Page_Rank','Google_Index','Links_pointing_to_page',
    'Statistical_report',
]

IPV4_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

def extract_features(url):
    raw = str(url).strip()
    from urllib.parse import urlparse
    p = urlparse(raw)
    host = p.hostname or ''
    features = {n: 0 for n in FEATURE_NAMES}
    # having_IP_Address
    features['having_IP_Address'] = 1 if IPV4_RE.match(host) else -1
    # URL_Length
    L = len(raw)
    features['URL_Length'] = 1 if L < 54 else (0 if L <= 75 else -1)
    # having_At_Symbol
    features['having_At_Symbol'] = 1 if '@' in raw else -1
    # double_slash_redirecting
    features['double_slash_redirecting'] = 1 if raw.rfind('//') > 6 else -1
    # Prefix_Suffix
    features['Prefix_Suffix'] = 1 if '-' in host else -1
    # having_Sub_Domain
    dots = host.count('.')
    features['having_Sub_Domain'] = -1 if dots == 1 else (0 if dots == 2 else 1)
    # SSLfinal_State
    features['SSLfinal_State'] = 1 if p.scheme == 'https' else -1
    # HTTPS_token
    features['HTTPS_token'] = 1 if 'https' in host.lower() and p.scheme != 'https' else -1
    # port
    features['port'] = 1 if (p.port and p.port not in (80,443)) else -1
    return [features[n] for n in FEATURE_NAMES], features

if __name__ == '__main__':
    import sys
    print(extract_features(sys.argv[1])[0])