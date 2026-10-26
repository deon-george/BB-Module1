"""Python feature extractor mirroring features.js exactly.

Feature names, order, and defaults match FEATURE_NAMES in features.js.
"""
import re

SPECIAL_CHARS = ['.', '-', '_', '/', '?', '=', '@', '&', '!', ' ', '~', ',', '+', '*', '#', '$', '%']

IPV4_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
IPV6_RE = re.compile(r'^[0-9a-fA-F:]+:[0-9a-fA-F:]*$')
EMAIL_RE = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')

EXTERNAL_DEFAULT_FEATURES = {
    'url_google_index': 0,
    'domain_google_index': 0,
    'url_shortened': 0,
}

PUBLIC_SUFFIXES = {
    'com','org','net','edu','gov','mil','int','biz','info','name','pro','mobi','aero','asia','cat','coop','jobs','travel','museum','tel','xxx','arpa',
    'com.cn','net.cn','org.cn','gov.cn','edu.cn','co.uk','org.uk','ac.uk','gov.uk','com.au','net.au','org.au','edu.au','gov.au','co.nz','net.nz','org.nz',
    'co.in','net.in','org.in','ac.in','edu.in','gov.in','co.za','org.za','net.za','co.kr','re.kr','or.kr','pe.kr','co.jp','ne.jp','or.jp','go.jp','ac.jp',
    'com.br','net.br','org.br','edu.br','gov.br','com.mx','org.mx','edu.mx','com.sg','net.sg','org.sg','edu.sg','gov.sg','co.id','web.id','ac.id','sch.id',
    'co.th','or.th','go.th','ac.th','co.il','net.il','org.il','ac.il','com.tr','net.tr','org.tr','edu.tr','gov.tr','com.pl','net.pl','org.pl','co.pt','com.pt','org.pt','edu.pt',
    'com.ph','net.ph','org.ph','edu.ph','com.vn','net.vn','org.vn','edu.vn','gov.vn','com.pk','net.pk','org.pk','edu.pk','com.bd','org.bd','net.bd','com.hk','net.hk','org.hk','edu.hk','gov.hk',
}

FEATURE_NAMES = [
  'qty_dot_url', 'qty_hyphen_url', 'qty_underline_url', 'qty_slash_url',
  'qty_questionmark_url', 'qty_equal_url', 'qty_at_url', 'qty_and_url',
  'qty_exclamation_url', 'qty_space_url', 'qty_tilde_url', 'qty_comma_url',
  'qty_plus_url', 'qty_asterisk_url', 'qty_hashtag_url', 'qty_dollar_url',
  'qty_percent_url', 'qty_tld_url', 'length_url',
  'qty_dot_domain', 'qty_hyphen_domain', 'qty_underline_domain',
  'qty_slash_domain', 'qty_questionmark_domain', 'qty_equal_domain',
  'qty_at_domain', 'qty_and_domain', 'qty_exclamation_domain',
  'qty_space_domain', 'qty_tilde_domain', 'qty_comma_domain',
  'qty_plus_domain', 'qty_asterisk_domain', 'qty_hashtag_domain',
  'qty_dollar_domain', 'qty_percent_domain', 'qty_vowels_domain',
  'domain_length', 'domain_in_ip', 'server_client_domain',
  'qty_dot_directory', 'qty_hyphen_directory', 'qty_underline_directory',
  'qty_slash_directory', 'qty_questionmark_directory', 'qty_equal_directory',
  'qty_at_directory', 'qty_and_directory', 'qty_exclamation_directory',
  'qty_space_directory', 'qty_tilde_directory', 'qty_comma_directory',
  'qty_plus_directory', 'qty_asterisk_directory', 'qty_hashtag_directory',
  'qty_dollar_directory', 'qty_percent_directory', 'directory_length',
  'qty_dot_file', 'qty_hyphen_file', 'qty_underline_file', 'qty_slash_file',
  'qty_questionmark_file', 'qty_equal_file', 'qty_at_file', 'qty_and_file',
  'qty_exclamation_file', 'qty_space_file', 'qty_tilde_file',
  'qty_comma_file', 'qty_plus_file', 'qty_asterisk_file', 'qty_hashtag_file',
  'qty_dollar_file', 'qty_percent_file', 'file_length',
  'qty_dot_params', 'qty_hyphen_params', 'qty_underline_params',
  'qty_slash_params', 'qty_questionmark_params', 'qty_equal_params',
  'qty_at_params', 'qty_and_params', 'qty_exclamation_params',
  'qty_space_params', 'qty_tilde_params', 'qty_comma_params',
  'qty_plus_params', 'qty_asterisk_params', 'qty_hashtag_params',
  'qty_dollar_params', 'qty_percent_params', 'params_length',
  'tld_present_params', 'qty_params', 'email_in_url',
  'time_response', 'domain_spf', 'asn_ip', 'time_domain_activation',
  'time_domain_expiration', 'qty_ip_resolved', 'qty_nameservers',
  'qty_mx_servers', 'ttl_hostname', 'tls_ssl_certificate', 'qty_redirects',
  'url_google_index', 'domain_google_index', 'url_shortened',
]

DIR_KEYS = [
    'qty_dot_directory', 'qty_hyphen_directory', 'qty_underline_directory',
    'qty_slash_directory', 'qty_questionmark_directory', 'qty_equal_directory',
    'qty_at_directory', 'qty_and_directory', 'qty_exclamation_directory',
    'qty_space_directory', 'qty_tilde_directory', 'qty_comma_directory',
    'qty_plus_directory', 'qty_asterisk_directory', 'qty_hashtag_directory',
    'qty_dollar_directory', 'qty_percent_directory', 'directory_length',
]
FILE_KEYS = [
    'qty_dot_file', 'qty_hyphen_file', 'qty_underline_file', 'qty_slash_file',
    'qty_questionmark_file', 'qty_equal_file', 'qty_at_file', 'qty_and_file',
    'qty_exclamation_file', 'qty_space_file', 'qty_tilde_file',
    'qty_comma_file', 'qty_plus_file', 'qty_asterisk_file', 'qty_hashtag_file',
    'qty_dollar_file', 'qty_percent_file', 'file_length',
]
PARAM_KEYS = [
    'qty_dot_params', 'qty_hyphen_params', 'qty_underline_params',
    'qty_slash_params', 'qty_questionmark_params', 'qty_equal_params',
    'qty_at_params', 'qty_and_params', 'qty_exclamation_params',
    'qty_space_params', 'qty_tilde_params', 'qty_comma_params',
    'qty_plus_params', 'qty_asterisk_params', 'qty_hashtag_params',
    'qty_dollar_params', 'qty_percent_params', 'params_length',
    'tld_present_params', 'qty_params',
]


def _char_counts(text):
    counts = {ch: 0 for ch in SPECIAL_CHARS}
    for ch in text:
        if ch in counts:
            counts[ch] += 1
    return counts


def _is_ip(hostname):
    return bool(IPV4_RE.match(hostname) or IPV6_RE.match(hostname))


def _tldextract_split(hostname):
    labels = hostname.split('.')
    suffix = ''
    suffix_len = 0
    for n in range(min(2, len(labels)), 0, -1):
        candidate = '.'.join(labels[len(labels)-n:]).lower()
        if candidate in PUBLIC_SUFFIXES:
            suffix = candidate
            suffix_len = n
            break
    if suffix_len == 0 and len(labels) >= 1:
        suffix = labels[-1].lower()
        suffix_len = 1
    if len(labels) > suffix_len:
        registered_domain = '.'.join(labels[len(labels)-suffix_len-1:]).lower()
    else:
        registered_domain = hostname.lower()
    return registered_domain, suffix


def _split_path(path):
    segments = [s for s in path.split('/')]
    while segments and segments[0] == '':
        segments.pop(0)
    if not segments:
        return '', ''
    file_str = segments[-1]
    directory_str = '/'.join(segments[:-1])
    return directory_str, file_str


def extract_features(url):
    raw = str(url).strip()
    if '://' not in raw:
        raw = 'https://' + raw
    from urllib.parse import urlparse
    parsed = urlparse(raw)
    hostname = (parsed.hostname or '').lower()
    path = parsed.path or ''
    query = parsed.query or ''

    if _is_ip(hostname):
        domain_str = hostname
        tld = ''
        domain_in_ip = 1
    else:
        rd, suffix = _tldextract_split(hostname)
        domain_str = rd
        tld = suffix
        domain_in_ip = 0

    directory_str, file_str = _split_path(path)

    features = {}

    # URL section
    uc = _char_counts(raw)
    features.update({
        'qty_dot_url': uc['.'], 'qty_hyphen_url': uc['-'], 'qty_underline_url': uc['_'],
        'qty_slash_url': uc['/'], 'qty_questionmark_url': uc['?'], 'qty_equal_url': uc['='],
        'qty_at_url': uc['@'], 'qty_and_url': uc['&'], 'qty_exclamation_url': uc['!'],
        'qty_space_url': uc[' '], 'qty_tilde_url': uc['~'], 'qty_comma_url': uc[','],
        'qty_plus_url': uc['+'], 'qty_asterisk_url': uc['*'], 'qty_hashtag_url': uc['#'],
        'qty_dollar_url': uc['$'], 'qty_percent_url': uc['%'],
        'qty_tld_url': len(tld), 'length_url': len(raw),
    })

    # Domain section
    dc = _char_counts(domain_str)
    vowels = sum(1 for ch in domain_str if ch in 'aeiouAEIOU')
    features.update({
        'qty_dot_domain': dc['.'], 'qty_hyphen_domain': dc['-'], 'qty_underline_domain': dc['_'],
        'qty_slash_domain': dc['/'], 'qty_questionmark_domain': dc['?'], 'qty_equal_domain': dc['='],
        'qty_at_domain': dc['@'], 'qty_and_domain': dc['&'], 'qty_exclamation_domain': dc['!'],
        'qty_space_domain': dc[' '], 'qty_tilde_domain': dc['~'], 'qty_comma_domain': dc[','],
        'qty_plus_domain': dc['+'], 'qty_asterisk_domain': dc['*'], 'qty_hashtag_domain': dc['#'],
        'qty_dollar_domain': dc['$'], 'qty_percent_domain': dc['%'],
        'qty_vowels_domain': vowels, 'domain_length': len(domain_str),
        'domain_in_ip': domain_in_ip,
        'server_client_domain': 1 if ('server' in domain_str or 'client' in domain_str) else 0,
    })

    # Directory section
    if directory_str:
        dirc = _char_counts(directory_str)
        features.update({
            'qty_dot_directory': dirc['.'], 'qty_hyphen_directory': dirc['-'],
            'qty_underline_directory': dirc['_'], 'qty_slash_directory': dirc['/'],
            'qty_questionmark_directory': dirc['?'], 'qty_equal_directory': dirc['='],
            'qty_at_directory': dirc['@'], 'qty_and_directory': dirc['&'],
            'qty_exclamation_directory': dirc['!'], 'qty_space_directory': dirc[' '],
            'qty_tilde_directory': dirc['~'], 'qty_comma_directory': dirc[','],
            'qty_plus_directory': dirc['+'], 'qty_asterisk_directory': dirc['*'],
            'qty_hashtag_directory': dirc['#'], 'qty_dollar_directory': dirc['$'],
            'qty_percent_directory': dirc['%'], 'directory_length': len(directory_str),
        })
    else:
        for k in DIR_KEYS:
            features[k] = -1

    # File section
    if file_str:
        fc = _char_counts(file_str)
        features.update({
            'qty_dot_file': fc['.'], 'qty_hyphen_file': fc['-'],
            'qty_underline_file': fc['_'], 'qty_slash_file': fc['/'],
            'qty_questionmark_file': fc['?'], 'qty_equal_file': fc['='],
            'qty_at_file': fc['@'], 'qty_and_file': fc['&'],
            'qty_exclamation_file': fc['!'], 'qty_space_file': fc[' '],
            'qty_tilde_file': fc['~'], 'qty_comma_file': fc[','],
            'qty_plus_file': fc['+'], 'qty_asterisk_file': fc['*'],
            'qty_hashtag_file': fc['#'], 'qty_dollar_file': fc['$'],
            'qty_percent_file': fc['%'], 'file_length': len(file_str),
        })
    else:
        for k in FILE_KEYS:
            features[k] = -1

    # Params section
    if query:
        pc = _char_counts(query)
        tld_re = re.compile(r'[A-Za-z0-9.-]+\.[A-Za-z]{2,24}')
        features.update({
            'qty_dot_params': pc['.'], 'qty_hyphen_params': pc['-'],
            'qty_underline_params': pc['_'], 'qty_slash_params': pc['/'],
            'qty_questionmark_params': pc['?'], 'qty_equal_params': pc['='],
            'qty_at_params': pc['@'], 'qty_and_params': pc['&'],
            'qty_exclamation_params': pc['!'], 'qty_space_params': pc[' '],
            'qty_tilde_params': pc['~'], 'qty_comma_params': pc[','],
            'qty_plus_params': pc['+'], 'qty_asterisk_params': pc['*'],
            'qty_hashtag_params': pc['#'], 'qty_dollar_params': pc['$'],
            'qty_percent_params': pc['%'], 'params_length': len(query),
            'tld_present_params': 1 if tld_re.search(query) else 0,
            'qty_params': len(query.split('&')),
        })
    else:
        for k in PARAM_KEYS:
            features[k] = -1

    features['email_in_url'] = 1 if EMAIL_RE.search(raw) else 0

    features.update({
        'time_response': 0.0, 'domain_spf': 0, 'asn_ip': 0,
        'time_domain_activation': 0, 'time_domain_expiration': 0,
        'qty_ip_resolved': 0, 'qty_nameservers': 0, 'qty_mx_servers': 0,
        'ttl_hostname': 0, 'tls_ssl_certificate': 0, 'qty_redirects': 0,
    })
    features.update(EXTERNAL_DEFAULT_FEATURES)

    return [features[name] for name in FEATURE_NAMES], features


if __name__ == '__main__':
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else 'https://example.com/login'
    vec, f = extract_features(url)
    print(len(vec))
    print(vec)
