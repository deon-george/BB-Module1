/**
 * URL feature extraction reproducing the 111-feature phishing dataset schema.
 *
 * Mirrors backend/features.py. Only deterministic lexical/structural features
 * are computed. Network/DNS/WHOIS/TLS features default to 0 (not derivable
 * offline in an extension, matching backend's non-network path) and the two
 * external-only signals (Google index / shortener) default to 0.
 *
 * Feature order MUST match FEATURE_NAMES (and the dataset column order).
 */

const SPECIAL_CHARS = [
  '.', '-', '_', '/', '?', '=', '@', '&', '!', ' ', '~', ',', '+', '*', '#',
  '$', '%',
];

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^[0-9a-fA-F:]+:[0-9a-fA-F:]*$/;
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;

const EXTERNAL_DEFAULT_FEATURES = {
  url_google_index: 0,
  domain_google_index: 0,
  url_shortened: 0,
};

/**
 * Minimal public-suffix list sufficient to reproduce tldextract's
 * registered_domain / suffix split for common TLDs and two-part suffixes
 * (e.g. com.cn, co.uk, com.au). Entries are lower-case.
 */
const PUBLIC_SUFFIXES = new Set([
  // Generic TLDs (single-label suffixes)
  'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'biz', 'info', 'name',
  'pro', 'mobi', 'aero', 'asia', 'cat', 'coop', 'jobs', 'travel', 'museum',
  'tel', 'xxx', 'arpa',
  // ccTLD two-part suffixes commonly used
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'net.nz', 'org.nz',
  'co.in', 'net.in', 'org.in', 'ac.in', 'edu.in', 'gov.in',
  'co.za', 'org.za', 'net.za',
  'co.kr', 're.kr', 'or.kr', 'pe.kr',
  'co.jp', 'ne.jp', 'or.jp', 'go.jp', 'ac.jp',
  'com.br', 'net.br', 'org.br', 'edu.br', 'gov.br',
  'com.mx', 'org.mx', 'edu.mx',
  'com.sg', 'net.sg', 'org.sg', 'edu.sg', 'gov.sg',
  'co.id', 'web.id', 'ac.id', 'sch.id',
  'co.th', 'or.th', 'go.th', 'ac.th',
  'co.il', 'net.il', 'org.il', 'ac.il',
  'com.tr', 'net.tr', 'org.tr', 'edu.tr', 'gov.tr',
  'com.pl', 'net.pl', 'org.pl',
  'co.pt', 'com.pt', 'org.pt', 'edu.pt',
  'com.ph', 'net.ph', 'org.ph', 'edu.ph',
  'com.vn', 'net.vn', 'org.vn', 'edu.vn', 'gov.vn',
  'com.pk', 'net.pk', 'org.pk', 'edu.pk',
  'com.bd', 'org.bd', 'net.bd',
  'com.hk', 'net.hk', 'org.hk', 'edu.hk', 'gov.hk',
]);

function _tldextractSplit(hostname) {
  // Reproduce tldextract.extract(): (registered_domain, suffix).
  const labels = hostname.split('.');
  let suffix = '';
  let suffixLen = 0;

  // Try longest suffix match first (2 labels, then 1).
  for (let n = Math.min(2, labels.length); n >= 1; n--) {
    const candidate = labels.slice(labels.length - n).join('.').toLowerCase();
    if (PUBLIC_SUFFIXES.has(candidate)) {
      suffix = candidate;
      suffixLen = n;
      break;
    }
  }

  // Fallback: no public-suffix match => treat last label as TLD.
  if (suffixLen === 0 && labels.length >= 1) {
    suffix = labels[labels.length - 1].toLowerCase();
    suffixLen = 1;
  }

  const registeredDomain =
    labels.length > suffixLen
      ? labels.slice(labels.length - suffixLen - 1).join('.').toLowerCase()
      : hostname.toLowerCase();

  return { registeredDomain, suffix };
}

const FEATURE_NAMES = [
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
];

function _charCounts(text) {
  const counts = {};
  for (const ch of SPECIAL_CHARS) {
    counts[ch] = 0;
  }
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (Object.prototype.hasOwnProperty.call(counts, ch)) {
      counts[ch]++;
    }
  }
  return counts;
}

function _isIp(hostname) {
  return IPV4_RE.test(hostname) || IPV6_RE.test(hostname);
}

function _splitPath(path) {
  // Return (directory_str, file_str) for a URL path.
  const segments = path.split('/');
  while (segments.length > 0 && segments[0] === '') {
    segments.shift();
  }
  if (segments.length === 0) {
    return ['', ''];
  }
  const fileStr = segments[segments.length - 1];
  const directoryStr = segments.slice(0, -1).join('/');
  return [directoryStr, fileStr];
}

/**
 * Extract the 111-feature vector for a URL.
 * Returns { feature_vector (number[]), features (object) }.
 * feature_vector follows FEATURE_NAMES ordering.
 */
function extractFeatures(url) {
  let raw = String(url).trim();
  if (!/:\/\//.test(raw)) {
    raw = 'https://' + raw;
  }

  const parsed = new URL(raw);
  const hostname = (parsed.hostname || '').toLowerCase();
  const path = parsed.pathname || '';
  const query = parsed.search ? parsed.search.slice(1) : '';

  // --- Domain decomposition ------------------------------------------------
  let domainStr, tld, domainInIp;
  if (_isIp(hostname)) {
    domainStr = hostname;
    tld = '';
    domainInIp = 1;
  } else {
    const { registeredDomain, suffix } = _tldextractSplit(hostname);
    domainStr = registeredDomain;
    tld = suffix;
    domainInIp = 0;
  }

  const [directoryStr, fileStr] = _splitPath(path);

  const features = {};

  // --- URL section ---------------------------------------------------------
  const urlCounts = _charCounts(raw);
  Object.assign(features, {
    qty_dot_url: urlCounts['.'],
    qty_hyphen_url: urlCounts['-'],
    qty_underline_url: urlCounts['_'],
    qty_slash_url: urlCounts['/'],
    qty_questionmark_url: urlCounts['?'],
    qty_equal_url: urlCounts['='],
    qty_at_url: urlCounts['@'],
    qty_and_url: urlCounts['&'],
    qty_exclamation_url: urlCounts['!'],
    qty_space_url: urlCounts[' '],
    qty_tilde_url: urlCounts['~'],
    qty_comma_url: urlCounts[','],
    qty_plus_url: urlCounts['+'],
    qty_asterisk_url: urlCounts['*'],
    qty_hashtag_url: urlCounts['#'],
    qty_dollar_url: urlCounts['$'],
    qty_percent_url: urlCounts['%'],
    qty_tld_url: tld.length,
    length_url: raw.length,
  });

  // --- Domain section ------------------------------------------------------
  const domainCounts = _charCounts(domainStr);
  let vowels = 0;
  for (let i = 0; i < domainStr.length; i++) {
    if ('aeiouAEIOU'.indexOf(domainStr[i]) !== -1) {
      vowels++;
    }
  }
  Object.assign(features, {
    qty_dot_domain: domainCounts['.'],
    qty_hyphen_domain: domainCounts['-'],
    qty_underline_domain: domainCounts['_'],
    qty_slash_domain: domainCounts['/'],
    qty_questionmark_domain: domainCounts['?'],
    qty_equal_domain: domainCounts['='],
    qty_at_domain: domainCounts['@'],
    qty_and_domain: domainCounts['&'],
    qty_exclamation_domain: domainCounts['!'],
    qty_space_domain: domainCounts[' '],
    qty_tilde_domain: domainCounts['~'],
    qty_comma_domain: domainCounts[','],
    qty_plus_domain: domainCounts['+'],
    qty_asterisk_domain: domainCounts['*'],
    qty_hashtag_domain: domainCounts['#'],
    qty_dollar_domain: domainCounts['$'],
    qty_percent_domain: domainCounts['%'],
    qty_vowels_domain: vowels,
    domain_length: domainStr.length,
    domain_in_ip: domainInIp,
    server_client_domain: (
      domainStr.indexOf('server') !== -1 || domainStr.indexOf('client') !== -1
    ) ? 1 : 0,
  });

  const DIR_KEYS = [
    'qty_dot_directory', 'qty_hyphen_directory', 'qty_underline_directory',
    'qty_slash_directory', 'qty_questionmark_directory', 'qty_equal_directory',
    'qty_at_directory', 'qty_and_directory', 'qty_exclamation_directory',
    'qty_space_directory', 'qty_tilde_directory', 'qty_comma_directory',
    'qty_plus_directory', 'qty_asterisk_directory', 'qty_hashtag_directory',
    'qty_dollar_directory', 'qty_percent_directory', 'directory_length',
  ];
  const FILE_KEYS = [
    'qty_dot_file', 'qty_hyphen_file', 'qty_underline_file', 'qty_slash_file',
    'qty_questionmark_file', 'qty_equal_file', 'qty_at_file', 'qty_and_file',
    'qty_exclamation_file', 'qty_space_file', 'qty_tilde_file',
    'qty_comma_file', 'qty_plus_file', 'qty_asterisk_file', 'qty_hashtag_file',
    'qty_dollar_file', 'qty_percent_file', 'file_length',
  ];
  const PARAM_KEYS = [
    'qty_dot_params', 'qty_hyphen_params', 'qty_underline_params',
    'qty_slash_params', 'qty_questionmark_params', 'qty_equal_params',
    'qty_at_params', 'qty_and_params', 'qty_exclamation_params',
    'qty_space_params', 'qty_tilde_params', 'qty_comma_params',
    'qty_plus_params', 'qty_asterisk_params', 'qty_hashtag_params',
    'qty_dollar_params', 'qty_percent_params', 'params_length',
    'tld_present_params', 'qty_params',
  ];

  // --- Directory section ---------------------------------------------------
  if (directoryStr) {
    const dirCounts = _charCounts(directoryStr);
    Object.assign(features, {
      qty_dot_directory: dirCounts['.'],
      qty_hyphen_directory: dirCounts['-'],
      qty_underline_directory: dirCounts['_'],
      qty_slash_directory: dirCounts['/'],
      qty_questionmark_directory: dirCounts['?'],
      qty_equal_directory: dirCounts['='],
      qty_at_directory: dirCounts['@'],
      qty_and_directory: dirCounts['&'],
      qty_exclamation_directory: dirCounts['!'],
      qty_space_directory: dirCounts[' '],
      qty_tilde_directory: dirCounts['~'],
      qty_comma_directory: dirCounts[','],
      qty_plus_directory: dirCounts['+'],
      qty_asterisk_directory: dirCounts['*'],
      qty_hashtag_directory: dirCounts['#'],
      qty_dollar_directory: dirCounts['$'],
      qty_percent_directory: dirCounts['%'],
      directory_length: directoryStr.length,
    });
  } else {
    for (const key of DIR_KEYS) features[key] = -1;
  }

  // --- File section --------------------------------------------------------
  if (fileStr) {
    const fileCounts = _charCounts(fileStr);
    Object.assign(features, {
      qty_dot_file: fileCounts['.'],
      qty_hyphen_file: fileCounts['-'],
      qty_underline_file: fileCounts['_'],
      qty_slash_file: fileCounts['/'],
      qty_questionmark_file: fileCounts['?'],
      qty_equal_file: fileCounts['='],
      qty_at_file: fileCounts['@'],
      qty_and_file: fileCounts['&'],
      qty_exclamation_file: fileCounts['!'],
      qty_space_file: fileCounts[' '],
      qty_tilde_file: fileCounts['~'],
      qty_comma_file: fileCounts[','],
      qty_plus_file: fileCounts['+'],
      qty_asterisk_file: fileCounts['*'],
      qty_hashtag_file: fileCounts['#'],
      qty_dollar_file: fileCounts['$'],
      qty_percent_file: fileCounts['%'],
      file_length: fileStr.length,
    });
  } else {
    for (const key of FILE_KEYS) features[key] = -1;
  }

  // --- Params section ------------------------------------------------------
  if (query) {
    const paramCounts = _charCounts(query);
    const tldRe = /[A-Za-z0-9.-]+\.[A-Za-z]{2,24}/;
    Object.assign(features, {
      qty_dot_params: paramCounts['.'],
      qty_hyphen_params: paramCounts['-'],
      qty_underline_params: paramCounts['_'],
      qty_slash_params: paramCounts['/'],
      qty_questionmark_params: paramCounts['?'],
      qty_equal_params: paramCounts['='],
      qty_at_params: paramCounts['@'],
      qty_and_params: paramCounts['&'],
      qty_exclamation_params: paramCounts['!'],
      qty_space_params: paramCounts[' '],
      qty_tilde_params: paramCounts['~'],
      qty_comma_params: paramCounts[','],
      qty_plus_params: paramCounts['+'],
      qty_asterisk_params: paramCounts['*'],
      qty_hashtag_params: paramCounts['#'],
      qty_dollar_params: paramCounts['$'],
      qty_percent_params: paramCounts['%'],
      params_length: query.length,
      tld_present_params: tldRe.test(query) ? 1 : 0,
      qty_params: query.split('&').length,
    });
  } else {
    for (const key of PARAM_KEYS) features[key] = -1;
  }

  // --- Email in URL --------------------------------------------------------
  features.email_in_url = EMAIL_RE.test(raw) ? 1 : 0;

  // --- Network / reputation features (offline defaults = 0) ----------------
  Object.assign(features, {
    time_response: 0.0,
    domain_spf: 0,
    asn_ip: 0,
    time_domain_activation: 0,
    time_domain_expiration: 0,
    qty_ip_resolved: 0,
    qty_nameservers: 0,
    qty_mx_servers: 0,
    ttl_hostname: 0,
    tls_ssl_certificate: 0,
    qty_redirects: 0,
  });

  // --- External-only signals (not derivable from a single URL) -------------
  Object.assign(features, EXTERNAL_DEFAULT_FEATURES);

  const featureVector = FEATURE_NAMES.map((name) => features[name]);
  return { feature_vector: featureVector, features };
}

export { FEATURE_NAMES, extractFeatures };
