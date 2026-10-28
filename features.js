const FEATURE_NAMES = [
  'having_IP_Address','URL_Length','Shortining_Service','having_At_Symbol',
  'double_slash_redirecting','Prefix_Suffix','having_Sub_Domain','SSLfinal_State',
  'Domain_registeration_length','Favicon','port','HTTPS_token','Request_URL',
  'URL_of_Anchor','Links_in_tags','SFH','Submitting_to_email','Abnormal_URL',
  'Redirect','on_mouseover','RightClick','popUpWidnow','Iframe','age_of_domain',
  'DNSRecord','web_traffic','Page_Rank','Google_Index','Links_pointing_to_page',
  'Statistical_report',
];

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

function extractFeatures(url) {
  const raw = String(url).trim();
  let p;
  try { p = new URL(raw); } catch { p = null; }
  const host = p ? p.hostname : '';
  const features = {};
  for (const n of FEATURE_NAMES) features[n] = 0;
  features['having_IP_Address'] = IPV4_RE.test(host) ? 1 : -1;
  const L = raw.length;
  features['URL_Length'] = L < 54 ? 1 : (L <= 75 ? 0 : -1);
  features['having_At_Symbol'] = raw.includes('@') ? 1 : -1;
  features['double_slash_redirecting'] = raw.lastIndexOf('//') > 6 ? 1 : -1;
  features['Prefix_Suffix'] = host.includes('-') ? 1 : -1;
  const dots = host.split('.').length - 1;
  features['having_Sub_Domain'] = dots === 1 ? -1 : (dots === 2 ? 0 : 1);
  features['SSLfinal_State'] = (p && p.protocol === 'https:') ? 1 : -1;
  features['HTTPS_token'] = (host.toLowerCase().includes('https') && !(p && p.protocol === 'https:')) ? 1 : -1;
  const port = p ? p.port : '';
  features['port'] = (port && !['80','443',''].includes(port)) ? 1 : -1;
  const fv = FEATURE_NAMES.map(n => features[n]);
  return { feature_vector: fv, features };
}

export { FEATURE_NAMES, extractFeatures };