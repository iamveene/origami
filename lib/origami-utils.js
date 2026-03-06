// Origami Shared Utilities
// Common helpers used by multiple analyzers

// Shannon entropy calculation
function origamiCalculateStringEntropy(str) {
  if (!str || str.length === 0) return 0;
  const len = str.length;
  const freq = {};
  for (let i = 0; i < len; i++) {
    freq[str[i]] = (freq[str[i]] || 0) + 1;
  }
  return Object.values(freq).reduce((ent, count) => {
    const p = count / len;
    return ent - p * Math.log2(p);
  }, 0);
}

// Domain classifier -- categorizes hostname for third-party analysis
function origamiClassifyDomain(hostname) {
  if (!hostname) return 'unknown-third-party';

  try {
    const currentHost = window.location.hostname;
    // Strip www. from both sides for more accurate comparison
    const currentBase = currentHost.replace(/^www\./, '');
    const targetBase = hostname.replace(/^www\./, '');
    if (hostname === currentHost || targetBase === currentBase) return 'first-party';
    // Subdomain check against base domain (e.g. assets.twitch.tv matches twitch.tv)
    if (hostname.endsWith('.' + currentBase)) return 'first-party';
    if (currentHost.endsWith('.' + targetBase)) return 'first-party';
    // Detect sibling CDN domains (e.g. licdn.com for linkedin.com, fbcdn.net for facebook.com)
    const siblingCDNs = {
      'linkedin.com': ['licdn.com', 'licdn.cn'],
      'facebook.com': ['fbcdn.net', 'fbcdn.com', 'fbsbx.com'],
      'twitter.com': ['twimg.com'],
      'x.com': ['twimg.com'],
      'instagram.com': ['cdninstagram.com'],
      'github.com': ['githubassets.com', 'githubusercontent.com'],
      'reddit.com': ['redditmedia.com', 'redditstatic.com'],
      'google.com': ['gstatic.com', 'ggpht.com'],
      'tiktok.com': ['tiktokcdn.com', 'ttwstatic.com'],
    };
    const currentDomain = currentBase.split('.').slice(-2).join('.');
    const siblings = siblingCDNs[currentDomain] || [];
    for (const sib of siblings) {
      if (hostname === sib || hostname.endsWith('.' + sib)) return 'first-party';
    }

    // Multi-TLD heuristic: organizations often use the same SLD across TLDs
    // (e.g., notion.com + notion.so, stripe.com + stripe.network)
    const targetParts = targetBase.split('.');
    const currentParts = currentBase.split('.');
    if (targetParts.length >= 2 && currentParts.length >= 2) {
      const targetSLD = targetParts[targetParts.length - 2];
      const currentSLD = currentParts[currentParts.length - 2];
      if (targetSLD === currentSLD && targetSLD.length >= 4) {
        const genericSLDs = new Set([
          'mail', 'shop', 'blog', 'news', 'help', 'docs', 'auth', 'cdn',
          'static', 'live', 'info', 'link', 'page', 'site', 'cloud', 'host', 'home'
        ]);
        if (!genericSLDs.has(targetSLD)) return 'first-party';
      }
    }
  } catch (e) { /* content script context may not have location */ }

  const cdnPatterns = [/cloudflare/i, /akamai/i, /cloudfront\.net/i, /fastly/i, /jsdelivr/i, /cdnjs/i, /unpkg/i, /bootstrapcdn/i, /gstatic\.com/i, /googleapis\.com/i, /cloudinary/i, /imgix/i, /licdn\./i, /discomax\.com/i, /wbd\.com/i, /media\.max\.com/i, /arc-cdn\.net/i, /trrsf\.com\.br/i, /zdassets\.com/i];
  const analyticsPatterns = [/google-analytics/i, /googletagmanager/i, /segment\.io/i, /segment\.com/i, /mixpanel/i, /hotjar/i, /amplitude/i, /plausible/i, /omtrdc\.net/i, /demdex\.net/i, /newrelic/i, /nr-data\.net/i, /datadoghq/i, /sentry\.io/i, /fullstory/i, /clarity\.ms/i, /optimizely/i, /launchdarkly/i, /split\.io/i, /heap\.io/i, /heapanalytics/i, /dotmetrics/i, /privacy-mgmt/i, /hsforms\.com/i, /hubspot\.com/i, /hubspotusercontent/i, /onetrust\.com/i, /cookielaw\.org/i, /parsely\.com/i, /chartbeat\.com/i, /comscore\.com/i, /scorecardresearch\.com/i, /brightcove\.com/i, /trustarc\.com/i, /go-mpulse\.net/i, /evergage\.com/i, /fundingchoicesmessages\.google/i, /ampcid\.google/i, /smarthint/i, /analytics\.google\.com/i, /youbora/i, /algorecs\.com/i, /cnstrc\.com/i, /online-metrix\.net/i, /analytics\.tiktok\.com/i, /mida\.so/i, /cookiebot\.com/i];
  const socialPatterns = [/facebook\.com/i, /fbcdn/i, /twitter\.com/i, /x\.com/i, /linkedin\.com/i, /instagram\.com/i];
  const adPatterns = [/doubleclick/i, /googlesyndication/i, /googleadservices/i, /adservice\.google/i, /adtrafficquality\.google/i, /facebook.*ads/i, /adnxs/i, /criteo\./i, /rubiconproject/i, /amazon-adsystem/i, /taboola/i, /outbrain/i, /pubmatic/i, /openx\./i, /casalemedia/i, /indexww/i, /adsrvr\.org/i, /bidswitch/i, /sharethrough/i, /doubleverify/i, /bat\.bing\.com/i, /newtail/i, /trackeame\.com/i, /tailtarget\.com/i, /ct\.pinterest\.com/i, /google\.com\.[a-z]{2,}/i, /roeye\.com/i, /byspotify\.com/i, /nextdoor\.com/i, /adswizz\.com/i, /stackadapt\.com/i, /ofsys\.com/i, /px\.ads\.linkedin\.com/i];
  const securityPatterns = [/threatmetrix/i, /iovation/i, /kount\.com/i, /fingerprintjs/i, /kasada/i, /perimeterx/i, /datadome/i, /recaptcha/i];
  const paymentPatterns = [/stripe\.com/i, /adyen\.com/i, /braintree/i, /paypal\.com/i];

  // Cloud provider infrastructure: API Gateway, serverless, and PaaS hosts
  // These are controlled by the site operator (not independent third parties),
  // so form submissions to them should be MEDIUM, not HIGH.
  const cloudApiPatterns = [
    /\.execute-api\.[a-z0-9-]+\.amazonaws\.com/i,  // AWS API Gateway
    /\.lambda-url\.[a-z0-9-]+\.on\.aws/i,          // AWS Lambda function URLs
    /\.cloudfunctions\.net/i,                       // GCP Cloud Functions
    /\.run\.app/i,                                  // GCP Cloud Run
    /\.azurewebsites\.net/i,                        // Azure Web Apps / Functions
    /\.azurefd\.net/i,                              // Azure Front Door
  ];

  if (cdnPatterns.some(p => p.test(hostname))) return 'cdn';
  if (analyticsPatterns.some(p => p.test(hostname))) return 'analytics';
  if (adPatterns.some(p => p.test(hostname))) return 'advertising';
  if (socialPatterns.some(p => p.test(hostname))) return 'social';
  if (securityPatterns.some(p => p.test(hostname))) return 'security';
  if (paymentPatterns.some(p => p.test(hostname))) return 'payment';
  if (cloudApiPatterns.some(p => p.test(hostname))) return 'cloud-api';
  return 'unknown-third-party';
}

// URL extractor from text blobs
function origamiExtractURLsFromText(text) {
  if (!text) return [];
  const urlPattern = /https?:\/\/[^\s"'<>\])}]+/gi;
  const matches = text.match(urlPattern) || [];
  return [...new Set(matches)];
}

// Shared PII regex patterns
const origamiSensitiveDataPatterns = {
  email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,
  phone: /(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]?\d{4}(?!\d)/,
  ssn: /\b\d{3}-\d{2}-\d{4}\b/,
  creditCard: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/,
  ipv4: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/
};

// Bundled/minified code detection (webpack, Closure Compiler, or high avg line length)
function origamiIsBundledOrMinified(scriptContent) {
  if (!scriptContent) return false;
  const isBundle = /webpackChunk|__webpack_require__|webpack_modules/.test(scriptContent)
    || /\bgoog\.\w/.test(scriptContent) || /_closure_exports_/.test(scriptContent);
  if (isBundle) return true;
  const lines = scriptContent.split('\n');
  const avgLen = scriptContent.length / lines.length;
  const threshold = (typeof ORIGAMI_MINIFIED_LINE_THRESHOLD !== 'undefined') ? ORIGAMI_MINIFIED_LINE_THRESHOLD : 600;
  return avgLen > threshold;
}

window.origamiCalculateStringEntropy = origamiCalculateStringEntropy;
window.origamiClassifyDomain = origamiClassifyDomain;
window.origamiExtractURLsFromText = origamiExtractURLsFromText;
window.origamiSensitiveDataPatterns = origamiSensitiveDataPatterns;
window.origamiIsBundledOrMinified = origamiIsBundledOrMinified;
