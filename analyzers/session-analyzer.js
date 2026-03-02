// Origami Session State Analyzer
// Analyzes JWTs, session cookies, OAuth state, and token lifecycle

class SessionAnalyzer {
  constructor() {
    this.findings = { tokens: [], cookies: [], oauthState: null, issues: [] };
  }

  base64UrlDecode(str) {
    try {
      let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
      const pad = base64.length % 4;
      if (pad) base64 += '='.repeat(4 - pad);
      return JSON.parse(atob(base64));
    } catch (e) {
      return null;
    }
  }

  decodeJWT(token) {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const header = this.base64UrlDecode(parts[0]);
    const payload = this.base64UrlDecode(parts[1]);
    if (!header || !payload) return null;
    return { header, payload, signature: parts[2] };
  }

  calculateEntropy(str) {
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

  scanForJWTs() {
    const jwtPattern = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
    const found = [];

    // Check localStorage
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        const value = localStorage.getItem(key);
        if (!value) continue;
        const matches = value.match(jwtPattern);
        if (matches) {
          matches.forEach(token => {
            found.push({ token, source: 'localStorage', key });
          });
        }
      }
    } catch (e) { /* storage access denied */ }

    // Check sessionStorage
    try {
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        const value = sessionStorage.getItem(key);
        if (!value) continue;
        const matches = value.match(jwtPattern);
        if (matches) {
          matches.forEach(token => {
            found.push({ token, source: 'sessionStorage', key });
          });
        }
      }
    } catch (e) { /* storage access denied */ }

    // Check cookies
    const cookies = document.cookie;
    const cookieMatches = cookies.match(jwtPattern);
    if (cookieMatches) {
      cookieMatches.forEach(token => {
        found.push({ token, source: 'cookie', key: 'document.cookie' });
      });
    }

    // Check URL (hash and query params)
    const urlMatches = window.location.href.match(jwtPattern);
    if (urlMatches) {
      urlMatches.forEach(token => {
        found.push({ token, source: 'url', key: window.location.href });
      });
      this.findings.issues.push({
        severity: 'HIGH',
        type: 'jwt-in-url',
        message: 'JWT token found in URL - tokens in URLs are logged in server access logs and browser history',
        cwe: 'CWE-598'
      });
    }

    // Decode each JWT and analyze
    for (const entry of found) {
      const decoded = this.decodeJWT(entry.token);
      if (!decoded) continue;

      const tokenInfo = {
        source: entry.source,
        storageKey: entry.key,
        header: decoded.header,
        payload: decoded.payload,
        truncatedToken: entry.token.substring(0, 20) + '...' + entry.token.substring(entry.token.length - 10),
        issues: []
      };

      const now = Math.floor(Date.now() / 1000);
      if (decoded.payload.exp) {
        if (decoded.payload.exp < now) {
          tokenInfo.issues.push({ severity: 'INFO', message: 'Token is expired (exp: ' + new Date(decoded.payload.exp * 1000).toISOString() + ')' });
        }
        if (decoded.payload.iat && (decoded.payload.exp - decoded.payload.iat) > 86400) {
          tokenInfo.issues.push({ severity: 'LOW', message: 'Long-lived token (lifetime > 24 hours)' });
        }
      } else {
        tokenInfo.issues.push({ severity: 'MEDIUM', message: 'Token has no expiration claim (exp missing)' });
      }

      if (decoded.header.alg === 'none') {
        tokenInfo.issues.push({ severity: 'CRITICAL', message: 'JWT uses "none" algorithm - signature not verified' });
      } else if (decoded.header.alg === 'HS256') {
        tokenInfo.issues.push({ severity: 'INFO', message: 'JWT uses symmetric algorithm (HS256) - secret must be protected server-side' });
      }

      this.findings.tokens.push(tokenInfo);
    }
  }

  scanSessionCookies() {
    const sessionPatterns = [
      /session/i, /jsessionid/i, /phpsessid/i,
      /asp\.net_sessionid/i, /connect\.sid/i, /laravel_session/i,
      /_session/i,
      /^sid$/i, /[_-]sid$/i, /^sess$/i, /[_-]sess$/i,  // Word-boundary sid/sess
      /[_-]token$/i, /^token$/i, /^access[_-]?token$/i, // Specific token patterns
      /^auth[_-]?token$/i, /^auth[_-]?key$/i, /[_-]auth$/i  // Specific auth patterns
    ];

    const cookies = document.cookie.split(';').map(c => {
      const [name, ...rest] = c.trim().split('=');
      return { name: name.trim(), value: rest.join('=') };
    }).filter(c => c.name);

    // Infrastructure cookies (CDN, WAF, bot protection) are not application sessions
    const infraCookieNames = new Set([
      '__cf_bm', 'cf_clearance', '__cflb', '_abck', 'ak_bmsc', 'bm_sz', 'bm_sv', 'bm_mi',
      'AWSALB', 'AWSALBCORS', 'AWSELB', 'AWSELBCORS', 'aws-waf-token',
      'datadome', '_pxhd', '_pxvid', '_px3', '_pxde', 'pxcts',
      'visid_incap', '_GRECAPTCHA', '_vuid', '_dd_s',
      'SERVERID', 'ROUTEID'
    ]);
    const infraCookiePrefixes = ['__cf_', 'cf_', 'bm_', 'ak_', 'aka-', '_px', 'incap_ses', 'nlbi_', 'BIGipServer', 'aws-waf-'];

    for (const cookie of cookies) {
      const isSessionCookie = sessionPatterns.some(p => p.test(cookie.name));
      if (!isSessionCookie) continue;
      const isInfra = infraCookieNames.has(cookie.name) || infraCookiePrefixes.some(p => cookie.name.startsWith(p));
      if (!isInfra) {
        const cookieInfo = {
          name: cookie.name,
          valueLength: cookie.value.length,
          entropy: this.calculateEntropy(cookie.value),
          isSession: true,
          issues: []
        };

        if (cookie.value.length >= 16 && cookieInfo.entropy < 3.0) {
          const analyticsSessionPrefixes = /^(analytics_|vx_|ga_|_ga_)/i;
          const severity = analyticsSessionPrefixes.test(cookie.name) ? 'INFO' : 'HIGH';
          cookieInfo.issues.push({ severity, message: 'Session cookie has low entropy (' + cookieInfo.entropy.toFixed(2) + ') - potentially predictable' });
        }

        this.findings.cookies.push(cookieInfo);
      }
    }
  }

  scanOAuthState() {
    const url = new URL(window.location.href);
    const params = url.searchParams;
    const hash = url.hash;

    const code = params.get('code');
    const state = params.get('state');
    const accessToken = params.get('access_token') || (hash && new URLSearchParams(hash.substring(1)).get('access_token'));
    const idToken = params.get('id_token') || (hash && new URLSearchParams(hash.substring(1)).get('id_token'));

    if (code || state || accessToken || idToken) {
      this.findings.oauthState = {
        hasCode: !!code,
        hasState: !!state,
        hasAccessToken: !!accessToken,
        hasIdToken: !!idToken,
        stateEntropy: state ? this.calculateEntropy(state) : null,
        issues: []
      };

      if (code && !state) {
        this.findings.oauthState.issues.push({ severity: 'HIGH', message: 'OAuth callback has authorization code but no state parameter (CSRF risk)', cwe: 'CWE-352' });
      }

      if (state && this.calculateEntropy(state) < 3.0) {
        this.findings.oauthState.issues.push({ severity: 'HIGH', message: 'OAuth state parameter has low entropy (' + this.calculateEntropy(state).toFixed(2) + ') - potentially predictable', cwe: 'CWE-330' });
      }

      if (accessToken) {
        this.findings.oauthState.issues.push({ severity: 'HIGH', message: 'Access token in URL (implicit flow) - token exposed in browser history and logs', cwe: 'CWE-598' });
      }

      if (idToken && !code) {
        this.findings.oauthState.issues.push({ severity: 'MEDIUM', message: 'ID token in URL fragment - implicit flow detected' });
      }

      if (code && !params.get('code_challenge_method')) {
        this.findings.oauthState.issues.push({ severity: 'LOW', message: 'No PKCE indicators detected on OAuth callback (code_challenge_method absent)' });
      }
    }
  }

  async analyze() {
    this.findings = { tokens: [], cookies: [], oauthState: null, issues: [] };

    this.scanForJWTs();
    this.scanSessionCookies();
    this.scanOAuthState();

    // Collect all issues from sub-analyses
    const allIssues = [...this.findings.issues];
    this.findings.tokens.forEach(t => allIssues.push(...t.issues));
    this.findings.cookies.forEach(c => allIssues.push(...c.issues));
    if (this.findings.oauthState) {
      allIssues.push(...this.findings.oauthState.issues);
    }
    this.findings.allIssues = allIssues;

    return this.findings;
  }
}

window.SessionAnalyzer = SessionAnalyzer;
