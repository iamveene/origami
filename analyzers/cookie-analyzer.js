// Origami Cookie Security Analyzer
// Analyzes cookies for security misconfigurations and sensitive data

class CookieSecurityAnalyzer {
  // Session/auth cookie name patterns
  static SESSION_AUTH_PATTERNS = [
    'session', 'sess', 'sessionid', 'sid', 'phpsessid',
    'jsessionid', 'aspsessionid', 'auth', 'token', 'jwt',
    'access_token', 'refresh_token', 'csrf', 'xsrf',
    'login', 'logged_in', 'credential', 'oauth', 'sso',
    'remember_me', 'remember', 'persistent_login',
    'api_key', 'apikey', 'secret'
  ];

  // Known third-party tracking/analytics cookie names
  static KNOWN_THIRD_PARTY_COOKIES = new Set([
    // Google Analytics / Ads
    '_ga', '_gid', '_gat', '_gcl_au', '_gcl_aw', '_ga_',
    'g_state',
    // Facebook
    '_fbp', '_fbc',
    // Pinterest
    '_pin_unauth', '_derived_epik', '_epik',
    // Microsoft / Bing
    '_uetsid', '_uetvid', '_clck', '_clsk',
    // HubSpot
    'hubspotutk', '__hstc', '__hssc', '__hssrc',
    // Reddit
    '_rdt_uuid',
    // Criteo
    'cto_bundle', 'cto_bidid',
    // Salesforce / Pardot
    'pardot', 'visitor_id',
    // Various analytics
    'sa-user-id', 'sa-user-id-v2', 'sa-user-id-v3', 'sa-r-source', 'sa-r-date',
    'FPGSID', 'FPAU', 'FPLC',
    '_d2id',
    // Zendesk
    '__zlcmid',
    // Optimizely
    'optimize_uuid',
    // Hotjar
    '_hjid', '_hjSessionUser', '_hjSession',
    // Segment
    'ajs_anonymous_id', 'ajs_user_id',
    // Consent management (OneTrust, Cookiebot, IAB)
    'OptanonConsent', 'OptanonAlertBoxClosed',
    'CookieConsent', 'cookieconsent_status',
    'euconsent-v2'
  ]);

  static THIRD_PARTY_PREFIXES = [
    '_ga_', '_gat_', '_dc_gtm_', '_gcl_', 'Optanon',
    '_tt_', 'mp_', '_cs_', 'amplitude_', '_li_', '_mkto_',
    '_hjSession', '_parsely', '_gd_', 'optimizely', '_vis_opt_', 'ajs_'
  ];

  // Known infrastructure cookies (CDN, WAF, bot protection, load balancers)
  static KNOWN_INFRASTRUCTURE_COOKIES = new Set([
    // Cloudflare
    '__cf_bm', 'cf_clearance', '__cflb', 'cf_ob_info', 'cf_use_ob',
    // AWS
    'AWSALB', 'AWSALBCORS', 'AWSELB', 'AWSELBCORS',
    // Akamai
    'AkaSrc', 'bm_sz', 'bm_sv', '_abck', 'ak_bmsc', 'bm_mi',
    // Fastly
    '_vuid',
    // Imperva / Incapsula
    'visid_incap',
    // Sucuri
    'sucuri_cloudproxy_uuid',
    // Google reCAPTCHA
    '_GRECAPTCHA',
    // Datadome
    'datadome',
    // PerimeterX / HUMAN Security
    '_pxhd', '_pxvid', '_px3', '_pxde', 'pxcts', '_pxff',
    // Generic load balancers
    'SERVERID', 'ROUTEID',
    // AWS WAF
    'aws-waf-token',
    // Datadog
    '_dd_s'
  ]);

  static INFRASTRUCTURE_PREFIXES = [
    '__cf_', 'cf_', 'AWSALB', 'AWSELB',
    'bm_', 'ak_', 'incap_ses', 'nlbi_',
    '_px', 'BIGipServer', 'aws-waf-token'
  ];

  // Known SaaS widget cookies
  static KNOWN_SAAS_COOKIES = new Set([
    // Intercom
    'intercom-id', 'intercom-session',
    // Stripe
    '__stripe_mid', '__stripe_sid',
    // Drift
    'drift_aid', 'drift_campaign_refresh', 'driftt_aid',
    // Crisp
    'crisp-client',
    // Zendesk (additional)
    '__zldp', '__zlcid',
    // LiveChat
    '__lc_cid', '__lc_cst',
    // Tawk.to
    'TawkConnectionTime',
    // WordPress
    'wordpress_test_cookie',
    // Faster / iFood analytics
    'aSessionId', 'aDeviceId', 'aFasterAppKey', 'aFasterAppId', 'aAppVersion',
    // MercadoLivre
    '_mldataSessionId'
  ]);

  static SAAS_PREFIXES = [
    'intercom-', '__stripe_', 'drift_', 'crisp-',
    '__lc_', 'wp-settings-', 'wordpress_',
    'fstr.', '_mldata'
  ];

  // Check if a cookie name matches a known third-party pattern
  static isKnownThirdPartyCookie(cookieName) {
    if (CookieSecurityAnalyzer.KNOWN_THIRD_PARTY_COOKIES.has(cookieName)) return true;
    return CookieSecurityAnalyzer.THIRD_PARTY_PREFIXES.some(prefix => cookieName.startsWith(prefix));
  }

  // Check if a cookie is a known infrastructure cookie
  static isKnownInfrastructureCookie(cookieName) {
    if (CookieSecurityAnalyzer.KNOWN_INFRASTRUCTURE_COOKIES.has(cookieName)) return true;
    return CookieSecurityAnalyzer.INFRASTRUCTURE_PREFIXES.some(prefix => cookieName.startsWith(prefix));
  }

  // Check if a cookie is a known SaaS widget cookie
  static isKnownSaaSCookie(cookieName) {
    if (CookieSecurityAnalyzer.KNOWN_SAAS_COOKIES.has(cookieName)) return true;
    return CookieSecurityAnalyzer.SAAS_PREFIXES.some(prefix => cookieName.startsWith(prefix));
  }

  // Classify a cookie by sensitivity: session_auth, infrastructure, tracking, or functional
  // Priority: known lists first (exact match), then heuristic pattern matching (substring)
  static classifyCookie(cookie) {
    // Known lists take priority over pattern matching to avoid false positives
    // (e.g., "intercom-session" is SaaS, not session_auth; "aSessionId" is analytics, not auth)
    if (CookieSecurityAnalyzer.isKnownInfrastructureCookie(cookie.name)) {
      return 'infrastructure';
    }

    if (CookieSecurityAnalyzer.isKnownThirdPartyCookie(cookie.name)) {
      return 'tracking';
    }

    if (CookieSecurityAnalyzer.isKnownSaaSCookie(cookie.name)) {
      return 'tracking';
    }

    // Heuristic: pattern matching as fallback for unknown cookies
    const name = cookie.name.toLowerCase();
    if (CookieSecurityAnalyzer.SESSION_AUTH_PATTERNS.some(s => name.includes(s))) {
      return 'session_auth';
    }

    return 'functional';
  }

  constructor() {
    this.results = [];
  }

  // Analyze all cookies for a given URL
  async analyze(url) {
    this.results = [];

    try {
      // Get all cookies for the current domain
      const urlObj = new URL(url);
      const cookies = await this.getCookies(urlObj);

      if (cookies.length === 0) {
        this.addFinding(
          'No Cookies',
          'INFO',
          'INFO',
          'No cookies found for this domain',
          null,
          null
        );
        return this.results;
      }

      // Analyze each cookie
      cookies.forEach(cookie => {
        this.analyzeCookie(cookie, urlObj);
      });

      // Summary with category breakdown
      const total = cookies.length;
      const secure = cookies.filter(c => c.secure).length;
      const httpOnly = cookies.filter(c => c.httpOnly).length;
      const sameSite = cookies.filter(c => c.sameSite && c.sameSite !== 'no_restriction').length;

      const categories = { session_auth: 0, infrastructure: 0, tracking: 0, functional: 0 };
      cookies.forEach(c => {
        categories[CookieSecurityAnalyzer.classifyCookie(c)]++;
      });

      this.addFinding(
        'Cookie Summary',
        'INFO',
        'INFO',
        `Found ${total} cookie(s): ${secure} secure, ${httpOnly} httpOnly, ${sameSite} with SameSite. ` +
        `Classification: ${categories.session_auth} session/auth, ${categories.infrastructure} infrastructure, ` +
        `${categories.tracking} tracking, ${categories.functional} functional`,
        null,
        { total, secure, httpOnly, sameSite, categories }
      );

      // Filter out OK-status cookies -- only return findings with actual issues
      this.results = this.results.filter(finding =>
        finding.status === 'VULNERABLE' || finding.check === 'Cookie Summary' || finding.status === 'ERROR'
      );

    } catch (error) {
      this.addFinding(
        'Cookie Analysis Error',
        'ERROR',
        'LOW',
        `Failed to analyze cookies: ${error.message}`,
        'Check browser permissions',
        null
      );
    }

    return this.results;
  }

  // Get cookies using Chrome API
  async getCookies(urlObj) {
    return new Promise((resolve) => {
      if (typeof chrome !== 'undefined' && chrome.cookies) {
        chrome.cookies.getAll({ domain: urlObj.hostname }, (cookies) => {
          resolve(cookies || []);
        });
      } else {
        // Fallback: parse document.cookie (limited information)
        resolve(this.parseDocumentCookies());
      }
    });
  }

  // Fallback method to parse document.cookie
  // NOTE: document.cookie CANNOT see HttpOnly cookies (they are hidden from JS by design).
  // Cookies visible here are inherently NOT HttpOnly, so missing HttpOnly flag is expected.
  // We also cannot determine the Secure flag from document.cookie.
  parseDocumentCookies() {
    const cookies = [];
    const cookieString = document.cookie;

    if (cookieString) {
      const pairs = cookieString.split(';');
      pairs.forEach(pair => {
        const eqIndex = pair.trim().indexOf('=');
        const name = eqIndex > -1 ? pair.trim().substring(0, eqIndex) : pair.trim();
        const value = eqIndex > -1 ? pair.trim().substring(eqIndex + 1) : '';
        if (name) {
          cookies.push({
            name: name,
            value: value || '',
            secure: false,
            httpOnly: false,
            sameSite: 'unspecified',
            _limitedAnalysis: true // Flag: Chrome cookies API was unavailable
          });
        }
      });
    }

    return cookies;
  }

  // Analyze individual cookie
  analyzeCookie(cookie, urlObj) {
    const isHttps = urlObj.protocol === 'https:';
    const isLimitedAnalysis = cookie._limitedAnalysis === true;
    const category = CookieSecurityAnalyzer.classifyCookie(cookie);
    const isSessionAuth = (category === 'session_auth');
    const isFunctional = (category === 'functional');
    const isInfraOrTracking = (category === 'infrastructure' || category === 'tracking');
    const issues = [];
    let highestSeverity = 'INFO';

    // When using document.cookie fallback, we cannot determine Secure/HttpOnly flags
    // HttpOnly cookies are invisible to JS, so cookies visible via document.cookie
    // are by definition NOT HttpOnly. However, we can't know the Secure flag.
    if (isLimitedAnalysis) {
      // Skip Secure flag check entirely - we can't determine it from document.cookie
      // Skip HttpOnly flag check - cookies visible in document.cookie are not HttpOnly by design
      // Only report sensitive data and other checks that don't depend on flags
    } else {
      // Check Secure flag (only relevant for session/auth and functional cookies)
      // Severity calibrated for adversarial exploitation: missing Secure requires MITM to exploit
      if (!cookie.secure && !isInfraOrTracking) {
        if (isHttps) {
          if (isSessionAuth) {
            issues.push('Missing Secure flag (vulnerable to downgrade attacks)');
            highestSeverity = this.maxSeverity(highestSeverity, 'LOW');
          } else if (isFunctional) {
            issues.push('Missing Secure flag');
            highestSeverity = this.maxSeverity(highestSeverity, 'INFO');
          }
        } else {
          if (isSessionAuth) {
            issues.push('Missing Secure flag (cookie sent over HTTP)');
            highestSeverity = this.maxSeverity(highestSeverity, 'MEDIUM');
          }
        }
      }

      // Check HttpOnly flag (only relevant for session/auth cookies)
      // Severity calibrated: exploiting missing HttpOnly requires XSS as prerequisite
      if (!cookie.httpOnly && isSessionAuth) {
        issues.push('Missing HttpOnly flag (accessible via JavaScript, XSS risk)');
        highestSeverity = this.maxSeverity(highestSeverity, 'LOW');
      }
    }

    // Check SameSite attribute (gate by category)
    const sameSite = cookie.sameSite || 'no_restriction';
    if (sameSite === 'no_restriction' || sameSite === 'unspecified') {
      if (isSessionAuth) {
        issues.push('Missing SameSite attribute (CSRF risk)');
        highestSeverity = this.maxSeverity(highestSeverity, 'LOW');
      } else if (isFunctional) {
        issues.push('Missing SameSite attribute');
        highestSeverity = this.maxSeverity(highestSeverity, 'INFO');
      }
    } else if (sameSite === 'lax' && isSessionAuth) {
      issues.push('SameSite=Lax may not be strict enough for session cookies');
      highestSeverity = this.maxSeverity(highestSeverity, 'INFO');
    }

    // Check __Host- prefix compliance
    if (cookie.name.startsWith('__Host-')) {
      const prefixIssues = [];
      if (!cookie.secure) prefixIssues.push('Secure flag not set');
      if (cookie.path !== '/') prefixIssues.push(`Path is "${cookie.path || '(not set)'}" instead of "/"`);
      if (cookie.domain) prefixIssues.push(`Domain attribute is set ("${cookie.domain}") but must be omitted`);
      if (prefixIssues.length > 0) {
        issues.push(`__Host- prefix violation: ${prefixIssues.join(', ')}`);
        highestSeverity = this.maxSeverity(highestSeverity, 'LOW');
      }
    }

    // Check __Secure- prefix compliance
    if (cookie.name.startsWith('__Secure-') && !cookie.secure) {
      issues.push('__Secure- prefix requires Secure flag');
      highestSeverity = this.maxSeverity(highestSeverity, 'LOW');
    }

    // Check SameSite=None without Secure
    if (sameSite === 'none' && !cookie.secure) {
      issues.push('SameSite=None without Secure flag (rejected by modern browsers)');
      highestSeverity = this.maxSeverity(highestSeverity, 'INFO');
    }

    // Check for sensitive data in cookie name/value (skip session/auth -- tokens are expected)
    let sensitiveCheck = { found: false };
    if (!isSessionAuth) {
      const cookieCategory = CookieSecurityAnalyzer.classifyCookie(cookie);
      sensitiveCheck = this.checkSensitiveData(cookie, cookieCategory);
      if (sensitiveCheck.found) {
        // Speculative detections (high-entropy base64) on tracking/functional cookies are LOW, not HIGH
        const sensitiveDataSeverity = sensitiveCheck.speculative ? 'LOW' : 'HIGH';
        issues.push(`Potential sensitive data: ${sensitiveCheck.type}`);
        highestSeverity = this.maxSeverity(highestSeverity, sensitiveDataSeverity);
      }
    }

    // Check expiration (only session/auth cookies)
    if (isSessionAuth) {
      if (cookie.expirationDate) {
        const now = Date.now() / 1000;
        const expiresIn = cookie.expirationDate - now;
        const daysUntilExpiry = expiresIn / (60 * 60 * 24);

        if (daysUntilExpiry > 365) {
          issues.push(`Long expiration: ${Math.round(daysUntilExpiry)} days`);
          highestSeverity = this.maxSeverity(highestSeverity, 'INFO');
        }
      } else {
        // Session cookie (no expiration = deleted on browser close)
        // Note: HttpOnly missing is already reported above (line 319); don't duplicate
      }
    }

    // Check domain scope (only session/auth cookies)
    if (cookie.domain && cookie.domain.startsWith('.') && isSessionAuth) {
      issues.push('Cookie applies to all subdomains');
      highestSeverity = this.maxSeverity(highestSeverity, 'INFO');
    }

    // Build recommendation
    const recommendations = [];
    if (!cookie.secure && (isSessionAuth || (isFunctional && isHttps))) {
      recommendations.push('Add Secure flag');
    }
    if (!cookie.httpOnly && isSessionAuth) {
      recommendations.push('Add HttpOnly flag');
    }
    if ((sameSite === 'no_restriction' || sameSite === 'unspecified') && !isInfraOrTracking) {
      recommendations.push('Add SameSite=Strict or SameSite=Lax');
    }
    if (sensitiveCheck.found) {
      recommendations.push('Do not store sensitive data in cookies; use secure server-side sessions');
    }

    // Infrastructure cookies (Cloudflare, AWS, Akamai, etc.) are not application-controlled
    // Functional cookies missing flags are low-signal noise -- cap at INFO
    // Exception: sensitive data in any cookie retains its severity
    if ((isInfraOrTracking || isFunctional) && issues.length > 0 && !sensitiveCheck.found) {
      highestSeverity = 'INFO';
    }

    const isNonSessionCategory = isInfraOrTracking || isFunctional;
    const hasSensitiveData = sensitiveCheck.found;
    const status = (issues.length > 0 && (!isNonSessionCategory || hasSensitiveData)) ? 'VULNERABLE' : (issues.length > 0 ? 'INFO' : 'OK');
    const categoryLabels = {
      session_auth: 'session/auth',
      infrastructure: 'infrastructure',
      tracking: 'third-party tracker',
      functional: 'functional'
    };
    const categoryLabel = categoryLabels[category];

    const message = issues.length > 0
      ? `Cookie "${cookie.name}" (${categoryLabel}) has security issues: ${issues.join(', ')}`
      : `Cookie "${cookie.name}" (${categoryLabel}) is properly configured`;

    this.addFinding(
      `Cookie: ${cookie.name}`,
      status,
      highestSeverity,
      message,
      recommendations.join('; '),
      {
        name: cookie.name,
        category: category,
        secure: cookie.secure || false,
        httpOnly: cookie.httpOnly || false,
        sameSite: sameSite,
        domain: cookie.domain,
        path: cookie.path,
        expirationDate: cookie.expirationDate,
        session: !cookie.expirationDate,
        issues: issues
      }
    );
  }

  // Check if cookie looks like a session cookie
  looksLikeSessionCookie(cookie) {
    const name = cookie.name.toLowerCase();
    return CookieSecurityAnalyzer.SESSION_AUTH_PATTERNS.some(s => name.includes(s));
  }

  // Check for sensitive data in cookies
  checkSensitiveData(cookie, cookieCategory) {
    const name = cookie.name.toLowerCase();
    const value = cookie.value || '';

    // Patterns for sensitive data (excluding credit card - uses Luhn validation below)
    const patterns = {
      'password': /(?<![a-z])pass(word|wd|phrase)?/i,
      'SSN': /\b\d{3}-\d{2}-\d{4}\b/,
      'email': /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/,
      'API key': /[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]|AKIA[0-9A-Z]{16}/,
      'JWT token': /^ey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\./,
      'private key': /BEGIN.*PRIVATE.*KEY/
    };

    // Check cookie name
    if (patterns.password.test(name)) {
      return { found: true, type: 'password in cookie name' };
    }

    // Check cookie value against patterns
    for (const [type, pattern] of Object.entries(patterns)) {
      if (pattern.test(value)) {
        // JWT tokens in functional cookies (not session/auth) are likely signed
        // preferences or non-auth payloads -- mark as speculative to downgrade severity
        if (type === 'JWT token' && cookieCategory === 'functional') {
          return { found: true, type: type, speculative: true };
        }
        return { found: true, type: type };
      }
    }

    // Credit card check with Luhn validation (avoids false positives on order numbers)
    if (this.isLikelyCreditCard(value)) {
      return { found: true, type: 'credit card number (Luhn validated)' };
    }

    // Check for long base64-like values that might be tokens (with entropy check)
    // Skip for tracking/functional cookies -- high-entropy base64 is expected in analytics IDs,
    // ad sync cookies, and similar non-sensitive values. Only flag for unclassified cookies.
    if (value.length > 60 && /^[A-Za-z0-9+/=_-]+$/.test(value)) {
      const skipCategories = ['tracking', 'functional', 'infrastructure'];
      if (!skipCategories.includes(cookieCategory) &&
          !this.looksLikeSessionCookie(cookie)) {
        const entropy = this.calculateEntropy(value);
        if (entropy > 5.0) {
          return { found: true, type: 'potential encoded token/key', speculative: true };
        }
      }
    }

    return { found: false, type: null };
  }

  // Check if a value likely contains a credit card number (Luhn validated)
  isLikelyCreditCard(value) {
    const cardPattern = /\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})\b/g;
    let match;
    while ((match = cardPattern.exec(value)) !== null) {
      const digits = match[1].replace(/[-\s]/g, '');
      if (digits.length < 13 || digits.length > 19) continue;
      // Must start with valid card prefix (Visa: 4, MC: 5, Amex: 3, Discover: 6)
      if (!/^[3-6]/.test(digits)) continue;
      if (this.luhnCheck(digits)) return true;
    }
    return false;
  }

  // Luhn algorithm for credit card validation
  luhnCheck(num) {
    let sum = 0;
    let alternate = false;
    for (let i = num.length - 1; i >= 0; i--) {
      let n = parseInt(num[i], 10);
      if (alternate) {
        n *= 2;
        if (n > 9) n -= 9;
      }
      sum += n;
      alternate = !alternate;
    }
    return sum % 10 === 0;
  }

  // Calculate Shannon entropy (higher = more random)
  calculateEntropy(str) {
    const len = str.length;
    const frequencies = {};
    for (let i = 0; i < len; i++) {
      frequencies[str[i]] = (frequencies[str[i]] || 0) + 1;
    }
    return Object.values(frequencies).reduce((entropy, count) => {
      const p = count / len;
      return entropy - p * Math.log2(p);
    }, 0);
  }

  // Compare severity levels
  maxSeverity(current, newSev) {
    const levels = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
    return levels[newSev] > levels[current] ? newSev : current;
  }

  // Helper to add finding
  addFinding(check, status, severity, message, recommendation, details) {
    this.results.push({
      check,
      status,
      severity,
      message,
      recommendation,
      details
    });
  }
}

// Export for use in extension
if (typeof module !== 'undefined' && module.exports) {
  module.exports = CookieSecurityAnalyzer;
}
