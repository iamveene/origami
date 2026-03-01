// Origami Finding Correlation and Attack Chain Predictor
// Correlates findings across all analyzers to identify multi-step attack chains

class CorrelationEngine {
  constructor() {
    this.chains = [];
    this.severityOrder = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  }

  correlate(allResults) {
    this.chains = [];

    if (!allResults) return this.chains;

    try {
      this._checkXSSMissingCSP(allResults);
      this._checkJWTLocalStorageXSS(allResults);
      this._checkCSRFNoSameSite(allResults);
      this._checkOpenRedirectOAuth(allResults);
      this._checkAPIKeyCORS(allResults);
      this._checkPrototypePollutionTemplate(allResults);
      this._checkSensitiveFilesNoContentType(allResults);
      this._checkJWTNoneAlgorithm(allResults);
      this._checkWeakCryptoExfiltration(allResults);
      this._checkCloudStorageSecrets(allResults);
      this._checkWebSocketTokenExposure(allResults);
      this._checkOAuthXSSTokenTheft(allResults);
    } catch (e) {
      console.error('Origami: Correlation engine error:', e.message);
    }

    console.log('Origami: Correlation engine found ' + this.chains.length + ' attack chain(s)');
    return this.chains;
  }

  // Rule 1: XSS + Missing CSP
  _checkXSSMissingCSP(allResults) {
    const vulns = allResults.vulnerabilities;
    const headers = allResults.headers;

    if (!Array.isArray(vulns) || !Array.isArray(headers)) return;

    const hasXSS = vulns.some(v =>
      v.type === 'XSS' || v.check === 'XSS Vulnerability' ||
      (v.details && v.details.type === 'XSS')
    );

    const hasWeakCSP = headers.some(h => {
      const msg = (h.message || '').toLowerCase();
      const check = (h.check || '').toLowerCase();
      return (check.includes('content-security-policy') || check.includes('csp')) &&
             (h.status === 'MISSING' || h.status === 'WEAK' || msg.includes('missing') || msg.includes('unsafe'));
    });

    if (hasXSS && hasWeakCSP) {
      const findings = [
        ...vulns.filter(v => v.type === 'XSS' || v.check === 'XSS Vulnerability' || (v.details && v.details.type === 'XSS')),
        ...headers.filter(h => {
          const check = (h.check || '').toLowerCase();
          return check.includes('content-security-policy') || check.includes('csp');
        })
      ];

      this.chains.push({
        id: 'xss-no-csp',
        name: 'XSS Exploitation (no CSP defense)',
        severity: this.getChainSeverity(findings, { maxSeverity: 'HIGH' }),
        findings: findings,
        description: 'Cross-site scripting vulnerabilities were found on a page without a Content Security Policy. An attacker can inject and execute arbitrary JavaScript without browser-level restrictions.',
        attackFlow: [
          'Attacker identifies XSS injection point on target page',
          'Attacker crafts malicious payload (script injection)',
          'No Content Security Policy blocks inline script execution',
          'Malicious script executes in victim browser context',
          'Attacker exfiltrates cookies, session tokens, or performs actions as victim'
        ],
        remediation: [
          'Implement a strict Content Security Policy that disallows unsafe-inline and unsafe-eval',
          'Sanitize all user input before rendering in the DOM',
          'Use framework-safe rendering methods (textContent, createTextNode)',
          'Deploy CSP in report-only mode first to avoid breaking functionality'
        ]
      });
    }
  }

  // Rule 2: JWT in localStorage + XSS
  _checkJWTLocalStorageXSS(allResults) {
    const vulns = allResults.vulnerabilities;
    const session = allResults.sessionState;

    if (!Array.isArray(vulns) || !session) return;

    const hasXSS = vulns.some(v =>
      v.type === 'XSS' || v.check === 'XSS Vulnerability' ||
      (v.details && v.details.type === 'XSS')
    );

    const hasLocalStorageToken = Array.isArray(session.tokens) && session.tokens.some(t =>
      t.source === 'localStorage'
    );

    if (hasXSS && hasLocalStorageToken) {
      const findings = [
        ...vulns.filter(v => v.type === 'XSS' || v.check === 'XSS Vulnerability' || (v.details && v.details.type === 'XSS')),
        ...session.tokens.filter(t => t.source === 'localStorage')
      ];

      this.chains.push({
        id: 'token-theft-xss',
        name: 'Token Theft via XSS',
        severity: this.getChainSeverity(findings, { maxSeverity: 'HIGH' }),
        findings: findings,
        description: 'JWT tokens stored in localStorage are accessible to JavaScript. Combined with an XSS vulnerability, an attacker can steal authentication tokens and impersonate the user.',
        attackFlow: [
          'Attacker exploits XSS vulnerability to inject JavaScript',
          'Injected script reads JWT from localStorage',
          'Token is exfiltrated to attacker-controlled server',
          'Attacker uses stolen JWT to impersonate victim',
          'Full account takeover without needing credentials'
        ],
        remediation: [
          'Store authentication tokens in httpOnly cookies instead of localStorage',
          'Fix all XSS vulnerabilities and implement input sanitization',
          'Implement token rotation and short expiration times',
          'Add fingerprint binding to tokens (IP, User-Agent)',
          'Deploy Content Security Policy to restrict script execution'
        ]
      });
    }
  }

  // Rule 3: Missing CSRF + No SameSite Cookies
  _checkCSRFNoSameSite(allResults) {
    const vulns = allResults.vulnerabilities;
    const cookies = allResults.cookies;

    if (!Array.isArray(vulns) || !Array.isArray(cookies)) return;

    const hasCSRF = vulns.some(v =>
      v.type === 'CSRF' || v.check === 'CSRF Protection' ||
      (v.details && v.details.type === 'CSRF')
    );

    const hasWeakSameSite = cookies.some(c => {
      const msg = (c.message || '').toLowerCase();
      const rawSameSite = c.details?.sameSite ?? c.sameSite ?? c.samesite ?? '';
      const sameSite = String(rawSameSite).toLowerCase();
      return sameSite === 'none' || sameSite === 'no_restriction' || msg.includes('samesite') ||
             (!sameSite && c.details?.issues && c.details.issues.some(i => typeof i === 'string' ? i.toLowerCase().includes('samesite') : (i.message || '').toLowerCase().includes('samesite')));
    });

    if (hasCSRF && hasWeakSameSite) {
      const findings = [
        ...vulns.filter(v => v.type === 'CSRF' || v.check === 'CSRF Protection' || (v.details && v.details.type === 'CSRF')),
        ...cookies.filter(c => {
          const rawSameSite = c.details?.sameSite ?? c.sameSite ?? c.samesite ?? '';
          const sameSite = String(rawSameSite).toLowerCase();
          return sameSite === 'none' || sameSite === 'no_restriction' || !sameSite;
        })
      ];

      this.chains.push({
        id: 'csrf-session-hijack',
        name: 'Session Hijacking via CSRF',
        // Capped at MEDIUM: CSRF requires social engineering + session cookies; individual findings are LOW/INFO
        severity: this.getChainSeverity(findings, { maxSeverity: 'MEDIUM' }),
        findings: findings,
        description: 'Forms without CSRF protection combined with cookies that lack SameSite restrictions allow cross-site request forgery attacks that can perform unauthorized actions using the victim session.',
        attackFlow: [
          'Attacker creates malicious page with hidden form targeting vulnerable endpoint',
          'Victim visits attacker page while authenticated to target site',
          'Browser sends session cookies with cross-origin request (no SameSite restriction)',
          'Target server processes the request as legitimate (no CSRF token validation)',
          'Unauthorized state-changing action is performed on behalf of victim'
        ],
        remediation: [
          'Implement CSRF tokens on all state-changing forms and API endpoints',
          'Set SameSite=Lax or SameSite=Strict on all session cookies',
          'Validate the Origin and Referer headers on sensitive requests',
          'Use the Double Submit Cookie pattern as an additional defense layer'
        ]
      });
    }
  }

  // Rule 4: Open Redirect + OAuth
  _checkOpenRedirectOAuth(allResults) {
    const templateFindings = allResults.templateFindings;
    const session = allResults.sessionState;

    if (!session) return;

    const hasOpenRedirect = (Array.isArray(templateFindings) && templateFindings.some(f =>
      f.templateId === 'open-redirect-params' || (f.name || '').toLowerCase().includes('open redirect')
    )) || (Array.isArray(allResults.vulnerabilities) && allResults.vulnerabilities.some(v =>
      v.type === 'Open Redirect' || v.check === 'Open Redirect' ||
      (v.details && v.details.type === 'Open Redirect')
    ));

    const hasOAuth = session.oauthState !== null && session.oauthState !== undefined;

    if (hasOpenRedirect && hasOAuth) {
      const findings = [];
      if (Array.isArray(templateFindings)) {
        findings.push(...templateFindings.filter(f =>
          f.templateId === 'open-redirect-params' || (f.name || '').toLowerCase().includes('open redirect')
        ));
      }
      if (Array.isArray(allResults.vulnerabilities)) {
        findings.push(...allResults.vulnerabilities.filter(v =>
          v.type === 'Open Redirect' || v.check === 'Open Redirect' ||
          (v.details && v.details.type === 'Open Redirect')
        ));
      }
      if (session.oauthState) {
        findings.push(session.oauthState);
      }

      this.chains.push({
        id: 'oauth-redirect-theft',
        name: 'OAuth Token Theft via Redirect',
        severity: this.getChainSeverity(findings, { maxSeverity: 'HIGH' }),
        findings: findings,
        description: 'An open redirect vulnerability on an OAuth callback domain allows an attacker to intercept authorization codes or access tokens by redirecting the OAuth flow to an attacker-controlled endpoint.',
        attackFlow: [
          'Attacker identifies open redirect on the OAuth redirect_uri domain',
          'Attacker crafts OAuth authorization URL with redirect_uri pointing to open redirect',
          'Victim initiates OAuth flow (login with provider)',
          'Authorization server redirects with code/token to open redirect endpoint',
          'Open redirect forwards the code/token to attacker-controlled server',
          'Attacker exchanges authorization code for access token'
        ],
        remediation: [
          'Fix all open redirect vulnerabilities by validating redirect URLs against a strict allowlist',
          'Register exact redirect_uri values with the OAuth provider (no wildcards)',
          'Implement PKCE (Proof Key for Code Exchange) for authorization code flows',
          'Use the state parameter with high-entropy values to prevent CSRF on OAuth callbacks'
        ]
      });
    }
  }

  // Rule 5: Exposed API Key + CORS Misconfigured
  _checkAPIKeyCORS(allResults) {
    const headers = allResults.headers;

    if (!Array.isArray(headers)) return;

    // Check for secrets found by scanner.js (stored in background)
    // In the unified results, secrets appear through templateFindings or plugins
    let hasSecrets = false;

    if (Array.isArray(allResults.templateFindings)) {
      hasSecrets = allResults.templateFindings.some(f =>
        (f.name || '').toLowerCase().includes('api key') ||
        (f.tags || []).some(t => t === 'api-key' || t === 'secret')
      );
    }

    if (!hasSecrets && Array.isArray(allResults.plugins)) {
      hasSecrets = allResults.plugins.some(p =>
        p.category === 'secrets' && Array.isArray(p.findings) && p.findings.length > 0
      );
    }

    const hasPermissiveCORS = headers.some(h => {
      const msg = (h.message || '').toLowerCase();
      const check = (h.check || '').toLowerCase();
      return (check.includes('cors') || check.includes('access-control') || msg.includes('access-control-allow-origin')) &&
             (msg.includes('*') || msg.includes('wildcard') || h.status === 'WEAK' || h.status === 'INSECURE');
    });

    if (hasSecrets && hasPermissiveCORS) {
      const findings = [];
      if (Array.isArray(allResults.templateFindings)) {
        findings.push(...allResults.templateFindings.filter(f =>
          (f.name || '').toLowerCase().includes('api key') ||
          (f.tags || []).some(t => t === 'api-key' || t === 'secret')
        ));
      }
      findings.push(...headers.filter(h => {
        const check = (h.check || '').toLowerCase();
        const msg = (h.message || '').toLowerCase();
        return check.includes('cors') || check.includes('access-control') || msg.includes('access-control-allow-origin');
      }));

      this.chains.push({
        id: 'api-key-cors-exfil',
        name: 'API Key Exfiltration via CORS',
        severity: this.getChainSeverity(findings, { maxSeverity: 'HIGH' }),
        findings: findings,
        description: 'API keys or secrets are exposed on a page with permissive CORS headers (Access-Control-Allow-Origin: *). Any origin can make cross-origin requests and read the response containing the secrets.',
        attackFlow: [
          'Attacker discovers API key or secret exposed in page source',
          'Target server has Access-Control-Allow-Origin: * allowing cross-origin reads',
          'Attacker creates malicious page that fetches the target page cross-origin',
          'Victim visits attacker page; browser sends authenticated request to target',
          'CORS allows attacker page to read the response containing API keys',
          'Attacker exfiltrates and abuses the API keys'
        ],
        remediation: [
          'Remove API keys and secrets from client-side code',
          'Restrict CORS Access-Control-Allow-Origin to specific trusted domains',
          'Use server-side proxying for API calls that require keys',
          'Rotate any exposed API keys immediately',
          'Implement API key scoping and rate limiting'
        ]
      });
    }
  }

  // Rule 6: Prototype Pollution + Template Injection
  _checkPrototypePollutionTemplate(allResults) {
    const vulns = allResults.vulnerabilities;

    if (!Array.isArray(vulns)) return;

    const hasPrototypePollution = vulns.some(v =>
      v.type === 'Prototype Pollution' || v.check === 'Prototype Pollution' ||
      (v.details && v.details.type === 'Prototype Pollution')
    );

    const hasTemplateInjection = vulns.some(v =>
      v.type === 'Template Injection' || v.check === 'Template Injection' ||
      (v.details && v.details.type === 'Template Injection')
    );

    if (hasPrototypePollution && hasTemplateInjection) {
      const findings = vulns.filter(v =>
        v.type === 'Prototype Pollution' || v.check === 'Prototype Pollution' ||
        v.type === 'Template Injection' || v.check === 'Template Injection' ||
        (v.details && (v.details.type === 'Prototype Pollution' || v.details.type === 'Template Injection'))
      );

      this.chains.push({
        id: 'proto-pollution-rce',
        name: 'Client-Side RCE via Prototype Pollution',
        severity: this.getChainSeverity(findings, { maxSeverity: 'HIGH' }),
        findings: findings,
        description: 'Prototype pollution combined with a template injection vulnerability can lead to remote code execution. The attacker pollutes Object.prototype with properties that are consumed by the template engine to execute arbitrary code.',
        attackFlow: [
          'Attacker identifies prototype pollution vector (e.g., deep merge, URL parameters)',
          'Attacker pollutes Object.prototype with template-engine-specific properties',
          'Template engine reads polluted prototype properties during rendering',
          'Polluted values are interpreted as template expressions',
          'Arbitrary JavaScript executes in the victim browser context'
        ],
        remediation: [
          'Use Object.create(null) for dictionary objects to prevent prototype chain access',
          'Validate and sanitize all merge/assign operations on user-controlled objects',
          'Freeze Object.prototype where possible',
          'Use template engines with strict sandboxing and auto-escaping',
          'Implement CSP to limit the impact of code execution'
        ]
      });
    }
  }

  // Rule 7: Sensitive Files + Missing X-Content-Type-Options
  _checkSensitiveFilesNoContentType(allResults) {
    const sensitiveFiles = allResults.sensitiveFiles;
    const headers = allResults.headers;

    if (!Array.isArray(headers)) return;

    const hasSensitiveFiles = Array.isArray(sensitiveFiles) && sensitiveFiles.length > 0 &&
      sensitiveFiles.some(f => !f.error);

    const missingContentTypeOptions = headers.some(h => {
      const check = (h.check || '').toLowerCase();
      return check.includes('x-content-type-options') &&
             (h.status === 'MISSING' || (h.message || '').toLowerCase().includes('missing'));
    });

    if (hasSensitiveFiles && missingContentTypeOptions) {
      const findings = [
        ...sensitiveFiles.filter(f => !f.error),
        ...headers.filter(h => (h.check || '').toLowerCase().includes('x-content-type-options'))
      ];

      this.chains.push({
        id: 'info-disclosure-amplification',
        name: 'Information Disclosure Amplification',
        // Capped at MEDIUM: sensitive files are the real finding; missing X-Content-Type-Options is defense-in-depth
        severity: this.getChainSeverity(findings, { maxSeverity: 'MEDIUM' }),
        findings: findings,
        description: 'Sensitive files are exposed and the server lacks X-Content-Type-Options header. Browsers may MIME-sniff responses, potentially interpreting sensitive data files as executable content.',
        attackFlow: [
          'Attacker discovers exposed sensitive files (e.g., .env, .git, backups)',
          'Server responds without X-Content-Type-Options: nosniff',
          'Browser MIME-sniffs the response and may execute content as script',
          'Sensitive configuration data, credentials, or source code is exposed',
          'Attacker uses disclosed information to escalate the attack'
        ],
        remediation: [
          'Remove or restrict access to sensitive files and directories',
          'Set X-Content-Type-Options: nosniff on all responses',
          'Configure the web server to deny access to dotfiles and backup files',
          'Implement proper access controls and authentication for sensitive resources'
        ]
      });
    }
  }

  // Rule 8: JWT None Algorithm
  _checkJWTNoneAlgorithm(allResults) {
    const session = allResults.sessionState;

    if (!session || !Array.isArray(session.tokens)) return;

    const hasNoneAlg = session.tokens.some(t => {
      if (t.header && t.header.alg === 'none') return true;
      if (Array.isArray(t.issues)) {
        return t.issues.some(i =>
          (i.message || '').toLowerCase().includes('"none" algorithm') ||
          (i.message || '').toLowerCase().includes('none algorithm')
        );
      }
      return false;
    });

    if (hasNoneAlg) {
      const findings = session.tokens.filter(t => {
        if (t.header && t.header.alg === 'none') return true;
        if (Array.isArray(t.issues)) {
          return t.issues.some(i =>
            (i.message || '').toLowerCase().includes('"none" algorithm') ||
            (i.message || '').toLowerCase().includes('none algorithm')
          );
        }
        return false;
      });

      this.chains.push({
        id: 'jwt-none-auth-bypass',
        name: 'Authentication Bypass via JWT None',
        severity: 'CRITICAL',
        findings: findings,
        description: 'A JWT token using the "none" algorithm was detected. This means the signature is not verified by the server, allowing an attacker to forge tokens with arbitrary claims and bypass authentication entirely.',
        attackFlow: [
          'Attacker intercepts or obtains a valid JWT from the application',
          'Attacker decodes the JWT and changes the algorithm to "none"',
          'Attacker modifies claims (e.g., user ID, role, permissions)',
          'Attacker removes the signature portion of the token',
          'Server accepts the forged token without signature verification',
          'Attacker gains unauthorized access with arbitrary privileges'
        ],
        remediation: [
          'Reject JWTs with alg: "none" on the server side',
          'Maintain a strict allowlist of acceptable signing algorithms',
          'Use asymmetric algorithms (RS256, ES256) for JWT signing',
          'Validate the algorithm header against expected values before verification',
          'Implement additional server-side session validation beyond JWT claims'
        ]
      });
    }
  }

  // Rule 9: Weak Cryptography + Data Exfiltration
  _checkWeakCryptoExfiltration(allResults) {
    const crypto = allResults.crypto;
    const exfiltration = allResults.exfiltration;

    if (!crypto || !Array.isArray(crypto.issues) || !exfiltration || !Array.isArray(exfiltration.issues)) return;

    const hasWeakCrypto = crypto.issues.some(i =>
      i.type === 'weak-cipher' || i.type === 'hardcoded-key' ||
      (i.message || '').toLowerCase().includes('weak') ||
      (i.message || '').toLowerCase().includes('deprecated')
    );

    const hasExfiltration = exfiltration.issues.length > 0;

    if (hasWeakCrypto && hasExfiltration) {
      const findings = [
        ...crypto.issues.filter(i =>
          i.type === 'weak-cipher' || i.type === 'hardcoded-key' ||
          (i.message || '').toLowerCase().includes('weak') ||
          (i.message || '').toLowerCase().includes('deprecated')
        ),
        ...exfiltration.issues
      ];

      this.chains.push({
        id: 'weak-crypto-exfiltration',
        name: 'Data Exfiltration with Weak Encryption',
        severity: this.getChainSeverity(findings, { maxSeverity: 'HIGH' }),
        findings: findings,
        description: 'Sensitive data is being transmitted (exfiltration patterns detected) and the application uses weak client-side cryptography. Intercepted data protected by weak ciphers can be trivially decrypted.',
        attackFlow: [
          'Attacker identifies data exfiltration patterns in the application',
          'Application uses weak client-side cryptography to protect transmitted data',
          'Attacker performs man-in-the-middle interception of the data in transit',
          'Weak cipher is broken using known cryptanalytic techniques',
          'Attacker recovers plaintext sensitive data from the intercepted traffic'
        ],
        remediation: [
          'Use strong encryption algorithms (AES-256-GCM) for any client-side cryptographic operations',
          'Avoid relying on client-side cryptography for protecting sensitive data',
          'Use TLS 1.3 for all data transport instead of custom encryption',
          'Audit and remove any hardcoded cryptographic keys from client-side code',
          'Implement certificate pinning to prevent MITM attacks'
        ]
      });
    }
  }

  // Rule 10: Cloud Storage + Exposed Credentials
  _checkCloudStorageSecrets(allResults) {
    const cloudStorage = allResults.cloudStorage;

    if (!cloudStorage || !Array.isArray(cloudStorage.buckets) || cloudStorage.buckets.length === 0) return;

    let hasSecrets = false;

    if (Array.isArray(allResults.templateFindings)) {
      hasSecrets = allResults.templateFindings.some(f =>
        (f.name || '').toLowerCase().includes('api key') ||
        (f.tags || []).some(t => t === 'api-key' || t === 'secret')
      );
    }

    if (!hasSecrets && Array.isArray(allResults.plugins)) {
      hasSecrets = allResults.plugins.some(p =>
        p.category === 'secrets' && Array.isArray(p.findings) && p.findings.length > 0
      );
    }

    if (hasSecrets) {
      const findings = [...cloudStorage.buckets];
      if (Array.isArray(allResults.templateFindings)) {
        findings.push(...allResults.templateFindings.filter(f =>
          (f.name || '').toLowerCase().includes('api key') ||
          (f.tags || []).some(t => t === 'api-key' || t === 'secret')
        ));
      }

      this.chains.push({
        id: 'cloud-storage-key-exposure',
        name: 'Cloud Storage Takeover via Exposed Credentials',
        severity: this.getChainSeverity(findings, { maxSeverity: 'HIGH' }),
        findings: findings,
        description: 'Cloud storage URLs are referenced alongside exposed API keys or secrets, potentially allowing unauthorized access to cloud resources.',
        attackFlow: [
          'Attacker discovers exposed API keys or secrets in the application source',
          'Attacker identifies cloud storage bucket URLs referenced in the application',
          'Attacker tests exposed credentials against the discovered cloud storage endpoints',
          'Credentials grant unauthorized read or write access to cloud storage buckets',
          'Attacker exfiltrates sensitive data or uploads malicious content to the buckets'
        ],
        remediation: [
          'Rotate all exposed API keys and cloud storage credentials immediately',
          'Restrict bucket permissions using the principle of least privilege',
          'Use IAM roles and temporary credentials instead of long-lived API keys',
          'Enable cloud storage access logging and monitoring for anomalous access',
          'Remove all hardcoded credentials from client-side code'
        ]
      });
    }
  }

  // Rule 11: Unencrypted WebSocket + Session Tokens
  _checkWebSocketTokenExposure(allResults) {
    const websockets = allResults.websockets;
    const session = allResults.sessionState;

    if (!websockets || !Array.isArray(websockets.issues) || !session || !Array.isArray(session.tokens)) return;

    const hasUnencryptedWS = websockets.issues.some(i =>
      (i.type || '').toLowerCase().includes('unencrypted') ||
      (i.message || '').toLowerCase().includes('ws://') ||
      (i.message || '').toLowerCase().includes('unencrypted')
    );

    const hasTokens = session.tokens.length > 0;

    if (hasUnencryptedWS && hasTokens) {
      const findings = [
        ...websockets.issues.filter(i =>
          (i.type || '').toLowerCase().includes('unencrypted') ||
          (i.message || '').toLowerCase().includes('ws://') ||
          (i.message || '').toLowerCase().includes('unencrypted')
        ),
        ...session.tokens
      ];

      this.chains.push({
        id: 'websocket-token-intercept',
        name: 'Session Token Interception via Unencrypted WebSocket',
        severity: this.getChainSeverity(findings, { maxSeverity: 'HIGH' }),
        findings: findings,
        description: 'Authentication tokens are present alongside unencrypted WebSocket connections. An attacker performing a man-in-the-middle attack can intercept tokens transmitted over ws:// connections and hijack user sessions.',
        attackFlow: [
          'Attacker positions on the network to perform man-in-the-middle attack',
          'Application establishes unencrypted WebSocket connection (ws://)',
          'Authentication tokens are transmitted or accessible during the session',
          'Attacker intercepts WebSocket traffic and extracts session tokens',
          'Attacker uses stolen tokens to impersonate the victim and access their account'
        ],
        remediation: [
          'Use wss:// (WebSocket Secure) for all WebSocket connections',
          'Implement token binding to prevent stolen tokens from being reused',
          'Use short-lived tokens with automatic rotation for WebSocket sessions',
          'Add mutual TLS authentication for sensitive WebSocket connections',
          'Monitor for concurrent sessions from different network locations'
        ]
      });
    }
  }

  // Rule 12: OAuth + XSS Token Theft
  _checkOAuthXSSTokenTheft(allResults) {
    const oauthFlows = allResults.oauthFlows;
    const vulns = allResults.vulnerabilities;

    if (!oauthFlows || !Array.isArray(oauthFlows.issues) || oauthFlows.issues.length === 0) return;
    if (!Array.isArray(vulns)) return;

    const hasXSS = vulns.some(v =>
      v.type === 'XSS' || v.check === 'XSS Vulnerability' ||
      (v.details && v.details.type === 'XSS')
    );

    if (hasXSS) {
      const findings = [
        ...oauthFlows.issues,
        ...vulns.filter(v =>
          v.type === 'XSS' || v.check === 'XSS Vulnerability' ||
          (v.details && v.details.type === 'XSS')
        )
      ];

      this.chains.push({
        id: 'oauth-xss-token-theft',
        name: 'OAuth Token Theft via XSS',
        severity: this.getChainSeverity(findings, { maxSeverity: 'HIGH' }),
        findings: findings,
        description: 'XSS vulnerabilities combined with active OAuth flows allow an attacker to steal OAuth tokens or authorization codes during the OAuth exchange, leading to account takeover.',
        attackFlow: [
          'Attacker identifies XSS vulnerability on a page involved in the OAuth flow',
          'Attacker crafts malicious payload that hooks into the OAuth callback handling',
          'Victim initiates OAuth login and the authorization code or token is returned',
          'XSS payload intercepts the OAuth token or code from the URL fragment or response',
          'Attacker exfiltrates the stolen token to a controlled server and gains account access'
        ],
        remediation: [
          'Fix all XSS vulnerabilities and implement strict input sanitization',
          'Implement PKCE (Proof Key for Code Exchange) for all OAuth authorization code flows',
          'Store OAuth tokens in httpOnly cookies rather than accessible JavaScript variables',
          'Validate all redirect URIs strictly on the authorization server',
          'Deploy Content Security Policy to prevent inline script execution during OAuth flows'
        ]
      });
    }
  }

  getChainSeverity(findings, options = {}) {
    if (!Array.isArray(findings) || findings.length === 0) return 'MEDIUM';

    const severities = findings.map(f => {
      const sev = (f.severity || 'LOW').toUpperCase();
      return this.severityOrder.includes(sev) ? sev : 'LOW';
    });

    // If any finding is already CRITICAL, chain is CRITICAL
    if (severities.includes('CRITICAL')) {
      return this._capSeverity('CRITICAL', options);
    }

    const highCount = severities.filter(s => s === 'HIGH').length;

    // 2+ HIGH findings escalate to CRITICAL only if at least one is confirmed exploitable
    if (highCount >= 2) {
      const hasConfirmed = findings.some(f =>
        (f.status || '').toUpperCase() === 'VULNERABLE'
      );
      return this._capSeverity(hasConfirmed ? 'CRITICAL' : 'HIGH', options);
    }

    // Single HIGH stays HIGH (no automatic escalation)
    if (highCount === 1) return this._capSeverity('HIGH', options);

    // MEDIUM stays MEDIUM (no auto-escalation from stacking)
    const mediumCount = severities.filter(s => s === 'MEDIUM').length;
    if (mediumCount >= 1) return this._capSeverity('MEDIUM', options);

    // Multiple LOWs stay LOW (no escalation)
    return this._capSeverity('LOW', options);
  }

  _capSeverity(severity, options) {
    if (options && options.maxSeverity) {
      const capIdx = this.severityOrder.indexOf(options.maxSeverity);
      const sevIdx = this.severityOrder.indexOf(severity);
      if (sevIdx > capIdx) return options.maxSeverity;
    }
    return severity;
  }

  generateNarrative(chain) {
    if (!chain) return '';

    try {
      let narrative = '';

      narrative += 'ATTACK CHAIN: ' + chain.name + '\n';
      narrative += 'Severity: ' + chain.severity + '\n\n';

      narrative += 'DESCRIPTION:\n';
      narrative += chain.description + '\n\n';

      narrative += 'ATTACK FLOW:\n';
      if (Array.isArray(chain.attackFlow)) {
        chain.attackFlow.forEach((step, i) => {
          narrative += '  ' + (i + 1) + '. ' + step + '\n';
        });
      }
      narrative += '\n';

      narrative += 'CORRELATED FINDINGS (' + (chain.findings ? chain.findings.length : 0) + '):\n';
      if (Array.isArray(chain.findings)) {
        chain.findings.forEach((finding, i) => {
          const name = finding.check || finding.name || finding.templateId || 'Finding';
          const sev = finding.severity || 'UNKNOWN';
          const msg = finding.message || '';
          narrative += '  [' + sev + '] ' + name;
          if (msg) narrative += ' - ' + msg;
          narrative += '\n';
        });
      }
      narrative += '\n';

      narrative += 'REMEDIATION:\n';
      if (Array.isArray(chain.remediation)) {
        chain.remediation.forEach((step, i) => {
          narrative += '  ' + (i + 1) + '. ' + step + '\n';
        });
      }

      return narrative;
    } catch (e) {
      console.error('Origami: Narrative generation error:', e.message);
      return 'Error generating narrative: ' + e.message;
    }
  }
}

window.CorrelationEngine = CorrelationEngine;
