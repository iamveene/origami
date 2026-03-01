// Origami OAuth/SAML Flow Interceptor
// Detects OAuth/OIDC flow parameters, SAML responses, and token storage issues

class OAuthInterceptor {
  constructor() {
    this.findings = { flows: [], issues: [], samlAssertions: [] };
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

  detectAuthorizationCode(params) {
    const code = params.get('code');
    if (!code) return;

    this.findings.flows.push({
      type: 'authorization_code',
      parameter: 'code',
      valueLength: code.length,
      present: true
    });

    // Check for missing state parameter (CSRF risk)
    if (!params.get('state')) {
      this.findings.issues.push({
        severity: 'HIGH',
        type: 'oauth-missing-state',
        message: 'OAuth authorization code present without state parameter - vulnerable to CSRF attacks',
        cwe: 'CWE-352',
        recommendation: 'Always include a cryptographically random state parameter in OAuth authorization requests and validate it on the callback'
      });
    }
  }

  detectStateParameter(params) {
    const state = params.get('state');
    if (!state) return;

    const entropy = this.calculateEntropy(state);

    this.findings.flows.push({
      type: 'state_parameter',
      parameter: 'state',
      valueLength: state.length,
      entropy: entropy,
      present: true
    });

    if (entropy < 3.0) {
      this.findings.issues.push({
        severity: 'HIGH',
        type: 'oauth-weak-state',
        message: 'OAuth state parameter has low entropy (' + entropy.toFixed(2) + ' bits/char) - potentially predictable and vulnerable to CSRF',
        cwe: 'CWE-330',
        recommendation: 'Use a cryptographically secure random value of at least 32 bytes for the state parameter'
      });
    }

    if (state.length < 8) {
      this.findings.issues.push({
        severity: 'MEDIUM',
        type: 'oauth-short-state',
        message: 'OAuth state parameter is very short (' + state.length + ' chars) - may be guessable',
        cwe: 'CWE-330',
        recommendation: 'State parameter should be at least 32 characters of cryptographically random data'
      });
    }
  }

  detectPKCE(params) {
    const codeChallenge = params.get('code_challenge');
    const codeChallengeMethod = params.get('code_challenge_method');
    const codeVerifier = params.get('code_verifier');

    if (codeChallenge || codeChallengeMethod || codeVerifier) {
      this.findings.flows.push({
        type: 'pkce',
        hasCodeChallenge: !!codeChallenge,
        codeChallengeMethod: codeChallengeMethod || null,
        hasCodeVerifier: !!codeVerifier,
        present: true
      });

      if (codeChallengeMethod && codeChallengeMethod.toLowerCase() === 'plain') {
        this.findings.issues.push({
          severity: 'MEDIUM',
          type: 'pkce-plain-method',
          message: 'PKCE is using plain code_challenge_method instead of S256 - reduces protection against authorization code interception',
          cwe: 'CWE-327',
          recommendation: 'Use S256 (SHA-256) for code_challenge_method instead of plain'
        });
      }

      if (codeVerifier) {
        this.findings.issues.push({
          severity: 'HIGH',
          type: 'pkce-verifier-exposed',
          message: 'PKCE code_verifier is exposed in URL parameters - this should only be sent in the token exchange request body',
          cwe: 'CWE-598',
          recommendation: 'The code_verifier must only be sent in the POST body of the token exchange request, never in URL parameters'
        });
      }
    } else {
      // No PKCE detected - but PKCE parameters (code_challenge) are only present
      // on the authorization *request* URL, not the callback URL where 'code' appears.
      // We can only flag this as INFO since we can't verify PKCE from the callback alone.
      const code = params.get('code');
      if (code) {
        this.findings.flows.push({
          type: 'pkce',
          present: false,
          note: 'PKCE cannot be verified from callback URL (code_challenge is only on authorization request)'
        });
      }
    }
  }

  detectImplicitFlowTokens(params, hashParams) {
    // Access token in URL fragment (implicit flow)
    const accessToken = params.get('access_token') || (hashParams && hashParams.get('access_token'));
    if (accessToken) {
      this.findings.flows.push({
        type: 'implicit_flow',
        parameter: 'access_token',
        location: params.get('access_token') ? 'query' : 'fragment',
        valueLength: accessToken.length,
        present: true
      });

      this.findings.issues.push({
        severity: 'HIGH',
        type: 'implicit-flow-access-token',
        message: 'Access token found in URL ' + (params.get('access_token') ? 'query string' : 'fragment') + ' (implicit flow) - token exposed in browser history, referrer headers, and server logs',
        cwe: 'CWE-598',
        recommendation: 'Migrate from implicit flow to authorization code flow with PKCE. Implicit flow is deprecated in OAuth 2.1'
      });
    }

    // ID token in URL fragment
    const idToken = params.get('id_token') || (hashParams && hashParams.get('id_token'));
    if (idToken) {
      this.findings.flows.push({
        type: 'implicit_flow',
        parameter: 'id_token',
        location: params.get('id_token') ? 'query' : 'fragment',
        valueLength: idToken.length,
        present: true
      });

      const code = params.get('code');
      if (!code) {
        this.findings.issues.push({
          severity: 'MEDIUM',
          type: 'implicit-flow-id-token',
          message: 'ID token found in URL fragment without authorization code - implicit or hybrid flow detected',
          cwe: 'CWE-598',
          recommendation: 'Use authorization code flow with PKCE instead of implicit flow for token delivery'
        });
      }
    }

    // Token type indicator
    const tokenType = params.get('token_type') || (hashParams && hashParams.get('token_type'));
    if (tokenType) {
      this.findings.flows.push({
        type: 'token_type',
        parameter: 'token_type',
        value: tokenType,
        present: true
      });
    }
  }

  detectRedirectUri(params) {
    const redirectUri = params.get('redirect_uri');
    if (!redirectUri) return;

    this.findings.flows.push({
      type: 'redirect_uri',
      parameter: 'redirect_uri',
      value: redirectUri,
      present: true
    });

    // Check for open redirect patterns
    const openRedirectPatterns = [
      /^https?:\/\/[^\/]*@/i,           // URL with credentials
      /^https?:\/\/.*\.\./,             // Path traversal
      /^\/\//,                           // Protocol-relative (can redirect to attacker domain)
      /^https?:\/\/localhost/i,          // Redirect to localhost
      /^https?:\/\/127\./,              // Redirect to loopback
      /^https?:\/\/0\./,                // Redirect to 0.0.0.0
      /[?&]url=/i,                      // Nested redirect
      /^javascript:/i,                  // JavaScript URI
      /^data:/i                          // Data URI
    ];

    for (const pattern of openRedirectPatterns) {
      if (pattern.test(redirectUri)) {
        this.findings.issues.push({
          severity: 'HIGH',
          type: 'oauth-open-redirect',
          message: 'Suspicious redirect_uri pattern detected that may allow open redirect: ' + redirectUri.substring(0, 100),
          cwe: 'CWE-601',
          recommendation: 'Validate redirect_uri against a strict allowlist of pre-registered URIs. Do not allow wildcards or partial matching.'
        });
        break;
      }
    }

    // Check if redirect_uri uses HTTP (not HTTPS)
    if (/^http:\/\//i.test(redirectUri) && !/localhost|127\.0\.0\.1/i.test(redirectUri)) {
      this.findings.issues.push({
        severity: 'MEDIUM',
        type: 'oauth-http-redirect',
        message: 'OAuth redirect_uri uses HTTP instead of HTTPS - tokens may be intercepted in transit',
        cwe: 'CWE-319',
        recommendation: 'Always use HTTPS for OAuth redirect URIs in production environments'
      });
    }
  }

  detectNonce(params, hashParams) {
    const nonce = params.get('nonce') || (hashParams && hashParams.get('nonce'));
    if (!nonce) return;

    this.findings.flows.push({
      type: 'oidc_nonce',
      parameter: 'nonce',
      valueLength: nonce.length,
      entropy: this.calculateEntropy(nonce),
      present: true
    });

    if (this.calculateEntropy(nonce) < 3.0) {
      this.findings.issues.push({
        severity: 'MEDIUM',
        type: 'oidc-weak-nonce',
        message: 'OIDC nonce parameter has low entropy (' + this.calculateEntropy(nonce).toFixed(2) + ' bits/char) - may be predictable',
        cwe: 'CWE-330',
        recommendation: 'Use a cryptographically random value for the OIDC nonce parameter'
      });
    }
  }

  detectSAMLResponse(params) {
    const samlResponse = params.get('SAMLResponse');
    const relayState = params.get('RelayState');

    if (!samlResponse) return;

    this.findings.flows.push({
      type: 'saml_response',
      parameter: 'SAMLResponse',
      valueLength: samlResponse.length,
      hasRelayState: !!relayState,
      present: true
    });

    // Decode and analyze SAML response
    try {
      if (typeof SAMLDecoder !== 'undefined') {
        const decoder = new SAMLDecoder();
        const decoded = decoder.decode(samlResponse);

        if (decoded.decoded) {
          this.findings.samlAssertions.push(decoded.decoded);
        }

        if (decoded.issues && decoded.issues.length > 0) {
          this.findings.issues.push(...decoded.issues);
        }
      } else {
        // Basic SAML checks without the decoder
        try {
          const xml = atob(samlResponse);

          if (!xml.includes('Signature') && !xml.includes('ds:Signature')) {
            this.findings.issues.push({
              severity: 'CRITICAL',
              type: 'saml-unsigned',
              message: 'SAML Response does not contain a digital signature - assertions can be forged',
              cwe: 'CWE-347',
              recommendation: 'Require signed SAML assertions and validate signatures before processing'
            });
          }

          // Check for expired assertions
          const notOnOrAfterMatch = xml.match(/NotOnOrAfter="([^"]+)"/);
          if (notOnOrAfterMatch) {
            const expiry = new Date(notOnOrAfterMatch[1]);
            if (expiry < new Date()) {
              this.findings.issues.push({
                severity: 'MEDIUM',
                type: 'saml-expired',
                message: 'SAML assertion has expired (NotOnOrAfter: ' + notOnOrAfterMatch[1] + ')',
                cwe: 'CWE-613',
                recommendation: 'Reject expired SAML assertions and ensure proper time synchronization'
              });
            }
          }
        } catch (e) {
          console.warn('Origami: Failed to decode SAMLResponse:', e.message);
        }
      }
    } catch (e) {
      console.error('Origami: SAML analysis error:', e.message);
    }

    // SAML via GET is problematic
    if (window.location.search.includes('SAMLResponse=')) {
      this.findings.issues.push({
        severity: 'MEDIUM',
        type: 'saml-get-binding',
        message: 'SAMLResponse delivered via HTTP GET binding - response visible in URL, browser history, and server logs',
        cwe: 'CWE-598',
        recommendation: 'Use HTTP POST binding for SAML responses to prevent exposure in URLs and logs'
      });
    }
  }

  scanStorageForTokens() {
    const tokenKeys = [
      'token', 'access_token', 'accessToken', 'access-token',
      'refresh_token', 'refreshToken', 'refresh-token',
      'id_token', 'idToken', 'id-token',
      'auth_token', 'authToken', 'auth-token',
      'bearer_token', 'bearerToken', 'bearer-token',
      'oauth_token', 'oauthToken', 'oauth-token',
      'session_token', 'sessionToken', 'session-token',
      'api_token', 'apiToken', 'api-token'
    ];

    const foundTokens = [];

    // Check localStorage
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        const keyLower = key.toLowerCase();
        const isTokenKey = this._isOAuthTokenKey(keyLower, tokenKeys);

        if (isTokenKey) {
          const value = localStorage.getItem(key);
          foundTokens.push({
            storage: 'localStorage',
            key: key,
            valueLength: value ? value.length : 0,
            isJWT: value ? /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value.trim()) : false
          });
        }
      }
    } catch (e) { /* storage access denied */ }

    // Check sessionStorage
    try {
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        const keyLower = key.toLowerCase();
        const isTokenKey = this._isOAuthTokenKey(keyLower, tokenKeys);

        if (isTokenKey) {
          const value = sessionStorage.getItem(key);
          foundTokens.push({
            storage: 'sessionStorage',
            key: key,
            valueLength: value ? value.length : 0,
            isJWT: value ? /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value.trim()) : false
          });
        }
      }
    } catch (e) { /* storage access denied */ }

    if (foundTokens.length > 0) {
      this.findings.flows.push({
        type: 'stored_tokens',
        tokens: foundTokens,
        count: foundTokens.length
      });

      // Check for refresh tokens in localStorage (should use httpOnly cookies)
      // Require key to look like an actual refresh token (e.g. refresh_token, refreshToken)
      // not just any key containing "refresh" (e.g. awswaf_token_refresh_timestamp)
      const refreshInStorage = foundTokens.filter(t => {
        const k = t.key.toLowerCase();
        return /(?:^|[_\-])refresh[_\-]?token(?:[_\-]|$)/i.test(k) ||
               /(?:^|[_\-])token[_\-]?refresh(?:[_\-]|$)/i.test(k) ||
               k === 'refresh_token' || k === 'refreshtoken' || k === 'refresh-token';
      });

      if (refreshInStorage.length > 0) {
        this.findings.issues.push({
          severity: 'HIGH',
          type: 'refresh-token-in-storage',
          message: 'Refresh token found in ' + refreshInStorage[0].storage + ' (key: "' + refreshInStorage[0].key + '") - vulnerable to XSS token theft',
          cwe: 'CWE-922',
          recommendation: 'Store refresh tokens in httpOnly, secure cookies instead of browser storage. Browser storage is accessible to JavaScript and vulnerable to XSS attacks.'
        });
      }

      // Check for access tokens in localStorage (less critical but still a concern)
      const accessInLocal = foundTokens.filter(t =>
        t.storage === 'localStorage' && (
          t.key.toLowerCase().includes('access') ||
          t.key.toLowerCase() === 'token' ||
          t.key.toLowerCase() === 'auth_token' ||
          t.key.toLowerCase() === 'authtoken'
        )
      );

      if (accessInLocal.length > 0) {
        this.findings.issues.push({
          severity: 'MEDIUM',
          type: 'access-token-in-localstorage',
          message: 'Access token found in localStorage (key: "' + accessInLocal[0].key + '") - persists after browser close and is accessible to XSS',
          cwe: 'CWE-922',
          recommendation: 'Consider using sessionStorage or httpOnly cookies for access tokens. localStorage persists indefinitely and survives browser restarts.'
        });
      }
    }
  }

  _isOAuthTokenKey(keyLower, tokenKeys) {
    // Exact match against known token key names
    if (tokenKeys.some(tk => keyLower === tk.toLowerCase())) return true;
    // For substring matching, require word-boundary alignment to avoid
    // matching infrastructure keys like "awswaf_token_refresh_timestamp"
    // or "consent_token_storage_key"
    const infraPrefixes = /^(?:awswaf|consent|cookie|config|cache|feature|ui|theme|lang|locale|prefs?|settings?|state|flags?|version)/;
    if (infraPrefixes.test(keyLower)) return false;
    // Allow substring match only if the key is short enough to plausibly be a token key
    // (real token keys are typically under 30 chars) and contains "token" as a distinct segment
    if (keyLower.length > 40) return false;
    return tokenKeys.some(tk => {
      const tkLower = tk.toLowerCase();
      if (!keyLower.includes(tkLower)) return false;
      // Verify word-boundary: the match must be at start/end or bounded by _/-/.
      const idx = keyLower.indexOf(tkLower);
      const before = idx === 0 || /[_\-.]/.test(keyLower[idx - 1]);
      const after = idx + tkLower.length >= keyLower.length || /[_\-.]/.test(keyLower[idx + tkLower.length]);
      return before && after;
    });
  }

  async analyze() {
    this.findings = { flows: [], issues: [], samlAssertions: [] };

    try {
      const url = new URL(window.location.href);
      const params = url.searchParams;
      let hashParams = null;

      if (url.hash && url.hash.length > 1) {
        try {
          hashParams = new URLSearchParams(url.hash.substring(1));
        } catch (e) {
          // Malformed hash fragment
        }
      }

      // Detect OAuth/OIDC URL parameters
      this.detectAuthorizationCode(params);
      this.detectStateParameter(params);
      this.detectPKCE(params);
      this.detectImplicitFlowTokens(params, hashParams);
      this.detectRedirectUri(params);
      this.detectNonce(params, hashParams);

      // Detect SAML
      this.detectSAMLResponse(params);

      // Check storage for OAuth tokens
      this.scanStorageForTokens();

    } catch (error) {
      console.error('Origami: OAuth interceptor error:', error.message);
      this.findings.issues.push({
        severity: 'INFO',
        type: 'analysis-error',
        message: 'OAuth/SAML analysis encountered an error: ' + error.message,
        cwe: null,
        recommendation: 'Check browser console for details'
      });
    }

    return this.findings;
  }
}

window.OAuthInterceptor = OAuthInterceptor;
