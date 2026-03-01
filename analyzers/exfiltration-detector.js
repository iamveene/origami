// Origami Data Exfiltration Pattern Detector
// Monitors outbound requests and identifies PII leakage, credential exposure, and suspicious data flows

class ExfiltrationDetector {
  constructor() {
    this.findings = { dataFlows: [], issues: [] };
    this._credentialParams = [
      'password', 'passwd', 'pass', 'pwd', 'key', 'secret',
      'api_key', 'apikey', 'api-key', 'access_token', 'accesstoken',
      'auth', 'auth_token', 'session', 'sessionid', 'session_id',
      'jwt', 'bearer', 'client_secret', 'private_key', 'refresh_token'
    ];
    this._highSeverityCreds = ['password', 'passwd', 'pass', 'pwd', 'secret', 'client_secret', 'private_key'];
    this._analyticsParams = new Set(['_ga', '_gid', '_gat', '_gcl_aw', '_fbc', '_fbp', 'fbclid', 'gclid', 'msclkid', 'dclid', 'sclid', 'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', '__hstc', '__hssc', '__hsfp', 'mc_cid', 'mc_eid', '_kx',
      'utm_id', 'utm_source_platform', 'utm_creative_format', 'utm_marketing_tactic',
      '_gl', '_ga_', 'gad_source', 'gbraid', 'wbraid', 'ttclid', 'li_fat_id', 'mc_tc', 'igshid', 'ref_src', 'ref_url']);
    this._authFlowParams = new Set([
      'state', 'nonce', 'code', 'code_verifier', 'code_challenge', 'code_challenge_method',
      'redirect_uri', 'redirect_url', 'return_url', 'return_to', 'returnTo',
      'response_type', 'response_mode', 'scope', 'client_id', 'audience',
      'SAMLRequest', 'SAMLResponse', 'RelayState', 'samlrequest', 'samlresponse', 'relaystate',
      'id_token', 'id_token_hint', 'login_hint', 'prompt', 'acr_values',
      'connection', 'realm', 'protocol', 'pfidpadapterid'
    ]);
    this._ssoUrlPatterns = /\/oauth[2]?\b|\/auth\/|\/login|\/sso\/|\/saml[2]?\b|\/callback|\/authorize|\/\.well-known\/|\/token\b|\/consent|\/signup|\/register|\/logout|\/connect\//i;
    // Short/common CDN and cache-busting params that carry timestamps, versions, or hashes -- never PII
    this._nonPIIParams = new Set(['e', 'v', 't', 'cb', 'ts', 'h', 'w', 'sz', 's', 'q', 'f', 'r', 'n', 'c', 'p',
      'ver', 'hash', 'etag', 'exp', 'expires', 'width', 'height', 'size', 'quality', 'format',
      'utv', 'cv', 'fst', 'bg', 'gu', 'random', 'rand', 'cachebuster', '_t', '_ts', '_v', '_r', '_n',
      'tid', 'sid', 'rid', 'uid', 'pid', 'eid', 'cid', 'aid', 'bid', 'did', 'fid', 'gid', 'mid',
      'x_source.tid', 'x_imp.ext.tid', 'l_pb_bid_id']);
    this._piiChecks = [
      { key: 'email', label: 'email', severity: 'MEDIUM', cwe: 'CWE-359' },
      { key: 'phone', label: 'phone', severity: 'MEDIUM', cwe: 'CWE-359' },
      { key: 'ssn', label: 'ssn', severity: 'CRITICAL', cwe: 'CWE-359' },
      { key: 'creditCard', label: 'credit-card', severity: 'CRITICAL', cwe: 'CWE-359' }
    ];
  }

  async analyze() {
    this.findings = { dataFlows: [], issues: [] };

    if (!window.origamiSensitiveDataPatterns) {
      console.warn('Origami: origamiSensitiveDataPatterns not available, PII detection disabled');
    }
    if (!window.origamiCalculateStringEntropy) {
      console.warn('Origami: origamiCalculateStringEntropy not available, entropy analysis disabled');
    }

    try {
      this._scanExistingRequests();
      this._checkImageBeacons();
      this._checkFormSubmissions();
      this._detectCredentialsInGetParams();
      this._detectPIIInPageContext();
      this._classifyThirdPartyDataFlows();
    } catch (e) {
      console.error('Origami: Exfiltration detector error:', e.message);
    }

    return this.findings;
  }

  _scanExistingRequests() {
    let entries;
    try { entries = performance.getEntriesByType('resource'); } catch (e) { return; }
    if (!entries || entries.length === 0) return;

    for (const entry of entries) {
      try { this._analyzeRequestURL(entry.name); } catch (e) { /* skip */ }
    }
  }

  _analyzeRequestURL(urlStr) {
    const parsed = this._parseHTTPURL(urlStr);
    if (!parsed || !parsed.search) return;

    const hostname = parsed.hostname;
    const classification = this._classify(hostname);
    const isFirstParty = classification === 'first-party';
    const isAuthFlowURL = this._ssoUrlPatterns.test(parsed.pathname);
    const dataTypes = [];

    for (const [paramName, paramValue] of parsed.searchParams) {
      if (!paramValue) continue;
      const paramLower = paramName.toLowerCase();

      // Suppress known analytics/advertising params
      if (this._analyticsParams.has(paramLower)) continue;

      // Suppress auth flow params (OAuth, SAML, OIDC) -- normal SSO, not exfiltration
      if (this._authFlowParams.has(paramName) || this._authFlowParams.has(paramLower)) continue;

      // Suppress non-credential params on first-party auth-flow URLs
      if (isFirstParty && isAuthFlowURL && !this._credentialParams.includes(paramLower)) continue;

      if (this._credentialParams.includes(paramLower)) {
        // Credentials in URL query strings are always suspicious, even on auth-flow URLs
        // (RFC 6749 Section 2.3.1: client credentials must NOT be sent in the request URI)

        dataTypes.push('credential:' + paramLower);
        const isHighSevCred = this._highSeverityCreds.includes(paramLower);
        const credSeverity = isHighSevCred ? 'HIGH' : (isFirstParty ? 'LOW' : 'MEDIUM');
        this._addIssue(credSeverity,
          'credential-in-url', 'Credential parameter "' + paramName + '" sent in URL query string',
          'CWE-598', { destination: hostname, method: 'GET', dataTypes: ['credential:' + paramLower],
          requestUrl: this._redact(urlStr), isFirstParty, classification },
          'Never transmit credentials in URL query parameters. Use POST with request body or Authorization headers.');
      }

      this._scanValueForPII(paramValue, paramName, hostname, classification, isFirstParty, urlStr, dataTypes);

      if (paramValue.length > 20 && window.origamiCalculateStringEntropy && !this._analyticsParams.has(paramLower)) {
        const entropy = window.origamiCalculateStringEntropy(paramValue);
        if (entropy > 5.0) {
          dataTypes.push('high-entropy-token');
          // Suppress token-leakage for advertising/analytics domains -- high-entropy values
          // in ad/analytics URLs are click/impression correlation IDs, not secrets
          if (!isFirstParty && classification !== 'advertising' && classification !== 'analytics') {
            this._addIssue('LOW', 'token-leakage',
              'High-entropy value (entropy: ' + entropy.toFixed(2) + ') in query param "' + paramName + '" sent to third-party',
              'CWE-200', { destination: hostname, method: 'GET', dataTypes: ['high-entropy-token'],
              requestUrl: this._redact(urlStr), isFirstParty: false, classification },
              'Avoid sending tokens or session identifiers in URL query strings to third-party domains.');
          }
        }
      }
    }

    if (dataTypes.length > 0) {
      this.findings.dataFlows.push({ destination: hostname, classification, dataTypes: [...new Set(dataTypes)], requestUrl: this._redact(urlStr) });
    }
  }

  _scanValueForPII(value, paramName, hostname, classification, isFirstParty, urlStr, dataTypes) {
    if (!window.origamiSensitiveDataPatterns) return;
    // Skip known non-PII params (CDN timestamps, cache busters, dimensions)
    if (this._nonPIIParams.has(paramName.toLowerCase())) return;
    // Skip purely numeric values on first-party/CDN -- these are IDs, timestamps, or dimensions
    if ((isFirstParty || classification === 'cdn' || classification === 'advertising' || classification === 'analytics') && /^\d+$/.test(value)) return;
    const patterns = window.origamiSensitiveDataPatterns;

    for (const check of this._piiChecks) {
      if (new RegExp(patterns[check.key].source).test(value)) {
        // Credit card regex needs Luhn validation to avoid matching random numeric strings
        if (check.key === 'creditCard') {
          const digits = value.replace(/\D/g, '');
          const match = digits.match(/(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})/);
          if (!match || !this._luhnCheck(match[0])) continue;
          // Suppress credit card matches on advertising/analytics domains
          if (classification === 'advertising' || classification === 'analytics') continue;
        }
        dataTypes.push(check.label);
        const severity = this._adjustSeverity(check.severity, classification, isFirstParty);
        this._addIssue(severity, 'pii-in-url',
          check.label.toUpperCase() + ' detected in query parameter "' + paramName + '"' + (isFirstParty ? '' : ' sent to ' + classification + ' domain'),
          check.cwe, { destination: hostname, method: 'GET', dataTypes: [check.label], requestUrl: this._redact(urlStr), isFirstParty, classification },
          'Do not include PII in URL query parameters. Use POST request body or encrypted transport with server-side handling.');
      }
    }
  }

  _checkImageBeacons() {
    const images = document.querySelectorAll('img');
    for (const img of images) {
      try {
        const src = img.getAttribute('src');
        if (!src) continue;
        const parsed = this._parseHTTPURL(src, window.location.href);
        if (!parsed) continue;

        const hostname = parsed.hostname;
        const classification = this._classify(hostname);
        const isFirstParty = classification === 'first-party';
        const isPixel = this._isTrackingPixel(img);

        if (parsed.search) {
          const dataTypes = [];
          for (const [paramName, paramValue] of parsed.searchParams) {
            if (!paramValue) continue;
            const paramLower = paramName.toLowerCase();

            // Suppress analytics and auth flow params
            if (this._analyticsParams.has(paramLower)) continue;
            if (this._authFlowParams.has(paramName) || this._authFlowParams.has(paramLower)) continue;

            this._scanValueForPII(paramValue, paramName, hostname, classification, isFirstParty, src, dataTypes);
            if (this._credentialParams.includes(paramLower)) {
              // Skip 'auth' param on image resource URLs -- CDN signed URL tokens, not credentials
              if (paramLower === 'auth') {
                const path = parsed.pathname.toLowerCase();
                if (/\.(jpe?g|png|gif|webp|svg|avif|ico|bmp|tiff?)\b/.test(path) || /\/re?sizer?\//.test(path) || /\/images?\//.test(path)) continue;
              }
              dataTypes.push('credential:' + paramLower);
              this._addIssue('HIGH', 'credential-in-beacon',
                'Credential parameter "' + paramName + '" found in image beacon URL', 'CWE-598',
                { destination: hostname, method: 'GET', dataTypes: ['credential:' + paramLower],
                requestUrl: this._redact(src), isFirstParty, classification },
                'Never include credentials in image beacon URLs. Use server-side tracking or POST-based beacons.');
            }
          }
          if (dataTypes.length > 0) {
            this.findings.dataFlows.push({ destination: hostname, classification, dataTypes: [...new Set(dataTypes)], requestUrl: this._redact(src) });
          }
        }

        if (isPixel && !isFirstParty && classification === 'unknown-third-party') {
          this._addIssue('INFO', 'tracking-pixel', 'Hidden tracking pixel detected (' + classification + '): ' + hostname,
            'CWE-200', { destination: hostname, method: 'GET', dataTypes: ['tracking-pixel'],
            requestUrl: this._redact(src), isFirstParty: false, classification },
            'Review tracking pixels to ensure they comply with privacy policies and user consent requirements.');
        }
      } catch (e) { /* skip */ }
    }

    // Prefetch/preconnect links carrying data in query strings
    const links = document.querySelectorAll('link[rel="prefetch"], link[rel="preconnect"], link[rel="dns-prefetch"]');
    for (const link of links) {
      try {
        const href = link.getAttribute('href');
        if (!href) continue;
        const parsed = this._parseHTTPURL(href, window.location.href);
        if (!parsed || !parsed.search) continue;
        const classification = this._classify(parsed.hostname);
        if (classification === 'first-party') continue;

        const dataTypes = [];
        for (const [pn, pv] of parsed.searchParams) {
          if (pv) this._scanValueForPII(pv, pn, parsed.hostname, classification, false, href, dataTypes);
        }
        if (dataTypes.length > 0) {
          this.findings.dataFlows.push({ destination: parsed.hostname, classification, dataTypes: [...new Set(dataTypes)], requestUrl: this._redact(href) });
        }
      } catch (e) { /* skip */ }
    }
  }

  _isTrackingPixel(img) {
    const w = img.width || parseInt(img.getAttribute('width'), 10) || 0;
    const h = img.height || parseInt(img.getAttribute('height'), 10) || 0;
    if ((w <= 1 && h <= 1) || w === 0 || h === 0) return true;
    try {
      const style = window.getComputedStyle(img);
      if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return true;
      const cw = parseInt(style.width, 10);
      const ch = parseInt(style.height, 10);
      if ((cw <= 1 && ch <= 1) || cw === 0 || ch === 0) return true;
    } catch (e) { /* no computed style */ }
    return false;
  }

  _checkFormSubmissions() {
    const forms = document.querySelectorAll('form');
    for (const form of forms) {
      try {
        const action = form.getAttribute('action');
        const method = (form.getAttribute('method') || 'GET').toUpperCase();
        let hostname, classification;
        try {
          const url = new URL(action || '', window.location.href);
          hostname = url.hostname;
          classification = this._classify(hostname);
        } catch (e) {
          hostname = window.location.hostname;
          classification = 'first-party';
        }
        const isFirstParty = classification === 'first-party';
        const sensitiveFields = this._detectSensitiveFormFields(form);
        const hiddenSensitive = this._detectSensitiveHiddenInputs(form);

        if (!isFirstParty && sensitiveFields.length > 0) {
          // Known analytics/marketing platforms legitimately collect form data;
          // downgrade severity for classified domains, keep HIGH for unknown third parties
          const formSeverity = (classification === 'analytics' || classification === 'advertising' || classification === 'cloud-api') ? 'MEDIUM' : 'HIGH';
          this._addIssue(formSeverity, 'sensitive-form-third-party',
            'Form with sensitive fields (' + sensitiveFields.join(', ') + ') submits to third-party: ' + hostname,
            'CWE-200', { destination: hostname, method, dataTypes: sensitiveFields, requestUrl: action || '(relative)', isFirstParty: false, classification },
            'Sensitive form data should only be submitted to first-party endpoints over HTTPS.');
        }

        if (method === 'GET' && sensitiveFields.length > 0) {
          const hasCritical = sensitiveFields.some(f => f === 'password' || f === 'credit-card' || f === 'ssn');
          this._addIssue(hasCritical ? 'HIGH' : 'MEDIUM', 'sensitive-form-get',
            'Form uses GET method with sensitive fields (' + sensitiveFields.join(', ') + ') -- data will appear in URL, server logs, and browser history',
            'CWE-598', { destination: hostname, method: 'GET', dataTypes: sensitiveFields, requestUrl: action || '(current page)', isFirstParty, classification },
            'Use POST method for forms containing sensitive data. Never use GET with password or credit card fields.');
        }

        if (hiddenSensitive.length > 0) {
          // Suppress high-entropy-only hidden inputs on first-party POST forms --
          // these are typically CSRF nonces, form IDs, and other legitimate tokens
          const hasRealPII = hiddenSensitive.some(i => i.type !== 'high-entropy-token');
          if (hasRealPII || !isFirstParty || method === 'GET') {
            this._addIssue('LOW', 'sensitive-hidden-inputs',
              'Form contains hidden inputs with sensitive-looking values: ' + hiddenSensitive.map(i => i.name).join(', '),
              'CWE-200', { destination: hostname, method, dataTypes: hiddenSensitive.map(i => i.type), requestUrl: action || '(current page)', isFirstParty, classification },
              'Review hidden form inputs to ensure sensitive data is not being silently transmitted.');
          }
        }

        const allTypes = [...sensitiveFields, ...hiddenSensitive.map(i => i.type)];
        if (allTypes.length > 0) {
          this.findings.dataFlows.push({ destination: hostname, classification, dataTypes: [...new Set(allTypes)], requestUrl: action || '(form submission)' });
        }
      } catch (e) { /* skip */ }
    }
  }

  _detectSensitiveFormFields(form) {
    const fields = [];
    const inputs = form.querySelectorAll('input, select, textarea');
    for (const input of inputs) {
      const type = (input.getAttribute('type') || '').toLowerCase();
      const combined = [input.getAttribute('name'), input.getAttribute('id'), input.getAttribute('autocomplete')]
        .map(v => (v || '').toLowerCase()).join(' ');
      const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();

      if (type === 'password') fields.push('password');
      else if (/credit.?card|cc.?num|card.?number|cc-number/i.test(combined) || ['cc-number', 'cc-exp', 'cc-csc'].includes(autocomplete)) fields.push('credit-card');
      else if (/\bssn\b|social.?sec|tax.?id/i.test(combined)) fields.push('ssn');
      else if (/\bemail\b/i.test(combined) || type === 'email') fields.push('email');
      else if (/\bphone\b|\btel\b|\bmobile\b/i.test(combined) || type === 'tel') fields.push('phone');
    }
    return [...new Set(fields)];
  }

  _detectSensitiveHiddenInputs(form) {
    const suspicious = [];
    const hiddens = form.querySelectorAll('input[type="hidden"]');
    for (const hidden of hiddens) {
      const name = hidden.getAttribute('name') || '';
      const value = hidden.getAttribute('value') || '';
      if (!value || value.length < 5) continue;

      // Suppress auth flow params in hidden inputs (normal SSO flows)
      if (this._authFlowParams.has(name) || this._authFlowParams.has(name.toLowerCase())) continue;

      // Suppress CSRF/anti-forgery tokens -- standard security mechanism, not exfiltration
      const nameLower = name.toLowerCase();
      if (/csrf|xsrf|antiforgery|request.?verif|authenticity.?token|^_token$|^__token|^csrfmiddleware/.test(nameLower)) continue;

      if (this._credentialParams.includes(name.toLowerCase())) {
        suspicious.push({ name, type: 'credential:' + name.toLowerCase() });
        continue;
      }

      if (window.origamiSensitiveDataPatterns) {
        const p = window.origamiSensitiveDataPatterns;
        if (new RegExp(p.email.source).test(value)) { suspicious.push({ name, type: 'email' }); continue; }
        if (new RegExp(p.ssn.source).test(value)) { suspicious.push({ name, type: 'ssn' }); continue; }
        if (new RegExp(p.creditCard.source).test(value)) {
          const digits = value.replace(/\D/g, '');
          const ccMatch = digits.match(/(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})/);
          if (ccMatch && this._luhnCheck(ccMatch[0])) {
            suspicious.push({ name, type: 'credit-card' });
          }
          continue;
        }
      }

      if (value.length > 20 && window.origamiCalculateStringEntropy && window.origamiCalculateStringEntropy(value) > 5.0) {
        suspicious.push({ name, type: 'high-entropy-token' });
      }
    }
    return suspicious;
  }

  _detectCredentialsInGetParams() {
    try {
      const proto = window.location.protocol;
      if (proto !== 'http:' && proto !== 'https:') return;
    } catch (e) { return; }
    let parsed;
    try { parsed = new URL(window.location.href); } catch (e) { return; }
    if (!parsed.search) return;

    const isAuthFlowURL = this._ssoUrlPatterns.test(parsed.pathname);

    for (const [paramName, paramValue] of parsed.searchParams) {
      if (!paramValue) continue;
      const paramLower = paramName.toLowerCase();

      // Suppress auth flow params
      if (this._authFlowParams.has(paramName) || this._authFlowParams.has(paramLower)) continue;

      // Suppress analytics params
      if (this._analyticsParams.has(paramLower)) continue;

      if (this._credentialParams.includes(paramLower)) {
        // Credentials in URLs are always suspicious -- RFC 6749 prohibits this even for auth flows

        this._addIssue(this._highSeverityCreds.includes(paramLower) ? 'HIGH' : 'MEDIUM',
          'credential-in-page-url',
          'Credential "' + paramName + '" present in current page URL -- exposed in browser history, server logs, and Referer header',
          'CWE-598', { destination: parsed.hostname, method: 'GET', dataTypes: ['credential:' + paramLower],
          requestUrl: this._redact(window.location.href), isFirstParty: true, classification: 'first-party' },
          'Credentials must never appear in URL query strings. Use POST body, Authorization header, or secure cookies.');
      }
    }
  }

  _detectPIIInPageContext() {
    if (!window.origamiSensitiveDataPatterns) return;
    const patterns = window.origamiSensitiveDataPatterns;
    const targets = [
      { url: window.location.href, source: 'page URL', fp: true },
      { url: document.referrer, source: 'Referer header', fp: false }
    ];

    for (const target of targets) {
      if (!target.url || target.url.length < 10) continue;
      for (const check of this._piiChecks) {
        if (new RegExp(patterns[check.key].source).test(target.url)) {
          const hostname = this._hostnameOf(target.url);
          this._addIssue(check.severity, 'pii-in-' + (target.fp ? 'page-url' : 'referrer'),
            (check.label === 'email' ? 'Email address' : check.label === 'phone' ? 'Phone number' : check.label === 'ssn' ? 'SSN' : 'Credit card number') +
            ' detected in ' + target.source + ' -- leaks via Referer header, browser history, and server logs',
            check.cwe, { destination: hostname, method: 'GET', dataTypes: [check.key], requestUrl: this._redact(target.url),
            isFirstParty: target.fp, classification: target.fp ? 'first-party' : this._classify(hostname) },
            'Remove PII from URLs. Use session-based lookups or POST parameters for user-identifying data.');
        }
      }
    }
  }

  _classifyThirdPartyDataFlows() {
    const flowMap = {};
    for (const flow of this.findings.dataFlows) {
      if (flow.classification === 'first-party') continue;
      if (!flowMap[flow.destination]) {
        flowMap[flow.destination] = { destination: flow.destination, classification: flow.classification, requestCount: 0, dataTypes: new Set() };
      }
      flowMap[flow.destination].requestCount++;
      for (const dt of flow.dataTypes) flowMap[flow.destination].dataTypes.add(dt);
    }

    for (const key of Object.keys(flowMap)) {
      const s = flowMap[key];
      const types = [...s.dataTypes];
      const hasPII = types.some(dt => dt === 'email' || dt === 'phone' || dt === 'ssn' || dt === 'credit-card');
      const hasCreds = types.some(dt => dt.startsWith('credential:'));
      const agg = '(aggregated -- ' + s.requestCount + ' requests)';

      if (hasPII && s.classification === 'unknown-third-party') {
        this._addIssue('HIGH', 'pii-to-unknown-third-party',
          'PII data (' + types.filter(dt => !dt.startsWith('credential:')).join(', ') + ') sent to unclassified third party: ' + s.destination,
          'CWE-359', { destination: s.destination, method: 'GET', dataTypes: types, requestUrl: agg, isFirstParty: false, classification: s.classification },
          'Review data flows to unknown third parties. Ensure user consent is obtained and data minimization principles are followed.');
      }

      if (hasCreds) {
        // For CDN/analytics/advertising domains, credential-named params (apikey, auth, key)
        // are typically public identifiers or service tokens, not secret credentials.
        // Only flag HIGH for unknown third parties or when high-severity creds are present.
        const credTypes = types.filter(dt => dt.startsWith('credential:'));
        const hasHighSevCred = credTypes.some(dt => {
          const param = dt.replace('credential:', '');
          return this._highSeverityCreds.includes(param);
        });
        const knownDomain = s.classification === 'cdn' || s.classification === 'analytics' || s.classification === 'advertising';
        const credSeverity = (knownDomain && !hasHighSevCred) ? 'MEDIUM' : 'HIGH';
        this._addIssue(credSeverity, 'credentials-to-third-party',
          'Credential data sent to third party (' + s.classification + '): ' + s.destination,
          'CWE-598', { destination: s.destination, method: 'GET', dataTypes: credTypes, requestUrl: agg, isFirstParty: false, classification: s.classification },
          'Credentials must never be sent to third-party domains. Review and remove credential leakage paths.');
      }

      if (types.length > 0 && !hasPII && !hasCreds) {
        this._addIssue('INFO', 'third-party-data-flow',
          'Data flow to ' + s.classification + ' domain: ' + s.destination + ' (' + s.requestCount + ' requests, types: ' + types.join(', ') + ')',
          'CWE-200', { destination: s.destination, method: 'GET', dataTypes: types, requestUrl: agg, isFirstParty: false, classification: s.classification },
          'Review third-party data flows for compliance with privacy policies.');
      }
    }
  }

  // --- Helpers ---

  _addIssue(severity, type, message, cwe, details, recommendation) {
    this.findings.issues.push({ severity, type, message, cwe, details, recommendation });
  }

  _classify(hostname) {
    return window.origamiClassifyDomain ? window.origamiClassifyDomain(hostname) : 'unknown-third-party';
  }

  _adjustSeverity(base, classification, isFirstParty) {
    if (!isFirstParty) return base;
    const downgrade = { CRITICAL: 'HIGH', HIGH: 'LOW', MEDIUM: 'INFO', LOW: 'INFO' };
    return downgrade[base] || base;
  }

  _parseHTTPURL(urlStr, base) {
    try {
      const u = base ? new URL(urlStr, base) : new URL(urlStr);
      return (u.protocol === 'https:' || u.protocol === 'http:') ? u : null;
    } catch (e) { return null; }
  }

  _hostnameOf(urlStr) {
    try { return new URL(urlStr).hostname; } catch (e) { return 'unknown'; }
  }

  _luhnCheck(num) {
    let sum = 0;
    let alt = false;
    for (let i = num.length - 1; i >= 0; i--) {
      let n = parseInt(num[i], 10);
      if (alt) { n *= 2; if (n > 9) n -= 9; }
      sum += n;
      alt = !alt;
    }
    return sum % 10 === 0;
  }

  _redact(urlStr) {
    try {
      const u = new URL(urlStr);
      const parts = [];
      for (const [key] of u.searchParams) parts.push(key + '=[REDACTED]');
      return u.origin + u.pathname + (parts.length > 0 ? '?' + parts.join('&') : '');
    } catch (e) {
      const q = urlStr.indexOf('?');
      return q > -1 ? urlStr.substring(0, q) + '?[REDACTED]' : urlStr;
    }
  }
}

window.ExfiltrationDetector = ExfiltrationDetector;
