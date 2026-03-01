// Origami Security Header Analyzer
// Analyzes HTTP response headers for security misconfigurations

class SecurityHeaderAnalyzer {
  constructor() {
    this.results = [];
  }

  // Analyze all security headers
  analyze(headers, url) {
    this.results = [];
    
    // Convert headers array to object for easier access
    const headerObj = {};
    if (Array.isArray(headers)) {
      headers.forEach(h => {
        headerObj[h.name.toLowerCase()] = h.value;
      });
    } else if (typeof headers === 'object') {
      // Already an object
      Object.keys(headers).forEach(key => {
        headerObj[key.toLowerCase()] = headers[key];
      });
    }
    
    // Run all checks
    this.checkCSP(headerObj, url);
    this.checkHSTS(headerObj, url);
    this.checkXFrameOptions(headerObj, url);
    this.checkXContentTypeOptions(headerObj, url);
    this.checkXXSSProtection(headerObj, url);
    this.checkReferrerPolicy(headerObj, url);
    this.checkPermissionsPolicy(headerObj, url);
    this.checkServerHeader(headerObj, url);
    this.checkCORS(headerObj, url);
    this.checkSecurityHeaders(headerObj, url);
    
    return this.results;
  }

  // Helper to add finding
  addFinding(check, status, severity, message, recommendation, details = null) {
    this.results.push({
      check,
      status,
      severity, // CRITICAL, HIGH, MEDIUM, LOW, INFO
      message,
      recommendation,
      details
    });
  }

  // Check Content-Security-Policy
  checkCSP(headers, url) {
    const csp = headers['content-security-policy'];
    const cspReport = headers['content-security-policy-report-only'];
    
    if (!csp && !cspReport) {
      this.addFinding(
        'Content-Security-Policy',
        'MISSING',
        'INFO',
        'Content-Security-Policy header is not set',
        'Implement a strict CSP to prevent XSS attacks. Start with a report-only policy to test.',
        { header: 'content-security-policy' }
      );
    } else if (cspReport && !csp) {
      this.addFinding(
        'Content-Security-Policy',
        'REPORT_ONLY',
        'INFO',
        'CSP is in report-only mode',
        'Move from report-only to enforcing mode once testing is complete.',
        { policy: cspReport }
      );
    } else {
      // Check for weak CSP
      const policy = csp || cspReport;
      const weaknesses = this.analyzeCSP(policy);

      if (weaknesses.length > 0) {
        const highestSeverity = weaknesses.some(w => w.severity === 'MEDIUM') ? 'MEDIUM' : 'LOW';
        this.addFinding(
          'Content-Security-Policy',
          'WEAK',
          highestSeverity,
          `CSP has potential weaknesses: ${weaknesses.map(w => w.text).join(', ')}`,
          'Strengthen your CSP by removing unsafe directives and using nonces or hashes.',
          { policy, weaknesses: weaknesses.map(w => w.text) }
        );
      } else {
        this.addFinding(
          'Content-Security-Policy',
          'OK',
          'INFO',
          'CSP is configured',
          null,
          { policy }
        );
      }
    }
  }

  // Analyze CSP for common weaknesses
  analyzeCSP(policy) {
    const weaknesses = [];

    // MEDIUM: directly exploitable for XSS (unsafe-inline/unsafe-eval/wildcard/data: in script-src or default-src)
    if (policy.includes("'unsafe-inline'")) {
      const directive = this.directiveContains(policy, "'unsafe-inline'", ['default-src', 'script-src']);
      if (directive) {
        weaknesses.push({ text: `unsafe-inline in ${directive}`, severity: 'MEDIUM' });
      }
    }
    if (policy.includes("'unsafe-eval'")) {
      const directive = this.directiveContains(policy, "'unsafe-eval'", ['default-src', 'script-src']);
      if (directive) {
        weaknesses.push({ text: `unsafe-eval in ${directive}`, severity: 'MEDIUM' });
      }
    }
    // Only flag wildcards in dangerous directives (not img-src, font-src, etc.)
    if (policy.includes('*')) {
      const scriptWildcard = this.directiveContains(policy, '*', ['default-src', 'script-src']);
      if (scriptWildcard) {
        weaknesses.push({ text: `wildcard source detected in ${scriptWildcard}`, severity: 'MEDIUM' });
      }
      const otherWildcard = this.directiveContains(policy, '*', ['object-src', 'connect-src']);
      if (otherWildcard) {
        weaknesses.push({ text: `wildcard source detected in ${otherWildcard}`, severity: 'LOW' });
      }
    }
    // Only flag data: URIs in directives where they're dangerous (not img-src)
    if (policy.includes('data:')) {
      const scriptData = this.directiveContains(policy, 'data:', ['default-src', 'script-src', 'object-src']);
      if (scriptData) {
        weaknesses.push({ text: `data: URI allowed in ${scriptData}`, severity: 'MEDIUM' });
      }
      const styleData = this.directiveContains(policy, 'data:', ['style-src']);
      if (styleData) {
        weaknesses.push({ text: `data: URI allowed in ${styleData}`, severity: 'LOW' });
      }
    }
    if (!policy.includes('default-src')) {
      weaknesses.push({ text: "no default-src fallback", severity: 'LOW' });
    }

    this.checkCSPBypasses(policy);

    return weaknesses;
  }

  // Check for known CSP bypass domains in script-src / default-src
  checkCSPBypasses(policy) {
    const CSP_BYPASS_DOMAINS = [
      { domain: '*.googleapis.com', reason: 'JSONP endpoints allow script execution bypass', severity: 'LOW' },
      { domain: '*.gstatic.com', reason: 'Known CSP bypass via Angular libraries', severity: 'LOW' },
      { domain: '*.cloudflare.com', reason: 'CDN with potential bypass endpoints', severity: 'INFO' },
      { domain: 'cdnjs.cloudflare.com', reason: 'JSONP and callback endpoints available', severity: 'MEDIUM' },
      { domain: '*.jsdelivr.net', reason: 'Arbitrary JavaScript hosting', severity: 'MEDIUM' },
      { domain: '*.unpkg.com', reason: 'Arbitrary npm package serving', severity: 'MEDIUM' },
      { domain: '*.rawgit.com', reason: 'Raw GitHub content serving', severity: 'MEDIUM' },
      { domain: '*.raw.githubusercontent.com', reason: 'Raw GitHub content serving', severity: 'MEDIUM' },
      { domain: '*.accounts.google.com', reason: 'OAuth callback with script execution', severity: 'MEDIUM' },
      { domain: '*.facebook.com', reason: 'JSONP endpoints available', severity: 'LOW' },
      { domain: '*.fbcdn.net', reason: 'Facebook CDN with callback endpoints', severity: 'LOW' },
      { domain: '*.google-analytics.com', reason: 'Script injection via tracking parameters', severity: 'INFO' },
    ];

    const directives = policy.split(';').map(d => d.trim());
    let scriptSources = null;

    for (const directive of directives) {
      const parts = directive.split(/\s+/);
      if (parts[0] === 'script-src') {
        scriptSources = parts.slice(1);
        break;
      }
    }

    if (!scriptSources) {
      for (const directive of directives) {
        const parts = directive.split(/\s+/);
        if (parts[0] === 'default-src') {
          scriptSources = parts.slice(1);
          break;
        }
      }
    }

    if (scriptSources) {
      for (const source of scriptSources) {
        for (const bypass of CSP_BYPASS_DOMAINS) {
          if (this.cspDomainMatches(source, bypass.domain)) {
            this.addFinding(
              'CSP Bypass Domain',
              'VULNERABLE',
              bypass.severity || 'HIGH',
              `CSP allows known bypass domain: ${source} - ${bypass.reason}`,
              'Remove this domain from CSP or use strict-dynamic with nonces instead of domain whitelisting.',
              { policy, domain: source, bypassDomain: bypass.domain, reason: bypass.reason }
            );
          }
        }
      }

      // Check unsafe-inline coexisting with nonce or hash in script-src
      const hasUnsafeInline = scriptSources.includes("'unsafe-inline'");
      const hasNonce = scriptSources.some(s => s.startsWith("'nonce-"));
      const hasHash = scriptSources.some(s => s.startsWith("'sha256-") || s.startsWith("'sha384-") || s.startsWith("'sha512-"));
      if (hasUnsafeInline && (hasNonce || hasHash)) {
        this.addFinding(
          'CSP unsafe-inline with nonce/hash',
          'INFO',
          'INFO',
          "unsafe-inline is ignored by browsers supporting nonces/hashes but creates a fallback risk for older browsers",
          'Remove unsafe-inline once you confirm nonce/hash coverage for all inline scripts.',
          { policy }
        );
      }
    }

    // Check for missing base-uri directive
    const hasBaseUri = directives.some(d => d.trim().startsWith('base-uri'));
    if (!hasBaseUri) {
      this.addFinding(
        'CSP Missing base-uri',
        'WEAK',
        'INFO',
        'Missing base-uri directive - allows base tag injection for relative URL hijacking',
        "Add base-uri 'self' or base-uri 'none' to prevent base tag injection attacks.",
        { policy }
      );
    }
  }

  // Check if a CSP source matches a known bypass domain pattern
  cspDomainMatches(source, bypassPattern) {
    const normalizedSource = source.toLowerCase().replace(/^https?:\/\//, '');
    const normalizedBypass = bypassPattern.toLowerCase();

    if (normalizedBypass.startsWith('*.')) {
      const suffix = normalizedBypass.substring(2);
      return normalizedSource === suffix || normalizedSource.endsWith('.' + suffix);
    }

    return normalizedSource === normalizedBypass;
  }

  // Check if a CSP value appears in any of the specified dangerous directives
  directiveContains(policy, value, dangerousDirectives) {
    const directives = policy.split(';').map(d => d.trim());
    for (const directive of directives) {
      const parts = directive.split(/\s+/);
      const directiveName = parts[0];
      if (dangerousDirectives.includes(directiveName) && directive.includes(value)) {
        return directiveName;
      }
    }
    return null;
  }

  // Check Strict-Transport-Security
  checkHSTS(headers, url) {
    const hsts = headers['strict-transport-security'];
    
    if (url.startsWith('https://')) {
      if (!hsts) {
        this.addFinding(
          'Strict-Transport-Security',
          'MISSING',
          'LOW',
          'HSTS header is not set on HTTPS site',
          'Add Strict-Transport-Security header with max-age of at least 31536000 (1 year).',
          { header: 'strict-transport-security' }
        );
      } else {
        // Parse max-age
        const maxAgeMatch = hsts.match(/max-age=(\d+)/);
        const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]) : 0;
        const includesSubdomains = hsts.includes('includeSubDomains');
        const preload = hsts.includes('preload');
        
        if (maxAge < 31536000) {
          this.addFinding(
            'Strict-Transport-Security',
            'WEAK',
            'INFO',
            `HSTS max-age is too short: ${maxAge} seconds`,
            'Increase max-age to at least 31536000 (1 year).',
            { hsts, maxAge }
          );
        } else if (!includesSubdomains) {
          this.addFinding(
            'Strict-Transport-Security',
            'INCOMPLETE',
            'INFO',
            'HSTS does not include subdomains',
            'Add includeSubDomains directive to protect subdomains.',
            { hsts }
          );
        } else {
          this.addFinding(
            'Strict-Transport-Security',
            'OK',
            'INFO',
            'HSTS is properly configured',
            preload ? 'Consider submitting to HSTS preload list' : null,
            { hsts, maxAge, includesSubdomains, preload }
          );
        }
      }
    }
  }

  // Check X-Frame-Options
  checkXFrameOptions(headers, url) {
    const xfo = headers['x-frame-options'];
    const csp = headers['content-security-policy'];
    
    // Check if frame-ancestors is set in CSP (preferred over X-Frame-Options)
    const hasFrameAncestors = csp && csp.includes('frame-ancestors');
    
    if (!xfo && !hasFrameAncestors) {
      this.addFinding(
        'X-Frame-Options',
        'MISSING',
        'INFO',
        'No clickjacking protection found',
        'Set X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors directive.',
        { header: 'x-frame-options' }
      );
    } else if (xfo) {
      const value = xfo.toUpperCase();
      if (value === 'DENY' || value === 'SAMEORIGIN') {
        this.addFinding(
          'X-Frame-Options',
          'OK',
          'INFO',
          `Clickjacking protection enabled: ${value}`,
          hasFrameAncestors ? null : 'Consider using CSP frame-ancestors instead for better control.',
          { xfo }
        );
      } else if (value.startsWith('ALLOW-FROM')) {
        this.addFinding(
          'X-Frame-Options',
          'DEPRECATED',
          'INFO',
          'ALLOW-FROM is deprecated',
          'Use CSP frame-ancestors directive instead.',
          { xfo }
        );
      }
    } else {
      this.addFinding(
        'X-Frame-Options',
        'OK',
        'INFO',
        'CSP frame-ancestors provides clickjacking protection',
        null,
        { csp }
      );
    }
  }

  // Check X-Content-Type-Options
  checkXContentTypeOptions(headers, url) {
    const xcto = headers['x-content-type-options'];
    
    if (!xcto) {
      this.addFinding(
        'X-Content-Type-Options',
        'MISSING',
        'LOW',
        'X-Content-Type-Options header is not set',
        'Set X-Content-Type-Options: nosniff to prevent MIME type sniffing.',
        { header: 'x-content-type-options' }
      );
    } else if (xcto.toLowerCase() === 'nosniff') {
      this.addFinding(
        'X-Content-Type-Options',
        'OK',
        'INFO',
        'MIME type sniffing is disabled',
        null,
        { xcto }
      );
    }
  }

  // Check X-XSS-Protection
  checkXXSSProtection(headers, url) {
    const xxp = headers['x-xss-protection'];

    if (!xxp) {
      this.addFinding(
        'X-XSS-Protection',
        'MISSING',
        'INFO',
        'X-XSS-Protection header is not set (deprecated, use CSP instead)',
        'This header is deprecated in modern browsers. Use Content-Security-Policy instead.',
        { header: 'x-xss-protection', note: 'Deprecated in modern browsers, use CSP instead' }
      );
    } else if (xxp === '1; mode=block' || xxp === '1') {
      this.addFinding(
        'X-XSS-Protection',
        'OK',
        'INFO',
        'XSS filter is enabled',
        'Note: This header is deprecated. Use Content-Security-Policy instead.',
        { xxp }
      );
    } else if (xxp === '0') {
      this.addFinding(
        'X-XSS-Protection',
        'DISABLED',
        'INFO',
        'XSS filter is explicitly disabled',
        'Either enable it or rely on CSP for XSS protection.',
        { xxp }
      );
    }
  }

  // Check Referrer-Policy
  checkReferrerPolicy(headers, url) {
    const rp = headers['referrer-policy'];
    
    if (!rp) {
      this.addFinding(
        'Referrer-Policy',
        'MISSING',
        'INFO',
        'Referrer-Policy header is not set',
        'Set Referrer-Policy to control referrer information leakage (e.g., strict-origin-when-cross-origin).',
        { header: 'referrer-policy' }
      );
    } else {
      const value = rp.toLowerCase();
      const weakPolicies = ['unsafe-url', 'no-referrer-when-downgrade'];
      
      if (weakPolicies.includes(value)) {
        this.addFinding(
          'Referrer-Policy',
          'WEAK',
          'LOW',
          `Referrer-Policy may leak information: ${value}`,
          'Use strict-origin-when-cross-origin or no-referrer for better privacy.',
          { rp }
        );
      } else {
        this.addFinding(
          'Referrer-Policy',
          'OK',
          'INFO',
          `Referrer-Policy is set: ${value}`,
          null,
          { rp }
        );
      }
    }
  }

  // Check Permissions-Policy (formerly Feature-Policy)
  checkPermissionsPolicy(headers, url) {
    const pp = headers['permissions-policy'];
    const fp = headers['feature-policy'];
    
    if (!pp && !fp) {
      this.addFinding(
        'Permissions-Policy',
        'MISSING',
        'INFO',
        'Permissions-Policy header is not set',
        'Consider setting Permissions-Policy to control browser features (camera, microphone, geolocation, etc.).',
        { header: 'permissions-policy' }
      );
    } else {
      this.addFinding(
        'Permissions-Policy',
        'OK',
        'INFO',
        'Permissions-Policy is configured',
        fp ? 'Note: Feature-Policy is deprecated, use Permissions-Policy' : null,
        { policy: pp || fp }
      );
    }
  }

  // Check Server header
  checkServerHeader(headers, url) {
    const server = headers['server'];
    const xPoweredBy = headers['x-powered-by'];
    
    if (server || xPoweredBy) {
      const exposed = [];
      if (server) exposed.push(`Server: ${server}`);
      if (xPoweredBy) exposed.push(`X-Powered-By: ${xPoweredBy}`);
      
      this.addFinding(
        'Information Disclosure',
        'EXPOSED',
        'INFO',
        'Server information is exposed in headers',
        'Remove or obfuscate Server and X-Powered-By headers to reduce information leakage.',
        { exposed }
      );
    } else {
      this.addFinding(
        'Information Disclosure',
        'OK',
        'INFO',
        'Server headers are not disclosed',
        null,
        null
      );
    }
  }

  // Check CORS configuration
  checkCORS(headers, url) {
    const acao = headers['access-control-allow-origin'];
    const acac = headers['access-control-allow-credentials'];
    
    if (acao) {
      if (acao === '*') {
        if (acac === 'true') {
          this.addFinding(
            'CORS Configuration',
            'CRITICAL',
            'CRITICAL',
            'CORS allows any origin with credentials',
            'Never use Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. This is a critical security vulnerability.',
            { acao, acac }
          );
        } else {
          this.addFinding(
            'CORS Configuration',
            'PERMISSIVE',
            'INFO',
            'CORS allows any origin',
            'Restrict Access-Control-Allow-Origin to specific trusted domains instead of using wildcard.',
            { acao }
          );
        }
      } else if (acao.includes('null')) {
        this.addFinding(
          'CORS Configuration',
          'VULNERABLE',
          'HIGH',
          'CORS allows null origin',
          'Never allow null origin as it can be exploited. Use specific domain names.',
          { acao }
        );
      } else {
        this.addFinding(
          'CORS Configuration',
          'OK',
          'INFO',
          `CORS is configured for: ${acao}`,
          acac === 'true' ? 'Verify that credentials are necessary and the origin is trusted.' : null,
          { acao, acac }
        );
      }
    }
  }

  // Check for additional security headers
  checkSecurityHeaders(headers, url) {
    // Cross-Origin-Embedder-Policy
    if (!headers['cross-origin-embedder-policy']) {
      this.addFinding(
        'Cross-Origin-Embedder-Policy',
        'MISSING',
        'INFO',
        'COEP header is not set',
        'Consider setting Cross-Origin-Embedder-Policy for enhanced isolation.',
        { header: 'cross-origin-embedder-policy', note: 'Required for SharedArrayBuffer' }
      );
    }

    // Cross-Origin-Opener-Policy
    if (!headers['cross-origin-opener-policy']) {
      this.addFinding(
        'Cross-Origin-Opener-Policy',
        'MISSING',
        'INFO',
        'COOP header is not set',
        'Consider setting Cross-Origin-Opener-Policy to isolate browsing context.',
        { header: 'cross-origin-opener-policy', note: 'Helps prevent cross-origin attacks' }
      );
    }

    // Cross-Origin-Resource-Policy
    if (!headers['cross-origin-resource-policy']) {
      this.addFinding(
        'Cross-Origin-Resource-Policy',
        'MISSING',
        'INFO',
        'CORP header is not set',
        'Consider setting Cross-Origin-Resource-Policy to control resource loading.',
        { header: 'cross-origin-resource-policy' }
      );
    }
  }
}

// Export for use in extension
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SecurityHeaderAnalyzer;
}

