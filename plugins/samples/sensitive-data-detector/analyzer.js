// Sensitive Data Detector Plugin for Origami
// Scans page content and inline scripts for exposed PII patterns

class SensitiveDataAnalyzer {
  constructor() {
    this.patterns = [
      {
        name: 'Credit Card (Visa)',
        check: 'credit-card-visa',
        regex: /\b4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b/g,
        severity: 'CRITICAL',
        recommendation: 'Remove credit card numbers from client-side code. Use tokenized references instead.'
      },
      {
        name: 'Credit Card (Mastercard)',
        check: 'credit-card-mastercard',
        regex: /\b5[1-5][0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b/g,
        severity: 'CRITICAL',
        recommendation: 'Remove credit card numbers from client-side code. Use tokenized references instead.'
      },
      {
        name: 'Credit Card (Amex)',
        check: 'credit-card-amex',
        regex: /\b3[47][0-9]{2}[\s-]?[0-9]{6}[\s-]?[0-9]{5}\b/g,
        severity: 'CRITICAL',
        recommendation: 'Remove credit card numbers from client-side code. Use tokenized references instead.'
      },
      {
        name: 'Social Security Number',
        check: 'ssn-exposure',
        regex: /\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b/g,
        severity: 'CRITICAL',
        recommendation: 'Never expose SSNs in client-side content. Mask all but the last four digits.'
      },
      {
        name: 'Email Address',
        check: 'email-in-source',
        regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
        severity: 'LOW',
        recommendation: 'Avoid exposing email addresses in HTML source. Use server-side rendering or obfuscation to reduce scraping risk.'
      },
      {
        name: 'Phone Number (US)',
        check: 'phone-number-us',
        regex: /\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/g,
        severity: 'MEDIUM',
        recommendation: 'Avoid embedding phone numbers in scripts or comments. Render them server-side when possible.'
      },
      {
        name: 'IPv4 Address',
        check: 'ipv4-exposure',
        regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
        severity: 'MEDIUM',
        recommendation: 'Internal IP addresses in client-side code can reveal network topology. Remove or replace with environment-resolved values.'
      }
    ];

    // IPs that are safe to ignore (localhost, example ranges, link-local)
    this.ignoredIPs = new Set([
      '127.0.0.1', '0.0.0.0', '255.255.255.255',
      '192.0.2.1', '198.51.100.1', '203.0.113.1'
    ]);

    // Common false-positive email domains to skip
    this.ignoredEmailDomains = new Set([
      'example.com', 'example.org', 'example.net',
      'test.com', 'localhost', 'placeholder.com'
    ]);
  }

  analyze(document, url) {
    const findings = [];

    try {
      // Scan visible body text
      const bodyText = document.body ? document.body.innerText : '';
      this._scanContent(bodyText, 'Page body text', findings);

      // Scan inline script contents
      const scripts = document.querySelectorAll('script:not([src])');
      scripts.forEach((script, index) => {
        const code = script.textContent || '';
        if (code.trim().length > 0) {
          this._scanContent(code, 'Inline script #' + (index + 1), findings);
        }
      });

      // Scan HTML comments
      this._scanComments(document, findings);

    } catch (e) {
      console.error('SensitiveDataAnalyzer: scan error:', e);
    }

    return findings;
  }

  _scanContent(text, location, findings) {
    for (const pattern of this.patterns) {
      // Reset regex lastIndex for global patterns
      pattern.regex.lastIndex = 0;

      let match;
      const seen = new Set();

      while ((match = pattern.regex.exec(text)) !== null) {
        const value = match[0].trim();

        // Deduplicate within the same location
        if (seen.has(value)) continue;
        seen.add(value);

        // Apply filters for known false positives
        if (pattern.check === 'ipv4-exposure' && this._isIgnoredIP(value)) continue;
        if (pattern.check === 'email-in-source' && this._isIgnoredEmail(value)) continue;
        if (pattern.check === 'ssn-exposure' && this._looksLikeDateOrVersion(value)) continue;
        if (pattern.check.startsWith('credit-card') && !this._passesLuhn(value)) continue;

        findings.push({
          check: pattern.check,
          severity: pattern.severity,
          message: pattern.name + ' detected in ' + location,
          details: {
            pattern: this._maskValue(value, pattern.check),
            location: location,
            recommendation: pattern.recommendation
          }
        });
      }
    }
  }

  _scanComments(document, findings) {
    const iterator = document.createTreeWalker(
      document.documentElement,
      NodeFilter.SHOW_COMMENT,
      null,
      false
    );

    let commentIndex = 0;
    let node;
    while ((node = iterator.nextNode())) {
      commentIndex++;
      const text = node.textContent || '';
      if (text.trim().length > 0) {
        this._scanContent(text, 'HTML comment #' + commentIndex, findings);
      }
    }
  }

  _isIgnoredIP(ip) {
    if (this.ignoredIPs.has(ip)) return true;
    // Ignore link-local (169.254.x.x)
    if (ip.startsWith('169.254.')) return true;
    // Ignore common CDN/public DNS
    if (ip === '8.8.8.8' || ip === '8.8.4.4' || ip === '1.1.1.1') return true;
    return false;
  }

  _isIgnoredEmail(email) {
    const domain = email.split('@')[1];
    return this.ignoredEmailDomains.has(domain);
  }

  _looksLikeDateOrVersion(value) {
    const parts = value.split(/[-\/]/);
    if (parts.length < 2) return false;
    const first = parseInt(parts[0], 10);
    // SSN area numbers 000, 666, and 900-999 are invalid
    if (first === 0 || first === 666 || first >= 900) return true;
    return false;
  }

  _passesLuhn(cardNumber) {
    const digits = cardNumber.replace(/[\s-]/g, '');
    if (digits.length < 13 || digits.length > 19) return false;

    let sum = 0;
    let alternate = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let n = parseInt(digits[i], 10);
      if (alternate) {
        n *= 2;
        if (n > 9) n -= 9;
      }
      sum += n;
      alternate = !alternate;
    }
    return sum % 10 === 0;
  }

  _maskValue(value, check) {
    if (check.startsWith('credit-card')) {
      const digits = value.replace(/[\s-]/g, '');
      return '****-****-****-' + digits.slice(-4);
    }
    if (check === 'ssn-exposure') {
      return '***-**-' + value.slice(-4);
    }
    return value;
  }
}
