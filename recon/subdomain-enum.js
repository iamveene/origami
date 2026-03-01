// Origami Subdomain Enumerator
// Passive subdomain discovery from various sources

class SubdomainEnumerator {
  constructor() {
    this.subdomains = new Set();
  }

  // Main enumeration function
  async enumerate(domain, document) {
    this.subdomains.clear();

    // 1. Extract from JavaScript files
    await this.extractFromJavaScript(document);

    // 2. Extract from HTML
    this.extractFromHTML(document);

    // 3. Extract from CSP headers
    await this.extractFromCSP();

    // 4. Extract from links and resources
    this.extractFromResources(document);

    // Return unique subdomains for the target domain
    const targetSubdomains = Array.from(this.subdomains)
      .filter(sub => sub === domain || sub.endsWith('.' + domain))
      .sort();

    return {
      domain,
      count: targetSubdomains.length,
      subdomains: targetSubdomains,
      timestamp: new Date().toISOString()
    };
  }

  // Extract subdomains from JavaScript
  async extractFromJavaScript(document) {
    const scripts = document.querySelectorAll('script');
    
    for (const script of scripts) {
      let code = script.textContent;

      // Also try to fetch external scripts
      if (script.src && script.src.startsWith(window.location.origin)) {
        try {
          const response = await fetch(script.src);
          code += await response.text();
        } catch (error) {
          // Can't fetch, skip
        }
      }

      if (code) {
        this.extractDomainsFromText(code);
      }
    }
  }

  // Extract subdomains from HTML
  extractFromHTML(document) {
    const html = document.documentElement.outerHTML;
    this.extractDomainsFromText(html);
  }

  // Extract from CSP headers
  async extractFromCSP() {
    try {
      const response = await fetch(window.location.href, { method: 'HEAD' });
      const csp = response.headers.get('content-security-policy');
      
      if (csp) {
        this.extractDomainsFromText(csp);
      }
    } catch (error) {
      // Can't check headers
    }
  }

  // Extract from page resources
  extractFromResources(document) {
    // Links
    document.querySelectorAll('a[href]').forEach(a => {
      try {
        const url = new URL(a.href);
        this.subdomains.add(url.hostname);
      } catch (e) {}
    });

    // Images
    document.querySelectorAll('img[src]').forEach(img => {
      try {
        const url = new URL(img.src);
        this.subdomains.add(url.hostname);
      } catch (e) {}
    });

    // Scripts
    document.querySelectorAll('script[src]').forEach(script => {
      try {
        const url = new URL(script.src);
        this.subdomains.add(url.hostname);
      } catch (e) {}
    });

    // Stylesheets
    document.querySelectorAll('link[href]').forEach(link => {
      try {
        const url = new URL(link.href);
        this.subdomains.add(url.hostname);
      } catch (e) {}
    });

    // Iframes
    document.querySelectorAll('iframe[src]').forEach(iframe => {
      try {
        const url = new URL(iframe.src);
        this.subdomains.add(url.hostname);
      } catch (e) {}
    });
  }

  // Extract domains from text using regex
  extractDomainsFromText(text) {
    // Match URLs
    const urlPattern = /https?:\/\/([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}/g;
    let match;
    
    while ((match = urlPattern.exec(text)) !== null) {
      try {
        const url = new URL(match[0]);
        this.subdomains.add(url.hostname);
      } catch (e) {}
    }

    // Match domain-like strings (without protocol)
    const domainPattern = /\b([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b/g;
    
    while ((match = domainPattern.exec(text)) !== null) {
      const domain = match[0];
      // Filter out common false positives
      if (!this.isFalsePositive(domain)) {
        this.subdomains.add(domain);
      }
    }
  }

  // Filter false positives
  isFalsePositive(domain) {
    const falsePositives = [
      'example.com',
      'example.org',
      'localhost',
      'test.com',
      'domain.com'
    ];

    return falsePositives.some(fp => domain === fp) || 
           domain.split('.').length < 2 ||
           /^\d+\.\d+\.\d+\.\d+$/.test(domain); // IP addresses
  }

  // Query Certificate Transparency logs (external API)
  async queryCertTransparency(domain, apiKey = null) {
    try {
      // Using crt.sh (no API key required)
      const response = await fetch(`https://crt.sh/?q=%.${domain}&output=json`, {
        headers: { 'Accept': 'application/json' }
      });

      if (!response.ok) {
        return [];
      }

      const data = await response.json();
      const subdomains = new Set();

      data.forEach(cert => {
        if (cert.name_value) {
          cert.name_value.split('\n').forEach(name => {
            if (name.includes(domain)) {
              subdomains.add(name.replace('*.', ''));
            }
          });
        }
      });

      return Array.from(subdomains);
    } catch (error) {
      console.error('CT log query failed:', error);
      return [];
    }
  }

  // Check if subdomain is active
  async checkSubdomain(subdomain) {
    try {
      const response = await fetch(`https://${subdomain}`, { 
        method: 'HEAD',
        mode: 'no-cors' // Avoid CORS issues
      });
      return { subdomain, active: true, status: response.status };
    } catch (error) {
      return { subdomain, active: false, error: error.message };
    }
  }
}

// Export for use in extension
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SubdomainEnumerator;
}

