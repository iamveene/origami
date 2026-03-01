// Origami Vulnerability Chain Builder
// Interactive workbench for building and analyzing attack chains from scan findings

class ChainBuilder {
  constructor() {
    this.availableFindings = [];
    this.chain = [];
    this.chainMeta = {
      name: '',
      description: '',
      severity: 'INFO',
      createdAt: null
    };
  }

  // Severity numeric mapping
  static SEVERITY_VALUES = {
    CRITICAL: 4,
    HIGH: 3,
    MEDIUM: 2,
    LOW: 1,
    INFO: 0
  };

  static SEVERITY_LABELS = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

  // Load available findings from scan results, flattening all analyzer categories
  setFindings(findings) {
    try {
      this.availableFindings = [];

      if (!findings || typeof findings !== 'object') {
        console.warn('Origami: ChainBuilder.setFindings called with invalid data');
        return;
      }

      // Flatten findings from all analyzer categories into a single array
      // Each finding gets a unique id based on its source category and index

      // Headers (array of check results)
      if (Array.isArray(findings.headers)) {
        findings.headers.forEach((finding, i) => {
          this.availableFindings.push({
            id: `header-${i}`,
            category: 'headers',
            type: finding.check || finding.type || 'Header Issue',
            severity: this._normalizeSeverity(finding.severity || finding.risk),
            message: finding.message || '',
            status: finding.status || '',
            details: finding.details || finding,
            recommendation: finding.recommendation || '',
            uri: finding.uri || finding.url || ''
          });
        });
      }

      // Cookies (array of cookie findings)
      if (Array.isArray(findings.cookies)) {
        findings.cookies.forEach((finding, i) => {
          this.availableFindings.push({
            id: `cookie-${i}`,
            category: 'cookies',
            type: finding.check || finding.type || 'Cookie Issue',
            severity: this._normalizeSeverity(finding.severity || finding.risk),
            message: finding.message || '',
            status: finding.status || '',
            details: finding.details || finding,
            recommendation: finding.recommendation || '',
            uri: finding.uri || finding.url || ''
          });
        });
      }

      // Vulnerabilities (array from vuln-scanner)
      if (Array.isArray(findings.vulnerabilities)) {
        findings.vulnerabilities.forEach((finding, i) => {
          this.availableFindings.push({
            id: `vuln-${i}`,
            category: 'vulnerabilities',
            type: finding.check || finding.type || 'Vulnerability',
            severity: this._normalizeSeverity(finding.severity || finding.risk),
            message: finding.message || '',
            status: finding.status || '',
            details: finding.details || finding,
            recommendation: finding.recommendation || '',
            uri: finding.uri || finding.url || '',
            pattern: finding.pattern || finding.details?.pattern || ''
          });
        });
      }

      // Technologies (array from tech fingerprinter)
      if (findings.technologies) {
        const techs = Array.isArray(findings.technologies)
          ? findings.technologies
          : [];
        techs.forEach((finding, i) => {
          this.availableFindings.push({
            id: `tech-${i}`,
            category: 'technologies',
            type: finding.check || finding.name || 'Technology',
            severity: this._normalizeSeverity(finding.severity || 'INFO'),
            message: finding.message || finding.version || '',
            status: finding.status || '',
            details: finding.details || finding,
            recommendation: finding.recommendation || '',
            uri: finding.uri || finding.url || ''
          });
        });
      }

      // Sensitive files (array from sensitive-file-scanner)
      if (Array.isArray(findings.sensitiveFiles)) {
        findings.sensitiveFiles.forEach((finding, i) => {
          this.availableFindings.push({
            id: `sensfile-${i}`,
            category: 'sensitiveFiles',
            type: finding.check || finding.type || 'Sensitive File',
            severity: this._normalizeSeverity(finding.severity || finding.risk),
            message: finding.message || finding.path || '',
            status: finding.status || '',
            details: finding.details || finding,
            recommendation: finding.recommendation || '',
            uri: finding.uri || finding.url || finding.path || ''
          });
        });
      }

      // Session state issues (from session-analyzer)
      if (findings.sessionState) {
        const sessionIssues = findings.sessionState.allIssues || findings.sessionState.issues || [];
        sessionIssues.forEach((finding, i) => {
          this.availableFindings.push({
            id: `session-${i}`,
            category: 'session',
            type: finding.type || 'Session Issue',
            severity: this._normalizeSeverity(finding.severity),
            message: finding.message || '',
            status: finding.status || '',
            details: finding,
            recommendation: finding.recommendation || '',
            uri: finding.uri || ''
          });
        });
      }

      // Crypto audit issues
      if (findings.crypto && Array.isArray(findings.crypto.issues)) {
        findings.crypto.issues.forEach((finding, i) => {
          this.availableFindings.push({
            id: `crypto-${i}`,
            category: 'crypto',
            type: finding.type || finding.check || 'Crypto Issue',
            severity: this._normalizeSeverity(finding.severity),
            message: finding.message || finding.details || '',
            raw: finding
          });
        });
      }

      // Cloud storage issues
      if (findings.cloudStorage && Array.isArray(findings.cloudStorage.issues)) {
        findings.cloudStorage.issues.forEach((finding, i) => {
          this.availableFindings.push({
            id: `cloudStorage-${i}`,
            category: 'cloudStorage',
            type: finding.type || finding.check || 'Cloud Storage Issue',
            severity: this._normalizeSeverity(finding.severity),
            message: finding.message || finding.details || '',
            raw: finding
          });
        });
      }

      // Exfiltration issues
      if (findings.exfiltration && Array.isArray(findings.exfiltration.issues)) {
        findings.exfiltration.issues.forEach((finding, i) => {
          this.availableFindings.push({
            id: `exfiltration-${i}`,
            category: 'exfiltration',
            type: finding.type || finding.check || 'Exfiltration Issue',
            severity: this._normalizeSeverity(finding.severity),
            message: finding.message || finding.details || '',
            raw: finding
          });
        });
      }

      // WebSocket issues
      if (findings.websockets && Array.isArray(findings.websockets.issues)) {
        findings.websockets.issues.forEach((finding, i) => {
          this.availableFindings.push({
            id: `websocket-${i}`,
            category: 'websockets',
            type: finding.type || finding.check || 'WebSocket Issue',
            severity: this._normalizeSeverity(finding.severity),
            message: finding.message || finding.details || '',
            raw: finding
          });
        });
      }

      // OAuth flow issues
      if (findings.oauthFlows && Array.isArray(findings.oauthFlows.issues)) {
        findings.oauthFlows.issues.forEach((finding, i) => {
          this.availableFindings.push({
            id: `oauth-${i}`,
            category: 'oauthFlows',
            type: finding.type || finding.check || 'Auth Flow Issue',
            severity: this._normalizeSeverity(finding.severity),
            message: finding.message || finding.details || '',
            raw: finding
          });
        });
      }

      // GraphQL issues
      if (findings.graphql && Array.isArray(findings.graphql.issues)) {
        findings.graphql.issues.forEach((finding, i) => {
          this.availableFindings.push({
            id: `graphql-${i}`,
            category: 'graphql',
            type: finding.type || finding.check || 'GraphQL Issue',
            severity: this._normalizeSeverity(finding.severity),
            message: finding.message || finding.details || '',
            raw: finding
          });
        });
      }

      // Template findings (from detection templates)
      if (Array.isArray(findings.templateFindings)) {
        findings.templateFindings.forEach((finding, i) => {
          this.availableFindings.push({
            id: `template-${i}`,
            category: 'templates',
            type: finding.check || finding.type || finding.id || 'Template Finding',
            severity: this._normalizeSeverity(finding.severity || finding.risk),
            message: finding.message || finding.description || '',
            status: finding.status || '',
            details: finding.details || finding,
            recommendation: finding.recommendation || '',
            uri: finding.uri || finding.url || ''
          });
        });
      }

      // Plugin findings (nested: each plugin has a findings array)
      if (Array.isArray(findings.plugins)) {
        findings.plugins.forEach((pluginResult, pi) => {
          (pluginResult.findings || []).forEach((finding, fi) => {
            this.availableFindings.push({
              id: `plugin-${pi}-${fi}`,
              category: 'plugins',
              type: finding.type || finding.check || pluginResult.pluginName || 'Plugin Finding',
              severity: this._normalizeSeverity(finding.severity || finding.risk),
              message: finding.message || '',
              raw: finding
            });
          });
        });
      }

      console.log('Origami: ChainBuilder loaded ' + this.availableFindings.length + ' findings');
    } catch (e) {
      console.error('Origami: ChainBuilder.setFindings error:', e);
    }
  }

  // Add a finding to the chain by its id
  addToChain(findingId) {
    try {
      const finding = this.availableFindings.find(f => f.id === findingId);
      if (!finding) {
        console.warn('Origami: ChainBuilder.addToChain - finding not found:', findingId);
        return false;
      }

      // Prevent duplicates in chain
      if (this.chain.some(f => f.id === findingId)) {
        console.warn('Origami: ChainBuilder.addToChain - finding already in chain:', findingId);
        return false;
      }

      this.chain.push({ ...finding });

      if (!this.chainMeta.createdAt) {
        this.chainMeta.createdAt = new Date().toISOString();
      }

      this.chainMeta.severity = this.calculateChainSeverity();
      return true;
    } catch (e) {
      console.error('Origami: ChainBuilder.addToChain error:', e);
      return false;
    }
  }

  // Remove a finding from the chain at position
  removeFromChain(index) {
    try {
      if (index < 0 || index >= this.chain.length) {
        console.warn('Origami: ChainBuilder.removeFromChain - index out of bounds:', index);
        return false;
      }

      this.chain.splice(index, 1);
      this.chainMeta.severity = this.chain.length > 0 ? this.calculateChainSeverity() : 'INFO';
      return true;
    } catch (e) {
      console.error('Origami: ChainBuilder.removeFromChain error:', e);
      return false;
    }
  }

  // Move a finding within the chain
  reorderChain(fromIndex, toIndex) {
    try {
      if (fromIndex < 0 || fromIndex >= this.chain.length ||
          toIndex < 0 || toIndex >= this.chain.length) {
        console.warn('Origami: ChainBuilder.reorderChain - index out of bounds');
        return false;
      }

      const item = this.chain.splice(fromIndex, 1)[0];
      this.chain.splice(toIndex, 0, item);
      return true;
    } catch (e) {
      console.error('Origami: ChainBuilder.reorderChain error:', e);
      return false;
    }
  }

  // Clear the current chain
  clearChain() {
    this.chain = [];
    this.chainMeta = {
      name: '',
      description: '',
      severity: 'INFO',
      createdAt: null
    };
  }

  // Return current chain state
  getChain() {
    return {
      meta: { ...this.chainMeta },
      steps: [...this.chain],
      stepCount: this.chain.length,
      availableCount: this.availableFindings.length
    };
  }

  // Calculate escalated severity based on chain contents
  // max(individual severities) + 1 level if chain has 2+ findings, capped at CRITICAL
  calculateChainSeverity() {
    if (this.chain.length === 0) return 'INFO';

    const maxValue = Math.max(
      ...this.chain.map(f => ChainBuilder.SEVERITY_VALUES[f.severity] || 0)
    );

    let escalated = maxValue;
    if (this.chain.length >= 2) {
      escalated = Math.min(maxValue + 1, ChainBuilder.SEVERITY_VALUES.CRITICAL);
    }

    return ChainBuilder.SEVERITY_LABELS[escalated] || 'INFO';
  }

  // Create a text summary of the attack chain (template-based, no AI)
  generateChainSummary() {
    if (this.chain.length === 0) {
      return 'No findings in chain.';
    }

    const steps = this.chain.map((finding, i) => {
      return 'Step ' + (i + 1) + ': [' + finding.type + '] ' + finding.message;
    });

    const severity = this.calculateChainSeverity();
    const name = this.chainMeta.name || 'Unnamed Chain';

    let summary = 'Attack Chain: ' + name + '\n';
    summary += 'Escalated Severity: ' + severity + '\n\n';
    summary += steps.join(' -> ');
    summary += ' -> Impact: ' + severity;

    if (this.chainMeta.description) {
      summary += '\n\nDescription: ' + this.chainMeta.description;
    }

    return summary;
  }

  // Export chain as JSON or markdown
  exportChain(format) {
    try {
      const severity = this.calculateChainSeverity();
      const narrative = this.generateChainSummary();

      if (format === 'json') {
        return JSON.stringify({
          name: this.chainMeta.name || 'Unnamed Chain',
          severity: severity,
          steps: this.chain.map((f, i) => ({
            step: i + 1,
            id: f.id,
            category: f.category,
            type: f.type,
            severity: f.severity,
            message: f.message,
            recommendation: f.recommendation,
            uri: f.uri
          })),
          narrative: narrative,
          exportedAt: new Date().toISOString()
        }, null, 2);
      }

      if (format === 'markdown') {
        let md = '# Attack Chain: ' + (this.chainMeta.name || 'Unnamed Chain') + '\n\n';
        md += '**Escalated Severity:** ' + severity + '\n\n';

        if (this.chainMeta.description) {
          md += '**Description:** ' + this.chainMeta.description + '\n\n';
        }

        md += '## Steps\n\n';
        this.chain.forEach((f, i) => {
          md += '### Step ' + (i + 1) + ': ' + f.type + '\n';
          md += '- **Severity:** ' + f.severity + '\n';
          md += '- **Category:** ' + f.category + '\n';
          md += '- **Finding:** ' + f.message + '\n';
          if (f.recommendation) {
            md += '- **Recommendation:** ' + f.recommendation + '\n';
          }
          if (f.uri) {
            md += '- **URI:** ' + f.uri + '\n';
          }
          md += '\n';
        });

        md += '## Chain Narrative\n\n';
        md += narrative + '\n\n';
        md += '---\n';
        md += '*Exported at: ' + new Date().toISOString() + '*\n';

        return md;
      }

      console.warn('Origami: ChainBuilder.exportChain - unsupported format:', format);
      return null;
    } catch (e) {
      console.error('Origami: ChainBuilder.exportChain error:', e);
      return null;
    }
  }

  // Suggest related findings that would strengthen the chain
  // Based on simple heuristic rules mapping vulnerability types to related weaknesses
  getSuggestedFindings() {
    try {
      if (this.chain.length === 0) return [];

      const chainIds = new Set(this.chain.map(f => f.id));
      const chainTypes = new Set();
      const chainCategories = new Set();

      this.chain.forEach(f => {
        chainTypes.add(this._normalizeType(f.type));
        chainCategories.add(f.category);
        if (f.pattern) chainTypes.add(this._normalizeType(f.pattern));
      });

      // Define relationships between finding types
      // Key: what is in the chain -> Value: what would strengthen it
      const relationships = {
        'xss': ['csp', 'content-security-policy', 'httponly', 'cookie', 'x-frame-options', 'cors'],
        'csrf': ['samesite', 'cookie', 'csrf', 'token', 'referrer-policy'],
        'sqli': ['parameterized', 'input validation', 'waf', 'database'],
        'injection': ['csp', 'content-security-policy', 'input validation', 'eval'],
        'open redirect': ['referrer-policy', 'url validation', 'location'],
        'ssrf': ['url validation', 'network', 'firewall'],
        'cookie': ['httponly', 'secure', 'samesite', 'session', 'xss'],
        'session': ['cookie', 'jwt', 'token', 'httponly', 'secure'],
        'jwt': ['algorithm', 'expiration', 'session', 'token'],
        'mixed content': ['hsts', 'strict-transport-security', 'upgrade-insecure'],
        'postmessage': ['origin', 'xss', 'iframe', 'x-frame-options'],
        'sensitive file': ['directory listing', 'information disclosure', 'backup'],
        'code injection': ['csp', 'eval', 'content-security-policy'],
        'template injection': ['xss', 'csp', 'sanitization'],
        'prototype pollution': ['xss', 'code injection', 'object'],
        'header': ['csp', 'hsts', 'x-frame-options', 'cors', 'referrer-policy'],
        'insecure random': ['session', 'token', 'csrf', 'nonce'],
        'missing subresource': ['sri', 'integrity', 'cdn'],
        'sensitive storage': ['xss', 'token', 'session', 'httponly']
      };

      const desiredKeywords = new Set();
      chainTypes.forEach(type => {
        for (const [key, related] of Object.entries(relationships)) {
          if (type.includes(key)) {
            related.forEach(r => desiredKeywords.add(r));
          }
        }
      });

      if (desiredKeywords.size === 0) return [];

      // Find available findings that match desired keywords and are not already in chain
      const suggestions = this.availableFindings.filter(f => {
        if (chainIds.has(f.id)) return false;

        const searchText = (f.type + ' ' + f.message + ' ' + f.category).toLowerCase();
        return Array.from(desiredKeywords).some(keyword => searchText.includes(keyword));
      });

      // Sort by severity (most severe first)
      suggestions.sort((a, b) => {
        return (ChainBuilder.SEVERITY_VALUES[b.severity] || 0) -
               (ChainBuilder.SEVERITY_VALUES[a.severity] || 0);
      });

      return suggestions.slice(0, 10);
    } catch (e) {
      console.error('Origami: ChainBuilder.getSuggestedFindings error:', e);
      return [];
    }
  }

  // Return a plain object for storage
  toSerializable() {
    return {
      availableFindings: this.availableFindings,
      chain: this.chain,
      chainMeta: { ...this.chainMeta }
    };
  }

  // Restore from stored data
  fromSerializable(data) {
    try {
      if (!data || typeof data !== 'object') {
        console.warn('Origami: ChainBuilder.fromSerializable called with invalid data');
        return;
      }

      this.availableFindings = Array.isArray(data.availableFindings) ? data.availableFindings : [];
      this.chain = Array.isArray(data.chain) ? data.chain : [];
      this.chainMeta = data.chainMeta || {
        name: '',
        description: '',
        severity: 'INFO',
        createdAt: null
      };

      // Recalculate severity to keep state consistent
      if (this.chain.length > 0) {
        this.chainMeta.severity = this.calculateChainSeverity();
      }
    } catch (e) {
      console.error('Origami: ChainBuilder.fromSerializable error:', e);
    }
  }

  // Normalize severity string to one of the known levels
  _normalizeSeverity(severity) {
    if (!severity) return 'INFO';
    const upper = String(severity).toUpperCase().trim();
    if (ChainBuilder.SEVERITY_VALUES.hasOwnProperty(upper)) return upper;
    return 'INFO';
  }

  // Normalize a type string for matching purposes
  _normalizeType(type) {
    if (!type) return '';
    return String(type).toLowerCase().trim();
  }
}

window.ChainBuilder = ChainBuilder;
