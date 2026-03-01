// Origami Sensitive File Scanner
// Probes for exposed sensitive files (.git, .env, backups, source maps, etc.)

class SensitiveFileScanner {
  constructor() {
    this.results = [];
    this.scannedPaths = new Set();
  }

  async scan(baseUrl) {
    this.results = [];
    this.scannedPaths.clear();

    const checks = [
      {
        paths: ['/.git/HEAD', '/.git/config'],
        name: 'Git Repository Exposure',
        severity: 'HIGH',
        validator: this.validateGitExposure.bind(this),
        recommendation: 'Block access to .git directory in web server configuration. Add rules to deny access to all dotfiles and directories.'
      },
      {
        paths: ['/.env', '/.env.local', '/.env.production', '/.env.development'],
        name: 'Environment File Exposure',
        severity: 'HIGH',
        validator: this.validateEnvFile.bind(this),
        recommendation: 'Remove .env files from the web root or configure the web server to deny access to dotfiles.'
      },
      {
        paths: ['/backup.sql', '/database.sql', '/dump.sql', '/db.sql', '/backup.zip', '/backup.tar.gz', '/site.bak'],
        name: 'Backup File Exposure',
        severity: 'HIGH',
        validator: this.validateBackupFile.bind(this),
        recommendation: 'Remove backup files from the web root. Store backups in a non-publicly-accessible location.'
      },
      {
        paths: [], // Dynamically discovered
        name: 'Source Map Exposure',
        severity: 'INFO',
        validator: this.validateSourceMap.bind(this),
        recommendation: 'Remove source maps from production or restrict access to authenticated users only.',
        dynamic: true,
        discoverer: this.discoverSourceMaps.bind(this)
      },
      {
        paths: ['/.well-known/security.txt', '/security.txt'],
        name: 'Security.txt',
        severity: 'INFO',
        validator: this.validateSecurityTxt.bind(this),
        recommendation: null
      },
      {
        paths: ['/css/', '/js/', '/images/', '/assets/', '/uploads/', '/static/'],
        name: 'Directory Listing',
        severity: 'LOW',
        validator: this.validateDirectoryListing.bind(this),
        recommendation: 'Disable directory listing in the web server configuration (e.g., Options -Indexes for Apache).'
      },
      {
        paths: ['/admin', '/administrator', '/wp-admin/', '/wp-login.php'],
        name: 'Admin Panel Exposure',
        severity: 'LOW',
        validator: this.validateAdminPanel.bind(this),
        recommendation: 'Restrict admin panel access by IP, add multi-factor authentication, or move to a non-standard path.'
      },
      {
        paths: ['/swagger.json', '/openapi.yaml', '/graphql'],
        name: 'API Documentation Exposure',
        severity: 'INFO',
        validator: this.validateAPIDocs.bind(this),
        recommendation: 'Restrict API documentation to authenticated users or internal networks only.'
      },
      {
        paths: ['/package.json', '/composer.json'],
        name: 'Config/Lockfile Exposure',
        severity: 'INFO',
        validator: this.validateConfigFile.bind(this),
        recommendation: 'Block access to package manager configuration files in the web server configuration.'
      },
      {
        paths: ['/robots.txt'],
        name: 'Robots.txt',
        severity: 'INFO',
        validator: this.validateRobotsTxt.bind(this),
        recommendation: null,
        postProcess: this.processRobotsTxt.bind(this)
      },
      {
        paths: ['/.well-known/openid-configuration'],
        name: 'OpenID Configuration',
        severity: 'INFO',
        validator: this.validateOpenIDConfig.bind(this),
        recommendation: 'Ensure OpenID configuration does not expose sensitive internal endpoints.'
      }
    ];

    for (const check of checks) {
      let paths = check.paths;
      if (check.dynamic && check.discoverer) {
        try {
          paths = await check.discoverer(baseUrl);
        } catch (e) {
          paths = [];
        }
      }
      for (const path of paths) {
        await this.checkPath(baseUrl, path, check);
      }
    }

    // Run post-processors for checks that need them (e.g., robots.txt disallow parsing)
    for (const check of checks) {
      if (check.postProcess) {
        try {
          check.postProcess();
        } catch (e) {
          // Post-processing failed, skip
        }
      }
    }

    return this.results;
  }

  // Detect soft 404 pages that return HTTP 200 but show error content
  isSoft404(text, response, requestUrl) {
    // Check if response URL differs from request (redirect-based 404)
    if (response.url && response.url !== requestUrl) {
      const responseUrl = response.url.toLowerCase();
      if (responseUrl.includes('404') || responseUrl.includes('not-found') ||
          responseUrl.includes('error') || responseUrl.includes('page-not-found')) {
        return true;
      }
    }

    // Check first 1000 chars of body for common 404 indicators
    const sample = text.substring(0, 1000).toLowerCase();
    const soft404Patterns = [
      /page\s*not\s*found/i,
      /404\s*[-–—]?\s*(not\s*found|error|page)/i,
      /not\s*found/i,
      /does\s*not\s*exist/i,
      /no\s*longer\s*available/i,
      /moved\s*permanently/i,
      /<title>[^<]*404[^<]*<\/title>/i,
      /<title>[^<]*not\s*found[^<]*<\/title>/i
    ];

    return soft404Patterns.some(p => p.test(sample));
  }

  async checkPath(baseUrl, path, check) {
    let url;
    try {
      url = new URL(path, baseUrl).href;
    } catch (e) {
      return;
    }

    // GraphQL introspection requires a query parameter
    let fetchUrl = url;
    if (path === '/graphql') {
      fetchUrl = url + '?query={__schema{types{name}}}';
    }

    if (this.scannedPaths.has(url)) return;
    this.scannedPaths.add(url);

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      const response = await fetch(fetchUrl, {
        method: 'GET',
        credentials: 'omit',
        redirect: 'follow',
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        const contentType = response.headers.get('content-type') || '';
        const text = await response.text();

        // Check for soft 404 before running validator
        if (this.isSoft404(text, response, url)) {
          return; // Skip - this is a custom error page, not the actual file
        }

        const validation = check.validator(text, contentType, path, response);
        if (validation.valid) {
          this.addFinding(check, path, url, validation, text);
        }
      }
    } catch (error) {
      // Network error, timeout, or CORS - skip silently
    }
  }

  // Validate .git/HEAD or .git/config response
  validateGitExposure(text, contentType, path) {
    // Reject HTML responses (soft 404 pages)
    if (contentType.includes('text/html')) {
      return { valid: false };
    }

    if (path.endsWith('/HEAD')) {
      const trimmed = text.trim();
      // Real .git/HEAD is either "ref: refs/heads/<branch>" or a 40-char hex SHA
      const isValid = /^ref: refs\/heads\/\S+$/.test(trimmed) ||
                     /^[0-9a-f]{40}$/.test(trimmed);
      return {
        valid: isValid,
        details: isValid ? `Git HEAD: ${trimmed}` : null
      };
    }

    if (path.endsWith('/config')) {
      const hasGitConfig = text.includes('[core]') ||
                          text.includes('[remote "origin"]') ||
                          text.includes('[branch');
      return {
        valid: hasGitConfig,
        details: hasGitConfig ? 'Git config file with repository configuration exposed' : null
      };
    }

    return { valid: false };
  }

  // Validate .env file response
  validateEnvFile(text, contentType) {
    // Reject HTML responses
    if (contentType.includes('text/html')) return { valid: false };
    if (text.includes('<html') || text.includes('<!DOCTYPE')) return { valid: false };
    // Look for KEY=VALUE pattern (environment variables)
    const envPattern = /^[A-Z_]+[A-Z0-9_]*=.+$/m;
    const isValid = envPattern.test(text);
    return {
      valid: isValid,
      details: isValid ? 'Environment file with configuration variables exposed' : null
    };
  }

  // Validate backup file response
  validateBackupFile(text, contentType, path) {
    // Reject HTML responses
    if (contentType.includes('text/html')) return { valid: false };
    // SQL files
    if (path.endsWith('.sql')) {
      const isSql = /^(--|CREATE|INSERT|DROP|ALTER|SET)\s/mi.test(text);
      return {
        valid: isSql,
        details: isSql ? 'SQL dump file accessible' : null
      };
    }
    // Binary/archive files
    if (path.endsWith('.zip') || path.endsWith('.tar.gz') || path.endsWith('.bak')) {
      const isBinary = contentType.includes('application/') ||
                       contentType.includes('octet-stream');
      return {
        valid: isBinary,
        details: isBinary ? 'Backup archive file accessible' : null
      };
    }
    return { valid: false };
  }

  // Discover source map URLs from loaded scripts
  async discoverSourceMaps(baseUrl) {
    const maps = [];
    try {
      const origin = new URL(baseUrl).origin;
      const scripts = document.querySelectorAll('script[src]');
      for (const script of scripts) {
        if (script.src.startsWith(origin)) {
          maps.push(script.src + '.map');
        }
      }
    } catch (e) {
      // Ignore errors
    }
    // Limit to first 10 to avoid excessive requests
    return maps.slice(0, 10);
  }

  // Validate source map response
  validateSourceMap(text, contentType) {
    if (contentType.includes('text/html')) return { valid: false };
    try {
      const json = JSON.parse(text);
      const isMap = json.version === 3 && json.sources && json.mappings;
      return {
        valid: isMap,
        details: isMap ? `Source map with ${json.sources.length} source file(s) exposed` : null
      };
    } catch {
      return { valid: false };
    }
  }

  // Validate security.txt response
  validateSecurityTxt(text, contentType) {
    if (contentType.includes('text/html') && !text.includes('Contact:')) {
      return { valid: false };
    }
    const hasContact = text.includes('Contact:');
    return {
      valid: hasContact,
      details: hasContact ? 'security.txt found with contact information' : null,
      isPositive: true // This is informational, not a vulnerability
    };
  }

  // Validate directory listing response
  validateDirectoryListing(text, contentType) {
    if (!contentType.includes('text/html')) return { valid: false };
    const patterns = [
      /Index of \//i,
      /\[To Parent Directory\]/i,
      /<title>Directory listing/i,
      /class="listing"/i,
      /Directory Listing for/i,
      /<title>Index of/i
    ];
    const isListing = patterns.some(p => p.test(text));
    return {
      valid: isListing,
      details: isListing ? 'Directory listing is enabled - file contents visible' : null
    };
  }

  // Validate admin panel response
  validateAdminPanel(text, contentType, path) {
    if (!contentType.includes('text/html')) return { valid: false };
    const hasLoginForm = /<form[^>]*>[\s\S]*?(?:type\s*=\s*["']password["']|name\s*=\s*["'](?:pass|password|pwd)["'])/i.test(text);
    const hasAdminIndicators = /(?:login|sign\s*in|admin|dashboard|control\s*panel)/i.test(text);
    const isValid = hasLoginForm;
    return {
      valid: isValid,
      details: isValid ? `Admin panel accessible at ${path}` : null
    };
  }

  // Validate API documentation response
  validateAPIDocs(text, contentType, path) {
    if (contentType.includes('text/html') && !path.includes('graphql')) return { valid: false };

    if (path.endsWith('swagger.json')) {
      try {
        const json = JSON.parse(text);
        const isValid = json.swagger || json.openapi;
        return {
          valid: !!isValid,
          details: isValid ? `Swagger/OpenAPI spec exposed (version: ${json.swagger || json.openapi})` : null
        };
      } catch {
        return { valid: false };
      }
    }

    if (path.endsWith('openapi.yaml')) {
      const isValid = /^(?:openapi|swagger)\s*:/m.test(text);
      return {
        valid: isValid,
        details: isValid ? 'OpenAPI YAML specification exposed' : null
      };
    }

    if (path.endsWith('graphql')) {
      try {
        const json = JSON.parse(text);
        const isValid = json.data && json.data.__schema;
        return {
          valid: !!isValid,
          details: isValid ? 'GraphQL introspection is enabled' : null
        };
      } catch {
        return { valid: false };
      }
    }

    return { valid: false };
  }

  // Validate config/lockfile response
  validateConfigFile(text, contentType, path) {
    if (contentType.includes('text/html')) return { valid: false };
    try {
      const json = JSON.parse(text);
      if (path.endsWith('package.json')) {
        const isValid = json.name && json.version;
        return {
          valid: !!isValid,
          details: isValid ? `package.json exposed (${json.name}@${json.version})` : null
        };
      }
      if (path.endsWith('composer.json')) {
        const isValid = json.require;
        return {
          valid: !!isValid,
          details: isValid ? 'composer.json with dependencies exposed' : null
        };
      }
    } catch {
      return { valid: false };
    }
    return { valid: false };
  }

  // Validate robots.txt response
  validateRobotsTxt(text, contentType) {
    if (contentType.includes('text/html')) return { valid: false };
    const isValid = /User-agent:/i.test(text) || /Disallow:/i.test(text);
    return {
      valid: isValid,
      details: isValid ? 'robots.txt found' : null,
      isPositive: true,
      _robotsText: isValid ? text : null
    };
  }

  // Post-process robots.txt to extract disallowed paths
  processRobotsTxt() {
    const robotsFinding = this.results.find(r => r.check === 'Robots.txt' && r.details?._robotsText);
    if (!robotsFinding) return;

    const text = robotsFinding.details._robotsText;
    delete robotsFinding.details._robotsText;

    const disallowPaths = [];
    const lines = text.split('\n');
    for (const line of lines) {
      const match = line.match(/^Disallow:\s*(.+)/i);
      if (match) {
        const path = match[1].trim();
        if (path && path !== '/') {
          disallowPaths.push(path);
        }
      }
    }

    if (disallowPaths.length > 0) {
      robotsFinding.details.disallowedPaths = disallowPaths;
      this.results.push({
        check: 'Robots.txt Hidden Paths',
        status: 'FOUND',
        severity: 'INFO',
        message: `robots.txt contains ${disallowPaths.length} disallowed path(s): ${disallowPaths.slice(0, 10).join(', ')}${disallowPaths.length > 10 ? '...' : ''}`,
        recommendation: 'Review disallowed paths for sensitive content. Consider if these paths should be discoverable.',
        details: {
          paths: disallowPaths
        },
        timestamp: new Date().toISOString()
      });
    }
  }

  // Validate OpenID configuration response
  validateOpenIDConfig(text, contentType) {
    if (contentType.includes('text/html')) return { valid: false };
    try {
      const json = JSON.parse(text);
      const isValid = json.issuer;
      return {
        valid: !!isValid,
        details: isValid ? `OpenID configuration exposed (issuer: ${json.issuer})` : null
      };
    } catch {
      return { valid: false };
    }
  }

  addFinding(check, path, url, validation, responseText) {
    this.results.push({
      check: check.name,
      status: validation.isPositive ? 'FOUND' : 'EXPOSED',
      severity: validation.isPositive ? 'INFO' : check.severity,
      message: `${check.name}: ${path} is accessible`,
      recommendation: check.recommendation,
      details: {
        path: path,
        url: url,
        validation: validation.details,
        responsePreview: responseText.substring(0, 500)
      },
      timestamp: new Date().toISOString(),
      uri: url
    });
  }
}

// Export for use in extension
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SensitiveFileScanner;
}
