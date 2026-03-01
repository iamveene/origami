// Origami Plugin Validator
// Validates plugin.json manifest schema before registration

class PluginValidator {
  constructor() {
    this.requiredFields = ['id', 'name', 'version', 'analyzerClass', 'resultCategory'];
    this.optionalFields = ['description', 'author', 'enabled', 'permissions', 'minOrigamiVersion'];
    this.validCategories = [
      'custom', 'secrets', 'headers', 'cookies', 'vulnerabilities',
      'technologies', 'network', 'privacy', 'compliance', 'recon'
    ];
    this.versionRegex = /^\d+\.\d+\.\d+$/;
    this.idRegex = /^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/;
  }

  validate(manifest) {
    const errors = [];

    if (!manifest || typeof manifest !== 'object') {
      return { valid: false, errors: ['Manifest must be a non-null object'] };
    }

    // Check required fields
    for (const field of this.requiredFields) {
      if (!manifest[field]) {
        errors.push(`Missing required field: ${field}`);
      }
    }

    if (errors.length > 0) {
      return { valid: false, errors };
    }

    // Validate id format (regex enforces 3-64 char length via quantifier)
    if (typeof manifest.id !== 'string' || !this.idRegex.test(manifest.id)) {
      errors.push('Plugin id must be 3-64 lowercase alphanumeric characters with hyphens (e.g., "my-plugin")');
    }

    // Validate name
    if (typeof manifest.name !== 'string' || manifest.name.length < 1 || manifest.name.length > 128) {
      errors.push('Plugin name must be a string between 1 and 128 characters');
    }

    // Validate version format
    if (typeof manifest.version !== 'string' || !this.versionRegex.test(manifest.version)) {
      errors.push('Version must follow semver format (e.g., "1.0.0")');
    }

    // Validate analyzerClass
    if (typeof manifest.analyzerClass !== 'string' || manifest.analyzerClass.length < 1) {
      errors.push('analyzerClass must be a non-empty string');
    } else if (!/^[A-Z][A-Za-z0-9]*$/.test(manifest.analyzerClass)) {
      errors.push('analyzerClass must be a valid class name starting with uppercase (e.g., "MyAnalyzer")');
    }

    // Validate resultCategory
    if (!this.validCategories.includes(manifest.resultCategory)) {
      errors.push(`resultCategory must be one of: ${this.validCategories.join(', ')}`);
    }

    // Validate optional fields if present
    if (manifest.description !== undefined && typeof manifest.description !== 'string') {
      errors.push('description must be a string');
    }

    if (manifest.author !== undefined && typeof manifest.author !== 'string') {
      errors.push('author must be a string');
    }

    if (manifest.enabled !== undefined && typeof manifest.enabled !== 'boolean') {
      errors.push('enabled must be a boolean');
    }

    return { valid: errors.length === 0, errors };
  }

  validateCode(code) {
    const errors = [];

    if (!code || typeof code !== 'string') {
      return { valid: false, errors: ['Plugin code must be a non-empty string'] };
    }

    if (code.length > 512 * 1024) {
      errors.push('Plugin code exceeds maximum size of 512KB');
    }

    // Block dangerous APIs that plugins should not access
    // These are also shadowed at runtime in plugin-loader.js for defense-in-depth
    const blockedPatterns = [
      { pattern: /\bfetch\s*\(/, name: 'fetch()' },
      { pattern: /\bXMLHttpRequest\b/, name: 'XMLHttpRequest' },
      { pattern: /\bchrome\s*\.\s*runtime\b/, name: 'chrome.runtime' },
      { pattern: /\bchrome\s*\.\s*storage\b/, name: 'chrome.storage' },
      { pattern: /\bchrome\s*\.\s*tabs\b/, name: 'chrome.tabs' },
      { pattern: /\bchrome\s*\.\s*cookies\b/, name: 'chrome.cookies' },
      { pattern: /\bchrome\s*\.\s*webRequest\b/, name: 'chrome.webRequest' },
      { pattern: /\beval\s*\(/, name: 'eval()' },
      { pattern: /\bFunction\s*\(/, name: 'Function()' },
      { pattern: /\bimportScripts\s*\(/, name: 'importScripts()' },
      { pattern: /\bWebSocket\s*\(/, name: 'WebSocket' },
      { pattern: /\bnavigator\s*\.\s*sendBeacon\b/, name: 'navigator.sendBeacon' },
      { pattern: /\blocation\s*\.\s*href\s*=/, name: 'location.href assignment' },
      { pattern: /\bwindow\s*\.\s*open\s*\(/, name: 'window.open()' },
      { pattern: /\bglobalThis\b/, name: 'globalThis' },
      { pattern: /\bself\s*\.\s*(?:fetch|XMLHttpRequest|WebSocket|eval|Function|importScripts|chrome)\b/, name: 'self.* bypass' }
    ];

    for (const blocked of blockedPatterns) {
      if (blocked.pattern.test(code)) {
        errors.push(`Plugin code contains blocked API: ${blocked.name}. Plugins cannot make network requests or access extension APIs.`);
      }
    }

    // Basic syntax check via Function constructor (does not execute)
    try {
      new Function(code);
    } catch (e) {
      errors.push(`Syntax error in plugin code: ${e.message}`);
    }

    return { valid: errors.length === 0, errors };
  }

  validatePlugin(pluginData) {
    if (!pluginData || !pluginData.manifest) {
      return { valid: false, errors: ['Plugin data must include a manifest object'] };
    }

    const manifestResult = this.validate(pluginData.manifest);
    if (!manifestResult.valid) {
      return manifestResult;
    }

    if (pluginData.code !== undefined) {
      const codeResult = this.validateCode(pluginData.code);
      if (!codeResult.valid) {
        return codeResult;
      }
    }

    return { valid: true, errors: [] };
  }
}

// Make available globally for content scripts
if (typeof window !== 'undefined') {
  window.PluginValidator = PluginValidator;
}
