// Origami Vulnerability Scanner
// Detects common web vulnerabilities in JavaScript code and DOM

class VulnerabilityScanner {
  constructor() {
    this.results = [];
    this.scannedScripts = new Set();
  }

  // Check if script is a known library or minified code
  isKnownLibrary(src, code) {
    // CDN detection
    const cdnPatterns = [
      /jsdelivr\.net/, /unpkg\.com/, /cdnjs\.cloudflare\.com/,
      /googleapis\.com/, /gstatic\.com/, /jquery\.com/,
      /cloudflare\.com/, /bootstrapcdn\.com/, /fontawesome\.com/,
      /code\.jquery\.com/, /ajax\.googleapis\.com/, /cdn\.jsdelivr\.net/,
      /unpkg\.com/, /esm\.sh/, /skypack\.dev/
    ];

    if (cdnPatterns.some(pattern => pattern.test(src))) {
      return true;
    }

    // Library path detection
    const libraryPaths = [
      '/node_modules/', '/vendor/', '/lib/', '/libs/',
      '/dist/', '/bundle/', '/vendor-', '.min.js',
      '/webpack/', '/rollup/', '/parcel/'
    ];

    if (libraryPaths.some(path => src.includes(path))) {
      return true;
    }

    // Library banner/copyright signatures (definitive indicators of vendor code)
    const librarySignatures = [
      '/*! jQuery', '/*! React', '/*! Vue', '/*! Angular',
      'Copyright (c) Facebook', 'Copyright jQuery Foundation',
      'Copyright (c) 2009-', // jQuery copyright pattern
      '@license', 'Licensed under', 'MIT License',
      '* lodash ', '* jQuery ', '* React ', '* Vue.js '
    ];

    if (librarySignatures.some(sig => code.includes(sig))) {
      return true;
    }

    // Minified detection (average line length > 500 chars)
    const lines = code.split('\n');
    const avgLineLength = code.length / lines.length;
    if (avgLineLength > 500) {
      return true;
    }

    return false;
  }

  // Main scan function
  async scan(document, url) {
    this.results = [];
    this.scannedScripts.clear();

    // Scan inline scripts
    await this.scanInlineScripts(document);

    // Scan external scripts
    await this.scanExternalScripts(document);

    // Scan DOM for vulnerabilities
    this.scanDOM(document);

    // Scan forms
    this.scanForms(document);

    // Scan for prototype pollution
    this.checkPrototypePollution();

    // Check for mixed content (HTTP resources on HTTPS pages)
    this.detectMixedContent(document);

    // Check for missing Subresource Integrity (SRI)
    this.checkSRI(document);

    // Check for sensitive data in web storage
    this.detectSensitiveStorage();

    return this.results;
  }

  // Scan inline scripts
  async scanInlineScripts(document) {
    const scripts = document.querySelectorAll('script:not([src])');

    // Cloudflare challenge/infrastructure patterns to skip
    const cfChallengePattern = /window\.__CF\$cv\$params|__cf_chl_|CloudflareChallenges|cf-challenge|__cf_email__/;

    scripts.forEach((script, index) => {
      if (script.textContent) {
        // Skip Cloudflare challenge/bot verification inline scripts
        if (cfChallengePattern.test(script.textContent)) {
          return;
        }
        // Skip inline scripts that are clearly minified (single line > 2000 chars with no comments)
        const lines = script.textContent.split('\n');
        if (lines.length === 1 && script.textContent.length > 2000 && !script.textContent.includes('//')) {
          return;
        }
        this.analyzeJavaScriptCode(
          script.textContent,
          `Inline script #${index + 1}`,
          window.location.href
        );
      }
    });
  }

  // Scan external scripts
  async scanExternalScripts(document) {
    // Load settings from storage
    const settings = await new Promise((resolve) => {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.sync) {
        chrome.storage.sync.get(['settings'], (data) => {
          resolve(data.settings || {});
        });
      } else {
        resolve({});
      }
    });

    const vulnScan = settings.vuln_scanning || { scan_libraries: false, scan_minified: false };

    const scripts = document.querySelectorAll('script[src]');

    for (const script of scripts) {
      const src = script.src;

      // Only scan same-origin scripts
      if (src.startsWith(window.location.origin) && !this.scannedScripts.has(src)) {
        this.scannedScripts.add(src);

        try {
          const response = await fetch(src);
          const code = await response.text();

          // Check if library and user wants to skip
          const isLibrary = this.isKnownLibrary(src, code);
          if (isLibrary && !vulnScan.scan_libraries) {
            console.log('Origami: Skipping library (user setting):', src);
            continue;
          }

          // Check if minified and user wants to skip
          const lines = code.split('\n');
          const isMinified = (code.length / lines.length) > 500;
          if (isMinified && !vulnScan.scan_minified) {
            console.log('Origami: Skipping minified file (user setting):', src);
            continue;
          }

          this.analyzeJavaScriptCode(code, src, src);
        } catch (error) {
          // Can't fetch, skip
        }
      }
    }
  }

  // Analyze JavaScript code for vulnerabilities
  analyzeJavaScriptCode(code, source, url) {
    // Detect Closure Compiler / webpack bundles
    const isClosureCompiler = /\bgoog\.\w/.test(code) || /_closure_exports_/.test(code);
    const isWebpackBundle = /webpackChunk|__webpack_require__|webpack_modules/.test(code);
    const isBundledCode = isClosureCompiler || isWebpackBundle;

    // XSS vulnerabilities
    this.detectXSS(code, source, url, isBundledCode);

    // SQL Injection patterns
    this.detectSQLi(code, source, url);

    // Insecure randomness: handled by crypto-auditor.js (has better context awareness)

    // eval() usage
    this.detectEval(code, source, url, isBundledCode);

    // Insecure deserialization (skip bundled code -- too many FPs from minified variable names)
    if (!isBundledCode) {
      this.detectInsecureDeserialization(code, source, url);
    }

    // Path traversal
    this.detectPathTraversal(code, source, url);

    // Open redirects
    this.detectOpenRedirects(code, source, url);

    // SSRF potential
    this.detectSSRF(code, source, url);

    // postMessage without origin validation
    this.detectPostMessageVulns(code, source, url);

    // Template injection (Angular, Vue, React)
    this.detectTemplateInjection(code, source, url);
  }

  // Detect XSS vulnerabilities
  detectXSS(code, source, url, isBundledCode) {
    // Cap XSS findings to INFO for minified/vendor code
    const lines = code.split('\n');
    const avgLineLength = code.length / lines.length;
    const minifiedThreshold = (typeof ORIGAMI_MINIFIED_LINE_THRESHOLD !== 'undefined') ? ORIGAMI_MINIFIED_LINE_THRESHOLD : 500;
    const isMinifiedCode = avgLineLength > minifiedThreshold || this.isKnownLibrary(source, code);
    if (isMinifiedCode) isBundledCode = true;
    const xssPatterns = [
      {
        pattern: /\.innerHTML\s*=\s*([^;]+)/g,
        name: 'innerHTML assignment',
        severity: 'MEDIUM',
        message: 'Direct innerHTML assignment can lead to XSS'
      },
      {
        pattern: /\.outerHTML\s*=\s*([^;]+)/g,
        name: 'outerHTML assignment',
        severity: 'MEDIUM',
        message: 'Direct outerHTML assignment can lead to XSS'
      },
      {
        pattern: /document\.write\s*\(/g,
        name: 'document.write',
        severity: 'MEDIUM',
        message: 'document.write() with user input can lead to XSS'
      },
      {
        pattern: /document\.writeln\s*\(/g,
        name: 'document.writeln',
        severity: 'MEDIUM',
        message: 'document.writeln() with user input can lead to XSS'
      },
      {
        pattern: /\.insertAdjacentHTML\s*\(/g,
        name: 'insertAdjacentHTML',
        severity: 'LOW',
        message: 'insertAdjacentHTML with untrusted input can lead to XSS'
      },
      {
        pattern: /location\.(hash|search)\s*=\s*([^;]+)/g,
        name: 'location manipulation',
        severity: 'MEDIUM',
        message: 'Setting location.hash/search with user input can lead to DOM-based XSS'
      },
      {
        pattern: /\$\([^)]*\)\.html\s*\(/g,
        name: 'jQuery .html()',
        severity: 'MEDIUM',
        message: 'jQuery .html() with untrusted input can lead to XSS'
      },
      {
        pattern: /\$\([^)]*\)\.append\s*\(/g,
        name: 'jQuery .append()',
        severity: 'INFO',
        message: 'jQuery .append() with untrusted HTML strings can lead to XSS'
      }
    ];

    xssPatterns.forEach(({ pattern, name, severity, message }) => {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        // Skip safe innerHTML/outerHTML assignments (clearing, null, sanitized)
        if (name === 'innerHTML assignment' || name === 'outerHTML assignment') {
          const assignedValue = match[1] ? match[1].trim() : '';
          const safeAssignments = /^['"`]\s*['"`]$|^''$|^""$|^``$|^null$|^undefined$|^0$/;
          if (safeAssignments.test(assignedValue)) continue;
          const sanitizerPatterns = /DOMPurify\.sanitize|sanitize\(|sanitizeHtml\(|escapeHtml\(|escapeHTML\(|htmlEncode\(|encodeHTML\(|filterXSS\(|xssFilter\(|cleanHtml\(|purify\(|\.textContent|createTextNode/;
          if (sanitizerPatterns.test(assignedValue)) continue;
          // Skip Cloudflare infrastructure patterns
          const cloudflarePattern = /__CF\$cv\$params|__cf_chl_|CloudflareChallenges|cf-challenge/;
          if (cloudflarePattern.test(assignedValue)) continue;
          // Skip hardcoded string literals (no user input involved)
          // e.g., el.innerHTML = '<h1>Welcome</h1>' or innerHTML = `<div>static</div>`
          if (/^['"`]/.test(assignedValue) && !this.containsUserInput(assignedValue)) continue;
        }

        // For location manipulation, check the ASSIGNED VALUE (RHS) for user input,
        // not the whole context (which inherently contains location.href on the LHS)
        if (name === 'location manipulation') {
          const assignedValue = match[2] ? match[2].trim() : '';
          // Skip hardcoded string URLs (not user-controlled)
          if (/^["'`]https?:\/\//.test(assignedValue)) continue;
          // Skip hardcoded relative URLs
          if (/^["'`]\//.test(assignedValue)) continue;
          // Only flag if the assigned value involves user input
          if (!this.containsUserInput(assignedValue)) continue;
        }

        // Check if it's using user-controlled input
        const context = this.getCodeContext(code, match.index, 100);
        const hasUserInput = this.containsUserInput(context);

        if (!hasUserInput) continue;

        let effectiveSeverity = severity;
        if (isBundledCode) {
          effectiveSeverity = 'INFO';
        }

        if (hasUserInput) {
          const extendedContext = this.getExtendedCodeContext(code, match.index, 5);

          this.addFinding(
            'XSS Vulnerability',
            'POTENTIAL',
            effectiveSeverity,
            `${name}: ${message}`,
            'Use textContent, createTextNode(), or a safe templating engine. Sanitize all user input.',
            {
              type: 'XSS',
              pattern: name,
              source,
              context: extendedContext.context,
              lineNumber: extendedContext.matchLine,
              matchedText: match[0],
              uri: url
            }
          );
        }
      }
    });
  }

  // Detect SQL Injection patterns
  detectSQLi(code, source, url) {
    // ENHANCEMENT 1: Detect minified files
    const lines = code.split('\n');
    const avgLineLength = code.length / lines.length;
    const minifiedThreshold = (typeof ORIGAMI_MINIFIED_LINE_THRESHOLD !== 'undefined') ? ORIGAMI_MINIFIED_LINE_THRESHOLD : 500;
    const isMinified = avgLineLength > minifiedThreshold;

    if (isMinified) {
      console.log('Origami: Skipping SQLi scan on minified file:', source);
      return; // Skip minified files entirely
    }

    // ENHANCEMENT 2: Enhanced patterns with SQL context requirements
    const sqliPatterns = [
      {
        pattern: /(query|sql|database|execute|prepare)\s*.*\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.*\+.*["']/gi,
        name: 'SQL query concatenation with context',
        severity: 'MEDIUM',
        requiresContext: ['query', 'sql', 'database', 'execute', 'connection', 'db.', 'prepare']
      },
      {
        pattern: /["'`]\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b[^"'`]*["'`]\s*\+/gi,
        name: 'SQL string concatenation',
        severity: 'MEDIUM',
        requiresContext: ['query', 'sql', 'database', 'execute', 'connection', 'db.', 'prepare']
      },
      {
        pattern: /query\s*=\s*["'`].*\$\{[^}]+\}.*["'`]/g,
        name: 'SQL template literal injection',
        severity: 'MEDIUM',
        requiresContext: ['query', 'sql', 'database', 'execute', 'select', 'insert', 'update', 'delete']
      },
      {
        pattern: /(execute|query|run)\s*\(\s*["'`].*(SELECT|INSERT|UPDATE|DELETE).*\+/gi,
        name: 'SQL execution with concatenation',
        severity: 'MEDIUM',
        requiresContext: ['execute', 'query', 'connection', 'db', 'database']
      }
    ];

    sqliPatterns.forEach(({ pattern, name, severity, requiresContext }) => {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        const extendedContext = this.getExtendedCodeContext(code, match.index, 10);
        const contextText = extendedContext.context.toLowerCase();

        // ENHANCEMENT 3: Validate context has SQL-related keywords
        const hasValidContext = requiresContext.some(keyword =>
          contextText.includes(keyword.toLowerCase())
        );

        if (!hasValidContext) {
          console.log('Origami: Skipping SQLi false positive (no SQL context):', match[0].substring(0, 50));
          continue; // Skip if no SQL-related context
        }

        // Skip matches inside comment blocks, license text, or CSS selectors
        const matchLine = extendedContext.context;
        if (/^\s*(\/\/|\/\*|\*|#|;|--|\/\*!|license|copyright)/im.test(matchLine)) continue;
        if (/\{[^}]*:[^}]*\}/.test(match[0])) continue; // CSS rule-like content

        this.addFinding(
          'SQL Injection',
          'POTENTIAL',
          severity,
          `${name} detected - SQL queries should use parameterized statements`,
          'Use prepared statements or parameterized queries. Never concatenate user input into SQL.',
          {
            type: 'SQLi',
            pattern: name,
            source,
            context: extendedContext.context,
            lineNumber: extendedContext.matchLine,
            matchedText: match[0],
            uri: url
          }
        );
      }
    });
  }

  // Detect insecure randomness
  detectInsecureRandom(code, source, url) {
    const randomPattern = /Math\.random\(\)/g;
    let match;
    
    while ((match = randomPattern.exec(code)) !== null) {
      const context = this.getCodeContext(code, match.index, 100);
      
      // Check if it's being used for security purposes
      const securityKeywords = ['token', 'key', 'secret', 'password', 'session', 'csrf', 'nonce', 'salt'];
      const isSecurityRelated = securityKeywords.some(keyword => 
        context.toLowerCase().includes(keyword)
      );
      
      if (isSecurityRelated) {
        this.addFinding(
          'Insecure Randomness',
          'VULNERABLE',
          'MEDIUM',
          'Math.random() is not cryptographically secure',
          'Use crypto.getRandomValues() or crypto.randomUUID() for security-sensitive operations.',
          {
            type: 'Insecure Random',
            source,
            context: context.trim()
          }
        );
      }
    }
  }

  // Detect eval() usage
  detectEval(code, source, url, isBundledCode) {
    // Suppress eval() findings entirely for minified or vendor code -- too noisy, not actionable
    const lines = code.split('\n');
    const avgLineLength = code.length / lines.length;
    const minifiedThreshold = (typeof ORIGAMI_MINIFIED_LINE_THRESHOLD !== 'undefined') ? ORIGAMI_MINIFIED_LINE_THRESHOLD : 500;
    const isMinified = avgLineLength > minifiedThreshold;
    const isVendorCode = this.isKnownLibrary(source, code);

    if (isMinified || isVendorCode || isBundledCode) {
      return;
    }

    const evalPatterns = [
      { pattern: /\beval\s*\(/g, name: 'eval()' },
      { pattern: /new\s+Function\s*\(/g, name: 'new Function()' },
      { pattern: /setTimeout\s*\(\s*["'`]/g, name: 'setTimeout with string' },
      { pattern: /setInterval\s*\(\s*["'`]/g, name: 'setInterval with string' },
      { pattern: /window\s*\[\s*['"]eval['"]\s*\]/g, name: 'window["eval"]' },
      { pattern: /globalThis\s*\.\s*eval\s*\(/g, name: 'globalThis.eval()' },
      { pattern: /\(0\s*,\s*eval\)\s*\(/g, name: 'indirect eval (0, eval)()' }
    ];

    // Bundler polyfills for globalThis detection -- not real code injection
    const polyfillPatterns = [
      /new\s+Function\s*\(\s*["']return\s+this["']\s*\)/,
      /\(0\s*,\s*eval\)\s*\(\s*["']this["']\s*\)/,
      /Function\s*\(\s*["']return\s+this["']\s*\)\s*\(\)/
    ];

    evalPatterns.forEach(({ pattern, name }) => {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        const context = this.getCodeContext(code, match.index, 100);

        // Skip bundler polyfills (globalThis detection patterns)
        if (polyfillPatterns.some(p => p.test(context))) continue;

        this.addFinding(
          'Code Injection',
          'DANGEROUS',
          'MEDIUM',
          `${name} detected - can execute arbitrary code`,
          'Avoid using eval() or Function constructor. Use safer alternatives like JSON.parse() for data.',
          {
            type: 'Code Injection',
            pattern: name,
            source,
            context: context.trim()
          }
        );
      }
    });
  }

  // Detect insecure deserialization
  detectInsecureDeserialization(code, source, url) {
    const pattern = /JSON\.parse\s*\(\s*([^)]+)\)/g;
    let match;

    const untrustedSources = [
      'location.hash',
      'postMessage', 'window.name', 'document.referrer'
    ];

    while ((match = pattern.exec(code)) !== null) {
      const parseArg = match[1] || '';

      // Only flag if the untrusted source is in the actual JSON.parse argument,
      // not just somewhere in the surrounding context (reduces FPs on minified code)
      const detectedSources = untrustedSources.filter(src => parseArg.includes(src));
      if (detectedSources.length === 0) continue;

      // Check surrounding context for validation patterns (try/catch, schema, validate, sanitize)
      const context = this.getCodeContext(code, match.index, 200);
      if (/(?:try\s*\{|validate|sanitize|schema|safeParse|zod|yup|joi|ajv)\b/i.test(context)) continue;

      const sourceDescription = detectedSources.join(', ');
      const extendedContext = this.getExtendedCodeContext(code, match.index, 5);

      this.addFinding(
        'Insecure Deserialization',
        'POTENTIAL',
        'LOW',
        `JSON.parse() on data from ${sourceDescription} without validation`,
        'Validate and sanitize data before parsing. Use a schema validator.',
        {
          type: 'Insecure Deserialization',
          source,
          context: extendedContext.context,
          lineNumber: extendedContext.matchLine,
          matchedText: match[0],
          uri: url
        }
      );
    }
  }

  // Detect path traversal
  detectPathTraversal(code, source, url) {
    const pattern = /['"]\.\.[\/\\]/g;
    let match;

    while ((match = pattern.exec(code)) !== null) {
      const context = this.getCodeContext(code, match.index, 100);

      // Skip JS module imports/requires (e.g., import x from '../utils', require('../lib'))
      if (/(?:import\s|from\s|require\s*\()/.test(context)) continue;
      // Skip sourceMappingURL references
      if (/sourceMappingURL/.test(context)) continue;

      this.addFinding(
        'Path Traversal',
        'POTENTIAL',
        'INFO',
        'Path traversal sequence (..) detected',
        'Validate and sanitize file paths. Use path normalization and whitelist allowed directories.',
        {
          type: 'Path Traversal',
          source,
          context: context.trim()
        }
      );
    }
  }

  // Detect open redirects
  detectOpenRedirects(code, source, url) {
    const patterns = [
      /window\.location\s*=\s*([^;]+)/g,
      /window\.location\.href\s*=\s*([^;]+)/g,
      /location\.replace\s*\(([^)]+)\)/g,
      /location\.assign\s*\(([^)]+)\)/g
    ];

    patterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        const assignedValue = match[1] ? match[1].trim() : '';

        // Skip hardcoded URL redirects (not user-controlled)
        if (/^["'`]https?:\/\//.test(assignedValue)) continue;
        // Skip hardcoded relative URLs
        if (/^["'`]\//.test(assignedValue)) continue;

        // Check the assigned value for user input first
        let hasUserInput = this.containsUserInput(assignedValue);

        // If RHS is a variable, check the broader surrounding context for data flow
        // e.g., var url = params.get('redirect'); window.location.href = url;
        if (!hasUserInput && /^[a-zA-Z_$][\w$]*$/.test(assignedValue)) {
          const extendedContext = this.getExtendedCodeContext(code, match.index, 10);
          const ctxText = extendedContext.context;
          // Look for the variable being assigned from user input in surrounding code
          const varAssignPattern = new RegExp(
            assignedValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') +
            '\\s*=\\s*([^;]+)',
            'g'
          );
          let varMatch;
          while ((varMatch = varAssignPattern.exec(ctxText)) !== null) {
            if (this.containsUserInput(varMatch[1])) {
              hasUserInput = true;
              break;
            }
          }
          // Also check for multi-hop data flow: if the broader context contains
          // user input sources (URLSearchParams, location.search, etc.) flowing
          // through intermediate variables into the redirect target
          if (!hasUserInput && this.containsUserInput(ctxText)) {
            // Verify the user input source is connected to the redirect variable
            // by checking the variable appears in the same context as the source
            const varUsed = new RegExp('\\b' + assignedValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b').test(ctxText);
            if (varUsed) {
              hasUserInput = true;
            }
          }
        }

        if (hasUserInput) {
          const context = this.getCodeContext(code, match.index, 100);
          this.addFinding(
            'Open Redirect',
            'POTENTIAL',
            'MEDIUM',
            'Redirect based on user input detected',
            'Validate redirect URLs against a whitelist. Never redirect to arbitrary user-supplied URLs.',
            {
              type: 'Open Redirect',
              source,
              context: context.trim()
            }
          );
        }
      }
    });
  }

  // Detect SSRF potential
  detectSSRF(code, source, url) {
    const patterns = [
      /fetch\s*\(([^)]+)\)/g,
      /XMLHttpRequest.*open\s*\(/g,
      /\$\.ajax\s*\(/g,
      /axios\.(get|post|put|delete)\s*\(/g
    ];

    patterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        const context = this.getCodeContext(code, match.index, 150);
        
        if (this.containsUserInput(context)) {
          this.addFinding(
            'SSRF Potential',
            'POTENTIAL',
            'INFO',
            'HTTP request with user-controlled URL detected',
            'Validate and whitelist URLs. Never make requests to arbitrary user-supplied URLs.',
            {
              type: 'SSRF',
              source,
              context: context.trim()
            }
          );
        }
      }
    });
  }

  // Scan DOM for vulnerabilities
  scanDOM(document) {
    // Check for inline event handlers
    const elementsWithHandlers = document.querySelectorAll('[onclick], [onerror], [onload], [onmouseover]');
    
    if (elementsWithHandlers.length > 0) {
      this.addFinding(
        'Inline Event Handlers',
        'FOUND',
        'INFO',
        `Found ${elementsWithHandlers.length} element(s) with inline event handlers`,
        'Use addEventListener() instead of inline event handlers for better CSP compatibility.',
        {
          type: 'Inline Handlers',
          count: elementsWithHandlers.length
        }
      );
    }

    // Check for javascript: URLs
    const jsLinks = document.querySelectorAll('[href^="javascript:"]');
    if (jsLinks.length > 0) {
      // Collect detailed information about each javascript: URL
      const samples = [];
      const MAX_SAMPLES = 5;

      jsLinks.forEach((el, index) => {
        if (index < MAX_SAMPLES) {
          const href = el.getAttribute('href') || '';
          const truncatedHref = href.length > 100
            ? href.substring(0, 100) + '...'
            : href;

          samples.push({
            tag: el.tagName.toLowerCase(),
            id: el.id || null,
            className: el.className ? String(el.className).substring(0, 50) : null,
            href: truncatedHref,
            textContent: (el.textContent || '').trim().substring(0, 50) || null
          });
        }
      });

      // Build descriptive message with examples
      let message = `Found ${jsLinks.length} javascript: URL(s)`;
      if (samples.length > 0) {
        const sampleLines = samples.map(s => {
          const identifier = s.id ? `#${s.id}` : (s.className ? `.${s.className.split(' ')[0]}` : '');
          return `<${s.tag}${identifier}> href="${s.href}"`;
        });
        message += '\n\nExamples:\n' + sampleLines.map(d => `  ${d}`).join('\n');
        if (jsLinks.length > MAX_SAMPLES) {
          message += `\n  ... and ${jsLinks.length - MAX_SAMPLES} more`;
        }
      }

      this.addFinding(
        'JavaScript URLs',
        'FOUND',
        'INFO',
        message,
        'javascript: URLs bypass Content Security Policy and can be XSS vectors. Replace with event listeners (addEventListener) or use button elements with click handlers.',
        {
          type: 'JavaScript URLs',
          count: jsLinks.length,
          samples: samples
        }
      );
    }
  }

  // Scan forms for CSRF vulnerabilities
  scanForms(document) {
    // Known third-party form providers that handle CSRF internally
    const knownThirdPartyFormProviders = [
      'hsforms.com', 'hubspot.com',
      'mailchimp.com', 'list-manage.com',
      'typeform.com', 'wufoo.com', 'jotform.com',
      'formspree.io', 'netlify.com', 'getform.io', 'basin.sh',
      'google.com/forms', 'docs.google.com',
      'forms.gle', 'surveymonkey.com',
      'airtable.com', 'tally.so',
      // Payment providers (handle CSRF internally)
      'checkout.stripe.com', 'js.stripe.com',
      'paypal.com', 'paypalobjects.com',
      'square.com', 'squareup.com',
      // Scheduling & booking
      'calendly.com',
      // Marketing automation
      'pardot.com', 'activecampaign.com',
      'convertkit.com', 'convertflow.com',
      // Form builders
      'gravityforms.com', 'wpforms.com',
      'webflow.com', 'webflow.io',
      // CRM & Support
      'salesforce.com', 'zendesk.com',
      'intercom.io', 'drift.com'
    ];

    const forms = document.querySelectorAll('form');

    forms.forEach((form, index) => {
      const method = (form.method || 'get').toUpperCase();
      const action = form.action;

      if (method === 'POST') {
        // Skip same-page/anchor/empty action forms (typically JS-handled SPA forms)
        const rawAction = form.getAttribute('action') || '';
        if (rawAction === '' || rawAction === '#' || rawAction.startsWith('#') || rawAction === 'javascript:void(0)') {
          return;
        }

        // Skip CSRF check for known third-party form providers
        if (action) {
          try {
            const actionUrl = new URL(action, window.location.href);
            const isThirdParty = knownThirdPartyFormProviders.some(provider =>
              actionUrl.hostname.includes(provider) || actionUrl.href.includes(provider)
            );
            if (isThirdParty) return;
          } catch (e) {
            // Invalid URL, continue with check
          }
        }
        // Check for CSRF token in form elements
        let hasCSRFToken = Array.from(form.elements).some(element => {
          const name = (element.name || '').toLowerCase();
          return name.includes('csrf') || name.includes('token') || name.includes('_token');
        });

        // Check for CSRF meta tags (Rails, Laravel, Django pattern)
        if (!hasCSRFToken) {
          const csrfMeta = document.querySelector(
            'meta[name="csrf-token"], meta[name="csrf_token"], meta[name="_token"], ' +
            'meta[name="csrfmiddlewaretoken"], meta[name="X-CSRF-Token"]'
          );
          if (csrfMeta) hasCSRFToken = true;
        }

        // Check for JS-based CSRF header patterns in inline scripts
        if (!hasCSRFToken) {
          const inlineScripts = document.querySelectorAll('script:not([src])');
          const csrfHeaderPattern = /[xX]-[cC][sS][rR][fF]|csrf[_-]?token|csrfmiddlewaretoken|_token/;
          for (const script of inlineScripts) {
            if (csrfHeaderPattern.test(script.textContent)) {
              hasCSRFToken = true;
              break;
            }
          }
        }

        // Check for frameworks that auto-manage CSRF (Rails UJS, Laravel, Turbo)
        if (!hasCSRFToken) {
          const scriptSrcs = Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
          const csrfFrameworks = [/rails-ujs|jquery[_-]ujs/, /turbo/, /laravel.*\.js/];
          if (scriptSrcs.some(src => csrfFrameworks.some(p => p.test(src)))) {
            hasCSRFToken = true;
          }
        }

        if (!hasCSRFToken) {
          this.addFinding(
            'CSRF Protection',
            'MISSING',
            'LOW',
            `Form #${index + 1} (${action || 'current page'}) has no apparent CSRF token`,
            'Add CSRF token to all state-changing forms. Implement SameSite cookie attribute.',
            {
              type: 'CSRF',
              formIndex: index,
              action: action,
              method: method
            }
          );
        }
      }
    });
  }

  // Check for prototype pollution (runtime detection of unexpected enumerable properties)
  checkPrototypePollution() {
    try {
      const cleanObj = {};
      const pollutedKeys = Object.keys(cleanObj).filter(k => k !== '');
      if (pollutedKeys.length > 0) {
        this.addFinding(
          'Prototype Pollution',
          'DETECTED',
          'MEDIUM',
          `Object.prototype has unexpected properties: ${pollutedKeys.slice(0, 5).join(', ')}`,
          'Investigate and remove prototype pollution. Use Object.create(null) for dictionaries.',
          {
            type: 'Prototype Pollution',
            properties: pollutedKeys.slice(0, 10)
          }
        );
      }
    } catch (error) {
      // Can't check, skip
    }
  }

  // Detect mixed content (HTTP resources loaded on HTTPS pages)
  detectMixedContent(document) {
    if (window.location.protocol !== 'https:') return;

    const mixedResources = [];

    // Active mixed content (high risk)
    document.querySelectorAll('script[src^="http:"]').forEach(el => {
      mixedResources.push({ type: 'script', url: el.src, active: true });
    });
    document.querySelectorAll('link[rel="stylesheet"][href^="http:"]').forEach(el => {
      mixedResources.push({ type: 'stylesheet', url: el.href, active: true });
    });
    document.querySelectorAll('object[data^="http:"]').forEach(el => {
      mixedResources.push({ type: 'object', url: el.data, active: true });
    });
    document.querySelectorAll('embed[src^="http:"]').forEach(el => {
      mixedResources.push({ type: 'embed', url: el.src, active: true });
    });
    document.querySelectorAll('iframe[src^="http:"]').forEach(el => {
      mixedResources.push({ type: 'iframe', url: el.src, active: true });
    });

    // Passive mixed content (medium risk)
    document.querySelectorAll('img[src^="http:"]').forEach(el => {
      mixedResources.push({ type: 'image', url: el.src, active: false });
    });
    document.querySelectorAll('video[src^="http:"], video source[src^="http:"]').forEach(el => {
      mixedResources.push({ type: 'video', url: el.src, active: false });
    });
    document.querySelectorAll('audio[src^="http:"], audio source[src^="http:"]').forEach(el => {
      mixedResources.push({ type: 'audio', url: el.src, active: false });
    });
    document.querySelectorAll('link[rel="preload"][href^="http:"], link[rel="prefetch"][href^="http:"]').forEach(el => {
      mixedResources.push({ type: 'preload', url: el.href, active: el.getAttribute('as') === 'script' || el.getAttribute('as') === 'style' });
    });

    if (mixedResources.length > 0) {
      const hasActive = mixedResources.some(r => r.active);
      this.addFinding(
        'Mixed Content',
        'FOUND',
        hasActive ? 'MEDIUM' : 'LOW',
        `Found ${mixedResources.length} HTTP resource(s) on HTTPS page${hasActive ? ' (includes active content)' : ''}`,
        'Serve all resources over HTTPS. Update URLs to use https:// or protocol-relative //.',
        {
          type: 'Mixed Content',
          resources: mixedResources.slice(0, 20), // Limit to 20
          activeContent: hasActive,
          count: mixedResources.length
        }
      );
    }
  }

  // Check for missing Subresource Integrity (SRI) on cross-origin scripts/styles
  checkSRI(document) {
    const missingIntegrity = [];
    const currentOrigin = window.location.origin;

    // Check external scripts
    document.querySelectorAll('script[src]').forEach(el => {
      if (el.src && !el.src.startsWith(currentOrigin) && !el.integrity) {
        missingIntegrity.push({ type: 'script', url: el.src });
      }
    });

    // Check external stylesheets
    document.querySelectorAll('link[rel="stylesheet"][href]').forEach(el => {
      if (el.href && !el.href.startsWith(currentOrigin) && !el.integrity) {
        missingIntegrity.push({ type: 'stylesheet', url: el.href });
      }
    });

    if (missingIntegrity.length > 0) {
      this.addFinding(
        'Missing Subresource Integrity',
        'MISSING',
        'INFO',
        `${missingIntegrity.length} cross-origin resource(s) lack SRI hashes`,
        'SRI is a defense-in-depth best practice, most useful for version-pinned CDN resources. Dynamic third-party scripts (analytics, widgets) cannot practically use SRI. Consider adding integrity attributes to critical, static dependencies.',
        {
          type: 'SRI',
          resources: missingIntegrity.slice(0, 20),
          count: missingIntegrity.length
        }
      );
    }
  }

  // Detect postMessage handlers without origin validation
  detectPostMessageVulns(code, source, url) {
    const patterns = [
      /addEventListener\s*\(\s*['"]message['"]/g,
      /\.onmessage\s*=/g
    ];

    for (const pattern of patterns) {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        const extendedContext = this.getExtendedCodeContext(code, match.index, 15);
        const contextText = extendedContext.context;

        const hasOriginCheck = /(?:event|e|message|msg|evt)\s*\.\s*origin|[a-zA-Z_$]\s*\.\s*origin\s*(?:!==?|===?|\.(?:indexOf|includes|startsWith|match))|\.(?:indexOf|includes)\s*\(\s*[a-zA-Z_$]+\s*\.\s*origin\s*\)/.test(contextText);

        if (!hasOriginCheck) {
          // IAB TCF/CMP specification requires postMessage handlers without origin
          // validation for cross-origin CMP iframe communication. Downgrade to LOW
          // for these spec-mandated patterns rather than suppressing entirely.
          const isTCFHandler = /__tcfapi|__cmp|__gpp|tcfPolicyVersion|cmpId/i.test(contextText);
          const severity = isTCFHandler ? 'LOW' : 'MEDIUM';
          const message = isTCFHandler
            ? 'postMessage handler without origin validation (TCF/CMP consent framework -- spec-mandated pattern)'
            : 'postMessage handler without origin validation';
          this.addFinding(
            'postMessage Vulnerability',
            'POTENTIAL',
            severity,
            message,
            'Always validate event.origin against a trusted allowlist before processing message data.',
            {
              type: 'postMessage',
              source,
              context: extendedContext.context,
              lineNumber: extendedContext.matchLine,
              matchedText: match[0],
              uri: url
            }
          );
        } else {
          // Only flag loose origin checks when using partial domain (no protocol prefix)
          // Full URL comparisons like .includes('https://trusted.com') are safe
          const looseMatch = contextText.match(/\.origin\s*\.\s*(?:indexOf|includes)\s*\(\s*['"]([^'"]*)['"]/);
          const hasLooseCheck = looseMatch && !looseMatch[1].startsWith('https://') && !looseMatch[1].startsWith('http://');
          // Array-based allowlists like ['https://a.com'].includes(event.origin) are safe
          const arrayIncludesOrigin = /\[.*\]\s*\.\s*includes\s*\(\s*(?:event|e|evt|msg|message)\s*\.\s*origin/.test(contextText);
          if (hasLooseCheck && !arrayIncludesOrigin) {
            this.addFinding(
              'postMessage Vulnerability',
              'POTENTIAL',
              'LOW',
              'postMessage handler uses loose origin comparison (indexOf/includes with partial domain instead of ===)',
              'Use strict equality (===) to validate event.origin against exact trusted origins.',
              {
                type: 'postMessage',
                source,
                context: extendedContext.context,
                lineNumber: extendedContext.matchLine,
                matchedText: match[0],
                uri: url
              }
            );
          }
        }
      }
    }
  }

  // Detect sensitive data stored in localStorage/sessionStorage
  detectSensitiveStorage() {
    try {
      const sensitivePatterns = [
        /token/i, /secret/i, /password/i, /api.?key/i,
        /auth/i, /session/i, /credential/i, /private.?key/i
      ];

      const jwtPattern = /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;
      const bearerPattern = /^Bearer\s+/i;

      const storages = [
        { store: localStorage, name: 'localStorage' },
        { store: sessionStorage, name: 'sessionStorage' }
      ];

      // Known analytics/SDK storage keys that match sensitive patterns but are not secrets
      const analyticsKeyPrefixes = [
        '_fp_', 'sentry', 'tt_', 'ab.storage', 'fedops', 'NRBA_', 'mpa',
        'amplitude', 'mixpanel', 'segment', 'fullstory', 'heap',
        'intercom', 'drift', 'hotjar', 'optimizely', 'pendo',
        'aws-waf', 'aws_waf', 'permutive', 'statsig', 'lngtd',
        '__tea_', '_hbs_', 'webapp-session',
        'session-replay', 'session_replay'
      ];

      for (const { store, name } of storages) {
        for (let i = 0; i < store.length; i++) {
          const key = store.key(i);
          if (!sensitivePatterns.some(p => p.test(key))) continue;

          // Skip known analytics/SDK keys
          if (analyticsKeyPrefixes.some(prefix => key.toLowerCase().startsWith(prefix.toLowerCase()))) continue;

          // P45: Skip keys containing "unauth" (explicitly unauthenticated, not sensitive)
          if (/unauth/i.test(key)) continue;

          // P46: Skip tracking/analytics instrumentation keys
          if (/tracking/i.test(key)) continue;

          // P47: Skip counter/tally keys (metadata about counts, not stored secrets)
          if (/^(numberOf|countOf|total[A-Z])/i.test(key)) continue;

          const value = store.getItem(key) || '';
          const entropy = this.calculateEntropy(value);
          const isJWT = jwtPattern.test(value);
          const isBearer = bearerPattern.test(value);

          // P31: Skip non-sensitive session metadata (short low-entropy values like "Desktop")
          if (!isJWT && !isBearer && value.length < 20 && entropy < 4.0) continue;
          // P31: Skip plain readable words/phrases (not tokens or secrets)
          if (!isJWT && !isBearer && /^[a-zA-Z][a-zA-Z0-9 _-]{0,30}$/.test(value) && !/[0-9]{6,}/.test(value)) continue;
          // P31: Skip JSON-wrapped metadata (e.g., {"data":"Desktop","creation":...})
          if (!isJWT && !isBearer) {
            try {
              const parsed = JSON.parse(value);
              if (typeof parsed === 'object' && parsed !== null) {
                const innerVal = parsed.data || parsed.value || parsed.name || '';
                if (typeof innerVal === 'string' && /^[a-zA-Z][a-zA-Z0-9 _-]{0,40}$/.test(innerVal) && !/[0-9]{6,}/.test(innerVal)) continue;
              }
            } catch (e) { /* not JSON, proceed with normal checks */ }
          }

          if (entropy > 3.5 || isJWT || isBearer) {
            const truncatedValue = value.length > 30 ? value.substring(0, 30) + '...' : value;
            const tokenType = isJWT ? ' (JWT token)' : isBearer ? ' (Bearer token)' : '';
            this.addFinding(
              'Sensitive Storage Data',
              'FOUND',
              'MEDIUM',
              `Sensitive data in ${name}: "${key}"${tokenType}`,
              'Avoid storing sensitive tokens or credentials in web storage. Use httpOnly cookies for session tokens.',
              {
                type: 'Sensitive Storage',
                storageName: name,
                key: key,
                valuePreview: truncatedValue,
                entropy: Math.round(entropy * 100) / 100
              }
            );
          }
        }
      }
    } catch (error) {
      // Storage access may be restricted
    }
  }

  // Calculate Shannon entropy for storage value analysis
  calculateEntropy(str) {
    if (!str || str.length === 0) return 0;
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

  // Detect client-side template injection patterns
  detectTemplateInjection(code, source, url) {
    const patterns = [
      {
        pattern: /v-html\s*=\s*["'][^"']*(?:user|input|query|param|data)/gi,
        name: 'Vue v-html with user input',
        severity: 'MEDIUM',
        message: 'Vue v-html directive with potentially user-controlled data'
      },
      {
        pattern: /\$sce\.trustAsHtml\s*\(/g,
        name: '$sce.trustAsHtml',
        severity: 'MEDIUM',
        message: 'AngularJS $sce.trustAsHtml bypasses sanitization'
      },
      {
        pattern: /bypassSecurityTrustHtml\s*\(/g,
        name: 'bypassSecurityTrustHtml',
        severity: 'MEDIUM',
        message: 'Angular bypassSecurityTrustHtml bypasses sanitization'
      },
      {
        pattern: /\[innerHTML\]\s*=\s*["'][^"']*(?:user|input|query|param|data)/gi,
        name: 'Angular [innerHTML] binding',
        severity: 'MEDIUM',
        message: 'Angular innerHTML binding with potentially user-controlled data'
      },
      {
        pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/g,
        name: 'React dangerouslySetInnerHTML',
        severity: 'MEDIUM',
        message: 'React dangerouslySetInnerHTML can lead to XSS if input is not sanitized'
      }
    ];

    for (const { pattern, name, severity, message } of patterns) {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        const extendedContext = this.getExtendedCodeContext(code, match.index, 5);
        const contextText = extendedContext.context;

        const hasUserInput = this.containsUserInput(contextText);
        const effectiveSeverity = hasUserInput ? severity : this.lowerSeverity(severity);

        this.addFinding(
          'Template Injection',
          'POTENTIAL',
          effectiveSeverity,
          `${name}: ${message}`,
          'Sanitize all user input before rendering as HTML. Use framework-safe rendering methods.',
          {
            type: 'Template Injection',
            pattern: name,
            source,
            context: extendedContext.context,
            lineNumber: extendedContext.matchLine,
            matchedText: match[0],
            uri: url
          }
        );
      }
    }
  }

  // Helper methods

  getCodeContext(code, index, length) {
    const start = Math.max(0, index - Math.floor(length / 2));
    const end = Math.min(code.length, index + Math.ceil(length / 2));
    const context = code.substring(start, end);
    
    // Calculate line number
    const beforeMatch = code.substring(0, index);
    const lineNumber = (beforeMatch.match(/\n/g) || []).length + 1;
    
    return context;
  }

  getLineNumber(code, index) {
    const beforeMatch = code.substring(0, index);
    return (beforeMatch.match(/\n/g) || []).length + 1;
  }

  getExtendedCodeContext(code, index, lines = 5) {
    // Get context spanning multiple lines around the match
    const allLines = code.split('\n');
    const lineNumber = this.getLineNumber(code, index);
    const startLine = Math.max(0, lineNumber - lines - 1);
    // Compensate: extend end window by lines lost at the start
    const linesLostBefore = Math.max(0, (lines + 1 - lineNumber) + 1);
    const endLine = Math.min(allLines.length, lineNumber + lines + linesLostBefore);
    
    const contextLines = allLines.slice(startLine, endLine);
    const context = contextLines.join('\n');
    
    return {
      context,
      startLine: startLine + 1,
      endLine: endLine,
      matchLine: lineNumber
    };
  }

  containsUserInput(context) {
    // Definitive user input sources (exact substring match is safe)
    // Note: location.href removed (it's the LHS of assignments, not user input;
    // location.search and location.hash already cover URL-based user input)
    // Note: localStorage/sessionStorage removed (same-origin storage, not external input)
    const definiteSources = [
      'location.search', 'location.hash',
      'document.URL', 'document.referrer', 'document.cookie',
      'window.name',
      'URLSearchParams', 'req.body', 'req.query', 'req.params'
    ];

    if (definiteSources.some(source => context.includes(source))) return true;

    // Sources that need word-boundary matching to avoid false positives
    // (e.g., 'input' should not match variable 'inputField', 'params' should not match 'searchParams')
    const boundaryPatterns = [
      /(?:(?:input|select|textarea|form|field|element|el|elem|target|currentTarget)\w*|getElementById\([^)]+\)|querySelector\([^)]+\)|querySelectorAll\([^)]+\))\.value\b/i, // .value on DOM elements
      /getElementById\s*\(/,      // DOM element access
      /querySelector\s*\([^)]*\)\./, // DOM element property access
      /\.params\[/,               // params["key"] access
      /\.query\[/,                // query["key"] access
      /getParameter\s*\(/         // Java-style parameter access
    ];

    return boundaryPatterns.some(pattern => pattern.test(context));
  }

  containsUntrustedSource(context) {
    // Note: localStorage/sessionStorage removed (same-origin storage, not external input)
    const untrustedSources = [
      'location.hash',
      'postMessage', 'window.name', 'document.referrer'
    ];

    return untrustedSources.some(source => context.includes(source));
  }

  looksLikeTestValue(str) {
    const testPatterns = [
      /test/i, /example/i, /sample/i, /dummy/i, /placeholder/i,
      /xxx+/i, /123+/, /abc+/i
    ];
    
    return testPatterns.some(pattern => pattern.test(str));
  }

  lowerSeverity(severity) {
    const levels = { CRITICAL: 'HIGH', HIGH: 'MEDIUM', MEDIUM: 'LOW', LOW: 'INFO' };
    return levels[severity] || severity;
  }

  addFinding(check, status, severity, message, recommendation, details) {
    this.results.push({
      check,
      status,
      severity,
      message,
      recommendation,
      details,
      timestamp: new Date().toISOString(),
      // Enhanced details for expandable UI
      source: details?.source || 'unknown',
      lineNumber: details?.lineNumber || null,
      codeContext: details?.context || null,
      pattern: details?.pattern || null,
      matchedText: details?.matchedText || null,
      uri: details?.uri || window.location.href
    });
  }
}

// Export for use in extension
if (typeof module !== 'undefined' && module.exports) {
  module.exports = VulnerabilityScanner;
}

