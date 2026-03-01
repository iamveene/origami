// Origami WebSocket & Real-Time Protocol Auditor
// Audits WebSocket and Server-Sent Events for security issues

class WebSocketAuditor {
  constructor() {
    this.findings = { connections: [], messages: [], issues: [] };
  }

  async analyze() {
    this.findings = { connections: [], messages: [], issues: [] };

    try {
      const scripts = document.querySelectorAll('script:not([src])');
      this._cachedScriptContent = Array.from(scripts).map(s => s.textContent || '').join('\n');
    } catch (e) {
      this._cachedScriptContent = '';
    }

    try {
      this._scanForWebSocketURLs();
      this._scanForEventSourceURLs();
      this._detectUnencryptedConnections();
      this._analyzeWebSocketCode();
      this._detectSensitiveDataPatterns();
      this._checkAuthenticationPatterns();
      this._detectSerializationRisks();
    } catch (e) {
      console.error('Origami: WebSocket auditor error:', e.message);
    }

    this._cachedScriptContent = null;
    return this.findings;
  }

  _getInlineScriptContent() {
    return this._cachedScriptContent || '';
  }

  _scanForWebSocketURLs() {
    const allScript = this._getInlineScriptContent();
    const seenURLs = new Set();

    // Scan inline scripts for ws:// and wss:// URL literals
    const wsURLPattern = /(['"`])(wss?:\/\/[^'"`\s]+)\1/g;
    let match;
    while ((match = wsURLPattern.exec(allScript)) !== null) {
      const url = match[2];
      if (seenURLs.has(url)) continue;
      seenURLs.add(url);
      this.findings.connections.push({
        url: url,
        protocol: url.startsWith('wss://') ? 'wss' : 'ws',
        type: 'websocket',
        foundIn: 'script',
        encrypted: url.startsWith('wss://')
      });
    }

    // Scan for WebSocket constructor calls with template literals or variables
    const wsConstructorPattern = /new\s+WebSocket\s*\(\s*(['"`])([^'"`]+)\1/g;
    while ((match = wsConstructorPattern.exec(allScript)) !== null) {
      const url = match[2];
      if (seenURLs.has(url)) continue;
      if (!/^wss?:\/\//.test(url)) continue;
      seenURLs.add(url);
      this.findings.connections.push({
        url: url,
        protocol: url.startsWith('wss://') ? 'wss' : 'ws',
        type: 'websocket',
        foundIn: 'script',
        encrypted: url.startsWith('wss://')
      });
    }

    // Scan for variable-based WebSocket construction (capture variable name)
    const wsVarPattern = /new\s+WebSocket\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)/g;
    while ((match = wsVarPattern.exec(allScript)) !== null) {
      const varName = match[1];
      // Look for variable assignment with ws/wss URL
      const varAssignPattern = new RegExp(
        varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') +
        '\\s*=\\s*[\'"`](wss?:\\/\\/[^\'"` ]+)[\'"`]'
      );
      const varMatch = allScript.match(varAssignPattern);
      if (varMatch) {
        const url = varMatch[1];
        if (seenURLs.has(url)) continue;
        seenURLs.add(url);
        this.findings.connections.push({
          url: url,
          protocol: url.startsWith('wss://') ? 'wss' : 'ws',
          type: 'websocket',
          foundIn: 'script',
          encrypted: url.startsWith('wss://')
        });
      }
    }

    // Scan HTML body for ws:// and wss:// references (data attributes, inline handlers)
    try {
      const bodyHTML = document.body ? document.body.innerHTML : '';
      const htmlWSPattern = /wss?:\/\/[^\s"'<>\])}]+/g;
      while ((match = htmlWSPattern.exec(bodyHTML)) !== null) {
        const url = match[0];
        if (seenURLs.has(url)) continue;
        seenURLs.add(url);
        this.findings.connections.push({
          url: url,
          protocol: url.startsWith('wss://') ? 'wss' : 'ws',
          type: 'websocket',
          foundIn: 'html',
          encrypted: url.startsWith('wss://')
        });
      }
    } catch (e) { /* body not accessible */ }

    // Check performance entries for WebSocket upgrade requests
    try {
      const entries = performance.getEntriesByType('resource');
      for (const entry of entries) {
        if (entry.name && /^wss?:\/\//.test(entry.name)) {
          const url = entry.name;
          if (seenURLs.has(url)) continue;
          seenURLs.add(url);
          this.findings.connections.push({
            url: url,
            protocol: url.startsWith('wss://') ? 'wss' : 'ws',
            type: 'websocket',
            foundIn: 'performance',
            encrypted: url.startsWith('wss://')
          });
        }
      }
    } catch (e) { /* performance API not available */ }
  }

  _scanForEventSourceURLs() {
    const allScript = this._getInlineScriptContent();
    const seenURLs = new Set();

    // Scan for EventSource constructor with string literal
    const esConstructorPattern = /new\s+EventSource\s*\(\s*(['"`])([^'"`]+)\1/g;
    let match;
    while ((match = esConstructorPattern.exec(allScript)) !== null) {
      const url = match[2];
      if (seenURLs.has(url)) continue;
      seenURLs.add(url);
      const isAbsolute = /^https?:\/\//.test(url);
      const encrypted = isAbsolute ? url.startsWith('https://') : this._isCurrentPageSecure();
      this.findings.connections.push({
        url: url,
        protocol: isAbsolute ? (url.startsWith('https://') ? 'https' : 'http') : 'relative',
        type: 'sse',
        foundIn: 'script',
        encrypted: encrypted
      });
    }

    // Scan for EventSource with variable references
    const esVarPattern = /new\s+EventSource\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)/g;
    while ((match = esVarPattern.exec(allScript)) !== null) {
      const varName = match[1];
      const varAssignPattern = new RegExp(
        varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') +
        '\\s*=\\s*[\'"`](https?:\\/\\/[^\'"` ]+)[\'"`]'
      );
      const varMatch = allScript.match(varAssignPattern);
      if (varMatch) {
        const url = varMatch[1];
        if (seenURLs.has(url)) continue;
        seenURLs.add(url);
        this.findings.connections.push({
          url: url,
          protocol: url.startsWith('https://') ? 'https' : 'http',
          type: 'sse',
          foundIn: 'script',
          encrypted: url.startsWith('https://')
        });
      }
    }
  }

  _isCurrentPageSecure() {
    try {
      return window.location.protocol === 'https:';
    } catch (e) {
      return false;
    }
  }

  _detectUnencryptedConnections() {
    for (const conn of this.findings.connections) {
      if (conn.type === 'websocket' && conn.protocol === 'ws') {
        this.findings.issues.push({
          severity: 'HIGH',
          type: 'ws-unencrypted',
          message: 'Unencrypted WebSocket connection (ws://) - data transmitted in cleartext',
          cwe: 'CWE-319',
          details: {
            url: conn.url,
            pattern: 'ws://',
            evidence: conn.url.substring(0, 120)
          },
          recommendation: 'Use wss:// (WebSocket Secure) to encrypt all WebSocket traffic with TLS.'
        });
      }

      if (conn.type === 'sse' && conn.protocol === 'http') {
        this.findings.issues.push({
          severity: 'HIGH',
          type: 'sse-unencrypted',
          message: 'Unencrypted Server-Sent Events connection (http://) - event stream transmitted in cleartext',
          cwe: 'CWE-319',
          details: {
            url: conn.url,
            pattern: 'http://',
            evidence: conn.url.substring(0, 120)
          },
          recommendation: 'Use https:// for SSE endpoints to encrypt the event stream with TLS.'
        });
      }
    }
  }

  _analyzeWebSocketCode() {
    const allScript = this._getInlineScriptContent();
    const lines = allScript.split('\n');
    const isBundledOrMinified = window.origamiIsBundledOrMinified && window.origamiIsBundledOrMinified(allScript);

    // Detect eval() or Function() in WebSocket message handling context
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      if (/\beval\s*\(/.test(line)) {
        // Skip feature detection evals -- short static strings testing browser syntax support
        // e.g., eval("async () => {}"), eval("() => {}"), eval("class {}")
        if (/\beval\s*\(\s*["'](?:async\s+)?(?:function|class|\([\s)]*\)\s*=>|\(\s*\)\s*\{)[^"']*["']\s*\)/.test(line)) continue;

        const isMinified = line.length > 500;
        const contextStart = isMinified ? i : Math.max(0, i - 10);
        const contextEnd = isMinified ? i : Math.min(lines.length - 1, i + 10);
        const context = lines.slice(contextStart, contextEnd + 1).join('\n');

        if (/onmessage|addEventListener\s*\(\s*['"]message['"]|\.on\s*\(\s*['"]message['"]|WebSocket|event\.data/i.test(context)) {
          const hasExplicitWS = /WebSocket|ws:\/\/|wss:\/\//i.test(context);
          const hasMessageListener = /addEventListener\s*\(\s*['"]message['"]|\.on\s*\(\s*['"]message['"]/i.test(context);
          const isLikelyPostMessage = hasMessageListener && !hasExplicitWS;
          const securityInfraPattern = /cdn-cgi\/challenge|cloudflare.*challenge|turnstile|datadome|perimeterx|kasada|akamai.*bot/i;
          const isSecurityInfra = securityInfraPattern.test(context);
          this.findings.issues.push({
            severity: (isSecurityInfra || isBundledOrMinified || isMinified || isLikelyPostMessage) ? 'INFO' : 'CRITICAL',
            type: 'ws-code-injection',
            message: isSecurityInfra
              ? 'eval() near WebSocket context in security infrastructure script (CAPTCHA/bot-detection -- expected pattern)'
              : isLikelyPostMessage
              ? 'eval() near postMessage handler (not WebSocket -- handled by postMessage detection)'
              : (isBundledOrMinified || isMinified)
              ? 'eval() near WebSocket context in bundled/minified code (likely build artifact)'
              : 'eval() used in WebSocket message handler - remote code execution via crafted messages',
            cwe: 'CWE-94',
            details: {
              pattern: 'eval() in message context',
              evidence: line.trim().substring(0, 200)
            },
            line: i + 1,
            recommendation: 'Never use eval() on data received from WebSocket messages. Parse data as JSON and validate structure.'
          });
        }
      }

      if (/new\s+Function\s*\(/.test(line)) {
        const isMinified = line.length > 500;
        const contextStart = isMinified ? i : Math.max(0, i - 10);
        const contextEnd = isMinified ? i : Math.min(lines.length - 1, i + 10);
        const context = lines.slice(contextStart, contextEnd + 1).join('\n');

        if (/onmessage|addEventListener\s*\(\s*['"]message['"]|\.on\s*\(\s*['"]message['"]|WebSocket|event\.data/i.test(context)) {
          const hasExplicitWS = /WebSocket|ws:\/\/|wss:\/\//i.test(context);
          const hasMessageListener = /addEventListener\s*\(\s*['"]message['"]|\.on\s*\(\s*['"]message['"]/i.test(context);
          const isLikelyPostMessage = hasMessageListener && !hasExplicitWS;
          const securityInfraPattern = /cdn-cgi\/challenge|cloudflare.*challenge|turnstile|datadome|perimeterx|kasada|akamai.*bot/i;
          const isSecurityInfra = securityInfraPattern.test(context);
          this.findings.issues.push({
            severity: (isSecurityInfra || isBundledOrMinified || isMinified || isLikelyPostMessage) ? 'INFO' : 'CRITICAL',
            type: 'ws-code-injection',
            message: isSecurityInfra
              ? 'Function constructor near WebSocket context in security infrastructure script (CAPTCHA/bot-detection -- expected pattern)'
              : isLikelyPostMessage
              ? 'Function constructor near postMessage handler (not WebSocket -- handled by postMessage detection)'
              : (isBundledOrMinified || isMinified)
              ? 'Function constructor near WebSocket context in bundled/minified code (likely build artifact)'
              : 'Function constructor used in WebSocket message handler - remote code execution risk',
            cwe: 'CWE-94',
            details: {
              pattern: 'new Function() in message context',
              evidence: line.trim().substring(0, 200)
            },
            line: i + 1,
            recommendation: 'Never use the Function constructor on WebSocket message data. Parse and validate data safely.'
          });
        }
      }
    }

    // Detect innerHTML/document.write with WebSocket message data (XSS via WS)
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      if (/\.innerHTML\s*[+]?=|document\.write\s*\(|\.outerHTML\s*[+]?=|\.insertAdjacentHTML\s*\(/.test(line)) {
        const isMinified = line.length > 500;
        const contextStart = isMinified ? i : Math.max(0, i - 10);
        const contextEnd = isMinified ? i : Math.min(lines.length - 1, i + 10);
        const context = lines.slice(contextStart, contextEnd + 1).join('\n');

        if (/onmessage|addEventListener\s*\(\s*['"]message['"]|\.on\s*\(\s*['"]message['"]|WebSocket|event\.data/i.test(context)) {
          const hasExplicitWS = /WebSocket|ws:\/\/|wss:\/\//i.test(context);
          const hasMessageListener = /addEventListener\s*\(\s*['"]message['"]|\.on\s*\(\s*['"]message['"]/i.test(context);
          const isLikelyPostMessage = hasMessageListener && !hasExplicitWS;
          const securityInfraPattern = /cdn-cgi\/challenge|cloudflare.*challenge|turnstile|datadome|perimeterx|kasada|akamai.*bot/i;
          const isSecurityInfra = securityInfraPattern.test(context);
          this.findings.issues.push({
            severity: (isSecurityInfra || isBundledOrMinified || isMinified || isLikelyPostMessage) ? 'INFO' : 'HIGH',
            type: 'ws-xss',
            message: isSecurityInfra
              ? 'innerHTML/document.write near WebSocket context in security infrastructure script (CAPTCHA/bot-detection -- expected pattern)'
              : isLikelyPostMessage
              ? 'innerHTML/document.write near postMessage handler (not WebSocket -- lower risk)'
              : (isBundledOrMinified || isMinified)
              ? 'innerHTML/document.write near WebSocket context in bundled/minified code (likely build artifact)'
              : 'WebSocket message data rendered as HTML - cross-site scripting via WebSocket messages',
            cwe: 'CWE-79',
            details: {
              pattern: 'innerHTML/document.write in message handler',
              evidence: line.trim().substring(0, 200)
            },
            line: i + 1,
            recommendation: 'Use textContent instead of innerHTML for rendering WebSocket data. Sanitize all WS message content before DOM insertion.'
          });
        }
      }
    }

    // Detect JSON.parse without try/catch in message handlers
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      if (/JSON\.parse\s*\(/.test(line)) {
        const contextStart = Math.max(0, i - 10);
        const contextEnd = Math.min(lines.length - 1, i + 10);
        const context = lines.slice(contextStart, contextEnd + 1).join('\n');

        if (/onmessage|addEventListener\s*\(\s*['"]message['"]|\.on\s*\(\s*['"]message['"]|WebSocket/i.test(context)) {
          const blockStart = Math.max(0, i - 5);
          const blockEnd = Math.min(lines.length - 1, i + 5);
          const nearbyCode = lines.slice(blockStart, blockEnd + 1).join('\n');

          if (!/try\s*\{/.test(nearbyCode) && !/catch\s*\(/.test(nearbyCode)) {
            this.findings.issues.push({
              severity: 'LOW',
              type: 'ws-unhandled-parse',
              message: 'JSON.parse in WebSocket handler without try/catch - malformed messages will crash the handler',
              cwe: 'CWE-20',
              details: {
                pattern: 'JSON.parse without error handling',
                evidence: line.trim().substring(0, 200)
              },
              line: i + 1,
              recommendation: 'Wrap JSON.parse calls in try/catch blocks to gracefully handle malformed WebSocket messages.'
            });
          }
        }
      }
    }

    // Detect direct .send() patterns for awareness
    const sendPattern = /\.send\s*\(/g;
    const sendMatches = allScript.match(sendPattern);
    if (sendMatches && sendMatches.length > 0) {
      const hasWebSocket = /WebSocket|\.onmessage|\.onopen/i.test(allScript);
      if (hasWebSocket) {
        this.findings.messages.push({
          type: 'ws-send-calls',
          count: sendMatches.length,
          note: 'WebSocket .send() calls detected in page scripts'
        });
      }
    }
  }

  _detectSensitiveDataPatterns() {
    const allScript = this._getInlineScriptContent();
    const lines = allScript.split('\n');
    const isBundledOrMinified = window.origamiIsBundledOrMinified && window.origamiIsBundledOrMinified(allScript);

    // Only analyze if there are WebSocket-related patterns in the page
    if (!/WebSocket|\.onmessage|\.send\s*\(|EventSource/i.test(allScript)) return;

    // Skip proximity-based detection in bundled/minified code -- meaningless in compressed code
    if (isBundledOrMinified) return;

    // Token/JWT patterns near send calls
    const tokenPatterns = [
      { pattern: /(?:token|jwt|bearer|authorization|session[_-]?id|api[_-]?key)/i, label: 'authentication token' },
      { pattern: /(?:password|passwd|pwd|secret)/i, label: 'password/secret' }
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      if (/\.send\s*\(/i.test(line)) {
        const isMinified = line.length > 500;
        const contextStart = isMinified ? i : Math.max(0, i - 5);
        const contextEnd = isMinified ? i : Math.min(lines.length - 1, i + 5);
        const context = lines.slice(contextStart, contextEnd + 1).join('\n');

        for (const check of tokenPatterns) {
          if (check.pattern.test(context)) {
            this.findings.issues.push({
              severity: 'LOW',
              type: 'ws-sensitive-data',
              message: 'Potential ' + check.label + ' transmitted via WebSocket .send() call',
              cwe: 'CWE-319',
              details: {
                pattern: check.pattern.source,
                evidence: line.trim().substring(0, 200)
              },
              line: i + 1,
              recommendation: 'Ensure sensitive data sent over WebSocket is encrypted (wss://) and consider using short-lived tokens.'
            });
            break;
          }
        }
      }
    }

    // Check for PII patterns using origamiSensitiveDataPatterns near WS context
    const sensitivePatterns = window.origamiSensitiveDataPatterns;
    if (!sensitivePatterns) return;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      if (/\.send\s*\(|onmessage/i.test(line)) {
        const contextStart = Math.max(0, i - 3);
        const contextEnd = Math.min(lines.length - 1, i + 3);
        const context = lines.slice(contextStart, contextEnd + 1).join('\n');

        for (const [type, pattern] of Object.entries(sensitivePatterns)) {
          if (type === 'ipv4') continue;
          const freshPattern = new RegExp(pattern.source);
          if (freshPattern.test(context)) {
            this.findings.issues.push({
              severity: 'LOW',
              type: 'ws-pii-exposure',
              message: 'Potential PII (' + type + ') pattern found near WebSocket handler',
              cwe: 'CWE-359',
              details: {
                pattern: type,
                evidence: line.trim().substring(0, 200)
              },
              line: i + 1,
              recommendation: 'Avoid transmitting PII over WebSocket connections. If necessary, ensure wss:// is used and data is minimized.'
            });
            break;
          }
        }
      }
    }
  }

  _checkAuthenticationPatterns() {
    const allScript = this._getInlineScriptContent();

    // Check for tokens in WebSocket URL query parameters
    for (const conn of this.findings.connections) {
      if (conn.type !== 'websocket') continue;

      try {
        const url = new URL(conn.url);
        const params = url.searchParams;
        const sensitiveParams = ['token', 'jwt', 'auth', 'key', 'apikey', 'api_key',
          'access_token', 'session', 'session_id', 'secret', 'password', 'authorization'];

        for (const param of sensitiveParams) {
          if (params.has(param) || params.has(param.toUpperCase())) {
            this.findings.issues.push({
              severity: 'HIGH',
              type: 'ws-token-in-url',
              message: 'Authentication token passed in WebSocket URL query parameter (' + param + ') - tokens in URLs are logged by proxies and browser history',
              cwe: 'CWE-598',
              details: {
                url: conn.url.substring(0, 120),
                pattern: 'query param: ' + param,
                evidence: url.search.substring(0, 100)
              },
              recommendation: 'Send authentication tokens via WebSocket subprotocol header or in the first message after connection. Never include tokens in URLs.'
            });
            break;
          }
        }
      } catch (e) {
        // URL with template variables or invalid format -- scan raw string
        if (/[?&](?:token|jwt|auth|key|apikey|api_key|access_token|session|secret|password)=/i.test(conn.url)) {
          this.findings.issues.push({
            severity: 'HIGH',
            type: 'ws-token-in-url',
            message: 'Authentication credential detected in WebSocket URL query string - tokens in URLs are logged by proxies',
            cwe: 'CWE-598',
            details: {
              url: conn.url.substring(0, 120),
              pattern: 'token in URL query',
              evidence: conn.url.substring(0, 150)
            },
            recommendation: 'Send authentication tokens via WebSocket subprotocol header or in the first message after connection. Never include tokens in URLs.'
          });
        }
      }
    }

    // Check for WebSocket subprotocol usage (second param)
    const subprotocolPattern = /new\s+WebSocket\s*\(\s*[^,)]+,\s*(?:\[[\s\S]*?\]|['"][^'"]+['"])/g;
    const subprotocolMatches = allScript.match(subprotocolPattern);
    if (subprotocolMatches) {
      this.findings.messages.push({
        type: 'ws-subprotocol',
        count: subprotocolMatches.length,
        note: 'WebSocket subprotocol parameter detected - custom protocol in use'
      });
    }

    // Check for missing authentication in WebSocket connections
    if (this.findings.connections.some(c => c.type === 'websocket')) {
      const hasAuthPattern = /(?:token|jwt|bearer|authorization|auth|api[_-]?key|credential|session)/i.test(allScript);
      const hasSubprotocol = subprotocolMatches && subprotocolMatches.length > 0;

      if (!hasAuthPattern && !hasSubprotocol) {
        this.findings.issues.push({
          severity: 'LOW',
          type: 'ws-no-auth',
          message: 'No authentication mechanism detected for WebSocket connection - connection may lack authorization',
          cwe: 'CWE-306',
          details: {
            pattern: 'no token/auth/jwt references found near WebSocket code',
            evidence: 'WebSocket connections found but no authentication patterns detected'
          },
          recommendation: 'Implement authentication for WebSocket connections using tokens, subprotocols, or initial handshake verification.'
        });
      }
    }
  }

  _detectSerializationRisks() {
    const allScript = this._getInlineScriptContent();
    const lines = allScript.split('\n');

    // Only analyze if there are WebSocket/message patterns
    if (!/WebSocket|onmessage|addEventListener\s*\(\s*['"]message['"]|EventSource/i.test(allScript)) return;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const contextStart = Math.max(0, i - 10);
      const contextEnd = Math.min(lines.length - 1, i + 10);
      const context = lines.slice(contextStart, contextEnd + 1).join('\n');

      const isWSContext = /onmessage|addEventListener\s*\(\s*['"]message['"]|\.on\s*\(\s*['"]message['"]|WebSocket|event\.data/i.test(context);
      if (!isWSContext) continue;

      // eval() with message data
      if (/\beval\s*\(\s*(?:event\.data|e\.data|msg\.data|data|message)/i.test(line)) {
        this.findings.issues.push({
          severity: 'CRITICAL',
          type: 'ws-unsafe-deserialization',
          message: 'eval() called directly on WebSocket message data - arbitrary code execution from server-pushed messages',
          cwe: 'CWE-502',
          details: {
            pattern: 'eval(message.data)',
            evidence: line.trim().substring(0, 200)
          },
          line: i + 1,
          recommendation: 'Never deserialize WebSocket data with eval(). Use JSON.parse() with schema validation.'
        });
      }

      // Function constructor with message data
      if (/new\s+Function\s*\(\s*(?:event\.data|e\.data|msg\.data|data|message)/i.test(line)) {
        this.findings.issues.push({
          severity: 'CRITICAL',
          type: 'ws-unsafe-deserialization',
          message: 'Function constructor called with WebSocket message data - code injection via crafted messages',
          cwe: 'CWE-502',
          details: {
            pattern: 'new Function(message.data)',
            evidence: line.trim().substring(0, 200)
          },
          line: i + 1,
          recommendation: 'Never pass WebSocket message data to the Function constructor. Parse data safely with JSON.parse() and validate.'
        });
      }

      // document.write with message data
      if (/document\.write\s*\(\s*(?:event\.data|e\.data|msg\.data|data|message)/i.test(line)) {
        this.findings.issues.push({
          severity: 'HIGH',
          type: 'ws-dom-injection',
          message: 'document.write() called with WebSocket message data - XSS via server-pushed content',
          cwe: 'CWE-79',
          details: {
            pattern: 'document.write(message.data)',
            evidence: line.trim().substring(0, 200)
          },
          line: i + 1,
          recommendation: 'Never pass WebSocket data to document.write(). Use textContent or create elements with validated content.'
        });
      }

      // innerHTML with message data
      if (/\.innerHTML\s*[+]?=\s*(?:event\.data|e\.data|msg\.data|data|message)/i.test(line)) {
        this.findings.issues.push({
          severity: 'HIGH',
          type: 'ws-dom-injection',
          message: 'innerHTML set with WebSocket message data - XSS via server-pushed HTML content',
          cwe: 'CWE-79',
          details: {
            pattern: 'innerHTML = message.data',
            evidence: line.trim().substring(0, 200)
          },
          line: i + 1,
          recommendation: 'Use textContent or DOMPurify to sanitize WebSocket data before inserting into the DOM.'
        });
      }

      // JSON.parse on message data without try/catch (lower severity)
      if (/JSON\.parse\s*\(\s*(?:event\.data|e\.data|msg\.data)/i.test(line)) {
        const blockStart = Math.max(0, i - 5);
        const blockEnd = Math.min(lines.length - 1, i + 5);
        const nearbyCode = lines.slice(blockStart, blockEnd + 1).join('\n');

        if (!/try\s*\{/.test(nearbyCode) && !/catch\s*\(/.test(nearbyCode)) {
          this.findings.issues.push({
            severity: 'LOW',
            type: 'ws-parse-no-validation',
            message: 'JSON.parse on WebSocket message data without error handling - malformed data may crash the handler',
            cwe: 'CWE-20',
            details: {
              pattern: 'JSON.parse(event.data) without try/catch',
              evidence: line.trim().substring(0, 200)
            },
            line: i + 1,
            recommendation: 'Wrap JSON.parse in try/catch and validate parsed data structure before use.'
          });
        }
      }
    }

    // Detect high-entropy strings near WebSocket construction (potential hardcoded tokens)
    const entropyFn = window.origamiCalculateStringEntropy;
    if (!entropyFn) return;

    for (const conn of this.findings.connections) {
      if (conn.type !== 'websocket') continue;

      try {
        const url = new URL(conn.url);
        const queryString = url.search;
        if (queryString.length > 20) {
          const entropy = entropyFn(queryString);
          if (entropy > 4.0) {
            this.findings.messages.push({
              type: 'ws-high-entropy-params',
              url: conn.url.substring(0, 80),
              entropy: Math.round(entropy * 100) / 100,
              note: 'High-entropy query parameters in WebSocket URL may indicate embedded credentials'
            });
          }
        }
      } catch (e) { /* URL with template variables */ }
    }
  }
}

window.WebSocketAuditor = WebSocketAuditor;
