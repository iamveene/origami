// Origami JavaScript Obfuscation Detector
// Detects obfuscated JavaScript on the page that may hide malicious behavior

class JSObfuscationDetector {
  constructor() {
    this.findings = { scripts: [], issues: [] };
    // Minimum script length to analyze (skip trivial snippets)
    this._minScriptLength = 200;
    // Thresholds for obfuscation scoring
    this._obfuscationThreshold = 3;  // score >= 3 triggers a finding
  }

  async analyze() {
    this.findings = { scripts: [], issues: [] };

    try {
      this._scanInlineScripts();
      this._scanExternalScripts();
    } catch (e) {
      console.error('Origami: JS obfuscation detector error:', e.message);
    }

    return this.findings;
  }

  _scanInlineScripts() {
    const scripts = document.querySelectorAll('script:not([src])');

    // Cloudflare challenge patterns to skip
    const cfPattern = /window\.__CF\$cv\$params|__cf_chl_|CloudflareChallenges|cf-challenge/;

    scripts.forEach((script, index) => {
      const code = script.textContent;
      if (!code || code.length < this._minScriptLength) return;
      if (cfPattern.test(code)) return;

      const result = this._analyzeCode(code, `inline-script-${index}`);
      if (result) {
        result.source = 'inline';
        result.index = index;
        this.findings.scripts.push(result);
      }
    });
  }

  _scanExternalScripts() {
    const scripts = document.querySelectorAll('script[src]');

    scripts.forEach(script => {
      const src = script.src || '';
      // Skip known CDNs and libraries - they are often minified but not malicious
      if (this._isKnownCDN(src)) return;

      // For external scripts we can only inspect if they were loaded same-origin
      // or if their content is accessible. We analyze the DOM element's text if available.
      // Most external scripts won't have textContent, so we check data attributes
      // and the src URL for suspicious patterns.
      this._analyzeExternalScriptURL(src);
    });
  }

  _analyzeCode(code, identifier) {
    const signals = [];
    let score = 0;

    // 1. Hex-encoded variable names (_0x pattern from obfuscator.io)
    const hexVarMatches = code.match(/\b_0x[0-9a-f]{4,}\b/gi);
    if (hexVarMatches) {
      const uniqueHexVars = new Set(hexVarMatches).size;
      if (uniqueHexVars >= 3) {
        score += 2;
        signals.push({ indicator: 'hex-variable-names', detail: `${uniqueHexVars} unique _0x-prefixed variables`, count: uniqueHexVars });
      }
    }

    // 2. Eval usage
    const evalMatches = code.match(/\beval\s*\(/g);
    if (evalMatches && evalMatches.length > 0) {
      score += 2;
      signals.push({ indicator: 'eval-usage', detail: `eval() called ${evalMatches.length} time(s)`, count: evalMatches.length });
    }

    // 3. Function constructor (indirect eval)
    const funcConstructor = code.match(/\bFunction\s*\(\s*['"]/g) || code.match(/new\s+Function\s*\(/g);
    if (funcConstructor) {
      score += 2;
      signals.push({ indicator: 'function-constructor', detail: `Function constructor used ${funcConstructor.length} time(s)`, count: funcConstructor.length });
    }

    // 4. String.fromCharCode used extensively (character code obfuscation)
    const fromCharCodeMatches = code.match(/String\.fromCharCode/g);
    if (fromCharCodeMatches && fromCharCodeMatches.length >= 3) {
      score += 1;
      signals.push({ indicator: 'charcode-encoding', detail: `String.fromCharCode used ${fromCharCodeMatches.length} time(s)`, count: fromCharCodeMatches.length });
    }

    // 5. Heavy use of atob/btoa (base64 obfuscation)
    const base64Matches = code.match(/\batob\s*\(/g);
    if (base64Matches && base64Matches.length >= 2) {
      score += 1;
      signals.push({ indicator: 'base64-decoding', detail: `atob() called ${base64Matches.length} time(s)`, count: base64Matches.length });
    }

    // 6. String array rotation / shuffling patterns (common in obfuscator.io output)
    const stringArrayPattern = /var\s+\w+\s*=\s*\[\s*(['"][^'"]*['"],?\s*){10,}\]/;
    if (stringArrayPattern.test(code)) {
      score += 2;
      signals.push({ indicator: 'string-array', detail: 'Large string array detected (potential string array rotation)' });
    }

    // 7. Bracket notation property access used heavily (obj['prop'] instead of obj.prop)
    const bracketAccessMatches = code.match(/\[['"][a-zA-Z_$][a-zA-Z0-9_$]*['"]\]/g);
    if (bracketAccessMatches && bracketAccessMatches.length >= 15) {
      score += 1;
      signals.push({ indicator: 'bracket-notation', detail: `Bracket notation property access used ${bracketAccessMatches.length} time(s)`, count: bracketAccessMatches.length });
    }

    // 8. Extremely long lines (obfuscated code is often packed into few lines)
    const lines = code.split('\n');
    const avgLineLength = code.length / Math.max(lines.length, 1);
    if (lines.length <= 5 && code.length > 2000) {
      score += 1;
      signals.push({ indicator: 'packed-code', detail: `${lines.length} line(s) with avg length ${Math.round(avgLineLength)} chars` });
    }

    // 9. Unicode escape sequences used heavily
    const unicodeEscapes = code.match(/\\u[0-9a-fA-F]{4}/g);
    if (unicodeEscapes && unicodeEscapes.length >= 10) {
      score += 1;
      signals.push({ indicator: 'unicode-escapes', detail: `${unicodeEscapes.length} unicode escape sequences`, count: unicodeEscapes.length });
    }

    // 10. Hex escape sequences used heavily
    const hexEscapes = code.match(/\\x[0-9a-fA-F]{2}/g);
    if (hexEscapes && hexEscapes.length >= 10) {
      score += 1;
      signals.push({ indicator: 'hex-escapes', detail: `${hexEscapes.length} hex escape sequences`, count: hexEscapes.length });
    }

    // 11. Self-defending / anti-debugging patterns
    const antiDebug = code.match(/\bdebugger\b/g);
    const setIntervalDebugger = /setInterval\s*\(\s*function\s*\(\)\s*\{[^}]*debugger/;
    if ((antiDebug && antiDebug.length >= 2) || setIntervalDebugger.test(code)) {
      score += 1;
      signals.push({ indicator: 'anti-debugging', detail: 'Anti-debugging patterns detected' });
    }

    // 12. JSFuck-style encoding (using only []()!+ characters)
    const jsfuckPattern = /\[\]\[['"][^'"]+['"]\]\[['"][^'"]+['"]\]\(/;
    if (jsfuckPattern.test(code)) {
      score += 3;
      signals.push({ indicator: 'jsfuck-encoding', detail: 'JSFuck-style encoding detected' });
    }

    // 13. High ratio of non-alphanumeric characters
    const nonAlphaRatio = this._nonAlphanumericRatio(code);
    if (nonAlphaRatio > 0.65 && code.length > 500) {
      score += 1;
      signals.push({ indicator: 'high-symbol-ratio', detail: `Non-alphanumeric ratio: ${(nonAlphaRatio * 100).toFixed(1)}%` });
    }

    if (score < this._obfuscationThreshold) return null;

    // Determine severity based on score
    const severity = this._scoreSeverity(score, signals);

    // Determine obfuscation type
    const obfuscationType = this._classifyObfuscationType(signals);

    this._addIssue(severity, 'js-obfuscation',
      `Obfuscated JavaScript detected (score: ${score}, type: ${obfuscationType})`,
      'CWE-506',
      {
        identifier,
        score,
        obfuscationType,
        signals,
        codeLength: code.length,
        snippet: code.substring(0, 200) + (code.length > 200 ? '...' : '')
      },
      'Review obfuscated scripts for malicious intent. Obfuscated code can hide credential theft, cryptomining, or supply chain attacks.'
    );

    return {
      identifier,
      score,
      severity,
      obfuscationType,
      signals,
      codeLength: code.length
    };
  }

  _analyzeExternalScriptURL(src) {
    if (!src) return;

    const signals = [];
    let score = 0;

    // Suspicious URL patterns
    try {
      const url = new URL(src);
      const path = url.pathname + url.search;

      // 1. Base64 in URL path (packed payload delivery)
      if (/[A-Za-z0-9+/]{50,}={0,2}/.test(path)) {
        score += 1;
        signals.push({ indicator: 'base64-url', detail: 'Long base64-like string in script URL path' });
      }

      // 2. Hex-encoded path segments
      if (/(%[0-9a-fA-F]{2}){10,}/.test(src)) {
        score += 1;
        signals.push({ indicator: 'hex-encoded-url', detail: 'Heavily URL-encoded script path' });
      }

      // 3. Extremely long query strings (often contain packed code)
      if (url.search.length > 500) {
        score += 1;
        signals.push({ indicator: 'long-query-string', detail: `Query string length: ${url.search.length} chars` });
      }

      // 4. Suspicious file names
      const suspiciousNames = /\/(pixel|track|beacon|collect|log|stat)\.js/i;
      if (suspiciousNames.test(url.pathname)) {
        // Not necessarily obfuscation, just a data point
      }

    } catch (e) {
      // Invalid URL - skip
      return;
    }

    if (score >= 2) {
      this._addIssue('LOW', 'suspicious-script-url',
        `External script with suspicious URL patterns: ${src.substring(0, 100)}`,
        'CWE-506',
        { src, signals, score },
        'Investigate external scripts with encoded or unusually long URLs for potential payload delivery.'
      );
    }
  }

  _nonAlphanumericRatio(code) {
    const stripped = code.replace(/\s/g, '');
    if (stripped.length === 0) return 0;
    const nonAlpha = stripped.replace(/[a-zA-Z0-9]/g, '').length;
    return nonAlpha / stripped.length;
  }

  _scoreSeverity(score, signals) {
    // Check for particularly concerning signals
    const hasEval = signals.some(s => s.indicator === 'eval-usage');
    const hasFuncConstructor = signals.some(s => s.indicator === 'function-constructor');
    const hasAntiDebug = signals.some(s => s.indicator === 'anti-debugging');
    const hasJSFuck = signals.some(s => s.indicator === 'jsfuck-encoding');

    // Obfuscation alone is LOW severity - it's informational but suspicious
    // Escalate if combined with anti-debugging or dangerous patterns
    if (hasJSFuck || (score >= 8 && (hasEval || hasFuncConstructor) && hasAntiDebug)) {
      return 'MEDIUM';
    }
    return 'LOW';
  }

  _classifyObfuscationType(signals) {
    const indicators = signals.map(s => s.indicator);
    const types = [];

    if (indicators.includes('hex-variable-names') || indicators.includes('string-array')) {
      types.push('obfuscator.io-style');
    }
    if (indicators.includes('eval-usage') || indicators.includes('function-constructor')) {
      types.push('eval-based');
    }
    if (indicators.includes('charcode-encoding')) {
      types.push('charcode');
    }
    if (indicators.includes('base64-decoding')) {
      types.push('base64');
    }
    if (indicators.includes('jsfuck-encoding')) {
      types.push('jsfuck');
    }
    if (indicators.includes('packed-code') && indicators.includes('high-symbol-ratio')) {
      types.push('packed');
    }
    if (indicators.includes('unicode-escapes') || indicators.includes('hex-escapes')) {
      types.push('string-encoding');
    }
    if (indicators.includes('anti-debugging')) {
      types.push('anti-debug');
    }

    return types.length > 0 ? types.join(', ') : 'generic';
  }

  _isKnownCDN(src) {
    const cdnPatterns = [
      /jsdelivr\.net/, /unpkg\.com/, /cdnjs\.cloudflare\.com/,
      /googleapis\.com/, /gstatic\.com/, /jquery\.com/,
      /cloudflare\.com/, /bootstrapcdn\.com/, /fontawesome\.com/,
      /code\.jquery\.com/, /ajax\.googleapis\.com/,
      /esm\.sh/, /skypack\.dev/,
      /google-analytics\.com/, /googletagmanager\.com/,
      /facebook\.net/, /twitter\.com/, /linkedin\.com/
    ];
    return cdnPatterns.some(pattern => pattern.test(src));
  }

  _addIssue(severity, type, message, cwe, details, recommendation) {
    this.findings.issues.push({ severity, type, message, cwe, details, recommendation });
  }
}
