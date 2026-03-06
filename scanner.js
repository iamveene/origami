// Origami Scanner - Content Script
// Scans JavaScript files for hardcoded secrets and API keys

(async () => {
  if (window.__origamiScannerInitialized) return;
  window.__origamiScannerInitialized = true;

  const results = [];
  const seen = new Set();
  const scannedUrls = new Set();

  // Pattern definitions - organized by risk level (fallback only, patterns loaded from storage take priority)
  const patterns = {
    CRITICAL: [
      // CRITICAL: Credentials enabling immediate account takeover, data breach, or financial loss
      // These have highly specific prefix formats (near-zero FP) and grant direct API access
      { name: 'AWS Access Key', regex: /(?:AKIA|ASIA)[0-9A-Z]{16}/g },
      { name: 'Stripe Live Key', regex: /sk_live_[0-9a-zA-Z]{24,}/g },
      { name: 'Private Key Header', regex: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
      { name: 'Azure Connection String', regex: /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+/g },
      { name: 'Database URL', regex: /(mongodb|mysql|postgresql|postgres|redis|amqp|mssql):\/\/[^:]+:[^@]+@[^\s]+/g },
    ],
    HIGH: [
      // HIGH: Credentials with specific prefix formats enabling direct service access
      { name: 'GitHub Token', regex: /(?:gh[pousr]_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{22,})/g },
      { name: 'Slack Token', regex: /xox[baprs]-[0-9]{8,}-[0-9A-Za-z-]{18,}/g },
      { name: 'Slack Webhook', regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8,12}\/[a-zA-Z0-9_]{24}/g },
      { name: 'SendGrid API Key', regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g },
      { name: 'GitLab Token', regex: /glpat-[0-9a-zA-Z_-]{20}/g },
      // OAuth2 - High-value long-lived credentials
      { name: 'Google OAuth2 Refresh Token', regex: /1\/\/[0-9A-Za-z_-]{43,}/g },
      { name: 'Google OAuth2 Client Secret', regex: /GOCSPX-[0-9A-Za-z_-]{28}/g },
      { name: 'Google OAuth2 Access Token', regex: /ya29\.[0-9A-Za-z_-]{20,}/g },
      // UUID/GUID as Client Credential (OAuth2, API secrets, SDK credentials, etc.)
      { name: 'Client Credential (UUID)', regex: /(client[_-]?(?:secret|id)|clientSecret|clientID|CLIENT_SECRET|CLIENT_ID|api[_-]?(?:secret|key)|apiSecret|apiKey)['"]?\s*[:=]\s*['"][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['"]/gi },
      { name: 'Google Cloud API Key', regex: /AIza[0-9A-Za-z-_]{35}/g },
      // Google OAuth2 Client IDs are intentionally public (RFC 6749) -- not secrets
      // { name: 'Google OAuth2 Client ID', regex: /[0-9]{8,21}-[a-z0-9]{32}\.apps\.googleusercontent\.com/g },
      // NOTE: Quoted Base64 disabled by default in popup.js - false positives on minified CDN files, data URIs, build artifacts
      // { name: 'Quoted Base64', regex: /["'](?=.*[A-Z])(?=.*[a-z])(?=.*[0-9+\/])[A-Za-z0-9+\/]{50,}={0,2}["']/g },
      { name: 'HashiCorp Vault Service Token', regex: /hvs\.[a-zA-Z0-9_-]{24,}/g },
      { name: 'HashiCorp Vault Batch Token', regex: /hvb\.[a-zA-Z0-9_-]{24,}/g },
      { name: 'Terraform Cloud Token', regex: /[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9_-]{60,}/g },
      { name: 'Databricks Token', regex: /dapi[a-f0-9]{32}/g },
      { name: 'Datadog API Key', regex: /(DD_API_KEY|datadog_api_key)['"]?\s*[:=]\s*['"][a-f0-9]{32,}['"]/g }
    ],
    MEDIUM: [
      { name: 'GCP Service Account Key', regex: /"type"\s*:\s*"service_account"/g },
      { name: 'JWT Token', regex: /ey[A-Za-z0-9_]{10,}\.ey[A-Za-z0-9_]{10,}\.[A-Za-z0-9_-]{10,}/g },
      { name: 'API Key Pattern', regex: /(api[_-]?key|apiKey|apikey|api[_-]?secret|apiSecret)['"]?\s*[:=]\s*['"][a-zA-Z0-9_-]{24,}['"]/g },
      { name: 'Access Token', regex: /(access[_-]?token|accessToken)['"]?\s*[:=]\s*['"][a-zA-Z0-9_-]{20,}['"]/g },
      { name: 'CircleCI Token', regex: /circle-token\s*[:=]\s*[a-f0-9]{40}/g },
      { name: 'Password Assignment', regex: /(password|passwd|pwd|secret)['"]?\s*[:=]\s*['"](?!var\(--)[^'"]{8,}['"]/gi },
      { name: 'Basic Auth in URL', regex: /https?:\/\/[a-zA-Z0-9._-]+:[^@\/\s]{3,}@[a-zA-Z0-9.-]+/g }
    ],
    LOW: [
      { name: 'Firebase Config', regex: /['"]AIza[0-9A-Za-z-_]{35}['"][\s\S]{0,500}(?:firebaseapp\.com|firebaseio\.com)/g },
      { name: 'Datadog APP Key', regex: /(DD_APP_KEY|datadog_app_key)['"]?\s*[:=]\s*['"][a-f0-9]{32,}['"]/g }
    ]
  };

  // Common test values to exclude (reduce false positives)
  const testValuePatterns = [
    /^test/i,
    /^example/i,
    /^sample/i,
    /^dummy/i,
    /^placeholder/i,
    /^your[_-]?/i,
    /^my[_-]?/i,
    /xxx+/i,
    /000+/,
    /111+/,
    /123+/,
    /abc+/i,
    /lorem/i,
    /ipsum/i,
    /^null$/i,
    /^undefined$/i,
    /^false$/i,
    /^true$/i,
    /^default/i,
    /^changeme/i,
    /^replace/i,
    /^TODO/i,
    /^FIXME/i,
    /^fake/i,
    /^mock/i,
    /^demo/i,
    /^temp\b/i,
    /\$\{.*\}/,      // Template literal placeholders like ${API_KEY}
    /^<[A-Z_]+>/,    // Angle-bracket placeholders like <YOUR_API_KEY>
    /^\[.+\]$/,      // Bracket placeholders like [API_KEY]
    /^v\d+(\.\d+)*$/,                // Version strings like v1.2.3
    /YOUR_API_KEY/i,                  // Config placeholder patterns
    /REPLACE_ME/i,
    /INSERT_KEY_HERE/i,
    /INSERT_TOKEN/i,
    /PUT_YOUR/i,
    /ADD_YOUR/i,
    /ENTER_YOUR/i,
    /^sk_test_/,                      // Stripe test keys
    /^pk_test_/,
    /={2,}$/                          // Base64 padding artifacts (trailing ==)
  ];

  // AWS example/documentation key prefixes to exclude
  const awsExampleKeys = [
    'AKIAEXAMPLE',
    'AKIAIOSFODNN7EXAMPLE',
    'AKIAI44QH8DHBEXAMPLE',
    'AKIAJALEXAMPLE',
    'ASIAEXAMPLE'
  ];

  // Calculate Shannon entropy (helps identify high-entropy secrets)
  function calculateEntropy(str) {
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

  // Check if value appears to be a test/dummy value
  function isTestValue(value) {
    return testValuePatterns.some(pattern => pattern.test(value));
  }

  // Known safe vendor-specific patterns (intentionally public browser tokens)
  const knownSafePatterns = [
    /^NRJS-/,     // New Relic browser agent license key
    /^NRBR-/      // New Relic browser reporting key
  ];

  // Check if a value is a known safe vendor pattern
  function isKnownSafeValue(value) {
    return knownSafePatterns.some(p => p.test(value));
  }

  // Check if match is in a known safe context (vendor-specific public tokens)
  function isKnownSafeContext(value, context) {
    // Webpack build hashes (hex-only strings in webpack chunk loading context)
    if (/^[a-f0-9]{8,32}$/i.test(value) &&
        (context.includes('webpackChunk') || context.includes('__webpack_require__') ||
         context.includes('webpack') || context.includes('chunk'))) {
      return true;
    }
    // Next.js build IDs and static asset hashes (NOT __NEXT_DATA__ props which may contain real secrets)
    if (context.includes('buildId') || context.includes('_next/static')) {
      return true;
    }
    // __NEXT_DATA__ only safe for hex-only build hashes, not real API keys/secrets
    if (context.includes('__NEXT_DATA__') && /^[a-f0-9]{8,32}$/i.test(value)) {
      return true;
    }
    // Cloudflare challenge tokens
    if (context.includes('__cf_chl_') || context.includes('cf-challenge') ||
        context.includes('_cf_translation') || context.includes('cloudflare')) {
      return true;
    }
    // Zendesk widget keys
    if (context.includes('zdassets.com') || context.includes('zendesk') ||
        context.includes('zopim') || context.includes('zE(')) {
      return true;
    }
    // New Relic NREUM transaction names and config values
    if (context.includes('NREUM') || context.includes('transactionName') ||
        context.includes('nr-data.net')) {
      return true;
    }
    // Secret scanner / security tool pattern definitions
    // (e.g., another tool's detection rules containing pattern strings)
    if ((context.includes('pattern:') || context.includes('regex:') || context.includes('pattern/')) &&
        (context.includes('name:') || context.includes('description:')) &&
        (context.includes('confidence') || context.includes('severity') || context.includes('risk'))) {
      return true;
    }
    return false;
  }

  // Check if a match is inside a regex literal, RegExp constructor, or pattern definition object
  // Returns 'regex_literal' | 'regexp_constructor' | 'pattern_definition' | null
  function isInRegexOrPatternDefinition(text, matchIndex, matchValue) {
    const before = text.substring(Math.max(0, matchIndex - 150), matchIndex);
    const after = text.substring(matchIndex + matchValue.length, Math.min(text.length, matchIndex + matchValue.length + 50));

    // Check 1: Regex literal — match is between /.../ delimiters
    // Look for an unescaped opening / before the match
    const regexOpenMatch = before.match(/\/[^\/]*$/);
    if (regexOpenMatch) {
      // Verify the / is likely a regex delimiter, not division
      // Check the character before the opening /
      const openPos = before.length - regexOpenMatch[0].length;
      const charBefore = openPos > 0 ? before[openPos - 1] : '';
      const regexPrecedingChars = ['(', '=', ':', ',', '[', '!', '&', '|', ';', '{', '}', '?', '+', '-', '~', '^', '%', '<', '>', '\n', '\r', '\t', ' ', ''];
      if (regexPrecedingChars.includes(charBefore)) {
        // Check for a closing / after the match
        if (/^[^\/]*\//.test(after)) {
          return 'regex_literal';
        }
      }
    }

    // Check 2: RegExp constructor — new RegExp("...") or RegExp("...")
    if (/(?:new\s+)?RegExp\s*\(\s*['"`][^'"]*$/.test(before)) {
      return 'regexp_constructor';
    }

    // Check 3: Pattern definition object — nearby keys indicate a detection rule
    const widerContext = text.substring(
      Math.max(0, matchIndex - 300),
      Math.min(text.length, matchIndex + matchValue.length + 200)
    );

    const patternDefSignals = [
      /pattern\s*:/i,
      /regex\s*:/i,
      /regexp\s*:/i,
      /rule\s*:/i,
      /detection\s*:/i,
      /signature\s*:/i,
      /matcher\s*:/i
    ];

    const nameSignals = [
      /name\s*:\s*["'][^"']*(?:key|secret|token|password|credential|certificate|private)/i,
      /description\s*:\s*["'][^"']*(?:detect|scan|find|match|check|start|pattern|header)/i,
      /confidence\s*:\s*["'](?:high|medium|low)["']/i
    ];

    const patternCount = patternDefSignals.filter(p => p.test(widerContext)).length;
    const nameCount = nameSignals.filter(p => p.test(widerContext)).length;

    // If we see at least 1 pattern-definition signal AND 1 name/description signal
    if (patternCount >= 1 && nameCount >= 1) {
      return 'pattern_definition';
    }

    return null;
  }

  // Check if a match position is inside a code comment
  function isInComment(text, index) {
    // Check for single-line comment
    const lineStart = text.lastIndexOf('\n', index) + 1;
    const linePrefix = text.substring(lineStart, index);
    if (/(?<!:)\/\//.test(linePrefix)) return true;
    // Check for multi-line comment
    const lastBlockStart = text.lastIndexOf('/*', index);
    if (lastBlockStart !== -1) {
      const lastBlockEnd = text.lastIndexOf('*/', index);
      if (lastBlockEnd < lastBlockStart) return true;
    }
    return false;
  }

  // Check if a value is a UUID (common database/request ID, not a secret)
  function isUUID(value) {
    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(value);
  }

  // Helper: Get line number from text position
  function getLineNumber(text, index) {
    const beforeMatch = text.substring(0, index);
    return (beforeMatch.match(/\n/g) || []).length + 1;
  }

  // Helper: Get extended code context with line numbers
  function getExtendedContext(text, index, linesAround = 5) {
    const allLines = text.split('\n');
    const lineNumber = getLineNumber(text, index);
    const startLine = Math.max(0, lineNumber - linesAround - 1);
    const endLine = Math.min(allLines.length, lineNumber + linesAround);
    
    const contextLines = allLines.slice(startLine, endLine);
    const context = contextLines.join('\n');
    
    return {
      context,
      startLine: startLine + 1,
      endLine: endLine,
      matchLine: lineNumber
    };
  }

  // Scan text content for secrets
  function scan(txt, url, enabledPatterns = []) {
    // Use provided patterns (loaded from storage)
    const allPatternSets = {};
    if (enabledPatterns && enabledPatterns.length > 0) {
      enabledPatterns.forEach(p => {
        // Skip Generic Pattern entirely — removed due to extremely high FP rate
        if (p.id === 'generic-pattern' || p.name === 'Generic Pattern') return;

        // Skip disabled patterns entirely — don't add them to the scan set
        if (p.enabled === false) return;

        if (!allPatternSets[p.risk]) {
          allPatternSets[p.risk] = [];
        }
        try {
          // Add 'g' flag for matchAll() compatibility
          allPatternSets[p.risk].push({ name: p.name, regex: new RegExp(p.regex, 'g') });
        } catch (e) {
          console.error(`Origami: Invalid regex in pattern ${p.name}:`, e);
        }
      });
    } else {
      // Fallback to hardcoded patterns if none provided
      allPatternSets.CRITICAL = patterns.CRITICAL;
      allPatternSets.HIGH = patterns.HIGH;
      allPatternSets.MEDIUM = patterns.MEDIUM;
      allPatternSets.LOW = patterns.LOW;
    }

    // Cross-pattern severity resolution for specific pattern matching
    {

      // Debug: Show what patterns are loaded and their risk levels
      console.log('Origami Debug: Loaded patterns by risk:', {
        CRITICAL: allPatternSets.CRITICAL?.map(p => p.name) || [],
        HIGH: allPatternSets.HIGH?.map(p => p.name) || [],
        MEDIUM: allPatternSets.MEDIUM?.map(p => p.name) || [],
        LOW: allPatternSets.LOW?.map(p => p.name) || []
      });

      // Collect all matches from all patterns first
      const allMatches = [];
      for (const [riskLevel, patternList] of Object.entries(allPatternSets)) {
        if (!Array.isArray(patternList)) continue;
        for (const pattern of patternList) {
          const matches = [...txt.matchAll(pattern.regex)];
          matches.forEach(match => {
            const value = match[0].trim();

            // Extract the actual secret portion for test-value checks (S-13 fix)
            // For key=value patterns like api_key="test123", check the value part, not the full match
            const extractedSecret = value.replace(/^.*?[=:]\s*['"]?/, '').replace(/['"]?\s*$/, '') || value;
            if (value.length < 10 || isTestValue(extractedSecret)) return;
            if (isKnownSafeValue(value)) return;
            if (isUUID(value)) return;

            // Skip Database URL matches inside comments or with test/localhost hostnames
            if (pattern.name === 'Database URL') {
              if (isInComment(txt, match.index)) return;
              if (/(@localhost|@127\.0\.0\.1|@0\.0\.0\.0|@example\.com|@test\b)/i.test(value)) return;
            }

            // Skip AWS example/documentation keys
            if (pattern.name === 'AWS Access Key') {
              if (awsExampleKeys.some(prefix => value.startsWith(prefix))) return;
            }

            // Google browser API keys (AIzaSy prefix) are publishable client-side keys
            // restricted by HTTP referrer -- not secrets, by design embedded in web pages
            if (pattern.name === 'Google Cloud API Key' && /^AIzaSy/.test(value)) return;

            // Skip generic API key pattern matches on CSS hex colors and hash values
            if (pattern.name === 'API Key Pattern') {
              const keyValue = value.replace(/.*?[=:]\s*['"]/, '').replace(/['"]$/, '');
              // Skip if value looks like a CSS hex color (3-8 hex digits)
              if (/^#?[0-9a-fA-F]{3,8}$/.test(keyValue)) return;
              // Skip if value is all lowercase hex (likely a hash like SHA256, not an API key)
              if (/^[0-9a-f]{24,}$/.test(keyValue)) return;
            }

            // Skip Basic Auth in URL false positives (protocol-relative URLs, port numbers, hostnames)
            if (pattern.name === 'Basic Auth in URL') {
              if (isInComment(txt, match.index)) return;
              const authMatch = value.match(/https?:\/\/[^:]+:([^@]+)@/);
              const password = authMatch ? authMatch[1] : '';
              if (/^\d+$/.test(password)) return;
              if (password.length < 8) return;
              if (/^[a-zA-Z][a-zA-Z0-9.-]*$/.test(password) && password.includes('.')) return;
              if (calculateEntropy(password) < 3.5) return;
            }

            // Validate JWT tokens by decoding header (must contain 'alg' field per RFC 7519)
            if (pattern.name === 'JWT Token') {
              try {
                const headerPart = value.split('.')[0].replace(/-/g, '+').replace(/_/g, '/');
                const decoded = atob(headerPart);
                const parsed = JSON.parse(decoded);
                if (!parsed.alg) return;
                // Skip consent management JWTs (OneTrust, etc.) -- public configuration tokens
                try {
                  const payloadPart = value.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
                  const payload = JSON.parse(atob(payloadPart));
                  if (payload.otJwtVersion || payload.consentType) return;
                  // App identity/config JWTs with no user-specific claims
                  if (payload.appId && payload.network && !payload.sub && !payload.email && !payload.userId) return;
                } catch (e) { /* payload decode failed, keep finding */ }
              } catch (e) { return; }
            }

            // Skip password-related UI text and descriptive strings (not actual credentials)
            if (pattern.name === 'Password Assignment') {
              const extractedVal = value.replace(/^.*?[=:]\s*['"]/, '').replace(/['"]$/, '');
              if (/^password\s+(?:quality|strength|must|should|is\s|has\s|cannot|can\s|required|policy|hint|reset|forgot|change|confirm)/i.test(extractedVal)) return;
              // Skip values ending with ? -- UI prompts/labels in any language, not credentials
              if (/\?\s*$/.test(extractedVal)) return;
              // Skip snake_case/kebab-case identifiers with 2+ segments (code identifiers, not passwords)
              if (/^[a-z][a-z0-9]*(?:[_-][a-z0-9]+){1,}$/.test(extractedVal)) return;
              // Skip if extracted value contains JS code patterns (minified code captured between quotes)
              if (/[\(\)\{\}].*[\(\)\{\}]/.test(extractedVal) && (/(?:catch|try|return|function|const|let|var|throw|null|void|typeof)\b/.test(extractedVal) || /\|\||&&/.test(extractedVal))) return;
            }

            // Validate Google OAuth2 Refresh Token matches (P27/P30: reduce URL and minified code FPs)
            if (pattern.name === 'Google OAuth2 Refresh Token') {
              // Skip protocol-relative URLs (//www.example.com)
              if (/^1\/\/[a-zA-Z][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(value)) return;
              // Skip if match is embedded in continuous base64 data (not a standalone token)
              const b64Before = txt.substring(Math.max(0, match.index - 16), match.index);
              const b64After = txt.substring(match.index + value.length, Math.min(txt.length, match.index + value.length + 16));
              if (/[A-Za-z0-9+\/]{16}$/.test(b64Before) && /^[A-Za-z0-9+\/]{16}/.test(b64After)) return;
              // Strip the 1// prefix and validate the token body
              const tokenBody = value.replace(/^1\/\//, '');
              // Real base64url tokens virtually always contain uppercase (P(no uppercase in 43+ chars) ~ 10^-10)
              if (!/[A-Z]/.test(tokenBody)) return;
              // URL paths use hyphens as word separators; real tokens have ~1.6% hyphens
              const hyphenRatio = (tokenBody.match(/-/g) || []).length / tokenBody.length;
              if (hyphenRatio > 0.10) return;
            }

            // Check for known safe context
            const nearbyContext = txt.substring(Math.max(0, match.index - 200), Math.min(txt.length, match.index + 200));
            if (isKnownSafeContext(value, nearbyContext)) return;

            // Check for regex/pattern definition context (false positive)
            const patternContext = isInRegexOrPatternDefinition(txt, match.index, value);
            if (patternContext === 'regex_literal' || patternContext === 'regexp_constructor') {
              // Definitively not a secret — skip entirely
              console.log('Origami Debug: Skipping regex context match:', {
                value: value.substring(0, 50),
                contextType: patternContext,
                pattern: pattern.name
              });
              return;
            }

            // Entropy check for generic/context-based patterns (filter low-randomness values)
            const entropyFilteredPatterns = [
              'API Key Pattern', 'Access Token', 'Client Secret (UUID)',
              'Password Assignment'
            ];
            if (entropyFilteredPatterns.includes(pattern.name)) {
              const keyValue = value.replace(/.*?[=:]\s*['"]/, '').replace(/['"]$/, '');
              // Higher entropy threshold for generic patterns (API Key Pattern, Access Token)
              const defaultThreshold = (typeof ORIGAMI_ENTROPY_THRESHOLD !== 'undefined') ? ORIGAMI_ENTROPY_THRESHOLD : 3.5;
              const threshold = (pattern.name === 'API Key Pattern' || pattern.name === 'Access Token') ? 4.5 : defaultThreshold;
              if (calculateEntropy(keyValue) < threshold) return;
              // Skip purely alphabetic or numeric values (not real keys)
              if (/^[a-zA-Z]+$/.test(keyValue) || /^[0-9]+$/.test(keyValue)) return;
            }

            allMatches.push({
              value: value,
              pattern: pattern.name,
              risk: riskLevel,
              index: match.index,
              patternContext: patternContext || undefined
            });
          });
        }
      }

      // Group matches by normalized secret value (extract actual key from context)
      const secretGroups = new Map();

      allMatches.forEach(match => {
        // Normalize the secret value using shared canonical function
        const normalizedKey = origamiNormalizeSecretKey(match.value);

        if (!secretGroups.has(normalizedKey)) {
          secretGroups.set(normalizedKey, []);
        }
        secretGroups.get(normalizedKey).push(match);
      });

      // Process each unique secret and determine highest severity
      secretGroups.forEach((matches, normalizedKey) => {
        if (seen.has(normalizedKey)) return;
        seen.add(normalizedKey);

        // Collect all matched patterns and determine highest severity
        let highestRisk = matches[0].risk;
        let highestPatternName = matches[0].pattern;
        const allMatchedPatterns = [];
        // Use shared severity order from constants.js
        const severityOrder = (typeof ORIGAMI_SEVERITY_ORDER !== 'undefined') ? ORIGAMI_SEVERITY_ORDER : { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };

        matches.forEach(match => {
          allMatchedPatterns.push({ name: match.pattern, risk: match.risk });

          const currentScore = origamiSeverityScore(match.risk);
          const highestScore = origamiSeverityScore(highestRisk);

          if (currentScore < highestScore) {
            highestRisk = match.risk;
            highestPatternName = match.pattern;
          }
        });

        // Sort patterns by severity (highest first) and deduplicate
        const uniquePatterns = new Map();
        allMatchedPatterns.forEach(p => {
          if (!uniquePatterns.has(p.name) || (origamiSeverityScore(p.risk) < origamiSeverityScore(uniquePatterns.get(p.name).risk))) {
            uniquePatterns.set(p.name, p);
          }
        });

        const sortedPatterns = Array.from(uniquePatterns.values())
          .sort((a, b) => origamiCompareSeverity(a.risk, b.risk))
          .map(p => p.name);

        // Firebase client API keys are intentionally public -- resolve dual-match to LOW
        const hasGoogleAPIPattern = sortedPatterns.some(p => p.toLowerCase().includes('google') && p.toLowerCase().includes('api'));
        const hasFirebasePattern = sortedPatterns.some(p => p.toLowerCase().includes('firebase'));
        if (hasGoogleAPIPattern && hasFirebasePattern) {
          highestRisk = 'LOW';
          highestPatternName = 'Firebase Config';
        }

        // Use the first match for context (preferably the one with highest severity)
        const primaryMatch = matches.find(m => m.risk === highestRisk) || matches[0];

        // Google Maps API keys in embed URLs are intentionally client-side -- downgrade to MEDIUM
        if (hasGoogleAPIPattern && !hasFirebasePattern) {
          // Check surrounding text context (primaryMatch.context is not set; use the text around the index)
          const contextStart = Math.max(0, primaryMatch.index - 200);
          const contextEnd = Math.min(txt.length, primaryMatch.index + primaryMatch.value.length + 200);
          const matchContext = txt.substring(contextStart, contextEnd);
          if (/maps\.google|googleapis\.com\/maps|maps\.googleapis/i.test(matchContext)) {
            highestRisk = 'MEDIUM';
            highestPatternName = 'Google Maps API Key (client-side)';
          }
        }

        // Google API keys default to MEDIUM -- exposure risks billing abuse and quota exhaustion.
        // The API validator will upgrade to HIGH/CRITICAL if dangerous services are enabled.
        if (highestPatternName === 'Google Cloud API Key' && highestRisk === 'HIGH') {
          highestRisk = 'MEDIUM';
        }
        const contextInfo = getExtendedContext(txt, primaryMatch.index, 5);

        // Propagate patternContext from any match in the group
        const groupPatternContext = matches.find(m => m.patternContext)?.patternContext || undefined;

        // Debug logging for Google API keys (masked to prevent console leakage)
        if (normalizedKey.includes('AIza')) {
          console.log('Origami Debug: Scanner found Google API key:', {
            normalizedKey: normalizedKey.substring(0, 8) + '****',
            matchedPatterns: sortedPatterns,
            finalRisk: highestRisk,
            finalPattern: highestPatternName
          });
        }

        results.push({
          url: url,
          key: normalizedKey.slice(0, 16) + '...' + normalizedKey.slice(-10),
          full_key: normalizedKey,
          risk: highestRisk,
          pattern_matched: highestPatternName,
          patterns_matched: sortedPatterns.length > 1 ? sortedPatterns : undefined,
          length: normalizedKey.length,
          lineNumber: contextInfo.matchLine,
          codeContext: contextInfo.context,
          source: url,
          matchedText: normalizedKey,
          patternContext: groupPatternContext,
          timestamp: new Date().toISOString(),
          uri: url
        });
      });

    }
  }

  // Extract Firebase configuration objects from JavaScript text
  function extractFirebaseConfigs(text) {
    const configs = [];
    // Match Firebase config objects: apiKey + at least one of authDomain|databaseURL|projectId|storageBucket
    const configPattern = /(?:firebase|fire)(?:Config|App|config|app)?\s*[:=]\s*\{([^}]{50,800})\}/gi;
    const genericObjPattern = /\{([^}]{50,800})\}/g;

    const candidates = [];
    let match;
    while ((match = configPattern.exec(text)) !== null) {
      candidates.push(match[1]);
    }
    // Also scan generic objects that contain apiKey
    while ((match = genericObjPattern.exec(text)) !== null) {
      if (/apiKey\s*[:=]/.test(match[1]) && /(?:authDomain|databaseURL|projectId|storageBucket)\s*[:=]/.test(match[1])) {
        candidates.push(match[1]);
      }
    }

    if (candidates.length > 0) {
      console.log('Origami: Firebase config candidates found:', candidates.length);
    }

    const seenKeys = new Set();
    for (const body of candidates) {
      const extract = (key) => {
        const m = body.match(new RegExp(key + '\\s*[:=]\\s*["\']([^"\']+)["\']'));
        return m ? m[1] : null;
      };

      const apiKey = extract('apiKey');
      if (!apiKey) {
        console.log('Origami: Firebase config candidate rejected: no apiKey field found');
        continue;
      }
      if (!apiKey.startsWith('AIza')) {
        console.log('Origami: Firebase config candidate rejected: apiKey does not start with AIza:', apiKey.substring(0, 10));
        continue;
      }
      if (seenKeys.has(apiKey)) continue;
      seenKeys.add(apiKey);

      const authDomain = extract('authDomain');
      const databaseURL = extract('databaseURL');
      let projectId = extract('projectId');
      const storageBucket = extract('storageBucket');
      const messagingSenderId = extract('messagingSenderId');
      const appId = extract('appId');

      // Derive projectId from authDomain if missing
      if (!projectId && authDomain) {
        projectId = authDomain.replace('.firebaseapp.com', '');
      }

      // Derive databaseURL from projectId if missing
      const derivedDatabaseURL = databaseURL || (projectId ? `https://${projectId}-default-rtdb.firebaseio.com` : null);

      configs.push({
        apiKey,
        authDomain: authDomain || null,
        databaseURL: derivedDatabaseURL,
        projectId: projectId || null,
        storageBucket: storageBucket || null,
        messagingSenderId: messagingSenderId || null,
        appId: appId || null
      });
    }

    return configs;
  }

  // Fetch and scan a JavaScript file
  async function scanJsFile(url, enabledPatterns = []) {
    if (scannedUrls.has(url)) return; // Already scanned
    scannedUrls.add(url);

    try {
      const response = await fetch(url, { credentials: 'include' });
      if (!response.ok) return;
      const text = await response.text();
      scan(text, url, enabledPatterns);
      // Also extract Firebase configs from external scripts
      const configs = extractFirebaseConfigs(text);
      configs.forEach(c => {
        if (!firebaseConfigs.some(existing => existing.apiKey === c.apiKey)) {
          firebaseConfigs.push(c);
        }
      });
    } catch (error) {
      console.debug(`Origami: Could not fetch ${url}:`, error.message);
    }
  }

  // Load patterns from storage
  async function loadEnabledPatterns() {
    return new Promise((resolve) => {
      chrome.storage.local.get(['secret_patterns'], (data) => {
        if (data.secret_patterns) {
          // Filter to enabled patterns only
          const enabled = data.secret_patterns.filter(p => p.enabled !== false);
          resolve(enabled);
        } else {
          // No patterns in storage, use empty array (will fallback to hardcoded)
          resolve([]);
        }
      });
    });
  }

  // Collected Firebase configs across all scanned texts
  const firebaseConfigs = [];

  // Main scanning logic
  async function performScan(legacyCustomPatterns = []) {
    results.length = 0;
    seen.clear();
    scannedUrls.clear();
    firebaseConfigs.length = 0;

    // Load patterns from storage
    const storedPatterns = await loadEnabledPatterns();

    // Merge with legacy custom patterns (for backward compatibility)
    const enabledPatterns = storedPatterns.length > 0 ? storedPatterns : legacyCustomPatterns;

    // Helper: scan text for secrets AND extract Firebase configs
    function scanAndExtract(text, url) {
      scan(text, url, enabledPatterns);
      const configs = extractFirebaseConfigs(text);
      configs.forEach(c => {
        if (!firebaseConfigs.some(existing => existing.apiKey === c.apiKey)) {
          firebaseConfigs.push(c);
        }
      });
    }

    // 1. Scan inline scripts (batched to avoid blocking the main thread on large pages)
    const inlineScripts = Array.from(document.querySelectorAll('script:not([src])'));
    const batchSize = (typeof ORIGAMI_INLINE_SCRIPT_BATCH_SIZE !== 'undefined') ? ORIGAMI_INLINE_SCRIPT_BATCH_SIZE : 50;
    for (let i = 0; i < inlineScripts.length; i += batchSize) {
      const batch = inlineScripts.slice(i, i + batchSize);
      batch.forEach(script => {
        if (script.textContent) {
          scanAndExtract(script.textContent, location.href + ' (inline script)');
        }
      });
      // Yield to main thread between batches
      if (i + batchSize < inlineScripts.length) {
        await new Promise(resolve => setTimeout(resolve, 0));
      }
    }

    // 2. Scan external scripts from same origin
    const externalScripts = document.querySelectorAll('script[src]');
    const scanPromises = [];

    externalScripts.forEach(script => {
      const url = script.src;
      // Only scan same-origin scripts for security
      if (url.startsWith(location.origin)) {
        scanPromises.push(scanJsFile(url, enabledPatterns));
      }
    });

    // 3. Discover and scan JS files referenced in HTML
    try {
      const htmlResponse = await fetch(location.href, { credentials: 'include' });
      const html = await htmlResponse.text();

      // Also extract Firebase configs from HTML itself
      const htmlConfigs = extractFirebaseConfigs(html);
      htmlConfigs.forEach(c => {
        if (!firebaseConfigs.some(existing => existing.apiKey === c.apiKey)) {
          firebaseConfigs.push(c);
        }
      });

      const jsFileMatches = html.matchAll(/["'](\/[^"']*\.js[^"']*)["']/gi);

      for (const match of jsFileMatches) {
        try {
          const url = new URL(match[1], location.origin).href;
          if (url.startsWith(location.origin) && !scannedUrls.has(url)) {
            scanPromises.push(scanJsFile(url, enabledPatterns));
          }
        } catch (e) {
          // Invalid URL, skip
        }
      }
    } catch (error) {
      console.debug('Origami: Could not fetch page HTML:', error.message);
    }

    // Wait for all scans to complete
    await Promise.all(scanPromises);

    if (firebaseConfigs.length > 0) {
      console.log('Origami: Extracted Firebase configs:', firebaseConfigs.map(c => ({
        projectId: c.projectId,
        apiKey: c.apiKey.substring(0, 8) + '****'
      })));
    }

    return results;
  }

  // Listen for messages from popup or background script
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'scanNow') {
      performScan().then(findings => {
        sendResponse({ findings: findings });
      });
      return true; // Will respond asynchronously
    } else if (request.action === 'getFindings') {
      sendResponse({ findings: results });
      return false;
    }
  });

  // Auto-scan on page load
  try {
    // Get settings to check if we should auto-scan
    chrome.storage.sync.get(['settings'], async (data) => {
      const settings = data.settings || { 
        notifications_enabled: true, 
        badge_enabled: true,
        auto_scan_enabled: true 
      };
      
      console.log('Origami: Auto-scan setting:', settings.auto_scan_enabled);
      
      if (settings.auto_scan_enabled !== false) {
        console.log('Origami: Starting auto-scan (secrets + security analysis)...');
        
        // Step 1: Scan for secrets
        const findings = await performScan();
        
        console.log('Origami: Secret scan complete, found', findings.length, 'secrets');
        
        // Send findings to background script (even if empty)
        chrome.runtime.sendMessage({
          action: 'scanComplete',
          findings: findings,
          firebaseConfigs: firebaseConfigs.length > 0 ? firebaseConfigs : undefined,
          url: location.href
        });
        
        // Step 2: Run security analysis (cookies, headers, vulnerabilities, technologies)
        console.log('Origami: Running security analysis...');

        // Wait for analyzer-coordinator to load using CustomEvent (no polling race condition)
        const waitForAnalyzer = (timeout = 10000) => {
          return new Promise((resolve, reject) => {
            if (typeof window.runAllAnalyzers === 'function') {
              return resolve();
            }

            let settled = false;

            const onReady = () => {
              if (settled) return;
              settled = true;
              clearTimeout(timer);
              resolve();
            };

            // Listen for the custom event dispatched by analyzer-coordinator.js
            document.addEventListener('origami-analyzers-ready', onReady, { once: true });

            // Fallback timeout
            const timer = setTimeout(() => {
              if (settled) return;
              settled = true;
              document.removeEventListener('origami-analyzers-ready', onReady);
              // Last-chance check before rejecting
              if (typeof window.runAllAnalyzers === 'function') {
                resolve();
              } else {
                reject(new Error('Security analyzer not loaded after timeout'));
              }
            }, timeout);
          });
        };

        try {
          await waitForAnalyzer(5000);
          const skipSensitiveFiles = settings.auto_scan_sensitive_files === false;
          const analysisResults = await window.runAllAnalyzers({ skipSensitiveFiles });
          console.log('Origami: Security analysis complete:', {
            cookies: analysisResults.cookies?.length || 0,
            headers: analysisResults.headers?.length || 0,
            vulnerabilities: analysisResults.vulnerabilities?.length || 0,
            technologies: analysisResults.technologies?.length || 0
          });

          chrome.runtime.sendMessage({
            action: 'securityAnalysisComplete',
            results: analysisResults,
            url: location.href
          });
        } catch (error) {
          console.error('Origami:', error.message);
        }
      } else {
        console.log('Origami: Auto-scan is disabled in settings');
      }
    });
  } catch (error) {
    console.error('Origami: Initialization error:', error);
  }
})();

