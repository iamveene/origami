// Origami Client-Side Encryption Weakness Detector
// Audits crypto library usage, key management, cipher selection, and anti-patterns

class CryptoAuditor {
  constructor() {
    this.findings = { libraries: [], operations: [], issues: [] };
  }

  _getAllScriptContent() {
    try {
      const scripts = document.querySelectorAll('script:not([src])');
      return Array.from(scripts).map(s => s.textContent || '').join('\n');
    } catch (e) {
      return '';
    }
  }

  async analyze() {
    this.findings = { libraries: [], operations: [], issues: [] };

    this._allScript = this._getAllScriptContent();

    this._detectCryptoLibraries();
    this._scanForHardcodedKeys();
    this._detectWeakCiphers();
    this._checkIVGeneration();
    this._checkKeyDerivation();
    this._detectECBMode();
    this._checkMissingAuthentication();
    this._scanWebCryptoAPI();
    this._detectCryptoAntiPatterns();

    this._deduplicateIssues();
    this._allScript = null;

    return this.findings;
  }

  _detectCryptoLibraries() {
    const libraryChecks = [
      { name: 'CryptoJS', globals: ['CryptoJS'], scriptPatterns: [/CryptoJS\./g, /crypto-js/gi] },
      { name: 'TweetNaCl', globals: ['nacl'], scriptPatterns: [/nacl\./g, /tweetnacl/gi] },
      { name: 'libsodium', globals: ['sodium', '_sodium'], scriptPatterns: [/libsodium/gi, /sodium\./g] },
      { name: 'SJCL', globals: ['sjcl'], scriptPatterns: [/sjcl\./g] },
      { name: 'node-forge', globals: ['forge'], scriptPatterns: [/forge\.pki/g, /forge\.cipher/g, /node-forge/gi] },
      { name: 'JSEncrypt', globals: ['JSEncrypt'], scriptPatterns: [/JSEncrypt/g, /jsencrypt/gi] },
      { name: 'asmCrypto', globals: ['asmCrypto'], scriptPatterns: [/asmCrypto/g, /asmcrypto/gi] },
      { name: 'elliptic', globals: ['elliptic'], scriptPatterns: [/elliptic\./g] },
      { name: 'openpgp', globals: ['openpgp'], scriptPatterns: [/openpgp\./g] },
      { name: 'Web Crypto API', globals: [], scriptPatterns: [/crypto\.subtle/g] }
    ];

    for (const lib of libraryChecks) {
      for (const global of lib.globals) {
        try {
          if (typeof window[global] !== 'undefined') {
            this.findings.libraries.push({
              name: lib.name,
              detectedVia: 'window.' + global,
              version: this._tryGetVersion(window[global])
            });
          }
        } catch (e) { /* access denied */ }
      }
    }

    const scriptContent = this._allScript;

    for (const lib of libraryChecks) {
      for (const pattern of lib.scriptPatterns) {
        const matches = scriptContent.match(pattern);
        if (matches && matches.length > 0) {
          const alreadyFound = this.findings.libraries.some(l => l.name === lib.name);
          if (!alreadyFound) {
            this.findings.libraries.push({
              name: lib.name,
              detectedVia: 'script-content',
              matchCount: matches.length
            });
          }
        }
      }
    }
  }

  _tryGetVersion(libObj) {
    if (!libObj) return null;
    return libObj.version || libObj.VERSION || libObj.lib?.version || null;
  }

  _scanForHardcodedKeys() {
    const allScript = this._allScript;
    if (!allScript) return;
    const lines = allScript.split('\n');

    const hexKeyPattern = /(?:['"`])([0-9a-fA-F]{32,128})(?:['"`])/g;

    const cryptoContextPatterns = [
      /CryptoJS/i, /\.encrypt\(/i, /\.decrypt\(/i, /createCipher/i,
      /crypto\.subtle/i, /forge\.cipher/i, /sjcl\.encrypt/i,
      /AES|DES|Blowfish|RC4/i, /secretKey|encryptionKey|aesKey|cryptoKey/i,
      /nacl\.secretbox/i, /sodium\.crypto/i
    ];

    const reportedKeys = new Set();
    const wellKnownHashes = new Set([
      '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a', // SHA-256("{}")
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', // SHA-256("")
    ]);

    for (let i = 0; i < lines.length; i++) {
      let match;
      hexKeyPattern.lastIndex = 0;
      while ((match = hexKeyPattern.exec(lines[i])) !== null) {
        const hexValue = match[1];

        if (reportedKeys.has(hexValue)) continue;
        if (wellKnownHashes.has(hexValue)) continue;

        // Filter out low-entropy hex strings (SHA hashes, content hashes, UUIDs)
        const entropyFn = window.origamiCalculateStringEntropy;
        if (entropyFn && entropyFn(hexValue) < 3.5) continue;
        // Skip 40-char (SHA-1/git) and 64-char (SHA-256) strings unless near crypto context
        if (hexValue.length === 40 || hexValue.length === 64) {
          // In minified code (long lines), "key" appears everywhere for non-crypto reasons
          // (Object.keys, React key props, map keys, etc.) -- require stronger evidence
          const isMinified = lines[i].length > 500;
          const sameLinePattern = isMinified
            ? /(?:secretKey|encryptionKey|aesKey|cryptoKey|hmacKey|\.encrypt\(|\.decrypt\(|createCipher)/i
            : /(?:key|secret|encrypt|decrypt|cipher|aes|des|hmac)/i;
          if (!sameLinePattern.test(lines[i])) continue;
        }

        const contextStart = Math.max(0, i - 3);
        const contextEnd = Math.min(lines.length - 1, i + 3);
        const contextLines = lines.slice(contextStart, contextEnd + 1).join('\n');

        // In minified code, broad patterns like /AES|DES/ match too frequently;
        // use only strong crypto function-call patterns for context matching
        const strongCryptoContextPatterns = [
          /CryptoJS/i, /\.encrypt\(/i, /\.decrypt\(/i, /createCipher/i,
          /crypto\.subtle/i, /forge\.cipher/i, /sjcl\.encrypt/i,
          /nacl\.secretbox/i, /sodium\.crypto/i,
          /secretKey|encryptionKey|aesKey|cryptoKey/i
        ];
        const isMinifiedContext = lines.slice(contextStart, contextEnd + 1).some(l => l.length > 500);
        const hasCryptoContext = isMinifiedContext
          ? strongCryptoContextPatterns.some(p => p.test(contextLines))
          : cryptoContextPatterns.some(p => p.test(contextLines));

        if (hasCryptoContext) {
          const byteLength = hexValue.length / 2;
          const keyType = byteLength === 16 ? 'AES-128' :
                          byteLength === 24 ? 'AES-192' :
                          byteLength === 32 ? 'AES-256' :
                          byteLength === 64 ? 'HMAC-SHA-512' :
                          byteLength + '-byte key';

          // Hash/fingerprint heuristic: if surrounding context indicates the hex
          // value is a hash, digest, or checksum rather than an encryption key,
          // downgrade to INFO since it is not exploitable as a key
          const isHashContext = /hash|digest|sha-?256|sha-?512|sha-?384|sha-?1\b|checksum|fingerprint|verify/i.test(contextLines);
          const severity = isHashContext ? 'INFO' : 'HIGH';

          this.findings.issues.push({
            severity: severity,
            type: 'hardcoded-crypto-key',
            message: 'Hardcoded ' + keyType + ' key found in JavaScript source (' + hexValue.length + ' hex chars)',
            cwe: 'CWE-321',
            evidence: hexValue.substring(0, 8) + '...' + hexValue.substring(hexValue.length - 8),
            line: i + 1,
            context: lines[i].trim().substring(0, 200),
            recommendation: 'Never hardcode cryptographic keys in client-side code. Use server-side key management or key derivation from user input.'
          });

          this.findings.operations.push({
            type: 'hardcoded-key',
            keyLength: byteLength,
            line: i + 1
          });

          reportedKeys.add(hexValue);
        }
      }
    }
  }

  _detectWeakCiphers() {
    const allScript = this._allScript;
    if (!allScript) return;

    const weakCipherPatterns = [
      { pattern: /CryptoJS\.DES\./g, cipher: 'DES', severity: 'HIGH', message: 'DES encryption detected - 56-bit key is trivially brute-forceable' },
      { pattern: /CryptoJS\.TripleDES\./g, cipher: '3DES', severity: 'MEDIUM', message: 'Triple DES detected - deprecated, use AES instead' },
      { pattern: /CryptoJS\.RC4\./g, cipher: 'RC4', severity: 'HIGH', message: 'RC4 stream cipher detected - known to be broken (RFC 7465)' },
      { pattern: /CryptoJS\.Rabbit\./g, cipher: 'Rabbit', severity: 'MEDIUM', message: 'Rabbit cipher detected - non-standard, limited security analysis' },
      { pattern: /CryptoJS\.Blowfish\./g, cipher: 'Blowfish', severity: 'MEDIUM', message: 'Blowfish cipher detected - 64-bit block size vulnerable to birthday attacks' },
      { pattern: /createCipher(?:iv)?\s*\(\s*['"](?:des|des3|rc4|blowfish|bf)/gi, cipher: 'Node-style weak cipher', severity: 'HIGH', message: 'Weak cipher algorithm in createCipher call' },
      { pattern: /algorithm:\s*['"](?:DES|3DES|RC4|RC2|IDEA)/gi, cipher: 'Configured weak cipher', severity: 'HIGH', message: 'Weak cipher configured in encryption options' },
      { pattern: /forge\.cipher\.createCipher\s*\(\s*['"](?:DES|3DES|RC4)/gi, cipher: 'forge weak cipher', severity: 'HIGH', message: 'Weak cipher in node-forge createCipher' }
    ];

    for (const check of weakCipherPatterns) {
      const matches = allScript.match(check.pattern);
      if (matches && matches.length > 0) {
        this.findings.issues.push({
          severity: check.severity,
          type: 'weak-cipher',
          message: check.message,
          cipher: check.cipher,
          cwe: 'CWE-327',
          occurrences: matches.length,
          recommendation: 'Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption.'
        });
        this.findings.operations.push({
          type: 'weak-cipher',
          cipher: check.cipher,
          count: matches.length
        });
      }
    }
  }

  _checkIVGeneration() {
    const allScript = this._allScript;
    if (!allScript) return;
    const lines = allScript.split('\n');

    const zeroIVPatterns = [
      /iv\s*[:=]\s*['"]0{16,}['"]/gi,
      /iv\s*[:=]\s*CryptoJS\.enc\.Hex\.parse\s*\(\s*['"]0+['"]\s*\)/gi,
      /iv\s*[:=]\s*new\s+Uint8Array\s*\(\s*(?:16|12)\s*\)/gi,
      /iv\s*[:=]\s*Buffer\.alloc\s*\(\s*(?:16|12)\s*\)/gi
    ];

    for (const pattern of zeroIVPatterns) {
      const matches = allScript.match(pattern);
      if (matches) {
        this.findings.issues.push({
          severity: 'HIGH',
          type: 'static-iv',
          message: 'Zero or static IV detected - reusing IVs breaks confidentiality guarantees',
          cwe: 'CWE-329',
          occurrences: matches.length,
          evidence: matches[0].substring(0, 100),
          recommendation: 'Generate a fresh random IV for every encryption operation using crypto.getRandomValues() or equivalent.'
        });
      }
    }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const staticIVMatch = line.match(/\biv\s*[:=]\s*(?:CryptoJS\.enc\.(?:Hex|Utf8)\.parse\s*\(\s*)?['"]([^'"]+)['"]/i);
      if (staticIVMatch) {
        const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 5)).join('\n');
        if (/\.encrypt\(|\.createCipher/i.test(context)) {
          this.findings.issues.push({
            severity: 'HIGH',
            type: 'static-iv',
            message: 'Hardcoded IV value found near encryption call - IV must be random per encryption',
            cwe: 'CWE-329',
            line: i + 1,
            evidence: line.trim().substring(0, 150),
            recommendation: 'Use crypto.getRandomValues(new Uint8Array(16)) for AES-CBC or 12 bytes for AES-GCM.'
          });
        }
      }
    }

    // Only flag Math.random() as weak IV if real crypto libraries/APIs are detected.
    // Analytics code commonly uses Math.random() for sampling/ID generation near
    // words like "key" (tracking key, cache key) -- this is not a crypto context.
    const hasCryptoLibrary = this.findings.libraries.length > 0;
    for (let i = 0; i < lines.length; i++) {
      if (/Math\.random\(\)/.test(lines[i])) {
        const context = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 3)).join('\n');
        if (/\biv\b|nonce|salt|random.*(?:byte|encrypt)/i.test(context)) {
          const isMinifiedLine = lines[i].length > 500;
          const isFingerprinting = /fingerprint|canvas.*hash|DFP|collectBrowser|deviceId|visualCanvas/i.test(context);
          this.findings.issues.push({
            severity: (isMinifiedLine || isFingerprinting) ? 'INFO' : (hasCryptoLibrary ? 'HIGH' : 'INFO'),
            type: 'weak-iv-generation',
            message: (isMinifiedLine || isFingerprinting)
              ? 'Math.random() near crypto-like context in ' + (isFingerprinting ? 'fingerprinting code' : 'minified bundle') + ' (likely non-crypto usage)'
              : 'Math.random() used near cryptographic context - not cryptographically secure',
            cwe: 'CWE-338',
            line: i + 1,
            evidence: lines[i].trim().substring(0, 150),
            recommendation: 'Use crypto.getRandomValues() or window.crypto.getRandomValues() for cryptographic randomness.'
          });
        }
      }
    }
  }

  _checkKeyDerivation() {
    const allScript = this._allScript;
    if (!allScript) return;

    const directPasswordPatterns = [
      { pattern: /CryptoJS\.AES\.encrypt\s*\(\s*[^,]{1,200},\s*['"][^'"]{1,30}['"]\s*\)/g, desc: 'CryptoJS.AES.encrypt with string password (auto-derives with insecure EVP_BytesToKey)' },
      { pattern: /CryptoJS\.AES\.encrypt\s*\(\s*[^,]{1,200},\s*(?:password|pass|pwd|secret|key)\s*[,)]/gi, desc: 'CryptoJS encrypt with variable likely containing a password' }
    ];

    for (const check of directPasswordPatterns) {
      const matches = allScript.match(check.pattern);
      if (matches) {
        this.findings.issues.push({
          severity: 'MEDIUM',
          type: 'weak-key-derivation',
          message: check.desc + ' - CryptoJS default uses MD5-based EVP_BytesToKey which is fast and GPU-crackable',
          cwe: 'CWE-916',
          occurrences: matches.length,
          recommendation: 'Use CryptoJS.PBKDF2() with at least 100,000 iterations, or use Web Crypto API with PBKDF2/scrypt.'
        });
      }
    }

    const properKDFPatterns = [
      /PBKDF2/i, /scrypt/i, /argon2/i, /Argon2/i,
      /crypto\.subtle\.deriveKey/i, /crypto\.subtle\.deriveBits/i,
      /crypto\.subtle\.generateKey/i
    ];
    const usesProperKDF = properKDFPatterns.some(p => p.test(allScript));
    const onlyWebCrypto = this.findings.libraries.length > 0 && this.findings.libraries.every(l => l.name === 'Web Crypto API');
    if (!usesProperKDF && this.findings.libraries.length > 0 && !onlyWebCrypto) {
      const hasCryptoOps = /\.encrypt\(|\.decrypt\(/i.test(allScript);
      if (hasCryptoOps) {
        this.findings.issues.push({
          severity: 'LOW',
          type: 'no-kdf-detected',
          message: 'Crypto operations detected but no key derivation function (PBKDF2/scrypt/Argon2) found',
          cwe: 'CWE-916',
          recommendation: 'If deriving keys from passwords, use PBKDF2 with high iteration count, scrypt, or Argon2.'
        });
      }
    }
  }

  _detectECBMode() {
    const allScript = this._allScript;
    if (!allScript) return;

    const explicitECB = allScript.match(/mode\s*:\s*CryptoJS\.mode\.ECB/g);
    if (explicitECB) {
      this.findings.issues.push({
        severity: 'HIGH',
        type: 'ecb-mode',
        message: 'AES-ECB mode explicitly used - ECB does not provide semantic security (identical plaintext blocks produce identical ciphertext)',
        cwe: 'CWE-327',
        occurrences: explicitECB.length,
        recommendation: 'Use AES-GCM (authenticated encryption) or AES-CBC with HMAC. Never use ECB for multi-block data.'
      });
    }

    const cryptoJSEncryptCalls = allScript.match(/CryptoJS\.AES\.encrypt\s*\(/g);
    if (cryptoJSEncryptCalls) {
      const hasModeSetting = /mode\s*:\s*CryptoJS\.mode\./i.test(allScript);
      if (!hasModeSetting) {
        this.findings.issues.push({
          severity: 'LOW',
          type: 'ecb-mode-default',
          message: 'CryptoJS AES encryption found without explicit mode setting - may default to ECB depending on key type',
          cwe: 'CWE-327',
          occurrences: cryptoJSEncryptCalls.length,
          recommendation: 'Always explicitly set mode: CryptoJS.mode.CBC or CryptoJS.mode.GCM with a random IV.'
        });
      }
    }
  }

  _checkMissingAuthentication() {
    const allScript = this._allScript;
    if (!allScript) return;

    const usesCBC = /mode\s*:\s*CryptoJS\.mode\.CBC/i.test(allScript);
    const usesHMAC = /CryptoJS\.Hmac|CryptoJS\.HmacSHA|\.sign\(|hmac/i.test(allScript);
    const usesGCM = /mode\s*:\s*CryptoJS\.mode\.(?:GCM|CCM)/i.test(allScript) ||
                    /AES-GCM|aes-gcm/i.test(allScript);

    if (usesCBC && !usesHMAC && !usesGCM) {
      this.findings.issues.push({
        severity: 'LOW',
        type: 'unauthenticated-encryption',
        message: 'CBC mode used without HMAC - vulnerable to padding oracle attacks (Encrypt-then-MAC pattern missing)',
        cwe: 'CWE-347',
        recommendation: 'Use AES-GCM for authenticated encryption, or apply HMAC-SHA256 over the ciphertext (Encrypt-then-MAC).'
      });
    }
  }

  _scanWebCryptoAPI() {
    const allScript = this._allScript;
    if (!allScript) return;

    if (!/crypto\.subtle/i.test(allScript)) return;

    this.findings.operations.push({ type: 'web-crypto-api', detected: true });

    const importKeyRawPattern = /crypto\.subtle\.importKey\s*\(\s*['"]raw['"]/g;
    const matches = allScript.match(importKeyRawPattern);
    if (matches) {
      this.findings.issues.push({
        severity: 'LOW',
        type: 'web-crypto-raw-import',
        message: 'Web Crypto API importKey with "raw" format - ensure key material is not hardcoded in source',
        cwe: 'CWE-321',
        occurrences: matches.length,
        recommendation: 'Derive keys using crypto.subtle.deriveKey() with PBKDF2 or generate with crypto.subtle.generateKey().'
      });
    }

    const extractablePattern = /crypto\.subtle\.generateKey\s*\([^)]*extractable\s*:\s*true/gi;
    const extractableMatches = allScript.match(extractablePattern);
    if (extractableMatches) {
      this.findings.issues.push({
        severity: 'LOW',
        type: 'web-crypto-extractable-key',
        message: 'Web Crypto API generateKey with extractable: true - key material can be exported from CryptoKey object',
        cwe: 'CWE-312',
        occurrences: extractableMatches.length,
        recommendation: 'Set extractable to false unless you specifically need to export the key.'
      });
    }

    const webCryptoCBC = /['"]AES-CBC['"]/.test(allScript);
    const webCryptoGCM = /['"]AES-GCM['"]/.test(allScript);
    if (webCryptoCBC && !webCryptoGCM) {
      this.findings.issues.push({
        severity: 'LOW',
        type: 'web-crypto-cbc-no-auth',
        message: 'Web Crypto API uses AES-CBC without AES-GCM - CBC does not provide authentication',
        cwe: 'CWE-347',
        recommendation: 'Prefer AES-GCM which provides both encryption and authentication.'
      });
    }
  }

  _detectCryptoAntiPatterns() {
    const allScript = this._allScript;
    if (!allScript) return;
    const lines = allScript.split('\n');
    const isBundledOrMinified = window.origamiIsBundledOrMinified && window.origamiIsBundledOrMinified(allScript);

    const flaggedLines = new Set(this.findings.issues.filter(f => f.type === 'weak-iv-generation').map(f => f.line));

    // Only flag Math.random() as a crypto anti-pattern if real crypto libraries/APIs
    // are present. Without crypto context, "key"/"token" matches are usually
    // analytics tracking keys, cache keys, or sampling IDs.
    const hasCryptoLibrary = this.findings.libraries.length > 0;
    for (let i = 0; i < lines.length; i++) {
      if (/Math\.random\(\)/.test(lines[i]) && !flaggedLines.has(i + 1)) {
        const isMinifiedLine = lines[i].length > 500;
        const context = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 3)).join('\n');
        // Detect module bundle patterns (webpack, CNN-style modules, etc.)
        const isModuleBundle = /(?:self|window)\.modules|__webpack_require__|webpackChunk|\$_mod_/i.test(context);
        if (/(?:key|encrypt|decrypt|cipher|token|secret|hash|salt|\biv\b|nonce)/i.test(context)) {
          this.findings.issues.push({
            severity: (isBundledOrMinified || isMinifiedLine || isModuleBundle) ? 'INFO' : (hasCryptoLibrary ? 'HIGH' : 'INFO'),
            type: 'math-random-crypto',
            message: (isBundledOrMinified || isMinifiedLine || isModuleBundle)
              ? 'Math.random() near crypto-like keywords in bundled/minified code (likely build artifact)'
              : 'Math.random() used in cryptographic context - output is predictable and not suitable for security',
            cwe: 'CWE-338',
            line: i + 1,
            evidence: lines[i].trim().substring(0, 150),
            recommendation: 'Use crypto.getRandomValues() for cryptographically secure random values.'
          });
        }
      }
    }

    for (let i = 0; i < lines.length; i++) {
      if (/btoa\s*\(|atob\s*\(/.test(lines[i])) {
        if (isBundledOrMinified) continue;
        const isMinified = lines[i].length > 500;
        const context = isMinified ? lines[i] : lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 3)).join('\n');
        if (/(?:encrypt|decrypt|secret|password|credential|sensitive|protect)/i.test(context)) {
          this.findings.issues.push({
            severity: 'LOW',
            type: 'base64-as-encryption',
            message: 'Base64 encoding (btoa/atob) used in security context - Base64 is encoding, not encryption',
            cwe: 'CWE-311',
            line: i + 1,
            evidence: lines[i].trim().substring(0, 150),
            recommendation: 'Use proper encryption (AES-256-GCM) instead of Base64 encoding for protecting sensitive data.'
          });
        }
      }
    }

    const xorPatterns = [
      /\^\s*0x[0-9a-fA-F]+/g,
      /charCodeAt.*\^/g,
      /\.map\s*\([^)]*\^/g
    ];

    for (const pattern of xorPatterns) {
      pattern.lastIndex = 0;
      let xorMatch;
      let xorCount = 0;
      let firstMatchIdx = -1;
      while ((xorMatch = pattern.exec(allScript)) !== null) {
        if (firstMatchIdx === -1) firstMatchIdx = xorMatch.index;
        xorCount++;
      }
      if (xorCount >= 3 && firstMatchIdx >= 0) {
        const context = allScript.substring(
          Math.max(0, firstMatchIdx - 100),
          Math.min(allScript.length, firstMatchIdx + 200)
        );
        if (/(?:encrypt|decrypt|cipher|obfuscat|scrambl|encod)/i.test(context)) {
          this.findings.issues.push({
            severity: isBundledOrMinified ? 'INFO' : 'MEDIUM',
            type: 'xor-cipher',
            message: 'XOR cipher pattern detected - XOR encryption is trivially breakable with known-plaintext or frequency analysis',
            cwe: 'CWE-327',
            occurrences: xorCount,
            recommendation: 'Use a standard encryption algorithm (AES-256-GCM, ChaCha20-Poly1305) instead of XOR-based ciphers.'
          });
          break;
        }
      }
    }
  }

  _deduplicateIssues() {
    const seen = new Set();
    this.findings.issues = this.findings.issues.filter(issue => {
      const key = issue.type + ':' + (issue.line || '') + ':' + (issue.cwe || '');
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
}

window.CryptoAuditor = CryptoAuditor;
