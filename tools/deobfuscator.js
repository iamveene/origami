// Origami JavaScript Deobfuscator
// Beautifies and deobfuscates JavaScript code

class JSDeobfuscator {
  constructor() {
    this.patterns = [];
  }

  // Main deobfuscation function
  deobfuscate(code) {
    let result = code;

    // Step 1: Beautify/format code
    result = this.beautify(result);

    // Step 2: Decode common encodings
    result = this.decodeStrings(result);

    // Step 3: Simplify string concatenations
    result = this.simplifyStringConcat(result);

    // Step 4: Evaluate simple expressions
    result = this.evaluateExpressions(result);

    // Step 5: Remove dead code
    result = this.removeDeadCode(result);

    // Step 6: Rename obfuscated variables (basic)
    result = this.renameVariables(result);

    return result;
  }

  // Beautify JavaScript code
  beautify(code) {
    try {
      // Basic beautification
      let beautified = code;

      // Add newlines after semicolons and braces
      beautified = beautified.replace(/;/g, ';\n');
      beautified = beautified.replace(/{/g, '{\n');
      beautified = beautified.replace(/}/g, '\n}\n');

      // Add spaces around operators
      beautified = beautified.replace(/([+\-*/%=<>!&|])/g, ' $1 ');

      // Fix multiple spaces
      beautified = beautified.replace(/  +/g, ' ');

      // Basic indentation
      beautified = this.indent(beautified);

      return beautified;
    } catch (error) {
      return code; // Return original if beautification fails
    }
  }

  // Add basic indentation
  indent(code) {
    const lines = code.split('\n');
    let indentLevel = 0;
    const indentSize = 2;

    return lines.map(line => {
      const trimmed = line.trim();
      
      if (trimmed.startsWith('}')) {
        indentLevel = Math.max(0, indentLevel - 1);
      }

      const indented = ' '.repeat(indentLevel * indentSize) + trimmed;

      if (trimmed.endsWith('{')) {
        indentLevel++;
      }

      return indented;
    }).join('\n');
  }

  // Decode encoded strings
  decodeStrings(code) {
    let result = code;

    // Decode hex strings
    result = result.replace(/\\x([0-9A-Fa-f]{2})/g, (match, hex) => {
      return String.fromCharCode(parseInt(hex, 16));
    });

    // Decode unicode escapes
    result = result.replace(/\\u([0-9A-Fa-f]{4})/g, (match, hex) => {
      return String.fromCharCode(parseInt(hex, 16));
    });

    // Decode base64 (if not too risky)
    result = result.replace(/atob\(['"]([A-Za-z0-9+/=]+)['"]\)/g, (match, b64) => {
      try {
        const decoded = atob(b64);
        return `"${this.escapeString(decoded)}"`;
      } catch {
        return match;
      }
    });

    return result;
  }

  // Simplify string concatenations
  simplifyStringConcat(code) {
    // Simple string concatenation: "a" + "b" -> "ab"
    return code.replace(/["']([^"']*)["']\s*\+\s*["']([^"']*)["']/g, '"$1$2"');
  }

  // Evaluate simple expressions
  evaluateExpressions(code) {
    let result = code;

    // Evaluate simple math
    const mathPattern = /(\d+)\s*([+\-*/%])\s*(\d+)/g;
    result = result.replace(mathPattern, (match, a, op, b) => {
      try {
        const numA = parseInt(a);
        const numB = parseInt(b);
        let res;

        switch (op) {
          case '+': res = numA + numB; break;
          case '-': res = numA - numB; break;
          case '*': res = numA * numB; break;
          case '/': res = numB !== 0 ? Math.floor(numA / numB) : match; break;
          case '%': res = numB !== 0 ? numA % numB : match; break;
          default: return match;
        }

        return res.toString();
      } catch {
        return match;
      }
    });

    return result;
  }

  // Remove dead code
  removeDeadCode(code) {
    let result = code;

    // Remove if (false) blocks
    result = result.replace(/if\s*\(\s*false\s*\)\s*{[^}]*}/g, '');

    // Remove unreachable code after return
    result = result.replace(/return\s+[^;]+;\s*[^}]+/g, match => {
      const returnStatement = match.match(/return\s+[^;]+;/)[0];
      return returnStatement;
    });

    return result;
  }

  // Rename obfuscated variables (very basic)
  renameVariables(code) {
    // Detect single-letter or hex-like variable names
    const obfuscatedPattern = /\b_0x[0-9a-f]{4,}\b/gi;
    const matches = code.match(obfuscatedPattern);

    if (!matches) return code;

    const uniqueVars = [...new Set(matches)];
    let result = code;
    let counter = 1;

    uniqueVars.forEach(varName => {
      const newName = `var_${counter++}`;
      const regex = new RegExp('\\b' + varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'g');
      result = result.replace(regex, newName);
    });

    return result;
  }

  // Escape string for safe output
  escapeString(str) {
    return str
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r')
      .replace(/\t/g, '\\t');
  }

  // Detect obfuscation type
  detectObfuscationType(code) {
    const types = [];

    // Check for common obfuscators
    if (code.includes('_0x') || /\b[a-f0-9]{32,}\b/i.test(code)) {
      types.push('Hex-based obfuscation');
    }

    if (code.match(/eval\s*\(/)) {
      types.push('Eval-based obfuscation');
    }

    if (code.match(/atob\s*\(/)) {
      types.push('Base64 encoding');
    }

    if (code.match(/String\.fromCharCode/)) {
      types.push('Character code obfuscation');
    }

    if (code.split('\n').length < 10 && code.length > 1000) {
      types.push('Minified code');
    }

    if (code.match(/\[\s*["'][^"']*["']\s*\]\s*\(\s*["'][^"']*["']\s*\)/)) {
      types.push('String array rotation');
    }

    return types.length > 0 ? types : ['Unknown or not obfuscated'];
  }

  // Analyze code complexity
  analyzeComplexity(code) {
    return {
      lines: code.split('\n').length,
      characters: code.length,
      functions: (code.match(/function\s+\w+/g) || []).length,
      variables: (code.match(/\b(var|let|const)\s+\w+/g) || []).length,
      evals: (code.match(/eval\s*\(/g) || []).length,
      obfuscated: this.detectObfuscationType(code)
    };
  }
}

// Export for use in extension
if (typeof module !== 'undefined' && module.exports) {
  module.exports = JSDeobfuscator;
}

