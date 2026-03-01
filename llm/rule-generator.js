// Origami AI Rule Generator
// Generates YAML detection templates from CVEs, PoCs, or vulnerability descriptions via LLM

class RuleGenerator {
  constructor() {
    this.templateSchema = {
      required: ['id', 'info', 'matchers'],
      infoRequired: ['name', 'severity'],
      validSeverities: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
      validTargets: ['url', 'body', 'scripts', 'headers', 'cookies', 'storage'],
      validMatcherTypes: ['regex']
    };
  }

  buildPrompt(input, inputType) {
    const typeContext = {
      cve: 'The following is a CVE identifier or CVE description. Generate a detection template that identifies whether a web application is vulnerable to or affected by this CVE.',
      poc: 'The following is a proof-of-concept (PoC) payload or exploit code. Generate a detection template that identifies the vulnerability this PoC targets by detecting indicators in the page.',
      description: 'The following is a vulnerability description. Generate a detection template that detects this vulnerability pattern in web applications.'
    };

    const context = typeContext[inputType] || typeContext.description;

    // Sanitize input that may originate from scan data (attacker-controlled)
    const sanitized = (input || '').replace(/\[TOOL_CALL\]/gi, '[T00L_CALL]')
      .replace(/\[\/TOOL_CALL\]/gi, '[/T00L_CALL]')
      .replace(/\[TOOL_RESULT\]/gi, '[T00L_RESULT]')
      .replace(/\[\/TOOL_RESULT\]/gi, '[/T00L_RESULT]');

    return `You are a security detection rule author. ${context}

INPUT:
${sanitized}

Generate a YAML detection template following this exact schema. The template will be parsed and run against web pages by a browser-based detection engine.

SCHEMA:
- id: unique-kebab-case-id (string, required)
- info:
    name: Human-readable name (string, required)
    severity: One of CRITICAL, HIGH, MEDIUM, LOW, INFO (string, required)
    cwe: CWE identifier like CWE-79 (string, optional)
    tags: list of lowercase tags (array, optional)
- matchers: (array, required, at least one entry)
    - type: regex (string, always "regex")
      target: One of url, body, scripts, headers, cookies, storage (string)
      patterns: list of regex patterns to match (array of strings)
- condition: "or" or "and" (string, optional, defaults to "or")
- extractors: (array, optional)
    - type: regex
      patterns: list of regex patterns to extract matched values

EXAMPLE:
id: exposed-debug-endpoint
info:
  name: Debug Endpoint Exposure
  severity: HIGH
  cwe: CWE-489
  tags:
    - debug
    - exposure
matchers:
  - type: regex
    target: body
    patterns:
      - "(?:__debug__|phpinfo|/debug/|/trace/|/actuator/)"
extractors:
  - type: regex
    patterns:
      - "(?:__debug__|phpinfo|/debug/|/trace/|/actuator/)[^\"'\\s]*"

RULES:
1. Output ONLY valid YAML, no markdown fences, no explanation before or after
2. Patterns must be valid JavaScript regex (no lookbehinds, no named groups)
3. Avoid nested quantifiers (e.g., (a+)+ ) that cause ReDoS
4. Use non-capturing groups (?:...) instead of capturing groups where possible
5. The id must be unique and descriptive in kebab-case
6. Choose the most appropriate target for each matcher (url for URL patterns, body for HTML content, scripts for JS, headers for HTTP headers, cookies for cookie values, storage for localStorage/sessionStorage)
7. Keep patterns focused and specific to minimize false positives
8. severity must be one of: CRITICAL, HIGH, MEDIUM, LOW, INFO`;
  }

  async generateRule(input, inputType) {
    if (!input || typeof input !== 'string' || input.trim().length === 0) {
      throw new Error('Input is required');
    }

    if (!['cve', 'poc', 'description'].includes(inputType)) {
      throw new Error('inputType must be one of: cve, poc, description');
    }

    const prompt = this.buildPrompt(input.trim(), inputType);

    try {
      const response = await this.sendToLLM(prompt);

      if (!response || typeof response !== 'string' || response.trim().length === 0) {
        throw new Error('LLM returned empty response');
      }

      let yamlText = this.cleanYamlResponse(response);
      const validation = this.validateGenerated(yamlText);

      if (!validation.valid) {
        console.warn('Origami: Generated template has validation issues:', validation.errors);
      }

      let parsed = null;
      try {
        parsed = this.parseYaml(yamlText);
      } catch (e) {
        console.error('Origami: Failed to parse generated YAML:', e.message);
      }

      return {
        yaml: yamlText,
        template: parsed,
        validation: validation
      };
    } catch (error) {
      console.error('Origami: Rule generation failed:', error.message);
      throw new Error('Rule generation failed: ' + error.message);
    }
  }

  async sendToLLM(prompt) {
    return new Promise((resolve, reject) => {
      try {
        chrome.runtime.sendMessage({
          action: 'llmAnalyze',
          prompt: prompt,
          systemPrompt: 'You are a security detection rule author. Output ONLY valid YAML with no markdown fences or explanations.',
          options: { temperature: 0.3, maxTokens: 8192 }
        }, (response) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }

          if (!response || !response.success) {
            reject(new Error(response?.error || 'LLM request failed'));
            return;
          }

          // Extract text from provider-specific response formats
          const data = response.data;
          const text = data?.candidates?.[0]?.content?.parts?.[0]?.text || // Gemini
                       data?.choices?.[0]?.message?.content || // OpenAI
                       data?.content?.[0]?.text || // Anthropic
                       data?.response || // Ollama
                       (typeof data === 'string' ? data : '');

          resolve(text);
        });
      } catch (e) {
        reject(new Error('Failed to send message to background: ' + e.message));
      }
    });
  }

  cleanYamlResponse(raw) {
    let cleaned = raw.trim();

    // Remove markdown code fences if present
    cleaned = cleaned.replace(/^```ya?ml?\s*\n?/i, '');
    cleaned = cleaned.replace(/\n?```\s*$/i, '');
    cleaned = cleaned.trim();

    // Remove any leading prose before the YAML (lines before 'id:')
    const idIndex = cleaned.search(/^id:/m);
    if (idIndex > 0) {
      cleaned = cleaned.substring(idIndex);
    }

    // Remove any trailing prose after the YAML ends
    // YAML ends after the last line that starts with proper indentation or a list item
    const lines = cleaned.split('\n');
    let lastYamlLine = lines.length - 1;
    for (let i = lines.length - 1; i >= 0; i--) {
      const line = lines[i].trim();
      if (line === '' || line.startsWith('#')) continue;
      // Check if line looks like YAML content
      if (/^[\s-]/.test(lines[i]) || /^[a-z_-]+:/i.test(lines[i]) || /^"/.test(line) || /^'/.test(line)) {
        lastYamlLine = i;
        break;
      }
      // Line looks like prose, remove it
      lastYamlLine = i - 1;
    }

    return lines.slice(0, lastYamlLine + 1).join('\n').trim();
  }

  parseYaml(yamlText) {
    if (typeof jsyaml !== 'undefined') {
      return jsyaml.load(yamlText);
    }

    // Fallback: minimal YAML parser for simple template structures
    return this.minimalYamlParse(yamlText);
  }

  minimalYamlParse(yamlText) {
    const result = {};
    const lines = yamlText.split('\n');
    const stack = [{ obj: result, indent: -1 }];
    let currentArray = null;
    let currentArrayKey = null;

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];
      if (line.trim() === '' || line.trim().startsWith('#')) continue;

      const indent = line.search(/\S/);
      const content = line.trim();

      // Pop stack to find parent at correct indent level
      while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
        stack.pop();
        currentArray = null;
        currentArrayKey = null;
      }

      const parent = stack[stack.length - 1].obj;

      if (content.startsWith('- ')) {
        // Array item
        const value = content.substring(2).trim();
        const unquoted = value.replace(/^["']|["']$/g, '');

        if (currentArray && Array.isArray(currentArray)) {
          if (value.includes(': ')) {
            const [k, ...rest] = value.split(': ');
            const v = rest.join(': ').replace(/^["']|["']$/g, '');
            const item = {};
            item[k.trim()] = v;
            currentArray.push(item);
          } else {
            currentArray.push(unquoted);
          }
        }
      } else if (content.includes(': ')) {
        const colonIdx = content.indexOf(': ');
        const key = content.substring(0, colonIdx).trim();
        const rawValue = content.substring(colonIdx + 2).trim();

        if (rawValue === '' || rawValue === '|' || rawValue === '>') {
          // Nested object or block scalar
          const child = {};
          parent[key] = child;
          stack.push({ obj: child, indent: indent });
        } else {
          const unquoted = rawValue.replace(/^["']|["']$/g, '');
          parent[key] = unquoted;
        }
      } else if (content.endsWith(':')) {
        const key = content.slice(0, -1).trim();
        // Check next line to determine if array or object
        const child = {};
        parent[key] = child;
        stack.push({ obj: child, indent: indent });

        // Peek ahead for arrays
        const nextLineIdx = lineIdx + 1;
        if (nextLineIdx < lines.length && lines[nextLineIdx].trim().startsWith('- ')) {
          const arr = [];
          parent[key] = arr;
          currentArray = arr;
          currentArrayKey = key;
        }
      }
    }

    return result;
  }

  validateGenerated(yamlText) {
    const errors = [];
    const warnings = [];

    if (!yamlText || typeof yamlText !== 'string' || yamlText.trim().length === 0) {
      errors.push('YAML text is empty');
      return { valid: false, errors, warnings };
    }

    let parsed;
    try {
      parsed = this.parseYaml(yamlText);
    } catch (e) {
      errors.push('YAML parse error: ' + e.message);
      return { valid: false, errors, warnings };
    }

    if (!parsed || typeof parsed !== 'object') {
      errors.push('Parsed YAML is not an object');
      return { valid: false, errors, warnings };
    }

    // Check required top-level fields
    if (!parsed.id || typeof parsed.id !== 'string') {
      errors.push('Missing or invalid "id" field (must be a non-empty string)');
    }

    if (!parsed.info || typeof parsed.info !== 'object') {
      errors.push('Missing or invalid "info" field (must be an object)');
    } else {
      if (!parsed.info.name || typeof parsed.info.name !== 'string') {
        errors.push('Missing or invalid "info.name" field');
      }
      if (!parsed.info.severity || typeof parsed.info.severity !== 'string') {
        errors.push('Missing or invalid "info.severity" field');
      } else if (!this.templateSchema.validSeverities.includes(parsed.info.severity.toUpperCase())) {
        errors.push('Invalid severity "' + parsed.info.severity + '". Must be one of: ' + this.templateSchema.validSeverities.join(', '));
      }
      if (parsed.info.cwe && typeof parsed.info.cwe === 'string' && !/^CWE-\d+$/.test(parsed.info.cwe)) {
        warnings.push('CWE format should be "CWE-NNN": got "' + parsed.info.cwe + '"');
      }
    }

    if (!parsed.matchers || !Array.isArray(parsed.matchers) || parsed.matchers.length === 0) {
      errors.push('Missing or empty "matchers" array');
    } else {
      for (let i = 0; i < parsed.matchers.length; i++) {
        const matcher = parsed.matchers[i];
        if (!matcher || typeof matcher !== 'object') {
          errors.push('Matcher [' + i + '] is not an object');
          continue;
        }
        if (matcher.target && !this.templateSchema.validTargets.includes(matcher.target)) {
          warnings.push('Matcher [' + i + '] has unknown target "' + matcher.target + '"');
        }
        if (!matcher.patterns || !Array.isArray(matcher.patterns) || matcher.patterns.length === 0) {
          errors.push('Matcher [' + i + '] has no patterns');
        } else {
          for (let j = 0; j < matcher.patterns.length; j++) {
            try {
              new RegExp(matcher.patterns[j], 'gi');
            } catch (e) {
              errors.push('Matcher [' + i + '] pattern [' + j + '] is invalid regex: ' + e.message);
            }
          }
        }
      }
    }

    // Validate extractors if present
    if (parsed.extractors && Array.isArray(parsed.extractors)) {
      for (let i = 0; i < parsed.extractors.length; i++) {
        const extractor = parsed.extractors[i];
        if (extractor.patterns && Array.isArray(extractor.patterns)) {
          for (let j = 0; j < extractor.patterns.length; j++) {
            try {
              new RegExp(extractor.patterns[j], 'gi');
            } catch (e) {
              errors.push('Extractor [' + i + '] pattern [' + j + '] is invalid regex: ' + e.message);
            }
          }
        }
      }
    }

    // Check for ReDoS-prone patterns
    const allPatterns = [];
    if (parsed.matchers) {
      parsed.matchers.forEach(m => {
        if (m.patterns) allPatterns.push(...m.patterns);
      });
    }
    if (parsed.extractors) {
      parsed.extractors.forEach(e => {
        if (e.patterns) allPatterns.push(...e.patterns);
      });
    }

    const redosCheck = /(\+|\*|\{)\s*(\+|\*|\{)/;
    for (const pat of allPatterns) {
      if (redosCheck.test(pat)) {
        warnings.push('Pattern may be vulnerable to ReDoS (nested quantifiers): ' + pat.substring(0, 60));
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings
    };
  }
}

window.RuleGenerator = RuleGenerator;
