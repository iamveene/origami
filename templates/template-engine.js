// Origami YAML Detection Template Engine
// Parses YAML templates and runs matchers against page context

class TemplateEngine {
  constructor() {
    this.templates = [];
  }

  async loadTemplates() {
    return new Promise((resolve) => {
      chrome.storage.local.get(['origami_templates'], (data) => {
        this.templates = (data.origami_templates || []).filter(t => t.enabled !== false);
        resolve(this.templates);
      });
    });
  }

  getTargetData(target) {
    switch (target) {
      case 'url':
        return window.location.href;
      case 'body':
        return document.body ? document.body.innerHTML : '';
      case 'scripts':
        return Array.from(document.querySelectorAll('script')).map(s => s.textContent || s.src).join('\n');
      case 'headers':
        return window._origamiHeaders ? JSON.stringify(window._origamiHeaders) : '';
      case 'cookies':
        return document.cookie;
      case 'storage':
        try {
          const ls = Object.keys(localStorage).map(k => k + '=' + localStorage.getItem(k)).join('\n');
          const ss = Object.keys(sessionStorage).map(k => k + '=' + sessionStorage.getItem(k)).join('\n');
          return ls + '\n' + ss;
        } catch (e) {
          return '';
        }
      default:
        return '';
    }
  }

  safeRegexExec(pattern, text, timeoutMs = 2000) {
    try {
      // Reject dangerous patterns that cause catastrophic backtracking (ReDoS)
      // Check for directly adjacent quantifiers: ++, *+, {n}+
      if (/(\+|\*|\{)\s*(\+|\*|\{)/.test(pattern)) {
        console.warn('Origami Template: Rejected pattern with nested quantifiers:', pattern);
        return [];
      }
      // Check for quantifier after quantified group close: (...)+ followed by +/*/{
      if (/\)[\s]*[+*]\s*[+*{]/.test(pattern)) {
        console.warn('Origami Template: Rejected pattern with quantified group quantifier:', pattern);
        return [];
      }
      // Check for multiple quantifiers inside a quantified group: (a+b+)+ or ([a-z]+)+
      if (/\([^)]*[+*][^)]*\)\s*[+*{]/.test(pattern)) {
        console.warn('Origami Template: Rejected pattern with quantifiers inside quantified group:', pattern);
        return [];
      }
      // Reject overly long patterns
      if (pattern.length > 500) {
        console.warn('Origami Template: Rejected pattern exceeding max length');
        return [];
      }

      const regex = new RegExp(pattern, 'gi');
      const matches = [];
      const startTime = Date.now();
      let match;
      // Limit input text length to bound worst-case regex execution time
      const safeText = text.length > 100000 ? text.substring(0, 100000) : text;

      while ((match = regex.exec(safeText)) !== null) {
        if (Date.now() - startTime > timeoutMs) {
          console.warn('Origami Template: Regex timeout after ' + timeoutMs + 'ms');
          break;
        }
        matches.push(match[0]);
        if (match[0].length === 0) { regex.lastIndex++; }
        if (matches.length > 100) break;
        // Prevent infinite loops on zero-length matches
        if (match[0].length === 0) {
          regex.lastIndex++;
        }
      }

      return matches;
    } catch (e) {
      console.error('Origami Template: Regex error:', e.message);
      return [];
    }
  }

  runTemplate(template) {
    if (!template.matchers || !Array.isArray(template.matchers)) return [];

    const condition = template.condition || 'or';
    const matcherResults = [];
    const allExtracted = [];
    const matchedTargets = [];

    for (const matcher of template.matchers) {
      const targetData = this.getTargetData(matcher.target || 'body');
      if (!targetData) {
        matcherResults.push(false);
        continue;
      }

      let matched = false;
      const allMatches = [];

      for (const pattern of (matcher.patterns || [])) {
        const patternMatches = this.safeRegexExec(pattern, targetData);
        if (patternMatches.length > 0) {
          matched = true;
          allMatches.push(...patternMatches);
        }
      }

      matcherResults.push(matched);

      if (matched) {
        let extracted = allMatches;
        if (template.extractors) {
          for (const extractor of template.extractors) {
            if (extractor.type === 'regex') {
              const extractedValues = [];
              for (const ep of (extractor.patterns || [])) {
                const eMatches = this.safeRegexExec(ep, targetData);
                extractedValues.push(...eMatches);
              }
              if (extractedValues.length > 0) extracted = extractedValues;
            }
          }
        }
        allExtracted.push(...extracted);
        matchedTargets.push(matcher.target || 'body');
      }
    }

    const anyMatched = matcherResults.some(r => r);
    const allMatched = matcherResults.every(r => r);

    if (condition === 'and' && !allMatched) return [];
    if (condition !== 'and' && !anyMatched) return [];

    return [{
      templateId: template.id,
      name: template.info?.name || template.id,
      severity: (template.info?.severity || 'MEDIUM').toUpperCase(),
      cwe: template.info?.cwe || null,
      tags: template.info?.tags || [],
      target: matchedTargets.join(', '),
      matches: allExtracted.slice(0, 10),
      message: 'Matched template: ' + (template.info?.name || template.id)
    }];
  }

  async runAll() {
    await this.loadTemplates();
    const allFindings = [];

    for (const template of this.templates) {
      try {
        const findings = this.runTemplate(template);
        allFindings.push(...findings);
      } catch (e) {
        console.error('Origami Template: Error running template ' + template.id + ':', e.message);
      }
    }

    return allFindings;
  }
}

// Builtin templates loaded into storage on first run
TemplateEngine.BUILTIN_TEMPLATES = [
  {
    id: 'jwt-in-query-param',
    builtin: true,
    enabled: true,
    info: { name: 'JWT in URL Query Parameter', severity: 'HIGH', cwe: 'CWE-598', tags: ['jwt', 'url', 'exposure'] },
    matchers: [{ type: 'regex', target: 'url', patterns: ['[?&][^=]+=eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+'] }],
    extractors: [{ type: 'regex', patterns: ['eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+'] }]
  },
  {
    id: 'debug-endpoints',
    builtin: true,
    enabled: true,
    info: { name: 'Debug Endpoint Exposure', severity: 'HIGH', cwe: 'CWE-489', tags: ['debug', 'exposure'] },
    matchers: [{ type: 'regex', target: 'body', patterns: ['(?:__debug__|phpinfo|/debug/|/trace/|/actuator/|/swagger-ui|/graphiql|/_profiler)'] }],
    extractors: [{ type: 'regex', patterns: ['(?:__debug__|phpinfo|/debug/|/trace/|/actuator/|/swagger-ui|/graphiql|/_profiler)[^"\'\\s]*'] }]
  },
  {
    id: 'api-key-in-url',
    builtin: true,
    enabled: true,
    info: { name: 'API Key in URL', severity: 'MEDIUM', cwe: 'CWE-598', tags: ['api-key', 'url'] },
    matchers: [{ type: 'regex', target: 'url', patterns: ['[?&](?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token)=[^&]{10,}'] }],
    extractors: [{ type: 'regex', patterns: ['(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token)=([^&]+)'] }]
  },
  {
    id: 'open-redirect-params',
    builtin: true,
    enabled: true,
    info: { name: 'Potential Open Redirect Parameter', severity: 'MEDIUM', cwe: 'CWE-601', tags: ['redirect', 'url'] },
    matchers: [{ type: 'regex', target: 'url', patterns: ['[?&](?:redirect|return|next|url|goto|dest|continue|target|rurl|return_to|redirect_uri|returnUrl)=https?%3A'] }],
    extractors: [{ type: 'regex', patterns: ['(?:redirect|return|next|url|goto|dest|continue|target|rurl|return_to|redirect_uri|returnUrl)=([^&]+)'] }]
  },
  {
    id: 'sensitive-comments',
    builtin: true,
    enabled: true,
    info: { name: 'Sensitive Information in Comments', severity: 'LOW', cwe: 'CWE-615', tags: ['comments', 'disclosure'] },
    matchers: [{ type: 'regex', target: 'body', patterns: ['<!--[^>]*(?:TODO|FIXME|HACK|XXX|BUG|password|secret|token|api[_-]?key|internal|admin)[^>]*-->'] }],
    extractors: [{ type: 'regex', patterns: ['<!--[^>]*(?:TODO|FIXME|HACK|XXX|BUG|password|secret|token|api[_-]?key|internal|admin)[^>]*-->'] }]
  }
];

window.TemplateEngine = TemplateEngine;
