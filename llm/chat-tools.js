// Origami AI Partner Chat Tools
// Tool registry and execution engine for AI Partner function calling

class ChatTools {
  constructor(tabId) {
    this.tabId = tabId;
    this._contextBuilder = new ContextBuilder();
    this._cachedResults = null;
    this._cachedFindings = null;
    this._cachedFindingsTimestamp = 0;
    this._cachedResultsTimestamp = 0;
  }

  // Tool registry: each tool has name, description, params schema, and execute function
  static TOOLS = {
    get_findings_summary: {
      name: 'get_findings_summary',
      description: 'Get an overview of all findings aggregated by category and severity.',
      params: [],
      execute: async function(params, context) {
        const allFindings = await context.tools._getAllFindings();
        if (!allFindings) return 'No scan data available. Run a scan first.';

        const categories = ['secrets', 'headers', 'cookies', 'vulnerabilities',
          'sensitiveFiles', 'session', 'technologies', 'correlationChains',
          'oauthFlows', 'graphql', 'crypto', 'cloudStorage', 'exfiltration', 'websockets'];

        const summary = [];
        let totalFindings = 0;

        categories.forEach(cat => {
          const items = context.tools._extractCategoryFindings(allFindings, cat);
          if (items.length === 0) return;
          totalFindings += items.length;

          const bySev = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
          items.forEach(f => {
            const sev = (f.severity || f.risk || 'INFO').toUpperCase();
            if (bySev.hasOwnProperty(sev)) bySev[sev]++;
          });

          const sevParts = [];
          if (bySev.CRITICAL > 0) sevParts.push(bySev.CRITICAL + ' Critical');
          if (bySev.HIGH > 0) sevParts.push(bySev.HIGH + ' High');
          if (bySev.MEDIUM > 0) sevParts.push(bySev.MEDIUM + ' Medium');
          if (bySev.LOW > 0) sevParts.push(bySev.LOW + ' Low');
          if (bySev.INFO > 0) sevParts.push(bySev.INFO + ' Info');

          summary.push(cat + ': ' + items.length + ' findings' +
            (sevParts.length > 0 ? ' (' + sevParts.join(', ') + ')' : ''));
        });

        if (summary.length === 0) return 'No findings detected. The page may not have been scanned yet.';

        return '<SCAN_DATA>\nTotal findings: ' + totalFindings + '\n' + summary.join('\n') + '\n</SCAN_DATA>';
      }
    },

    get_findings_by_category: {
      name: 'get_findings_by_category',
      description: 'Get detailed findings for a specific category.',
      params: [
        { name: 'category', type: 'string', description: 'Category name: headers, cookies, vulnerabilities, secrets, sensitiveFiles, session, technologies, correlationChains' }
      ],
      execute: async function(params, context) {
        const category = params.category;
        if (!category) return 'Error: category parameter is required.';

        const allFindings = await context.tools._getAllFindings();
        if (!allFindings) return 'No scan data available. Run a scan first.';

        const items = context.tools._extractCategoryFindings(allFindings, category);
        if (items.length === 0) return 'No findings in category: ' + category;

        const formatted = context.tools._contextBuilder.formatFindingsForContext(items, category);
        return '<SCAN_DATA>\n' + formatted + '\n</SCAN_DATA>';
      }
    },

    get_finding_detail: {
      name: 'get_finding_detail',
      description: 'Get full detail for a specific finding by category and index.',
      params: [
        { name: 'category', type: 'string', description: 'Category name' },
        { name: 'index', type: 'number', description: 'Finding index (1-based)' }
      ],
      execute: async function(params, context) {
        const category = params.category;
        const index = parseInt(params.index, 10);
        if (!category || isNaN(index)) return 'Error: category and index parameters are required.';

        const allFindings = await context.tools._getAllFindings();
        if (!allFindings) return 'No scan data available. Run a scan first.';

        const items = context.tools._extractCategoryFindings(allFindings, category);
        if (index < 1 || index > items.length) {
          return 'Error: index ' + index + ' out of range. Category "' + category + '" has ' + items.length + ' findings.';
        }

        const finding = items[index - 1];
        const sanitize = context.tools._contextBuilder.sanitizeForPrompt.bind(context.tools._contextBuilder);
        const detail = sanitize(JSON.stringify(finding, null, 2));
        return '<SCAN_DATA>\nFinding #' + index + ' from ' + category + ':\n' + detail + '\n</SCAN_DATA>';
      }
    },

    generate_poc: {
      name: 'generate_poc',
      description: 'Generate a proof-of-concept for a specific finding.',
      params: [
        { name: 'category', type: 'string', description: 'Category name' },
        { name: 'index', type: 'number', description: 'Finding index (1-based)' }
      ],
      execute: async function(params, context) {
        const category = params.category;
        const index = parseInt(params.index, 10);
        if (!category || isNaN(index)) return 'Error: category and index parameters are required.';

        const allFindings = await context.tools._getAllFindings();
        if (!allFindings) return 'No scan data available.';

        const items = context.tools._extractCategoryFindings(allFindings, category);
        if (index < 1 || index > items.length) {
          return 'Error: index ' + index + ' out of range for ' + category + '.';
        }

        const finding = items[index - 1];

        try {
          const generator = new PoCGenerator();
          const secResults = await context.tools._getSecurityResults();
          const techs = context.tools._contextBuilder._extractTechnologies(
            secResults ? secResults.technologies : null
          );

          const pocContext = {
            url: secResults?.url || '',
            technologies: techs.map(t => ({ name: t })),
            csp: null
          };

          // Extract CSP from headers if available
          if (secResults?.headers) {
            const headerItems = context.tools._extractItems(secResults.headers);
            const cspHeader = headerItems.find(h =>
              (h.check || '').toLowerCase().includes('content-security-policy')
            );
            if (cspHeader) {
              pocContext.csp = cspHeader.details?.value || cspHeader.message || '';
            }
          }

          const result = await generator.generate(finding, pocContext);
          return 'PoC generated for ' + (finding.check || finding.type || 'finding') + ':\n' +
            JSON.stringify(result.poc, null, 2);
        } catch (e) {
          console.error('Origami: generate_poc tool error:', e);
          return 'PoC generation failed: ' + e.message;
        }
      }
    },

    run_scan: {
      name: 'run_scan',
      description: 'Trigger a new Origami scan on the current page.',
      params: [],
      execute: async function(params, context) {
        try {
          await new Promise((resolve, reject) => {
            chrome.tabs.sendMessage(context.tools.tabId, { action: 'runAllAnalyzers' }, (response) => {
              if (chrome.runtime.lastError) {
                reject(new Error(chrome.runtime.lastError.message));
                return;
              }
              resolve(response);
            });
          });
          // Invalidate cache so subsequent tool calls get fresh data
          context.tools._cachedResults = null;
          context.tools._cachedFindings = null;
          context.tools._cachedFindingsTimestamp = 0;
          context.tools._cachedResultsTimestamp = 0;
          return 'Scan triggered on the current page. Results will be available shortly. ' +
            'Use get_findings_summary to check results after a few seconds.';
        } catch (e) {
          console.error('Origami: run_scan tool error:', e);
          return 'Failed to trigger scan: ' + e.message + '. The page may need to be reloaded.';
        }
      }
    },

    analyze_code: {
      name: 'analyze_code',
      description: 'Perform a security code review of a code block using the LLM.',
      params: [
        { name: 'code', type: 'string', description: 'The code to analyze' },
        { name: 'language', type: 'string', description: 'Programming language (default: javascript)' }
      ],
      execute: async function(params, context) {
        const code = params.code;
        if (!code) return 'Error: code parameter is required.';
        const language = params.language || 'javascript';

        try {
          const promptData = SecurityPrompts.codeReview(code, language);

          const response = await new Promise((resolve, reject) => {
            chrome.runtime.sendMessage({
              action: 'llmAnalyze',
              prompt: promptData.prompt + '\n\nCode:\n' + promptData.context,
              systemPrompt: 'You are a cybersecurity expert performing a security code review. Be specific and actionable.',
              options: promptData.options
            }, (resp) => {
              if (chrome.runtime.lastError) {
                reject(new Error(chrome.runtime.lastError.message));
                return;
              }
              if (!resp || !resp.success) {
                reject(new Error(resp?.error || 'LLM analysis request failed'));
                return;
              }
              const data = resp.data;
              const text = data?.candidates?.[0]?.content?.parts?.[0]?.text ||
                           data?.choices?.[0]?.message?.content ||
                           data?.content?.[0]?.text ||
                           data?.response ||
                           (typeof data === 'string' ? data : '');
              resolve(text);
            });
          });

          return response || 'No analysis returned from LLM.';
        } catch (e) {
          console.error('Origami: analyze_code tool error:', e);
          return 'Code analysis failed: ' + e.message;
        }
      }
    },

    get_technologies: {
      name: 'get_technologies',
      description: 'Get detected technologies and their versions.',
      params: [],
      execute: async function(params, context) {
        const results = await context.tools._getSecurityResults();
        if (!results || !results.technologies) return 'No technology data available.';

        const techs = context.tools._contextBuilder._extractTechnologies(results.technologies);
        if (techs.length === 0) return 'No technologies detected.';

        return '<SCAN_DATA>\nDetected Technologies:\n' + techs.map((t, i) => (i + 1) + '. ' + t).join('\n') + '\n</SCAN_DATA>';
      }
    },

    get_security_score: {
      name: 'get_security_score',
      description: 'Get the security score and breakdown by category.',
      params: [],
      execute: async function(params, context) {
        const results = await context.tools._getSecurityResults();
        if (!results) return 'No security score data available.';

        const scoreData = results.scoreData || results.score || null;
        if (!scoreData || typeof scoreData !== 'object') return 'Security score not calculated yet.';

        const lines = [];
        lines.push('Overall Score: ' + (scoreData.score ?? '?') + '/100 (Grade: ' + (scoreData.grade || '?') + ')');

        if (scoreData.breakdown) {
          lines.push('\nCategory Breakdown:');
          Object.entries(scoreData.breakdown).forEach(([cat, data]) => {
            if (data.findings > 0 || data.deductions > 0) {
              lines.push('  ' + cat + ': ' + data.score + '/100 (' + data.findings + ' findings, -' + data.deductions + ' pts)');
            }
          });
        }

        if (scoreData.positives && scoreData.positives.length > 0) {
          lines.push('\nPositives:');
          scoreData.positives.forEach(p => lines.push('  + ' + p));
        }

        if (scoreData.negatives && scoreData.negatives.length > 0) {
          lines.push('\nNegatives:');
          scoreData.negatives.forEach(n => lines.push('  - ' + n));
        }

        return '<SCAN_DATA>\n' + lines.join('\n') + '\n</SCAN_DATA>';
      }
    },

    check_cves: {
      name: 'check_cves',
      description: 'Get CVE and end-of-life data for detected technologies.',
      params: [],
      execute: async function(params, context) {
        const results = await context.tools._getSecurityResults();
        if (!results || !results.technologies) return 'No technology data available for CVE checking.';

        const techs = results.technologies;
        const cveData = [];

        const processTechs = (items) => {
          if (!Array.isArray(items)) return;
          items.forEach(t => {
            if (!t || typeof t !== 'object') return;
            const entry = { name: t.name || 'Unknown', version: t.version || '' };
            if (t.endOfLife || (t.eolStatus && t.eolStatus.status === 'EOL')) {
              entry.eol = true;
            }
            if (t.vulnerabilities && Array.isArray(t.vulnerabilities) && t.vulnerabilities.length > 0) {
              entry.cves = t.vulnerabilities.map(v => ({
                id: v.id || v.cveId || 'Unknown',
                severity: v.severity || '',
                score: v.score || v.severity_score || 0
              }));
            }
            if (entry.eol || entry.cves) {
              cveData.push(entry);
            }
          });
        };

        if (Array.isArray(techs)) {
          processTechs(techs);
        } else if (typeof techs === 'object') {
          Object.values(techs).forEach(val => {
            if (Array.isArray(val)) processTechs(val);
          });
        }

        if (cveData.length === 0) return 'No CVEs or EOL technologies detected.';

        const lines = ['CVE/EOL Report:'];
        cveData.forEach(entry => {
          lines.push('\n' + entry.name + (entry.version ? ' ' + entry.version : ''));
          if (entry.eol) lines.push('  [!] END OF LIFE');
          if (entry.cves) {
            entry.cves.forEach(cve => {
              lines.push('  - ' + cve.id + ' (score: ' + cve.score + ', severity: ' + (cve.severity || 'unknown') + ')');
            });
          }
        });

        return '<SCAN_DATA>\n' + lines.join('\n') + '\n</SCAN_DATA>';
      }
    },

    get_attack_chains: {
      name: 'get_attack_chains',
      description: 'Get correlation engine attack chains that combine multiple findings.',
      params: [],
      execute: async function(params, context) {
        const results = await context.tools._getSecurityResults();
        if (!results || !results.correlationChains) return 'No attack chains detected.';

        const chains = Array.isArray(results.correlationChains) ? results.correlationChains : [];
        if (chains.length === 0) return 'No attack chains detected.';

        const lines = ['Attack Chains (' + chains.length + ' detected):'];
        chains.forEach((chain, i) => {
          lines.push('\n[' + (i + 1) + '] ' + (chain.name || chain.id || 'Chain') +
            ' (Severity: ' + (chain.severity || 'Unknown') + ')');
          if (chain.description) lines.push('    Description: ' + chain.description);
          if (chain.attackFlow && Array.isArray(chain.attackFlow)) {
            lines.push('    Flow: ' + chain.attackFlow.join(' -> '));
          }
          if (chain.findings && Array.isArray(chain.findings)) {
            lines.push('    Findings: ' + chain.findings.length + ' correlated');
          }
        });

        lines.push('\nIMPORTANT: These are the ONLY attack chains detected by the correlation engine. Do not fabricate additional chains, endpoints, or IDOR patterns not present in this data. If suggesting further investigation, clearly label it as SUGGESTED INVESTIGATION.');
        return '<SCAN_DATA>\n' + lines.join('\n') + '\n</SCAN_DATA>';
      }
    },

    assess_risk: {
      name: 'assess_risk',
      description: 'Run AI risk scoring on all findings via the Intent Engine.',
      params: [],
      execute: async function(params, context) {
        try {
          const allFindings = await context.tools._getAllFindings();
          if (!allFindings) return 'No findings available for risk assessment.';

          const engine = new IntentEngine();
          const result = await engine.evaluate(allFindings, { useLLM: false });

          const lines = ['Risk Assessment Summary:'];
          lines.push('Total scored: ' + result.summary.totalFindings);
          lines.push('Signal-to-noise: ' + result.summary.signalToNoise + '%');
          lines.push('Top category: ' + result.summary.topCategory);
          lines.push('Recommendation: ' + result.summary.recommendation);

          if (result.topFindings && result.topFindings.length > 0) {
            lines.push('\nTop Findings by Risk:');
            result.topFindings.slice(0, 10).forEach((f, i) => {
              lines.push('[' + (i + 1) + '] ' + f.type + ' (' + f.severity + ') - Score: ' + f.composite + '/100');
              lines.push('    Category: ' + f.category + ' | Exploitability: ' + f.scores.exploitability +
                ' | Impact: ' + f.scores.businessImpact);
            });
          }

          lines.push('\nCALIBRATION NOTES:');
          lines.push('- Severity levels are pre-calibrated. Trust scanner severity over generic assumptions.');
          lines.push('- Google API keys (AIzaSy) = browser-scoped public keys, MEDIUM max. Do not escalate to CRITICAL/HIGH.');
          lines.push('- Firebase config keys = intentionally public, LOW severity.');
          lines.push('- Only reference findings present in this data. Do not fabricate endpoints or chains.');
          lines.push('- Label any hypothetical investigation as SUGGESTED INVESTIGATION.');

          return lines.join('\n');
        } catch (e) {
          console.error('Origami: assess_risk tool error:', e);
          return 'Risk assessment failed: ' + e.message;
        }
      }
    },

    send_http_request: {
      name: 'send_http_request',
      description: 'Send an HTTP request to a target URL and return the response. Use for verifying vulnerabilities, probing endpoints, or testing SQL injection payloads interactively.',
      params: [
        { name: 'url', type: 'string', description: 'Full target URL including query string' }
      ],
      execute: async function(params, context) {
        const url = params.url;
        if (!url) return 'Error: url parameter is required.';
        try { new URL(url); } catch (e) { return 'Error: invalid URL.'; }
        return new Promise((resolve) => {
          chrome.runtime.sendMessage({
            action: 'sqliRequest',
            url: url,
            method: (params.method || 'GET').toUpperCase(),
            headers: params.headers || {},
            body: params.body || '',
            timeout: 10000
          }, (resp) => {
            if (chrome.runtime.lastError) {
              resolve('Error: ' + chrome.runtime.lastError.message);
              return;
            }
            if (!resp) { resolve('Error: no response from background'); return; }
            if (resp.error) { resolve('Error: ' + resp.error); return; }
            const body = resp.body || '';
            const limit = 8000;
            const truncNote = (resp.truncated || body.length > limit) ? '\n[truncated at 8KB]' : '';
            resolve(JSON.stringify({
              status: resp.status,
              statusText: resp.statusText,
              timing_ms: resp.timing,
              body: body.substring(0, limit) + truncNote
            }, null, 2));
          });
        });
      }
    }
  };

  // Parse [TOOL_CALL]...[/TOOL_CALL] blocks from LLM response text
  parseToolCalls(responseText) {
    if (!responseText) return [];

    const calls = [];
    const pattern = /\[TOOL_CALL\]\s*\n?([\s\S]*?)\[\/TOOL_CALL\]/gi;
    let match;

    while ((match = pattern.exec(responseText)) !== null) {
      const block = match[1].trim();

      const toolMatch = block.match(/^tool:\s*(.+)$/m);
      // Capture everything after "params:" including multi-line JSON
      const paramsMatch = block.match(/^params:\s*([\s\S]+)/m);

      if (toolMatch) {
        const toolName = toolMatch[1].trim();
        let params = {};
        if (paramsMatch) {
          try {
            params = JSON.parse(paramsMatch[1].trim());
          } catch (e) {
            console.error('Origami: Failed to parse tool params:', paramsMatch[1].trim());
          }
        }
        calls.push({ tool: toolName, params: params });
      }
    }

    return calls;
  }

  // Strip tool call blocks from response text, returning only natural language
  stripToolCalls(responseText) {
    if (!responseText) return '';
    return responseText.replace(/\[TOOL_CALL\]\s*\n?[\s\S]*?\[\/TOOL_CALL\]/gi, '').trim();
  }

  // Validate parameters against tool schema
  validateParams(toolName, params) {
    const tool = ChatTools.TOOLS[toolName];
    if (!tool) return { valid: false, error: 'Unknown tool: ' + toolName };

    for (const paramDef of tool.params) {
      const value = params[paramDef.name];
      if (value === undefined || value === null) {
        return { valid: false, error: 'Missing required parameter: ' + paramDef.name };
      }
      if (paramDef.type === 'number' && typeof value !== 'number' && isNaN(Number(value))) {
        return { valid: false, error: 'Parameter ' + paramDef.name + ' must be a number.' };
      }
    }

    return { valid: true };
  }

  // Execute a tool by name with given params
  async executeTool(toolName, params) {
    const tool = ChatTools.TOOLS[toolName];
    if (!tool) {
      return '[TOOL_RESULT]\ntool: ' + toolName + '\nresult: Error: Unknown tool "' + toolName + '"\n[/TOOL_RESULT]';
    }

    const validation = this.validateParams(toolName, params);
    if (!validation.valid) {
      return '[TOOL_RESULT]\ntool: ' + toolName + '\nresult: ' + validation.error + '\n[/TOOL_RESULT]';
    }

    try {
      const context = { tools: this };
      const result = await tool.execute(params, context);
      const errorNote = this._detectResponseError(result);
      const prefix = errorNote ? errorNote + '\n' : '';
      return '[TOOL_RESULT]\n' + prefix + 'tool: ' + toolName + '\nresult: ' + result + '\n[/TOOL_RESULT]';
    } catch (e) {
      console.error('Origami: Tool execution error for ' + toolName + ':', e);
      return '[TOOL_RESULT]\ntool: ' + toolName + '\nresult: Error executing tool: ' + e.message + '\n[/TOOL_RESULT]';
    }
  }

  // Detect database/server error patterns in a tool result string.
  // Returns an annotation string if an error is detected, null otherwise.
  _detectResponseError(resultStr) {
    const patterns = [
      /mysql_connect\(\)/i,
      /mysql_fetch/i,
      /Warning:\s/,
      /You have an error in your SQL/i,
      /syntax error.*SQL/i,
      /Connection refused/i,
      /website is out of order/i,
      /\bORA-\d{4,}/,
      /SQLSTATE\[/i
    ];
    for (const p of patterns) {
      if (p.test(resultStr)) return '[ERROR_DETECTED: database_error]';
    }
    return null;
  }

  // -- Private helpers for data access --

  // Get all findings via background.js (with short cache)
  async _getAllFindings() {
    const now = Date.now();
    if (this._cachedFindings && (now - this._cachedFindingsTimestamp) < 5000) {
      return this._cachedFindings;
    }

    try {
      const findings = await new Promise((resolve, reject) => {
        chrome.runtime.sendMessage({
          action: 'getAllFindings',
          tabId: this.tabId
        }, (response) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          resolve(response);
        });
      });
      this._cachedFindings = findings;
      this._cachedFindingsTimestamp = now;
      return findings;
    } catch (e) {
      console.error('Origami: _getAllFindings error:', e);
      return null;
    }
  }

  // Get security results via background.js (with short cache)
  async _getSecurityResults() {
    const now = Date.now();
    if (this._cachedResults && (now - this._cachedResultsTimestamp) < 5000) {
      return this._cachedResults;
    }

    try {
      const response = await new Promise((resolve, reject) => {
        chrome.runtime.sendMessage({
          action: 'getTabSecurityResults',
          tabId: this.tabId
        }, (resp) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          resolve(resp);
        });
      });
      const results = response?.results || null;
      this._cachedResults = results;
      this._cachedResultsTimestamp = now;
      return results;
    } catch (e) {
      console.error('Origami: _getSecurityResults error:', e);
      return null;
    }
  }

  // Extract findings array from a category within allFindings
  _extractCategoryFindings(allFindings, category) {
    if (!allFindings) return [];

    const data = allFindings[category];
    return this._extractItems(data);
  }

  // Extract items from various data shapes (array, {findings:[]}, {issues:[]})
  _extractItems(data) {
    if (!data) return [];
    if (Array.isArray(data)) return data;
    if (data.findings && Array.isArray(data.findings)) return data.findings;
    if (data.issues && Array.isArray(data.issues)) return data.issues;
    if (data.tokens && Array.isArray(data.tokens)) {
      // Session state: flatten token issues
      const issues = [];
      data.tokens.forEach(t => {
        if (t.issues && Array.isArray(t.issues)) issues.push(...t.issues);
      });
      if (data.findings) {
        const f = Array.isArray(data.findings) ? data.findings : [data.findings];
        issues.push(...f);
      }
      return issues;
    }
    return [];
  }
}

window.ChatTools = ChatTools;
