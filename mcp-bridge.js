// Origami MCP Bridge Client
// WebSocket client that connects background.js to the origami-mcp-server.
// Handles incoming MCP tool requests and routes them to the appropriate extension functionality.

class MCPBridge {
  constructor() {
    this.ws = null;
    this.enabled = false;
    this.wsUrl = 'ws://127.0.0.1:9340';
    this.wsToken = '';
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 10;
    this.reconnectTimer = null;
    this.connected = false;
  }

  // Initialize from saved settings
  async init() {
    try {
      const data = await chrome.storage.sync.get(['settings']);
      const settings = data.settings || {};
      const mcpSettings = settings.mcpBridge || {};
      this.enabled = mcpSettings.enabled || false;
      this.wsUrl = mcpSettings.wsUrl || 'ws://127.0.0.1:9340';
      this.wsToken = mcpSettings.wsToken || '';

      if (this.enabled) {
        this.connect();
        // Recreate keepalive alarm in case it was cleared by an extension reload
        chrome.alarms.create('origami-mcp-keepalive', { periodInMinutes: 0.4 });
      }
    } catch (e) {
      console.error('Origami MCP: Init error:', e.message);
    }
  }

  connect() {
    // Clear any pending reconnect timer to prevent duplicate connections
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    try {
      // Append auth token to WebSocket URL
      const connectUrl = this.wsToken
        ? this.wsUrl + '?token=' + encodeURIComponent(this.wsToken)
        : this.wsUrl;
      this.ws = new WebSocket(connectUrl);

      this.ws.onopen = () => {
        console.log('Origami MCP: Connected to MCP server at ' + this.wsUrl);
        this.connected = true;
        this.reconnectAttempts = 0;
      };

      this.ws.onmessage = (event) => {
        this._handleMessage(event.data);
      };

      this.ws.onclose = (event) => {
        console.log('Origami MCP: Disconnected (code: ' + event.code + ')');
        this.connected = false;
        this.ws = null;

        // Auto-reconnect unless cleanly closed or disabled
        if (this.enabled && event.code !== 1000) {
          this._scheduleReconnect();
        }
      };

      this.ws.onerror = (error) => {
        // WebSocket errors are followed by onclose, so just log
        console.error('Origami MCP: WebSocket error');
      };
    } catch (e) {
      console.error('Origami MCP: Connection error:', e.message);
      this._scheduleReconnect();
    }
  }

  disconnect() {
    this.enabled = false;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.close(1000, 'disabled');
      this.ws = null;
    }
    this.connected = false;
    this.reconnectAttempts = 0;
  }

  _scheduleReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.log('Origami MCP: Max reconnect attempts reached. Call mcpBridge.connect() to retry.');
      return;
    }

    const delay = Math.min(2000 * Math.pow(1.5, this.reconnectAttempts), 30000);
    this.reconnectAttempts++;
    console.log('Origami MCP: Reconnecting in ' + Math.round(delay / 1000) + 's (attempt ' + this.reconnectAttempts + ')');

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      if (this.enabled) {
        this.connect();
      }
    }, delay);
  }

  _send(msg) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      // Log dropped messages so they don't silently vanish
      if (msg.type === 'response' && msg.id) {
        console.warn('Origami MCP: Dropped response for request ' + msg.id + ' — WebSocket not connected');
      }
      return;
    }
    try {
      const payload = JSON.stringify(msg);
      this.ws.send(payload);
    } catch (e) {
      console.error('Origami MCP: Failed to serialize message:', e.message);
      // Send error response if this was a response to a request
      if (msg.id && msg.type === 'response') {
        try {
          const fallback = JSON.stringify({ type: 'response', id: msg.id, error: 'Response too large to serialize: ' + e.message });
          this.ws.send(fallback);
        } catch (_) { /* truly cannot send */ }
      }
    }
  }

  async _handleMessage(raw) {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch (e) {
      console.error('Origami MCP: Invalid message:', e.message);
      return;
    }

    // Handshake from server
    if (msg.type === 'handshake') {
      console.log('Origami MCP: Handshake received from ' + msg.server + ' v' + msg.version);
      return;
    }

    // Tool request from MCP server
    if (msg.type === 'request' && msg.id && msg.action) {
      try {
        const result = await this._executeAction(msg.action, msg.params || {});
        this._send({ type: 'response', id: msg.id, data: result });
      } catch (e) {
        console.error('Origami MCP: Action error (' + msg.action + '):', e.message);
        this._send({ type: 'response', id: msg.id, error: e.message });
      }
      return;
    }
  }

  // Actions that don't require an active tab
  static TAB_INDEPENDENT_ACTIONS = new Set(['getPageInfo', 'sendRequest']);

  // Add data integrity boundary to all security data responses.
  // Prevents LLM hallucination by explicitly constraining what data exists.
  _addDataBoundary(result, action) {
    if (!result || result.error) return result;
    // Preserve existing detailed boundaries (e.g., attack chains, assess risk)
    if (result.important) return result;

    const boundaries = {
      getFindingsSummary: 'This summary represents the complete scan. Categories showing 0 findings have none detected -- do not fabricate findings for empty categories or infer findings beyond what is counted here.',
      getFindingsByCategory: 'These are ALL findings in this category. Only reference findings by the index numbers and data present here. Do not fabricate additional findings, evidence, or details not in this response.',
      getFindingDetail: 'This is the complete finding object with all scanner-detected metadata. Do not infer additional fields, evidence, code context, or details not present in this data.',
      getSecurityScore: 'This score is computed from confirmed scanner findings only. Do not fabricate score justifications or deductions not present in this data.',
      getTechnologies: 'Only these technologies were detected on the page. Do not assume or fabricate additional technologies, versions, or CVEs not in this data.',
      checkCves: 'Only these CVE and end-of-life entries were matched to detected technologies. Do not fabricate CVE numbers, vulnerability details, or affected versions not in this data.',
      generatePoC: 'This PoC was generated from the specific finding data. All payloads must be verified against the actual target in an authorized testing context before reporting.',
      getSessionAnalysis: 'Only reference session tokens, JWTs, and cookie data present in this response. Do not fabricate session identifiers, token claims, or storage entries not in this data.',
      getAuthFlows: 'Only reference OAuth/SAML flows present in this response. Do not fabricate authorization endpoints, redirect URIs, or flow parameters not detected by the scanner.',
      getGraphQLSchema: 'Only reference GraphQL endpoints, types, and schema elements present in this response. Do not fabricate queries, mutations, or schema fields not in this data.',
      exportReport: 'This report contains only confirmed scanner findings. Do not add findings, attack chains, or analysis not present in the original scan data.',
    };

    result.important = boundaries[action] || 'Only reference data present in this response. Do not fabricate findings, endpoints, attack chains, or IDOR patterns not detected by the scanner. If suggesting further investigation, clearly label it as SUGGESTED INVESTIGATION separate from confirmed findings.';
    return result;
  }

  // Entry point for all MCP tool actions. Applies data boundaries and size limits.
  async _executeAction(action, params) {
    let result = await this._routeAction(action, params);
    result = this._truncateResponse(result, params.maxResponseSize);
    return this._addDataBoundary(result, action);
  }

  // Attach resolved tabId to results so callers can pass it explicitly in subsequent calls.
  // This prevents the mcp_context_tab race when multiple sessions are active.
  _attachTabId(result, tabId) {
    if (result && typeof result === 'object' && !result.error && tabId) {
      result._tabId = tabId;
    }
    return result;
  }

  // Truncate oversized responses to prevent context window overflow.
  // Default limit: 50K chars. Caller can override via maxResponseSize param.
  _truncateResponse(result, maxSize) {
    if (!result || result.error) return result;
    const limit = Math.min(maxSize || 50000, 200000);
    let serialized;
    try {
      serialized = JSON.stringify(result);
    } catch { return result; }

    if (serialized.length <= limit) return result;

    // Truncate large string fields first (evidence, details, content)
    const truncated = JSON.parse(serialized);
    const stringLimit = 2000;

    const truncateObj = (obj) => {
      if (!obj || typeof obj !== 'object') return;
      for (const key of Object.keys(obj)) {
        const val = obj[key];
        if (typeof val === 'string' && val.length > stringLimit) {
          obj[key] = val.substring(0, stringLimit) + '... [truncated, ' + val.length + ' total chars]';
        } else if (Array.isArray(val)) {
          // Truncate array items; if array is very large, cap it
          if (val.length > 100) {
            const removed = val.length - 50;
            obj[key] = val.slice(0, 50);
            obj[key].push({ _truncated: removed + ' more items omitted. Use get_finding_detail for individual findings.' });
          }
          val.forEach(item => truncateObj(item));
        } else if (typeof val === 'object' && val !== null) {
          truncateObj(val);
        }
      }
    };

    truncateObj(truncated);
    // Re-check size after field truncation
    try {
      const recheck = JSON.stringify(truncated);
      if (recheck.length > limit) {
        truncated._responseTruncated = true;
        truncated._note = 'Response truncated from ' + serialized.length + ' to ~' + limit + ' chars. Use get_finding_detail with specific index for full data.';
      }
    } catch { /* proceed with truncated version */ }
    return truncated;
  }

  // Actions that only read data and should NOT focus/activate the target tab
  static READ_ONLY_ACTIONS = new Set([
    'getPageInfo', 'getFindingsSummary', 'getFindingsByCategory', 'getFindingDetail',
    'getSecurityScore', 'getTechnologies', 'checkCves', 'getAttackChains', 'assessRisk',
    'getSessionAnalysis', 'getAuthFlows', 'getGraphQLSchema', 'exportReport',
  ]);

  // Route MCP actions to extension functionality
  async _routeAction(action, params) {
    let activeTab;
    let tabId;

    if (params.tabId) {
      // Caller specified an explicit tab
      try {
        activeTab = await chrome.tabs.get(params.tabId);
        tabId = params.tabId;
        // Only focus/activate for actions that interact with the page (scan, override)
        if (!MCPBridge.READ_ONLY_ACTIONS.has(action)) {
          await chrome.windows.update(activeTab.windowId, { focused: true });
          await chrome.tabs.update(params.tabId, { active: true });
          activeTab = await chrome.tabs.get(params.tabId);
        }
      } catch (e) {
        return { error: true, message: 'Tab ' + params.tabId + ' not found: ' + e.message };
      }
    } else {
      // Check for popup-stored MCP context tab (set when popup opens with ?target=<tabId>).
      // This prevents MCP from reading from the popup tab (which stores no findings)
      // when the popup is open in full-window mode and is the active Chrome tab.
      try {
        const ctx = await chrome.storage.local.get('mcp_context_tab');
        if (ctx.mcp_context_tab) {
          try {
            activeTab = await chrome.tabs.get(ctx.mcp_context_tab);
            tabId = ctx.mcp_context_tab;
          } catch (e) {
            // Stored tab no longer exists; clear it and fall through to active tab
            await chrome.storage.local.remove('mcp_context_tab');
          }
        }
      } catch (e) { /* storage unavailable */ }

      if (!tabId) {
        // Fall back to current active tab
        activeTab = await this._getActiveTab();
        if (!activeTab && !MCPBridge.TAB_INDEPENDENT_ACTIONS.has(action)) {
          return { error: true, message: 'No active tab found. Open a page in Chrome first.' };
        }
        tabId = activeTab?.id;
      }
    }

    // Execute action and attach resolved tabId for caller reference
    let result;
    switch (action) {
      case 'getPageInfo':
        result = this._getPageInfo(activeTab);
        break;
      case 'runScan':
        result = await this._runScan(tabId);
        break;
      case 'getFindingsSummary':
        result = await this._getFindingsSummary(tabId);
        break;
      case 'getFindingsByCategory':
        result = await this._getFindingsByCategory(tabId, params.category);
        break;
      case 'getFindingDetail':
        result = await this._getFindingDetail(tabId, params.category, params.index);
        break;
      case 'getSecurityScore':
        result = await this._getSecurityScore(tabId);
        break;
      case 'getTechnologies':
        result = await this._getTechnologies(tabId);
        break;
      case 'checkCves':
        result = await this._checkCves(tabId);
        break;
      case 'getAttackChains':
        result = await this._getAttackChains(tabId);
        break;
      case 'assessRisk':
        result = await this._assessRisk(tabId);
        break;
      case 'generatePoC':
        result = await this._generatePoC(tabId, params.category, params.index);
        break;
      case 'overrideSeverity':
        result = await this._overrideSeverity(tabId, params.category, params.index, params.newSeverity, params.reason);
        break;
      case 'sendRequest':
        result = await this._sendRequest(params.url, params.method, params.headers, params.body, params.maxResponseBody);
        break;
      case 'getSessionAnalysis':
        result = await this._getSessionAnalysis(tabId);
        break;
      case 'getAuthFlows':
        result = await this._getAuthFlows(tabId);
        break;
      case 'getGraphQLSchema':
        result = await this._getGraphQLSchema(tabId);
        break;
      case 'exportReport':
        result = await this._exportReport(tabId, params.format, params.includeAiSummary);
        break;
      default:
        return { error: true, message: 'Unknown action: ' + action };
    }
    return this._attachTabId(result, tabId);
  }

  // ─── Action Implementations ──────────────────────────────────────────────

  async _getActiveTab() {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    return tabs[0] || null;
  }

  // Inject content scripts if they are not already present on the tab.
  // Tabs created/navigated by MCP automation may miss the manifest-driven
  // content script injection lifecycle.
  async _ensureContentScripts(tabId) {
    // Fast path: check if coordinator is present via function probe (no messaging overhead)
    try {
      const [{ result: alreadyPresent }] = await chrome.scripting.executeScript({
        target: { tabId },
        func: () => typeof window.runAllAnalyzers === 'function',
      });
      if (alreadyPresent) return;
    } catch { /* tab may not be scriptable -- fall through to injection */ }

    // Content scripts not present -- inject them.
    // Each script has an injection guard (B3 fix) so re-injection is safe.
    try {
      await chrome.scripting.executeScript({
        target: { tabId },
        files: [
          'constants.js',
          'scanner.js',
          'analyzers/header-analyzer.js',
          'analyzers/cookie-analyzer.js',
          'analyzers/vuln-scanner.js',
          'analyzers/tech-fingerprinter.js',
          'analyzers/sensitive-file-scanner.js',
          'analyzers/resource-collector.js',
          'analyzers/session-analyzer.js',
          'analyzers/oauth-interceptor.js',
          'analyzers/saml-decoder.js',
          'analyzers/graphql-mapper.js',
          'analyzers/surface-tracker.js',
          'analyzers/correlation-engine.js',
          'lib/origami-utils.js',
          'analyzers/crypto-auditor.js',
          'analyzers/cloud-storage-mapper.js',
          'analyzers/exfiltration-detector.js',
          'analyzers/websocket-auditor.js',
          'analyzers/js-obfuscation-detector.js',
          'lib/js-yaml.min.js',
          'templates/template-engine.js',
          'workbench/chain-builder.js',
          'plugins/plugin-validator.js',
          'plugins/plugin-registry.js',
          'plugins/plugin-loader.js',
          'analyzers/analyzer-coordinator.js',
        ],
      });
      // Give scripts a moment to initialize
      await new Promise(r => setTimeout(r, 500));
    } catch (e) {
      console.error('Origami MCP: Failed to inject content scripts:', e.message);
    }
  }

  _getPageInfo(tab) {
    if (!tab) return { error: true, message: 'No active tab' };
    let domain = '';
    try { domain = new URL(tab.url).hostname; } catch (e) { /* ignore */ }
    return {
      url: tab.url,
      title: tab.title,
      domain: domain,
      tabId: tab.id,
    };
  }

  async _runScan(tabId) {
    // Ensure content scripts are injected (they may be missing on tabs
    // created/navigated programmatically by MCP automation)
    await this._ensureContentScripts(tabId);

    return new Promise((resolve) => {
      chrome.tabs.sendMessage(tabId, { action: 'runSecurityAnalysis' }, async (response) => {
        if (chrome.runtime.lastError) {
          resolve({ error: true, message: 'Failed to trigger scan: ' + chrome.runtime.lastError.message });
          return;
        }

        // The content script returns { results } with all analyzer data.
        // Store results in background so subsequent MCP tool calls can read them.
        // (Auto-scan via scanner.js sends securityAnalysisComplete, but the
        //  runSecurityAnalysis listener in analyzer-coordinator does not.)
        if (response && response.results) {
          try {
            if (typeof saveTabSecurityResults === 'function') {
              await saveTabSecurityResults(tabId, response.results);
            } else {
              // Fallback: write directly to storage
              await chrome.storage.local.set({ [`tab_security_${tabId}`]: response.results });
            }
          } catch (e) {
            console.error('Origami MCP: Failed to persist scan results:', e.message);
          }

          const cats = Object.keys(response.results).filter(k => {
            const v = response.results[k];
            return Array.isArray(v) ? v.length > 0 : !!v;
          });
          resolve({
            success: true,
            message: 'Scan complete. Results stored for ' + cats.length + ' categories: ' + cats.join(', ') + '. Use get_findings_summary for an overview.',
          });
        } else if (response && response.error) {
          resolve({ error: true, message: 'Scan failed: ' + response.error });
        } else {
          resolve({
            success: true,
            message: 'Scan triggered but returned no results. The page may not have analyzable content.',
          });
        }
      });
    });
  }

  _effectiveSeverity(f) {
    const o = f.severityOverride;
    if (!o) return (f.severity || f.risk || 'INFO').toUpperCase();
    if (typeof o === 'string') return o.toUpperCase();
    return (o.overriddenSeverity || f.severity || f.risk || 'INFO').toUpperCase();
  }

  // Exploitability score (0-100): how easily can this finding be exploited in practice?
  _computeExploitability(type, category, severity) {
    const t = (type || '').toLowerCase();
    const c = (category || '').toLowerCase();

    // Secrets: depends on type
    if (c === 'secrets') {
      if (/google.*(api|aizasy)/i.test(t) || /aizasy/i.test(t)) return 40; // browser-scoped, referrer-restricted
      if (/firebase.*realtime|realtime.*database|\.json.*database/i.test(t)) return 90; // just a GET request
      if (/firebase.*auth.*anonymous|anonymous.*signup/i.test(t)) return 80; // anonymous token generation
      if (/firebase/i.test(t)) return 25; // intentionally public config keys
      if (/aws|azure|gcp.*service/i.test(t)) return 90; // cloud credentials
      if (/private.key|rsa|ssh/i.test(t)) return 85;
      if (/password|passwd/i.test(t)) return 80;
      if (/jwt|bearer|oauth.*token|refresh.token/i.test(t)) return 85;
      if (/api.key|api.secret|access.key/i.test(t)) return 70;
      return 55; // generic secret
    }

    // Vulnerabilities
    if (c === 'vulnerabilities') {
      if (/sqli|sql.injection/i.test(t)) return 95;
      if (/xss|cross.site.script/i.test(t)) return 85;
      if (/csrf/i.test(t)) return 70;
      if (/ssrf/i.test(t)) return 80;
      if (/rce|command.injection|remote.code/i.test(t)) return 95;
      if (/prototype.pollution/i.test(t)) return 60;
      if (/open.redirect/i.test(t)) return 65;
      if (/idor|insecure.direct/i.test(t)) return 75;
      return 60;
    }

    // Headers: defensive, not directly exploitable
    if (c === 'headers') return 25;

    // Cookies
    if (c === 'cookies') return 35;

    // Sensitive files
    if (c === 'sensitivefiles') return 50;

    // Correlation chains: already compound
    if (c === 'correlationchains') return 75;

    // Session/OAuth
    if (c === 'sessionstate' || c === 'oauthflows') return 65;

    // Crypto, cloud, exfil, websockets
    if (c === 'crypto') return 50;
    if (c === 'cloudstorage') return 60;
    if (c === 'exfiltration') return 70;
    if (c === 'websockets') return 55;

    return 40;
  }

  // PoC ease score (0-100): how easy is it to build a working proof of concept? Higher = easier.
  _computePoCEase(type, category) {
    const t = (type || '').toLowerCase();
    const c = (category || '').toLowerCase();

    if (c === 'secrets') {
      if (/google.*(api|aizasy)/i.test(t) || /aizasy/i.test(t)) return 90; // just curl with key
      if (/firebase/i.test(t)) return 85;
      if (/aws/i.test(t)) return 80;
      if (/password|passwd/i.test(t)) return 95; // direct login
      if (/jwt|bearer/i.test(t)) return 85; // replay token
      return 70;
    }

    if (c === 'vulnerabilities') {
      if (/xss|cross.site.script/i.test(t)) return 85;
      if (/sqli|sql.injection/i.test(t)) return 80;
      if (/csrf/i.test(t)) return 75;
      if (/open.redirect/i.test(t)) return 90;
      if (/rce|command.injection/i.test(t)) return 70;
      if (/prototype.pollution/i.test(t)) return 50;
      return 60;
    }

    if (c === 'headers') return 20; // informational, no direct PoC
    if (c === 'cookies') return 30;
    if (c === 'sensitivefiles') return 80; // just browse to the file
    if (c === 'correlationchains') return 55;
    if (c === 'sessionstate') return 60;
    if (c === 'oauthflows') return 55;
    if (c === 'crypto') return 40;
    if (c === 'cloudstorage') return 65;
    if (c === 'exfiltration') return 50;
    if (c === 'websockets') return 45;

    return 40;
  }

  async _getFindingsSummary(tabId) {
    const allFindings = await this._getAllFindings(tabId);
    if (!allFindings) return { error: true, message: 'No scan data available. Run a scan first.' };

    const categories = [
      'secrets', 'headers', 'cookies', 'vulnerabilities',
      'sensitiveFiles', 'sessionState', 'technologies', 'correlationChains',
      'oauthFlows', 'graphql', 'crypto', 'cloudStorage', 'exfiltration', 'websockets',
    ];

    const summary = {};
    let totalFindings = 0;

    categories.forEach(cat => {
      const items = this._extractItems(allFindings[cat]);
      if (items.length === 0) return;
      totalFindings += items.length;

      const bySev = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
      items.forEach(f => {
        const sev = this._effectiveSeverity(f);
        if (Object.prototype.hasOwnProperty.call(bySev, sev)) bySev[sev]++;
      });

      summary[cat] = { count: items.length, ...bySev };
    });

    return { totalFindings, categories: summary };
  }

  async _getFindingsByCategory(tabId, category) {
    if (!category) return { error: true, message: 'category parameter is required' };
    const allFindings = await this._getAllFindings(tabId);
    if (!allFindings) return { error: true, message: 'No scan data available.' };

    const items = this._extractItems(allFindings[category]);
    if (items.length === 0) return { category, count: 0, findings: [] };

    // Sanitize findings for list view — generous limits for code inspection
    const sanitized = items.map((f, i) => {
      const details = f.details || f.pattern || f.matchedText || '';
      const detailStr = typeof details === 'object' ? JSON.stringify(details) : String(details);
      const evidence = f.evidence || f.context || '';
      const evidenceStr = typeof evidence === 'object' ? JSON.stringify(evidence) : String(evidence);

      return {
        index: i + 1,
        type: f.check || f.type || f.name || f.templateId || category,
        severity: this._effectiveSeverity(f),
        message: f.message || f.description || '',
        details: detailStr.substring(0, 2000),
        evidence: evidenceStr.substring(0, 1500),
        ...(f.recommendation || f.details?.recommendation ? { recommendation: f.recommendation || f.details?.recommendation } : {}),
        ...(f.aiAssessment ? { aiAssessment: f.aiAssessment } : {}),
        ...(f.severityOverride ? { originalSeverity: f.severity || f.risk } : {}),
      };
    });

    return { category, count: sanitized.length, findings: sanitized };
  }

  async _getFindingDetail(tabId, category, index) {
    if (!category || index == null) return { error: true, message: 'category and index are required' };
    const allFindings = await this._getAllFindings(tabId);
    if (!allFindings) return { error: true, message: 'No scan data available.' };

    const items = this._extractItems(allFindings[category]);
    if (index < 1 || index > items.length) {
      return { error: true, message: 'Index ' + index + ' out of range. Category "' + category + '" has ' + items.length + ' findings.' };
    }

    return { category, index, finding: items[index - 1] };
  }

  async _getSecurityScore(tabId) {
    const results = await this._getSecurityResults(tabId);
    if (!results) return { error: true, message: 'No security data available.' };

    // If popup already computed and stored a score, use it
    if (results.scoreData || results.score) {
      return results.scoreData || results.score;
    }

    // Otherwise compute score here (popup's SecurityScorer doesn't persist to storage)
    let score = 100;
    const deductions = [];
    const positives = [];

    const SEVERITY_DEDUCTIONS = { CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3, INFO: 0 };
    const MAX_DEDUCTION_PER_CATEGORY = 40;

    const categories = ['headers', 'cookies', 'vulnerabilities', 'sensitiveFiles'];
    for (const cat of categories) {
      const items = this._extractItems(results[cat]);
      let catDeduction = 0;
      items.forEach(f => {
        const sev = this._effectiveSeverity(f);
        const d = SEVERITY_DEDUCTIONS[sev] || 0;
        catDeduction += d;
      });
      catDeduction = Math.min(catDeduction, MAX_DEDUCTION_PER_CATEGORY);
      if (catDeduction > 0) {
        deductions.push({ category: cat, points: catDeduction, count: items.length });
      } else if (items.length === 0 && cat === 'vulnerabilities') {
        positives.push('No vulnerabilities detected');
      }
      score -= catDeduction;
    }

    // Check positive security headers
    const headers = this._extractItems(results.headers);
    const headerChecks = headers.filter(h => h.severity === 'INFO' || h.status === 'present');
    if (headerChecks.length > 0) positives.push(headerChecks.length + ' security headers present');

    score = Math.max(0, Math.min(100, score));
    const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';

    return { score, grade, deductions, positives };
  }

  async _getTechnologies(tabId) {
    const results = await this._getSecurityResults(tabId);
    if (!results || !results.technologies) return { error: true, message: 'No technology data available.' };

    const techs = results.technologies;
    // Normalize to array
    let techList = [];
    if (Array.isArray(techs)) {
      techList = techs;
    } else if (typeof techs === 'object') {
      for (const [category, items] of Object.entries(techs)) {
        if (Array.isArray(items)) {
          techList.push(...items.map(t => ({ ...t, category })));
        }
      }
    }

    return { count: techList.length, technologies: techList };
  }

  async _checkCves(tabId) {
    const results = await this._getSecurityResults(tabId);
    if (!results || !results.technologies) return { error: true, message: 'No technology data available.' };

    const cveData = [];
    const processTechs = (items) => {
      if (!Array.isArray(items)) return;
      items.forEach(t => {
        if (!t || typeof t !== 'object') return;
        const entry = { name: t.name || 'Unknown', version: t.version || '' };
        if (t.endOfLife || (t.eolStatus && t.eolStatus.status === 'EOL')) entry.eol = true;
        if (t.vulnerabilities && Array.isArray(t.vulnerabilities) && t.vulnerabilities.length > 0) {
          entry.cves = t.vulnerabilities;
        }
        if (entry.eol || entry.cves) cveData.push(entry);
      });
    };

    const techs = results.technologies;
    if (Array.isArray(techs)) {
      processTechs(techs);
    } else if (typeof techs === 'object') {
      Object.values(techs).forEach(val => {
        if (Array.isArray(val)) processTechs(val);
      });
    }

    return { count: cveData.length, entries: cveData };
  }

  async _getAttackChains(tabId) {
    const results = await this._getSecurityResults(tabId);
    let chains = results?.correlationChains;

    // Fallback: check individual chain storage (populated by correlationChainsDetected message
    // even when securityAnalysisComplete hasn't stored them in tab_security_)
    if (!chains || (Array.isArray(chains) && chains.length === 0)) {
      try {
        const key = `tab_chains_${tabId}`;
        const stored = await chrome.storage.local.get(key);
        if (stored[key] && Array.isArray(stored[key]) && stored[key].length > 0) {
          chains = stored[key];
        }
      } catch (e) { /* ignore storage errors */ }
    }

    if (!chains || !Array.isArray(chains)) return { count: 0, chains: [], important: 'No attack chains were detected by the correlation engine. Do not fabricate or infer attack chains that are not present in this data.' };
    return {
      count: chains.length,
      chains,
      important: 'These are the ONLY attack chains detected by the correlation engine. Do not fabricate additional chains, endpoints, or IDOR patterns not present in this data. If suggesting further investigation, clearly label it as SUGGESTED INVESTIGATION separate from confirmed findings.',
    };
  }

  async _assessRisk(tabId) {
    const allFindings = await this._getAllFindings(tabId);
    if (!allFindings) return { error: true, message: 'No findings available.' };

    // Run the Intent Engine scoring (heuristic only — no LLM call from here)
    // The Intent Engine class is in the content script context, so we replicate
    // core scoring logic here for the background worker context.
    const categories = [
      'secrets', 'headers', 'cookies', 'vulnerabilities',
      'sensitiveFiles', 'sessionState', 'correlationChains',
      'oauthFlows', 'graphql', 'crypto', 'cloudStorage', 'exfiltration', 'websockets',
    ];
    const scored = [];

    categories.forEach(cat => {
      const items = this._extractItems(allFindings[cat]);
      items.forEach((f, i) => {
        const severity = this._effectiveSeverity(f);
        const sevScore = { CRITICAL: 95, HIGH: 75, MEDIUM: 50, LOW: 25, INFO: 10 }[severity] || 10;
        const type = f.check || f.type || f.name || cat;
        const exploitability = this._computeExploitability(type, cat, severity);
        const pocEase = this._computePoCEase(type, cat);
        const composite = Math.round(sevScore * 0.4 + exploitability * 0.4 + pocEase * 0.2);

        scored.push({
          index: i + 1,
          category: cat,
          type,
          severity,
          scores: { severity: sevScore, exploitability, pocEase, composite },
          message: (f.message || f.description || '').substring(0, 500),
          details: (f.details?.recommendation || '').substring(0, 300),
        });
      });
    });

    scored.sort((a, b) => b.scores.composite - a.scores.composite);

    return {
      totalScored: scored.length,
      topFindings: scored.slice(0, 50),
      severityBreakdown: {
        CRITICAL: scored.filter(s => s.severity === 'CRITICAL').length,
        HIGH: scored.filter(s => s.severity === 'HIGH').length,
        MEDIUM: scored.filter(s => s.severity === 'MEDIUM').length,
        LOW: scored.filter(s => s.severity === 'LOW').length,
        INFO: scored.filter(s => s.severity === 'INFO').length,
      },
      assessmentGuidelines: {
        CRITICAL: 'Immediately exploitable with no special conditions. Direct path to data breach, RCE, or full account takeover.',
        HIGH: 'Exploitable with minimal conditions. Significant data exposure or privilege escalation.',
        MEDIUM: 'Exploitable under specific conditions (user interaction, specific configuration). Conditional risk.',
        LOW: 'Defense-in-depth issue. Not directly exploitable but weakens security posture.',
        INFO: 'Informational finding. No direct security impact but useful for reconnaissance.',
      },
      calibrationNotes: [
        'Severity levels are pre-calibrated by the scanner engine. Trust them over generic security assumptions.',
        'Google API keys (AIzaSy prefix) are browser-scoped public keys restricted by HTTP referrer. MEDIUM severity max. Only escalate if API Validator confirms dangerous services (e.g., Cloud Functions, IAM).',
        'Firebase config keys (apiKey, authDomain, projectId) are intentionally public by design. LOW severity. However, anonymous signup via Identity Toolkit can be chained with Realtime Database access (auth != null rules) for data exfiltration -- this chain is CRITICAL.',
        'Missing security headers are defense-in-depth issues (LOW/INFO), not directly exploitable vulnerabilities.',
        'Cookie flags (HttpOnly, Secure, SameSite) are best-practice recommendations, severity depends on cookie purpose.',
      ],
      important: 'Only reference findings present in this scan data. Do not fabricate endpoints, IDOR patterns, or attack chains not detected by the scanner. If suggesting further investigation, clearly label it as SUGGESTED INVESTIGATION separate from confirmed findings.',
    };
  }

  async _generatePoC(tabId, category, index) {
    if (!category || index == null) return { error: true, message: 'category and index are required' };

    const allFindings = await this._getAllFindings(tabId);
    if (!allFindings) return { error: true, message: 'No scan data available.' };

    const items = this._extractItems(allFindings[category]);
    if (index < 1 || index > items.length) {
      return { error: true, message: 'Index ' + index + ' out of range.' };
    }

    const finding = items[index - 1];

    // Build PoC prompt directly and call LLM via the background helper
    const findingType = finding.check || finding.type || finding.name || category;
    const findingSev = this._effectiveSeverity(finding);
    const findingMsg = finding.message || finding.description || '';
    const findingPattern = finding.pattern || finding.details?.pattern || finding.matchedText || '';
    const findingLocation = finding.uri || finding.url || finding.details?.uri || finding.source || '';
    const findingContext = finding.codeContext || finding.details?.context || '';

    // Look up Google API validation results if this is a Google API key finding
    let apiValidationSection = '';
    if (category === 'secrets') {
      const isGoogleAPIKey = finding.pattern_matched === 'Google Cloud API Key' ||
        (finding.full_key || finding.key || '').startsWith('AIza');
      if (isGoogleAPIKey && typeof apiValidationResults !== 'undefined') {
        const keyNorm = normalizeSecretKey(finding.full_key || finding.key);
        const validation = apiValidationResults.get(keyNorm);
        if (validation && validation.results) {
          apiValidationSection = this._buildApiValidationSection(validation, finding.upgrade_reason);
        }
      }
    }

    const prompt = [
      'SECURITY ASSESSMENT -- PROOF OF CONCEPT',
      '========================================',
      '',
      'This report is generated by Origami, a security auditing tool installed by the user',
      'to assess their own web applications. Generate a proof-of-concept for the vulnerability',
      'described below. Include remediation guidance.',
      '',
      '## Target Vulnerability',
      '- Type: ' + findingType,
      '- Severity: ' + findingSev,
      findingMsg ? '- Description: ' + findingMsg : '',
      findingPattern ? '- Evidence: ' + String(findingPattern).substring(0, 2000) : '',
      findingLocation ? '- Location: ' + findingLocation : '',
      findingContext ? '- Code Context:\n```\n' + String(findingContext).substring(0, 1000) + '\n```' : '',
      apiValidationSection,
      '',
      '## Output Format',
      '',
      'PAYLOAD: [exploit payload or reproduction steps]',
      'EXPLANATION: [how and why the vulnerability works]',
      'IMPACT: [what damage this could cause]',
      'REMEDIATION: [how to fix the vulnerability]',
    ].filter(Boolean).join('\n');

    const systemPrompt = 'You are a security assessment tool generating proof-of-concept reports. The user has installed this tool to audit their own web applications. Provide a clear, educational PoC with remediation guidance.';

    // Check if _backgroundLlmAnalyze is available (defined in background.js)
    if (typeof _backgroundLlmAnalyze !== 'function') {
      return { error: true, message: 'LLM infrastructure not available in this context.' };
    }

    const llmResult = await _backgroundLlmAnalyze(prompt, systemPrompt, { temperature: 0.3, maxTokens: 8192 });

    if (!llmResult.success) {
      return { error: true, message: 'PoC generation requires LLM: ' + llmResult.error };
    }

    // Extract text from provider response
    const data = llmResult.data;
    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text ||
                 data?.choices?.[0]?.message?.content ||
                 data?.content?.[0]?.text ||
                 data?.response ||
                 (typeof data === 'string' ? data : JSON.stringify(data));

    const refused = !text.includes('PAYLOAD:') &&
      /i (cannot|can't|won't|will not|am unable)|against my (guidelines|policy)|decline to (generate|provide)/i.test(text);

    return {
      finding: { type: findingType, severity: findingSev, message: findingMsg },
      poc: text,
      ...(refused ? { refused: true, note: 'LLM declined to generate a PoC for this finding. Review the poc field for the LLM\'s explanation.' } : {}),
      model: data?.model || data?.modelVersion || 'unknown',
      generatedAt: new Date().toISOString(),
    };
  }

  async _overrideSeverity(tabId, category, index, newSeverity, reason) {
    if (!category || !index || !newSeverity) {
      return { error: true, message: 'category, index, and newSeverity are required' };
    }

    // Validate severity on bridge side (defense in depth)
    const VALID_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    if (!VALID_SEVERITIES.includes(newSeverity.toUpperCase())) {
      return { error: true, message: 'Invalid severity. Must be one of: ' + VALID_SEVERITIES.join(', ') };
    }
    newSeverity = newSeverity.toUpperCase();

    if (category === 'secrets') {
      // Override severity in secrets (tab findings)
      const findings = await this._loadTabFindings(tabId);
      if (index < 1 || index > findings.length) {
        return { error: true, message: 'Index ' + index + ' out of range for secrets.' };
      }
      const finding = findings[index - 1];
      const oldSeverity = this._effectiveSeverity(finding);
      finding.severityOverride = { overriddenSeverity: newSeverity, timestamp: new Date().toISOString(), source: 'mcp-claude-code', reason };

      // Save back to storage and invalidate in-memory cache
      const storageKey = `tab_findings_${tabId}`;
      await chrome.storage.local.set({ [storageKey]: findings });
      if (typeof tabFindings !== 'undefined' && tabFindings instanceof Map) {
        tabFindings.set(tabId, findings);
      }

      return {
        success: true,
        category,
        index,
        oldSeverity,
        newSeverity,
        reason,
      };
    } else {
      // Override severity in security results
      const results = await this._getSecurityResults(tabId);
      if (!results || !results[category]) {
        return { error: true, message: 'No data for category: ' + category };
      }

      const items = this._extractItems(results[category]);
      if (index < 1 || index > items.length) {
        return { error: true, message: 'Index ' + index + ' out of range.' };
      }

      const finding = items[index - 1];
      const oldSeverity = this._effectiveSeverity(finding);
      finding.severityOverride = { overriddenSeverity: newSeverity, timestamp: new Date().toISOString(), source: 'mcp-claude-code', reason };

      // Save back to storage and invalidate in-memory cache
      const storageKey = `tab_security_${tabId}`;
      await chrome.storage.local.set({ [storageKey]: results });
      if (typeof tabSecurityResults !== 'undefined' && tabSecurityResults instanceof Map) {
        tabSecurityResults.set(tabId, results);
      }

      return {
        success: true,
        category,
        index,
        oldSeverity,
        newSeverity,
        reason,
      };
    }
  }

  async _sendRequest(url, method, headers, body, maxResponseBody) {
    if (!url) return { error: true, message: 'url is required' };
    method = method || 'GET';

    const startTime = Date.now();
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);

    try {
      const fetchOptions = {
        method,
        headers: headers || {},
      };
      if (body && ['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) {
        fetchOptions.body = body;
      }

      const response = await fetch(url, { ...fetchOptions, signal: controller.signal });
      clearTimeout(timeoutId);
      const elapsed = Date.now() - startTime;

      const responseHeaders = {};
      response.headers.forEach((v, k) => { responseHeaders[k] = v; });

      // Dynamic body limit — default 50KB, Claude can request up to 500KB for large files
      const text = await response.text();
      const MAX_BODY = Math.min(maxResponseBody || 50000, 500000);
      const truncated = text.length > MAX_BODY;

      return {
        status: response.status,
        statusText: response.statusText,
        elapsed: elapsed + 'ms',
        headers: responseHeaders,
        bodyLength: text.length,
        body: truncated ? text.substring(0, MAX_BODY) + '\n... [truncated, ' + text.length + ' total chars]' : text,
        truncated,
        contentType: responseHeaders['content-type'] || null,
        securityHeaders: {
          csp: responseHeaders['content-security-policy'] || null,
          hsts: responseHeaders['strict-transport-security'] || null,
          xfo: responseHeaders['x-frame-options'] || null,
          xcto: responseHeaders['x-content-type-options'] || null,
          cors: responseHeaders['access-control-allow-origin'] || null,
        },
      };
    } catch (e) {
      clearTimeout(timeoutId);
      const elapsed = Date.now() - startTime;
      if (e.name === 'AbortError') return { error: true, message: 'Request timed out after 30s', elapsed: elapsed + 'ms' };
      return { error: true, message: 'Request failed: ' + e.message, elapsed: elapsed + 'ms' };
    }
  }

  async _getSessionAnalysis(tabId) {
    const allFindings = await this._getAllFindings(tabId);
    if (!allFindings) return { error: true, message: 'No scan data available.' };
    return allFindings.sessionState || { message: 'No session analysis data available.' };
  }

  async _getAuthFlows(tabId) {
    const allFindings = await this._getAllFindings(tabId);
    if (!allFindings) return { error: true, message: 'No scan data available.' };

    const flows = {};
    const oauthData = allFindings.oauthFlows;

    if (oauthData) {
      // OAuth flows are stored at oauthFlows.flows
      if (oauthData.flows && oauthData.flows.length > 0) flows.oauth = oauthData.flows;
      if (oauthData.issues && oauthData.issues.length > 0) flows.oauthIssues = oauthData.issues;
      // SAML assertions are nested at oauthFlows.samlAssertions
      if (oauthData.samlAssertions && oauthData.samlAssertions.length > 0) flows.saml = oauthData.samlAssertions;
    }

    return Object.keys(flows).length > 0 ? flows : { message: 'No OAuth/SAML flows captured.' };
  }

  async _getGraphQLSchema(tabId) {
    const allFindings = await this._getAllFindings(tabId);
    if (!allFindings || !allFindings.graphql) return { message: 'No GraphQL data detected.' };
    return allFindings.graphql;
  }

  async _exportReport(tabId, format, includeAiSummary) {
    const allFindings = await this._getAllFindings(tabId);
    const securityResults = await this._getSecurityResults(tabId);

    if (!allFindings && !securityResults) {
      return { error: true, message: 'No scan data to export.' };
    }

    // Use the resolved tabId (not active tab) to get the correct target URL
    let tab = null;
    try { tab = await chrome.tabs.get(tabId); } catch (e) { /* tab may be closed */ }
    const domain = tab ? (() => { try { return new URL(tab.url).hostname; } catch (e) { return 'unknown'; } })() : 'unknown';

    const metadata = {
      tool: 'Origami',
      version: '0.5.0',
      generatedAt: new Date().toISOString(),
      url: tab?.url || '',
      domain: domain,
      format: format,
    };

    // Compute score (popup's SecurityScorer doesn't persist, so compute here)
    let scoreData = securityResults?.scoreData || securityResults?.score || null;
    if (!scoreData && securityResults) {
      // Reuse the same scoring logic as _getSecurityScore
      const scoreResult = await this._getSecurityScore(tabId);
      if (scoreResult && !scoreResult.error) scoreData = scoreResult;
    }

    const report = {
      metadata,
      score: scoreData,
      findings: allFindings,
    };

    if (format === 'json') {
      return report;
    }

    // Build markdown/html directly in background context
    let md = '# Origami Security Report\n\n';
    md += '**Target:** ' + (tab?.url || 'N/A') + '  \n';
    md += '**Domain:** ' + domain + '  \n';
    md += '**Generated:** ' + metadata.generatedAt + '  \n';
    md += '**Tool:** Origami v0.5.0  \n\n';

    if (report.score) {
      md += '## Security Score\n\n';
      md += '**Score:** ' + (report.score.score || 'N/A') + '/100  \n';
      md += '**Grade:** ' + (report.score.grade || 'N/A') + '  \n\n';
    }

    // Render each category
    const categories = [
      ['secrets', 'Secrets'], ['headers', 'Security Headers'], ['cookies', 'Cookies'],
      ['vulnerabilities', 'Vulnerabilities'], ['sensitiveFiles', 'Sensitive Files'],
      ['sessionState', 'Session/JWT Analysis'], ['oauthFlows', 'OAuth/SAML Flows'],
      ['graphql', 'GraphQL'], ['correlationChains', 'Attack Chains'],
      ['crypto', 'Cryptographic Issues'], ['cloudStorage', 'Cloud Storage'],
      ['exfiltration', 'Exfiltration Risks'], ['websockets', 'WebSocket Issues'],
    ];

    for (const [key, title] of categories) {
      const items = this._extractItems(allFindings?.[key]);
      if (items.length === 0) continue;

      md += '## ' + title + ' (' + items.length + ')\n\n';
      items.forEach((f, i) => {
        const sev = this._effectiveSeverity(f);
        const msg = f.message || f.description || f.check || f.type || '';
        md += (i + 1) + '. **[' + sev + ']** ' + msg + '\n';
        if (f.details?.recommendation) md += '   - _Recommendation:_ ' + f.details.recommendation + '\n';
      });
      md += '\n';
    }

    // Technologies section
    if (allFindings?.technologies) {
      const techs = allFindings.technologies;
      let techList = [];
      if (Array.isArray(techs)) {
        techList = techs;
      } else if (typeof techs === 'object') {
        for (const items of Object.values(techs)) {
          if (Array.isArray(items)) techList.push(...items);
        }
      }
      if (techList.length > 0) {
        md += '## Technologies Detected (' + techList.length + ')\n\n';
        techList.forEach(t => {
          md += '- ' + (t.name || 'Unknown') + (t.version ? ' v' + t.version : '') + '\n';
        });
        md += '\n';
      }
    }

    // Optional AI summary
    if (includeAiSummary && typeof _backgroundLlmAnalyze === 'function') {
      const summaryPrompt = 'Write a concise executive summary (3-5 paragraphs) of this security scan:\n\n' + md.substring(0, 12000);
      const llmResult = await _backgroundLlmAnalyze(summaryPrompt, 'You are a security consultant writing an executive summary.', { maxTokens: 2048 });
      if (llmResult.success) {
        const data = llmResult.data;
        const text = data?.candidates?.[0]?.content?.parts?.[0]?.text ||
                     data?.choices?.[0]?.message?.content ||
                     data?.content?.[0]?.text ||
                     data?.response || '';
        if (text) {
          md = '# Origami Security Report\n\n## Executive Summary\n\n' + text + '\n\n---\n\n' + md.substring(md.indexOf('**Target:**'));
        }
      }
    }

    if (format === 'html') {
      // Wrap markdown in a basic HTML shell
      const escapedDomain = domain.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
      const html = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Origami Report - ' + escapedDomain + '</title>'
        + '<style>body{font-family:system-ui,sans-serif;max-width:900px;margin:2em auto;padding:0 1em;background:#0d1117;color:#c9d1d9}'
        + 'h1,h2{color:#58a6ff}code{background:#161b22;padding:2px 6px;border-radius:3px}</style></head><body>'
        + '<pre style="white-space:pre-wrap">' + md.replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</pre></body></html>';
      return { format: 'html', content: html };
    }

    return { format: 'markdown', content: md };
  }

  // ─── Data Access Helpers ─────────────────────────────────────────────────

  // Direct calls to background.js functions (same service worker context).
  // chrome.runtime.sendMessage does NOT deliver back to the sender in MV3,
  // so we call loadTabSecurityResults / loadTabFindings directly.

  async _getAllFindings(tabId) {
    try {
      const allFindings = {};

      const securityResults = await loadTabSecurityResults(tabId);
      if (securityResults) {
        allFindings.headers = securityResults.headers || null;
        allFindings.cookies = securityResults.cookies || null;
        allFindings.vulnerabilities = securityResults.vulnerabilities || null;
        allFindings.technologies = securityResults.technologies || null;
        allFindings.sensitiveFiles = securityResults.sensitiveFiles || null;
        allFindings.sessionState = securityResults.sessionState || null;
        allFindings.oauthFlows = securityResults.oauthFlows || null;
        allFindings.graphql = securityResults.graphql || null;
        allFindings.templateFindings = securityResults.templateFindings || null;
        allFindings.plugins = securityResults.plugins || null;
        allFindings.jsObfuscation = securityResults.jsObfuscation || null;
      }

      const findings = await loadTabFindings(tabId);
      if (findings && findings.length > 0) {
        allFindings.secrets = findings;
      }

      const cryptoKey = `tab_crypto_${tabId}`;
      const cryptoData = await chrome.storage.local.get(cryptoKey);
      allFindings.crypto = cryptoData[cryptoKey] || null;

      const cloudKey = `tab_cloud_storage_${tabId}`;
      const cloudData = await chrome.storage.local.get(cloudKey);
      allFindings.cloudStorage = cloudData[cloudKey] || null;

      const exfilKey = `tab_exfiltration_${tabId}`;
      const exfilData = await chrome.storage.local.get(exfilKey);
      allFindings.exfiltration = exfilData[exfilKey] || null;

      const wsKey = `tab_websockets_${tabId}`;
      const wsData = await chrome.storage.local.get(wsKey);
      allFindings.websockets = wsData[wsKey] || null;

      const obfuscationKey = `tab_js_obfuscation_${tabId}`;
      const obfuscationData = await chrome.storage.local.get(obfuscationKey);
      allFindings.jsObfuscation = allFindings.jsObfuscation || obfuscationData[obfuscationKey] || null;

      const chainsKey = `tab_chains_${tabId}`;
      const chainsData = await chrome.storage.local.get(chainsKey);
      allFindings.correlationChains = chainsData[chainsKey] || null;

      return allFindings;
    } catch (e) {
      console.error('Origami MCP: _getAllFindings error:', e.message);
      return null;
    }
  }

  async _getSecurityResults(tabId) {
    try {
      return await loadTabSecurityResults(tabId);
    } catch (e) {
      console.error('Origami MCP: _getSecurityResults error:', e.message);
      return null;
    }
  }

  async _loadTabFindings(tabId) {
    try {
      return await loadTabFindings(tabId);
    } catch (e) {
      console.error('Origami MCP: _loadTabFindings error:', e.message);
      return [];
    }
  }

  _buildApiValidationSection(validation, upgradeReason) {
    const enabled = validation.results.filter(r =>
      r.status === 'ENABLED' || r.status === 'ENABLED (Quota Exceeded)');
    if (enabled.length === 0) return '';

    const lines = [
      '',
      '## Google API Validation Results',
      '',
      'The user ran API validation on this key. ' + enabled.length + ' of ' + validation.total_count + ' tested APIs are enabled.',
      upgradeReason ? 'Risk escalation reason: ' + upgradeReason : '',
      'IMPORTANT: Prioritize PoC for the highest-impact enabled service (Firebase Auth > RTDB/Firestore/Storage > Cloud APIs > Maps/Geolocation).',
      '',
    ];

    enabled.forEach(r => {
      let entry = '- ' + r.service + ': ' + r.status;
      if (r.message) entry += ' -- ' + r.message;
      if (r.impact) entry += ' [Impact: ' + r.impact + ']';

      // Add structured details without leaking real tokens
      const d = r.details || {};
      if (r.service === 'Firebase Auth (Identity Toolkit)') {
        if (d.tokenObtained) entry += '\n  - Anonymous token minted successfully (idToken obtained)';
        if (r.localId) entry += '\n  - Anonymous user ID: ' + r.localId;
        if (d.authType) entry += '\n  - Auth type: ' + d.authType;
      } else if (r.service === 'Firebase Realtime Database') {
        if (d.accessLevel) entry += '\n  - Access level: ' + d.accessLevel;
        if (d.topLevelKeys && d.topLevelKeys.length > 0) entry += '\n  - Top-level keys: ' + d.topLevelKeys.slice(0, 10).join(', ');
        if (d.databaseUrl) entry += '\n  - Database URL: ' + d.databaseUrl;
      } else if (r.service === 'Cloud Firestore') {
        if (d.collections && d.collections.length > 0) entry += '\n  - Collections: ' + d.collections.slice(0, 10).join(', ');
      } else if (r.service === 'Firebase Storage') {
        if (d.itemCount != null) entry += '\n  - Files found: ' + d.itemCount;
        if (d.sampleFiles && d.sampleFiles.length > 0) entry += '\n  - Sample files: ' + d.sampleFiles.slice(0, 5).join(', ');
      }

      lines.push(entry);
    });

    lines.push('');
    lines.push('When Firebase Auth is enabled with anonymous signup, demonstrate the full chain:');
    lines.push('1. Mint anonymous token via identitytoolkit.googleapis.com/v1/accounts:signUp?key=KEY');
    lines.push('2. Use idToken to access RTDB/Firestore/Storage (auth != null bypass)');
    lines.push('3. Extract project config via identitytoolkit.googleapis.com/v1/projects?key=KEY');
    lines.push('Do NOT generate a generic Maps/Geolocation PoC when Firebase services are available.');

    return lines.filter(Boolean).join('\n');
  }

  _extractItems(data) {
    if (!data) return [];
    if (Array.isArray(data)) return data;
    if (data.findings && Array.isArray(data.findings)) return data.findings;
    if (data.allIssues && Array.isArray(data.allIssues) && data.allIssues.length > 0) return data.allIssues;
    if (data.issues && Array.isArray(data.issues) && data.issues.length > 0) return data.issues;
    if (data.tokens && Array.isArray(data.tokens)) {
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
    // Warn about unrecognized shapes to catch future data structure changes
    if (typeof data === 'object' && Object.keys(data).length > 0) {
      console.warn('Origami MCP: _extractItems unrecognized data shape, keys:', Object.keys(data).join(', '));
    }
    return [];
  }

  // Notify MCP server of events (scan complete, new findings, etc.)
  notifyEvent(event, data) {
    if (!this.connected) return;
    this._send({ type: 'event', event, data });
  }
}

// Export global instance
const mcpBridge = new MCPBridge();
