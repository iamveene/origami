// Origami Background Service Worker
// Coordinates scanning, notifications, webhooks, and history management

// MCP Bridge: must be imported at top-level for MV3 service worker compatibility
importScripts('mcp-bridge.js');

// Reusable LLM call function — used by the llmAnalyze message handler and mcp-bridge.js
// Returns { success, data, error } without using sendResponse, so any context can call it.
async function _backgroundLlmAnalyze(prompt, systemPrompt, options) {
  const data = await chrome.storage.sync.get(['settings']);
  const settings = data.settings || { llm: {} };
  const llm = settings.llm || {};

  if (!llm.enabled) {
    return { success: false, error: 'LLM not configured. Go to Settings to set up an AI provider.' };
  }

  const provider = llm.provider || 'ollama';
  const apiKey = llm.apiKey || '';
  const model = llm.model || '';
  const ollamaEndpoint = llm.endpoint || 'http://127.0.0.1:11434';
  const temperature = options?.temperature ?? llm.temperature ?? 0.3;
  const maxTokens = options?.maxTokens ?? llm.maxTokens ?? 8192;

  if (['openai', 'anthropic', 'gemini'].includes(provider) && !apiKey) {
    return { success: false, error: 'LLM API key not configured.' };
  }

  let fetchEndpoint = '';
  let fetchHeaders = {};
  let fetchBody = {};

  if (provider === 'gemini') {
    fetchEndpoint = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
    fetchHeaders = { 'Content-Type': 'application/json' };
    fetchBody = {
      systemInstruction: systemPrompt ? { parts: [{ text: systemPrompt }] } : undefined,
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { temperature, maxOutputTokens: maxTokens },
      thinkingConfig: { thinkingBudget: 0 },
      safetySettings: [
        { category: 'HARM_CATEGORY_HARASSMENT', threshold: 'BLOCK_NONE' },
        { category: 'HARM_CATEGORY_HATE_SPEECH', threshold: 'BLOCK_NONE' },
        { category: 'HARM_CATEGORY_SEXUALLY_EXPLICIT', threshold: 'BLOCK_NONE' },
        { category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_NONE' }
      ]
    };
  } else if (provider === 'openai') {
    fetchEndpoint = 'https://api.openai.com/v1/chat/completions';
    fetchHeaders = { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + apiKey };
    const messages = [];
    if (systemPrompt) messages.push({ role: 'system', content: systemPrompt });
    messages.push({ role: 'user', content: prompt });
    fetchBody = { model: model || 'gpt-4o', messages, temperature, max_tokens: maxTokens };
  } else if (provider === 'anthropic') {
    fetchEndpoint = 'https://api.anthropic.com/v1/messages';
    fetchHeaders = {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
      'anthropic-dangerous-direct-browser-access': 'true'
    };
    fetchBody = {
      model: model || 'claude-sonnet-4-5-20250929',
      max_tokens: maxTokens,
      temperature: temperature || 0.3,
      messages: [{ role: 'user', content: prompt }]
    };
    if (systemPrompt) fetchBody.system = systemPrompt;
  } else if (provider === 'ollama') {
    fetchEndpoint = ollamaEndpoint.replace(/\/+$/, '') + '/api/generate';
    fetchHeaders = { 'Content-Type': 'application/json' };
    const fullPrompt = systemPrompt ? (systemPrompt + '\n\n' + prompt) : prompt;
    fetchBody = {
      model: model || 'llama3.1:8b',
      prompt: fullPrompt,
      stream: false,
      options: { temperature, num_predict: maxTokens }
    };
  } else {
    return { success: false, error: 'Unknown LLM provider: ' + provider };
  }

  const isLocalRequest = fetchEndpoint.includes('localhost') || fetchEndpoint.includes('127.0.0.1');
  const cleanHeaders = { ...fetchHeaders };
  delete cleanHeaders['Origin'];
  delete cleanHeaders['Referer'];

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 120000);

  const fetchOptions = {
    method: 'POST',
    headers: cleanHeaders,
    body: JSON.stringify(fetchBody),
    signal: controller.signal
  };

  if (isLocalRequest) {
    fetchOptions.mode = 'cors';
    fetchOptions.credentials = 'omit';
    fetchOptions.referrerPolicy = 'no-referrer';
    fetchOptions.referrer = '';
  }

  try {
    const response = await fetch(fetchEndpoint, fetchOptions);
    clearTimeout(timeoutId);

    if (!response.ok) {
      const errorText = await response.text();
      if (isLocalRequest && response.status === 403) {
        return { success: false, error: 'Ollama rejected the request (403). Run with OLLAMA_ORIGINS="chrome-extension://*".' };
      }
      return { success: false, error: 'LLM API error (' + response.status + '): ' + errorText.substring(0, 500) };
    }

    const responseData = await response.json();
    return { success: true, data: responseData };
  } catch (error) {
    clearTimeout(timeoutId);
    if (error.name === 'AbortError') {
      return { success: false, error: 'LLM request timed out after 120 seconds' };
    }
    return { success: false, error: 'LLM request failed: ' + error.message };
  }
}

// Default settings
const DEFAULT_SETTINGS = {
  notifications_enabled: true,
  badge_enabled: true,
  badge_count_filter: 'critical_high', // 'all', 'critical', 'critical_high', 'critical_high_medium'
  badge_type_filter: {
    secrets: true,
    headers: true,
    cookies: true,
    vulnerabilities: true,
    sensitiveFiles: true,
    session: true,
    oauth: true,
    graphql: true,
    crypto: true,
    cloudStorage: true,
    exfiltration: true,
    websocket: true,
    jsObfuscation: true
  },
  auto_scan_enabled: true,
  auto_scan_sensitive_files: true,
  webhook: {
    enabled: false,
    url: '',
    method: 'POST',
    params: {}
  },
  custom_patterns: [], // Legacy - kept for backward compatibility
  history_enabled: true,
  api_validation: {
    enabled: true,
    auto_test: false,
    use_referer: true,
    quick_test_only: true
  },
  vuln_scanning: {
    scan_libraries: false,  // Default: OFF (skip libraries for fewer false positives)
    scan_minified: false    // Default: OFF (skip minified files)
  },
  llm: {
    enabled: true,
    provider: 'ollama',
    model: 'llama3.1:8b',
    apiKey: '',
    endpoint: 'http://127.0.0.1:11434',
    temperature: 0.3,
    maxTokens: 2000
  },
  mcpBridge: {
    enabled: false,
    wsUrl: 'ws://127.0.0.1:9340'
  },
  googleApiTesting: {
    // User's service selection preferences (27 total services)
    selectedServices: {
      // Original APIs (15)
      'youtube': true,
      'maps-static': true,
      'geolocation': true,
      'custom-search': true,
      'fcm': true,
      'translation': true,
      'books': true,
      'timezone': true,
      'directions': true,
      'places': true,
      'geocoding': true,
      'distance-matrix': true,
      'elevation': true,
      'pagespeed': true,
      'fonts': true,
      // AI/ML APIs (7)
      'vertex-ai': true,
      'gemini': true,
      'vision': true,
      'speech': true,
      'video-intelligence': true,
      'natural-language': true,
      'text-to-speech': true,
      // Infrastructure APIs (5)
      'resource-manager': true,
      'compute-engine': true,
      'cloud-storage': true,
      'secret-manager': true,
      'bigquery': true
    },
    // Active preset: 'custom', 'quick', 'ai-ml', 'infrastructure', 'all'
    activePreset: 'all',
    // Discovered project IDs (persisted for reuse)
    discoveredProjects: [],
    // Cost safety settings
    skipExpensiveTests: true,
    maxTestsPerScan: 27
  },
  cve_checking: {
    enabled: true,  // Enable CVE/EOL checking by default
    severity_filter: 'all',  // 'all', 'critical_high', 'critical'
    show_eol_warnings: true
  },
  analyzers: {
    session: true,
    oauth: true,
    graphql: true,
    crypto: true,
    cloudStorage: true,
    exfiltration: true,
    websocket: true,
    correlationEngine: true,
    surfaceTracker: true,
    jsObfuscation: true
  },
  httpHistory: {
    enabled: false,
    fullCapture: false,
    captureScope: 'same-origin',
    captureBodies: true,
    maxBodySize: 512 * 1024,
    retentionDays: 7,
    maxTotalSizeMB: 200,
    excludeMimeTypes: ['image/', 'font/', 'video/', 'audio/']
  }
};

const DEFAULT_WHITELIST = {
  domains: [],
  patterns: []
};

// ============================================================================
// Shared constants and helpers (normalizeSecretKey, severity utils)
// ============================================================================
importScripts('constants.js');
// ============================================================================

// CVE & EOL Checker - loaded from canonical source
// ============================================================================
importScripts('analyzers/cve-checker.js');
// ============================================================================

// Brute Force Directory/File Scanner
// ============================================================================
importScripts('analyzers/brute-force-scanner.js');
// ============================================================================

// Web Crawler
// ============================================================================
importScripts('analyzers/crawler.js');
// ============================================================================

// ============================================================================
// HTTP History -- IndexedDB helpers
// ============================================================================

var _httpHistoryDb = null;

// HTTP History capture state (in-memory, broadcast to content scripts)
// Use var so these are on globalThis (accessible from Playwright service worker evaluate)
var httpCaptureEnabled = false;
var httpCaptureScope = 'same-origin';
var httpFullCaptureTabId = null; // Tier 2: tab currently being debugged

function openHttpHistoryDb() {
  if (_httpHistoryDb) return Promise.resolve(_httpHistoryDb);
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(ORIGAMI_HTTP_HISTORY_DB_NAME, ORIGAMI_HTTP_HISTORY_DB_VERSION);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(ORIGAMI_HTTP_HISTORY_STORE)) {
        const store = db.createObjectStore(ORIGAMI_HTTP_HISTORY_STORE, { keyPath: 'id', autoIncrement: true });
        store.createIndex('timestamp', 'timestamp', { unique: false });
        store.createIndex('domain', 'domain', { unique: false });
        store.createIndex('method', 'method', { unique: false });
        store.createIndex('status', 'status', { unique: false });
        store.createIndex('contentType', 'contentType', { unique: false });
        store.createIndex('tabId', 'tabId', { unique: false });
      }
    };
    req.onsuccess = (e) => {
      _httpHistoryDb = e.target.result;
      _httpHistoryDb.onclose = () => { _httpHistoryDb = null; };
      resolve(_httpHistoryDb);
    };
    req.onerror = (e) => reject(e.target.error);
  });
}

async function addHttpHistoryEntry(entry) {
  const db = await openHttpHistoryDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(ORIGAMI_HTTP_HISTORY_STORE, 'readwrite');
    const store = tx.objectStore(ORIGAMI_HTTP_HISTORY_STORE);
    // Ensure required fields
    const record = {
      timestamp: entry.timestamp || Date.now(),
      method: entry.method || 'GET',
      url: entry.url || '',
      domain: entry.domain || '',
      path: entry.path || '',
      requestHeaders: entry.requestHeaders || {},
      requestBody: entry.requestBody || '',
      requestBodySize: entry.requestBodySize || 0,
      status: entry.status || 0,
      statusText: entry.statusText || '',
      contentType: entry.contentType || '',
      responseHeaders: entry.responseHeaders || {},
      responseBody: entry.responseBody || '',
      responseBodySize: entry.responseBodySize || 0,
      truncated: entry.truncated || false,
      timing: entry.timing || 0,
      tabId: entry.tabId || 0,
      tabUrl: entry.tabUrl || '',
      source: entry.source || 'unknown',
      tier: entry.tier || 1,
      redirectChain: entry.redirectChain || [],
      wsFrames: entry.wsFrames || [],
      pinned: false,
      hasCredentials: entry.hasCredentials || false
    };
    const req = store.add(record);
    req.onsuccess = () => resolve(req.result);
    req.onerror = (e) => reject(e.target.error);
  });
}

async function getHttpHistory(filters) {
  const db = await openHttpHistoryDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(ORIGAMI_HTTP_HISTORY_STORE, 'readonly');
    const store = tx.objectStore(ORIGAMI_HTTP_HISTORY_STORE);
    const index = store.index('timestamp');
    const results = [];
    const offset = filters.offset || 0;
    const limit = filters.limit || ORIGAMI_HTTP_HISTORY_PAGE_SIZE;
    let skipped = 0;

    // Walk backwards (newest first)
    const cursorReq = index.openCursor(null, 'prev');
    cursorReq.onsuccess = (e) => {
      const cursor = e.target.result;
      if (!cursor || results.length >= limit) {
        resolve(results);
        return;
      }
      const entry = cursor.value;

      // Apply filters
      if (filters.method && filters.method !== 'ALL' && entry.method !== filters.method) {
        cursor.continue();
        return;
      }
      if (filters.statusGroup) {
        const s = entry.status;
        if (filters.statusGroup === '2xx' && (s < 200 || s >= 300)) { cursor.continue(); return; }
        if (filters.statusGroup === '3xx' && (s < 300 || s >= 400)) { cursor.continue(); return; }
        if (filters.statusGroup === '4xx' && (s < 400 || s >= 500)) { cursor.continue(); return; }
        if (filters.statusGroup === '5xx' && (s < 500 || s >= 600)) { cursor.continue(); return; }
        if (filters.statusGroup === '0' && s !== 0) { cursor.continue(); return; }
      }
      if (filters.domain && !entry.domain.includes(filters.domain)) {
        cursor.continue();
        return;
      }
      if (filters.search) {
        const term = filters.search.toLowerCase();
        if (!entry.url.toLowerCase().includes(term) &&
            !entry.domain.toLowerCase().includes(term) &&
            !entry.path.toLowerCase().includes(term)) {
          cursor.continue();
          return;
        }
      }
      if (filters.source && entry.source !== filters.source) {
        cursor.continue();
        return;
      }
      if (filters.hasCredentials && !entry.hasCredentials) {
        cursor.continue();
        return;
      }
      if (filters.contentTypeFilter) {
        const ct = (entry.contentType || '').toLowerCase();
        if (filters.contentTypeFilter === 'json' && !ct.includes('json')) { cursor.continue(); return; }
        if (filters.contentTypeFilter === 'html' && !ct.includes('html')) { cursor.continue(); return; }
        if (filters.contentTypeFilter === 'xml' && !ct.includes('xml')) { cursor.continue(); return; }
        if (filters.contentTypeFilter === 'form' && !ct.includes('form')) { cursor.continue(); return; }
        if (filters.contentTypeFilter === 'text' && !ct.includes('text')) { cursor.continue(); return; }
      }

      // Pagination offset
      if (skipped < offset) {
        skipped++;
        cursor.continue();
        return;
      }

      // Strip response body for list view (too large for IPC)
      const slim = { ...entry };
      delete slim.responseBody;
      delete slim.requestBody;
      results.push(slim);
      cursor.continue();
    };
    cursorReq.onerror = (e) => reject(e.target.error);
  });
}

async function getHttpHistoryEntry(id) {
  const db = await openHttpHistoryDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(ORIGAMI_HTTP_HISTORY_STORE, 'readonly');
    const store = tx.objectStore(ORIGAMI_HTTP_HISTORY_STORE);
    const req = store.get(id);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = (e) => reject(e.target.error);
  });
}

async function clearHttpHistory() {
  const db = await openHttpHistoryDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(ORIGAMI_HTTP_HISTORY_STORE, 'readwrite');
    const store = tx.objectStore(ORIGAMI_HTTP_HISTORY_STORE);
    const req = store.clear();
    req.onsuccess = () => resolve();
    req.onerror = (e) => reject(e.target.error);
  });
}

async function getHttpHistoryCount() {
  const db = await openHttpHistoryDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(ORIGAMI_HTTP_HISTORY_STORE, 'readonly');
    const store = tx.objectStore(ORIGAMI_HTTP_HISTORY_STORE);
    const req = store.count();
    req.onsuccess = () => resolve(req.result);
    req.onerror = (e) => reject(e.target.error);
  });
}

async function toggleHttpHistoryPin(id, pinned) {
  const db = await openHttpHistoryDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(ORIGAMI_HTTP_HISTORY_STORE, 'readwrite');
    const store = tx.objectStore(ORIGAMI_HTTP_HISTORY_STORE);
    const getReq = store.get(id);
    getReq.onsuccess = () => {
      const record = getReq.result;
      if (!record) { resolve(false); return; }
      record.pinned = pinned;
      const putReq = store.put(record);
      putReq.onsuccess = () => resolve(true);
      putReq.onerror = (e) => reject(e.target.error);
    };
    getReq.onerror = (e) => reject(e.target.error);
  });
}

async function evictHttpHistory() {
  try {
    const db = await openHttpHistoryDb();

    // 1. Prune response bodies older than 24 hours
    const bodyThreshold = Date.now() - (ORIGAMI_HTTP_HISTORY_BODY_RETENTION_HOURS * 60 * 60 * 1000);
    await new Promise((resolve, reject) => {
      const tx = db.transaction(ORIGAMI_HTTP_HISTORY_STORE, 'readwrite');
      const store = tx.objectStore(ORIGAMI_HTTP_HISTORY_STORE);
      const index = store.index('timestamp');
      const range = IDBKeyRange.upperBound(bodyThreshold);
      const cursorReq = index.openCursor(range);
      cursorReq.onsuccess = (e) => {
        const cursor = e.target.result;
        if (!cursor) { resolve(); return; }
        const record = cursor.value;
        if (!record.pinned && (record.responseBody || record.requestBody)) {
          record.responseBody = '';
          record.requestBody = '';
          record.bodiesPruned = true;
          cursor.update(record);
        }
        cursor.continue();
      };
      cursorReq.onerror = (e) => reject(e.target.error);
    });

    // 2. Delete metadata older than retention period
    const metadataThreshold = Date.now() - (ORIGAMI_HTTP_HISTORY_RETENTION_DAYS * 24 * 60 * 60 * 1000);
    await new Promise((resolve, reject) => {
      const tx = db.transaction(ORIGAMI_HTTP_HISTORY_STORE, 'readwrite');
      const store = tx.objectStore(ORIGAMI_HTTP_HISTORY_STORE);
      const index = store.index('timestamp');
      const range = IDBKeyRange.upperBound(metadataThreshold);
      const cursorReq = index.openCursor(range);
      cursorReq.onsuccess = (e) => {
        const cursor = e.target.result;
        if (!cursor) { resolve(); return; }
        if (!cursor.value.pinned) {
          cursor.delete();
        }
        cursor.continue();
      };
      cursorReq.onerror = (e) => reject(e.target.error);
    });

    console.log('Origami: HTTP History eviction complete');
  } catch (e) {
    console.error('Origami: HTTP History eviction error:', e);
  }
}

// Broadcast capture state to all tabs
function broadcastHttpCaptureState() {
  chrome.tabs.query({}, (tabs) => {
    for (const tab of tabs) {
      chrome.tabs.sendMessage(tab.id, {
        action: 'httpCaptureControl',
        enabled: httpCaptureEnabled,
        scope: httpCaptureScope
      }).catch(() => {});
    }
  });
}

// ============================================================================
// HTTP History -- Tier 2 (chrome.debugger) Full Capture
// ============================================================================

// CDP state per debuggee
const cdpPendingRequests = new Map(); // requestId -> { method, url, headers, body, startTime, ... }

function enableFullCapture(tabId) {
  return new Promise((resolve, reject) => {
    chrome.debugger.attach({ tabId }, '1.3', () => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      httpFullCaptureTabId = tabId;
      // Enable Network domain
      chrome.debugger.sendCommand({ tabId }, 'Network.enable', {
        maxPostDataSize: 512 * 1024
      }, () => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        resolve();
      });
    });
  });
}

function disableFullCapture(tabId) {
  return new Promise((resolve) => {
    if (!tabId) { resolve(); return; }
    cdpPendingRequests.clear();
    chrome.debugger.detach({ tabId }, () => {
      if (tabId === httpFullCaptureTabId) httpFullCaptureTabId = null;
      resolve();
    });
  });
}

// CDP event handler
chrome.debugger.onEvent.addListener(async (source, method, params) => {
  if (source.tabId !== httpFullCaptureTabId) return;
  if (!httpCaptureEnabled) return;

  const tabId = source.tabId;

  if (method === 'Network.requestWillBeSent') {
    const req = params.request || {};
    const type = params.type || 'Other';
    cdpPendingRequests.set(params.requestId, {
      method: req.method || 'GET',
      url: req.url || '',
      headers: req.headers || {},
      postData: req.postData || '',
      startTime: Date.now(),
      type: type,
      redirectChain: params.redirectResponse ? [{
        url: params.redirectResponse.url,
        status: params.redirectResponse.status
      }] : []
    });
  }

  if (method === 'Network.responseReceived') {
    const pending = cdpPendingRequests.get(params.requestId);
    if (!pending) return;
    const resp = params.response || {};
    pending.status = resp.status || 0;
    pending.statusText = resp.statusText || '';
    pending.responseHeaders = resp.headers || {};
    pending.contentType = resp.mimeType || '';
    pending.timing = Math.round(Date.now() - pending.startTime);
  }

  if (method === 'Network.loadingFinished') {
    const pending = cdpPendingRequests.get(params.requestId);
    if (!pending) return;
    cdpPendingRequests.delete(params.requestId);

    let responseBody = '';
    let responseBodySize = 0;
    let truncated = false;
    const contentType = pending.contentType || '';

    // Skip binary MIME types for body retrieval
    const excludeMime = ORIGAMI_HTTP_HISTORY_EXCLUDE_MIME;
    const shouldSkipBody = excludeMime.some(prefix => contentType.toLowerCase().includes(prefix));

    if (!shouldSkipBody) {
      try {
        const bodyResult = await new Promise((resolve, reject) => {
          chrome.debugger.sendCommand({ tabId }, 'Network.getResponseBody', {
            requestId: params.requestId
          }, (result) => {
            if (chrome.runtime.lastError) {
              reject(new Error(chrome.runtime.lastError.message));
            } else {
              resolve(result);
            }
          });
        });
        const bodyText = bodyResult.body || '';
        responseBodySize = bodyText.length;
        if (bodyText.length > ORIGAMI_HTTP_HISTORY_MAX_BODY_SIZE) {
          responseBody = bodyText.substring(0, ORIGAMI_HTTP_HISTORY_MAX_BODY_SIZE);
          truncated = true;
        } else {
          responseBody = bodyText;
        }
      } catch (e) {
        responseBody = '[body unavailable]';
      }
    } else {
      responseBody = '[excluded: ' + contentType + ']';
    }

    // Map CDP resource type to source label
    const typeMap = {
      'Document': 'cdp-document', 'XHR': 'cdp-xhr', 'Fetch': 'cdp-xhr',
      'Script': 'cdp-script', 'Stylesheet': 'cdp-stylesheet',
      'Image': 'cdp-image', 'Font': 'cdp-font', 'WebSocket': 'cdp-websocket',
      'Other': 'cdp-other', 'Media': 'cdp-other', 'Manifest': 'cdp-other',
      'Ping': 'cdp-other', 'Preflight': 'cdp-other'
    };

    const domain = (() => { try { return new URL(pending.url).hostname; } catch (e) { return ''; } })();
    const path = (() => { try { return new URL(pending.url).pathname; } catch (e) { return ''; } })();

    // Scope check
    let shouldStore = true;
    if (httpCaptureScope === 'same-origin') {
      // For CDP we check against the tab URL's origin
      try {
        const tabInfo = await chrome.tabs.get(tabId);
        const tabOrigin = new URL(tabInfo.url).origin;
        const reqOrigin = new URL(pending.url).origin;
        if (tabOrigin !== reqOrigin) shouldStore = false;
      } catch (e) { /* store it */ }
    }

    if (!shouldStore) return;

    const credFields = ORIGAMI_HTTP_HISTORY_CREDENTIAL_FIELDS;
    const hasCredentials = credFields.some(f => (pending.postData || '').toLowerCase().includes(f));

    try {
      await addHttpHistoryEntry({
        timestamp: Date.now(),
        method: pending.method,
        url: pending.url,
        domain: domain,
        path: path,
        requestHeaders: pending.headers,
        requestBody: pending.postData,
        requestBodySize: (pending.postData || '').length,
        status: pending.status || 0,
        statusText: pending.statusText || '',
        contentType: contentType,
        responseHeaders: pending.responseHeaders || {},
        responseBody: responseBody,
        responseBodySize: responseBodySize,
        truncated: truncated,
        timing: pending.timing || Math.round(Date.now() - pending.startTime),
        tabId: tabId,
        tabUrl: pending.url,
        source: typeMap[pending.type] || 'cdp-other',
        tier: 2,
        redirectChain: pending.redirectChain || [],
        wsFrames: [],
        hasCredentials: hasCredentials
      });
    } catch (e) {
      console.error('Origami: Failed to store CDP entry:', e);
    }
  }

  // WebSocket frames (Tier 2 bonus)
  if (method === 'Network.webSocketFrameSent' || method === 'Network.webSocketFrameReceived') {
    const direction = method.includes('Sent') ? 'sent' : 'received';
    const payload = params.response?.payloadData || '';
    // Store as a standalone entry
    try {
      const domain = (() => { try { return new URL(params.url || '').hostname; } catch (e) { return ''; } })();
      await addHttpHistoryEntry({
        timestamp: Date.now(),
        method: 'WS',
        url: params.url || 'ws://unknown',
        domain: domain,
        path: '',
        requestHeaders: {},
        requestBody: direction === 'sent' ? payload : '',
        requestBodySize: direction === 'sent' ? payload.length : 0,
        status: 0,
        statusText: 'WebSocket ' + direction,
        contentType: 'websocket',
        responseHeaders: {},
        responseBody: direction === 'received' ? payload : '',
        responseBodySize: direction === 'received' ? payload.length : 0,
        truncated: false,
        timing: 0,
        tabId: tabId,
        tabUrl: '',
        source: 'cdp-websocket',
        tier: 2,
        redirectChain: [],
        wsFrames: [{ direction, data: payload, timestamp: Date.now() }],
        hasCredentials: false
      });
    } catch (e) { /* ignore WS store errors */ }
  }
});

// Clean up debugger on tab close
chrome.debugger.onDetach.addListener((source, reason) => {
  if (source.tabId === httpFullCaptureTabId) {
    httpFullCaptureTabId = null;
    cdpPendingRequests.clear();
  }
});

// Restore capture state from settings on startup
chrome.storage.sync.get(['settings'], (data) => {
  const settings = data.settings || DEFAULT_SETTINGS;
  httpCaptureEnabled = !!(settings.httpHistory && settings.httpHistory.enabled);
  httpCaptureScope = (settings.httpHistory && settings.httpHistory.captureScope) || 'same-origin';
});

// ============================================================================

// Initialize storage on install
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.sync.get(['settings', 'whitelist'], (data) => {
    if (!data.settings) {
      chrome.storage.sync.set({ settings: DEFAULT_SETTINGS });
    }
    if (!data.whitelist) {
      chrome.storage.sync.set({ whitelist: DEFAULT_WHITELIST });
    }
  });
  // History uses local storage (higher capacity - 10MB vs 100KB)
  chrome.storage.local.get(['history'], (data) => {
    if (!data.history) {
      chrome.storage.local.set({ history: [] });
    }
  });

  // Migrate secret_patterns from sync to local storage (one-time migration)
  chrome.storage.sync.get(['secret_patterns'], (syncData) => {
    if (syncData.secret_patterns) {
      chrome.storage.local.set({ secret_patterns: syncData.secret_patterns }, () => {
        chrome.storage.sync.remove('secret_patterns');
        console.log('Origami: Migrated secret_patterns from sync to local storage');
      });
    }
  });

  // Migrate history from sync to local storage (v0.5.0 migration - higher capacity)
  chrome.storage.sync.get(['history'], (syncData) => {
    if (syncData.history && syncData.history.length > 0) {
      chrome.storage.local.get(['history'], (localData) => {
        const localHistory = localData.history || [];
        // Merge: sync history first (older), then local (newer)
        const merged = [...syncData.history, ...localHistory];
        // Deduplicate by timestamp
        const unique = Array.from(new Map(merged.map(e => [e.timestamp, e])).values());
        unique.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        const trimmed = unique.slice(0, 100);
        chrome.storage.local.set({ history: trimmed }, () => {
          chrome.storage.sync.remove('history');
          console.log(`Origami: Migrated ${syncData.history.length} history entries from sync to local storage`);
        });
      });
    }
  });

  console.log('Origami installed successfully!');
});

// Check if a URL is whitelisted
function isWhitelisted(url, whitelist) {
  if (!whitelist || !whitelist.domains) return false;
  
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    
    // Check if domain is in whitelist
    return whitelist.domains.some(whitelistedDomain => {
      return domain === whitelistedDomain || domain.endsWith('.' + whitelistedDomain);
    });
  } catch (e) {
    return false;
  }
}

// Check if a regex pattern is safe from catastrophic backtracking (ReDoS)
function isSafeRegex(pattern) {
  // Reject patterns with nested quantifiers that cause catastrophic backtracking
  // e.g., (a+)+, (a*)*b, ([a-z]+)+, (a|a)+
  if (/(\+|\*|\{[^}]*\})\s*\)[\s]*(\+|\*|\{)/.test(pattern)) return false;
  if (/(\+|\*)\s*(\+|\*|\{)/.test(pattern)) return false;
  // Reject patterns longer than 200 chars to limit complexity
  if (pattern.length > 200) return false;
  return true;
}

// Check if a secret matches a whitelisted pattern
function isSecretWhitelisted(secret, whitelist) {
  if (!whitelist || !whitelist.patterns) return false;

  return whitelist.patterns.some(pattern => {
    try {
      // Check if it's a regex pattern (starts with / and ends with / plus optional flags)
      if (pattern.startsWith('/') && /\/[gimsuy]*$/.test(pattern)) {
        const lastSlash = pattern.lastIndexOf('/');
        const regexPattern = pattern.slice(1, lastSlash);
        const flags = pattern.slice(lastSlash + 1);
        if (!isSafeRegex(regexPattern)) {
          console.warn('Origami: Rejected potentially unsafe whitelist regex:', pattern);
          return false;
        }
        const regex = new RegExp(regexPattern, flags);
        // Use a timeout-safe test: limit input length
        const testValue = secret.substring(0, 1000);
        return regex.test(testValue);
      } else {
        // Plain string match
        return secret.includes(pattern);
      }
    } catch (e) {
      // Invalid regex, try plain string match
      return secret.includes(pattern);
    }
  });
}

// Normalize secret key by extracting the actual secret value
// Delegate to shared canonical normalization in constants.js
function normalizeSecretKey(secretValue) {
  return origamiNormalizeSecretKey(secretValue);
}

// Deduplicate secrets by keeping highest severity and merging pattern names
function deduplicateSecrets(findings) {
  if (!findings || findings.length === 0) return [];

  const secretMap = new Map();
  const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };

  findings.forEach(finding => {
    // Use normalized key for deduplication
    const secretKey = normalizeSecretKey(finding.full_key || finding.key);

    // Debug: Log normalization for Google API keys (masked to prevent console leakage)
    if ((finding.full_key || finding.key).includes('AIza')) {
      const maskedOriginal = (finding.full_key || finding.key).substring(0, 8) + '****';
      const maskedNormalized = secretKey.substring(0, 8) + '****';
      console.log('Origami: Normalizing secret:', {
        original: maskedOriginal,
        normalized: maskedNormalized,
        pattern: finding.pattern_matched,
        risk: finding.risk
      });
    }

    if (secretMap.has(secretKey)) {
      const existing = secretMap.get(secretKey);

      // Debug logging for duplicate detection (masked to prevent console leakage)
      const isGoogleKey = secretKey.includes('AIza');
      if (isGoogleKey) {
        console.log('Origami Debug: Duplicate secret detected:', {
          key: secretKey.substring(0, 8) + '****',
          existingPattern: existing.pattern_matched,
          existingRisk: existing.risk,
          currentPattern: finding.pattern_matched,
          currentRisk: finding.risk
        });
      }

      // Build patterns_matched array if not exists
      if (!existing.patterns_matched) {
        existing.patterns_matched = [existing.pattern_matched];
      }

      // Add current pattern if not already in the list
      if (finding.pattern_matched && !existing.patterns_matched.includes(finding.pattern_matched)) {
        existing.patterns_matched.push(finding.pattern_matched);
        if (isGoogleKey) {
          console.log('Origami Debug: Added pattern to existing finding:', {
            pattern: finding.pattern_matched,
            allPatterns: existing.patterns_matched
          });
        }
      }

      // Keep the finding with higher severity (lower severity number)
      // Use !== undefined to avoid treating 0 (CRITICAL) as falsy
      const currentSeverity = severityOrder[finding.risk] !== undefined ? severityOrder[finding.risk] : 5;
      const existingSeverity = severityOrder[existing.risk] !== undefined ? severityOrder[existing.risk] : 5;

      // Build locations array to preserve all source contexts
      if (!existing.locations) {
        existing.locations = [{
          url: existing.url || existing.source || existing.uri,
          lineNumber: existing.lineNumber,
          codeContext: existing.codeContext,
          matchedText: existing.matchedText
        }];
      }
      const currentLocation = {
        url: finding.url || finding.source || finding.uri,
        lineNumber: finding.lineNumber,
        codeContext: finding.codeContext,
        matchedText: finding.matchedText
      };
      const locationExists = existing.locations.some(loc =>
        loc.url === currentLocation.url && loc.lineNumber === currentLocation.lineNumber
      );
      if (!locationExists && currentLocation.url) {
        existing.locations.push(currentLocation);
      }

      if (currentSeverity < existingSeverity) {
        // Current has higher severity, use it but preserve data from existing
        finding.patterns_matched = existing.patterns_matched;
        finding.locations = existing.locations;

        if (isGoogleKey) {
          console.log('Origami Debug: Replacing with higher severity finding:', {
            oldRisk: existing.risk,
            newRisk: finding.risk,
            patterns: finding.patterns_matched
          });
        }

        // Preserve AI assessment and severity override if existing has them but current doesn't
        if (!finding.aiAssessment && existing.aiAssessment) {
          finding.aiAssessment = existing.aiAssessment;
        }
        if (!finding.severityOverride && existing.severityOverride) {
          finding.severityOverride = existing.severityOverride;
        }

        secretMap.set(secretKey, finding);
      } else if (currentSeverity === existingSeverity) {
        // Same severity, keep existing but merge AI assessment and override from current if better
        if (isGoogleKey) {
          console.log('Origami Debug: Keeping existing finding (same severity):', {
            risk: existing.risk,
            patterns: existing.patterns_matched
          });
        }

        if (!existing.aiAssessment && finding.aiAssessment) {
          existing.aiAssessment = finding.aiAssessment;
        }
        if (!existing.severityOverride && finding.severityOverride) {
          existing.severityOverride = finding.severityOverride;
        }

        secretMap.set(secretKey, existing);
      } else {
        // Existing has higher severity, keep it but merge AI assessment from current if needed
        if (isGoogleKey) {
          console.log('Origami Debug: Keeping existing finding (higher severity):', {
            existingRisk: existing.risk,
            currentRisk: finding.risk,
            patterns: existing.patterns_matched
          });
        }

        if (!existing.aiAssessment && finding.aiAssessment) {
          existing.aiAssessment = finding.aiAssessment;
        }
        if (!existing.severityOverride && finding.severityOverride) {
          existing.severityOverride = finding.severityOverride;
        }

        secretMap.set(secretKey, existing);
      }
    } else {
      // First occurrence of this secret (masked to prevent console leakage)
      if ((finding.full_key || finding.key).includes('AIza')) {
        console.log('Origami Debug: First occurrence of Google API key:', {
          key: secretKey.substring(0, 8) + '****',
          pattern: finding.pattern_matched,
          risk: finding.risk,
          patterns: finding.patterns_matched
        });
      }
      secretMap.set(secretKey, finding);
    }
  });

  return Array.from(secretMap.values());
}

// Filter findings based on whitelist
function filterFindings(findings, url, whitelist) {
  if (!findings || findings.length === 0) return [];

  // Check if URL is whitelisted
  if (isWhitelisted(url, whitelist)) {
    return [];
  }

  // Filter out whitelisted secrets (fall back to finding.key if full_key is missing)
  return findings.filter(finding => {
    const secretValue = finding.full_key || finding.key;
    return !secretValue || !isSecretWhitelisted(secretValue, whitelist);
  });
}

// Update badge with finding count (includes secrets and security findings)
async function updateBadge(tabId, findings, settings, securityResults = null) {
  if (!settings.badge_enabled) {
    chrome.action.setBadgeText({ tabId: tabId, text: '' });
    return;
  }
  
  // If security results not provided, try to load them
  if (!securityResults) {
    securityResults = await loadTabSecurityResults(tabId);
  }
  
  // Combine all findings (secrets + security issues), tagged by type
  const allFindings = findings.map(f => ({ ...f, _type: 'secrets' }));

  // Add security findings with normalized risk field
  if (securityResults) {
    const categories = ['headers', 'cookies', 'vulnerabilities', 'sensitiveFiles'];
    categories.forEach(category => {
      (securityResults[category] || []).forEach(item => {
        // Skip informational/OK items from badge count (summaries, properly configured items)
        if (item.status === 'INFO' || item.status === 'OK') return;
        const effectiveSeverity = item.severityOverride?.overriddenSeverity || item.severity || 'info';
        const risk = effectiveSeverity.toUpperCase();
        allFindings.push({ ...item, risk, _type: category });
      });
    });

    // Include findings from new analyzers stored in securityResults
    const nestedCategories = {
      session: (securityResults.sessionState?.allIssues?.length > 0
        ? securityResults.sessionState.allIssues
        : securityResults.sessionState?.issues) || [],
      oauth: securityResults.oauthFlows?.issues || [],
      graphql: securityResults.graphql?.issues || [],
      crypto: securityResults.crypto?.issues || [],
      cloudStorage: securityResults.cloudStorage?.issues || [],
      exfiltration: securityResults.exfiltration?.issues || [],
      websocket: securityResults.websockets?.issues || [],
      jsObfuscation: securityResults.jsObfuscation?.issues || []
    };
    Object.entries(nestedCategories).forEach(([cat, issues]) => {
      if (!Array.isArray(issues)) return;
      issues.forEach(item => {
        if (item.status === 'INFO' || item.status === 'OK') return;
        const effectiveSeverity = item.severityOverride?.overriddenSeverity || item.severity || 'info';
        const risk = effectiveSeverity.toUpperCase();
        allFindings.push({ ...item, risk, _type: cat });
      });
    });
  }
  
  // Use overridden severity for secret findings too
  const allFindingsWithOverride = allFindings.map(f => {
    if (f.severityOverride) {
      return { ...f, risk: f.severityOverride.overriddenSeverity.toUpperCase() };
    }
    return f;
  });
  
  // Filter findings based on badge_count_filter setting (excluding false positives)
  const filter = settings.badge_count_filter || 'all';
  let filteredFindings = allFindingsWithOverride.filter(f => f.risk !== 'NONE'); // Exclude false positives
  
  switch (filter) {
    case 'critical':
      filteredFindings = filteredFindings.filter(f => f.risk === 'CRITICAL');
      break;
    case 'critical_high':
      filteredFindings = filteredFindings.filter(f => f.risk === 'CRITICAL' || f.risk === 'HIGH');
      break;
    case 'critical_high_medium':
      filteredFindings = filteredFindings.filter(f => f.risk === 'CRITICAL' || f.risk === 'HIGH' || f.risk === 'MEDIUM');
      break;
    case 'all':
    default:
      // Already filtered to exclude NONE
      break;
  }

  // Filter by finding type
  const typeFilter = settings.badge_type_filter || { secrets: true, headers: true, cookies: true, vulnerabilities: true, sensitiveFiles: true, session: true, oauth: true, graphql: true, crypto: true, cloudStorage: true, exfiltration: true, websocket: true, jsObfuscation: true };
  filteredFindings = filteredFindings.filter(f => typeFilter[f._type] !== false);

  const count = filteredFindings.length;
  
  if (count === 0) {
    chrome.action.setBadgeText({ tabId: tabId, text: '' });
  } else {
    chrome.action.setBadgeText({ 
      tabId: tabId, 
      text: count > 99 ? '99+' : count.toString() 
    });
    
    // Set badge color based on highest severity finding
    const hasCritical = filteredFindings.some(f => f.risk === 'CRITICAL');
    const hasHigh = filteredFindings.some(f => f.risk === 'HIGH');
    const hasMedium = filteredFindings.some(f => f.risk === 'MEDIUM');
    const hasLow = filteredFindings.some(f => f.risk === 'LOW');
    const hasInfo = filteredFindings.some(f => f.risk === 'INFO');

    let badgeColor;
    if (hasCritical) {
      badgeColor = '#dc3545'; // Red for Critical
    } else if (hasHigh) {
      badgeColor = '#fd7e14'; // Orange for High
    } else if (hasMedium) {
      badgeColor = '#ffc107'; // Yellow for Medium
    } else if (hasLow) {
      badgeColor = '#28a745'; // Green for Low
    } else if (hasInfo) {
      badgeColor = '#3B82F6'; // Blue for Info
    } else {
      badgeColor = '#6b7280'; // Gray for other/no findings
    }
    
    chrome.action.setBadgeBackgroundColor({ 
      tabId: tabId, 
      color: badgeColor
    });
  }
}

// Send browser notification
function sendNotification(findings, url, settings) {
  if (!settings.notifications_enabled) return;
  
  // Only notify for CRITICAL and HIGH findings
  const criticalCount = findings.filter(f => f.risk === 'CRITICAL').length;
  const highCount = findings.filter(f => f.risk === 'HIGH').length;
  
  if (criticalCount === 0 && highCount === 0) return;

  let domain;
  try { domain = new URL(url).hostname; } catch(e) { domain = url || 'unknown'; }
  let message = '';
  
  if (criticalCount > 0) {
    message = `Found ${criticalCount} CRITICAL secret${criticalCount > 1 ? 's' : ''} on ${domain}`;
  } else {
    message = `Found ${highCount} HIGH risk secret${highCount > 1 ? 's' : ''} on ${domain}`;
  }
  
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: 'Origami: Secrets Detected!',
    message: message,
    priority: 2
  });
}

// Validate a URL against an allowlist of known safe endpoint patterns
// Used by SSRF-sensitive handlers (llmRequest, validateSecret, graphqlProxy, streaming)
function isAllowedLLMEndpoint(url) {
  try {
    const parsed = new URL(url);
    // Only allow HTTPS for cloud providers
    const allowedHosts = [
      'api.openai.com',
      'api.anthropic.com',
      'generativelanguage.googleapis.com',
      'api.groq.com',
      'api.mistral.ai',
      'api.cohere.ai',
      'api.together.xyz',
      'openrouter.ai'
    ];
    if (parsed.protocol === 'https:' && allowedHosts.some(h => parsed.hostname === h || parsed.hostname.endsWith('.' + h))) {
      return true;
    }
    // Allow localhost/127.0.0.1 for Ollama (local LLM) - HTTP only for local
    if ((parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1') &&
        (parsed.protocol === 'http:' || parsed.protocol === 'https:')) {
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

// Validate a URL for secret validation endpoints (known API providers only)
function isAllowedValidationEndpoint(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') return false;
    const allowedHosts = [
      'api.github.com',
      'api.stripe.com',
      'api.openai.com',
      'api.anthropic.com',
      'generativelanguage.googleapis.com',
      'api.sendgrid.com',
      'api.mailgun.net',
      'api.twilio.com',
      'api.slack.com',
      'slack.com',
      'hooks.slack.com',
      'discord.com',
      'api.heroku.com',
      'api.dropboxapi.com',
      'www.googleapis.com',
      'maps.googleapis.com',
      'oauth2.googleapis.com',
      'sts.amazonaws.com',
      'management.azure.com',
      'api.digitalocean.com',
      'api.cloudflare.com',
      'api.datadog.com',
      'app.datadoghq.com',
      'sentry.io'
    ];
    return allowedHosts.some(h => parsed.hostname === h || parsed.hostname.endsWith('.' + h));
  } catch {
    return false;
  }
}

// Validate webhook URL to prevent SSRF
function isWebhookUrlSafe(webhookUrl) {
  try {
    const parsed = new URL(webhookUrl);
    // Only allow HTTPS
    if (parsed.protocol !== 'https:') return false;
    // Block localhost, loopback, and all private/reserved addresses
    const hostname = parsed.hostname.toLowerCase();
    const blockedHosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]', '[::ffff:127.0.0.1]'];
    if (blockedHosts.includes(hostname)) return false;
    // Block private IP ranges (including hex, octal, IPv6-mapped)
    const ip = hostname;
    if (/^10\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
        /^192\.168\./.test(ip) || /^169\.254\./.test(ip) ||
        /^0\./.test(ip) || /^127\./.test(ip) ||
        /^fc00/i.test(ip) || /^fe80/i.test(ip) || /^fd/i.test(ip) ||
        /^0x/i.test(ip) || /^0[0-7]+\./.test(ip) ||
        /^\[.*ffff.*\]/i.test(ip) || /^\[fc/i.test(ip) || /^\[fe80/i.test(ip) ||
        ip === '[::1]' || ip === '::1') return false;
    // Block numeric-only hostnames (decimal IP like 2130706433)
    if (/^\d+$/.test(ip)) return false;
    // Block known localhost aliases
    if (hostname === 'localtest.me' || hostname.endsWith('.localhost')) return false;
    return true;
  } catch {
    return false;
  }
}

// Send webhook
async function sendWebhook(findings, url, settings, securityResults) {
  if (!settings.webhook || !settings.webhook.enabled || !settings.webhook.url) {
    return;
  }

  if (!isWebhookUrlSafe(settings.webhook.url)) {
    console.warn('Origami: Webhook URL points to localhost or private network, skipping for security');
    return;
  }
  
  let domain;
  try { domain = new URL(url).hostname; } catch(e) { domain = url || 'unknown'; }

  const payload = {
    timestamp: new Date().toISOString(),
    url: url,
    domain: domain,
    findings: findings.map(f => ({
      key: f.key,
      masked_key: f.full_key ? f.full_key.substring(0, 4) + '****' + f.full_key.substring(f.full_key.length - 4) : f.key,
      risk: f.risk,
      pattern_matched: f.pattern_matched,
      length: f.length
    })),
    summary: {
      total: findings.length,
      critical: findings.filter(f => f.risk === 'CRITICAL').length,
      high: findings.filter(f => f.risk === 'HIGH').length,
      medium: findings.filter(f => f.risk === 'MEDIUM').length
    },
    security_findings: securityResults ? {
      headers: (securityResults.headers || []).length,
      cookies: (securityResults.cookies || []).length,
      vulnerabilities: (securityResults.vulnerabilities || []).length,
      sensitiveFiles: (securityResults.sensitiveFiles || []).length,
      session: (securityResults.sessionState?.allIssues || securityResults.sessionState?.issues || []).length,
      oauth: (securityResults.oauthFlows?.issues || []).length,
      graphql: (securityResults.graphql?.issues || []).length,
      crypto: (securityResults.crypto?.issues || []).length,
      cloudStorage: (securityResults.cloudStorage?.issues || []).length,
      exfiltration: (securityResults.exfiltration?.issues || []).length,
      websockets: (securityResults.websockets?.issues || []).length,
      jsObfuscation: (securityResults.jsObfuscation?.issues || []).length
    } : null,
    ...settings.webhook.params // Include custom parameters
  };
  
  try {
    const response = await fetch(settings.webhook.url, {
      method: settings.webhook.method || 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });
    
    if (!response.ok) {
      console.error('Origami: Webhook failed with status', response.status);
      // Retry logic could be added here
    } else {
      console.log('Origami: Webhook sent successfully');
    }
  } catch (error) {
    console.error('Origami: Webhook error:', error);
  }
}

// Add to history (stored in local storage for higher capacity - 10MB vs 100KB)
async function addToHistory(findings, url, settings, securityResults) {
  if (!settings.history_enabled) return;

  chrome.storage.local.get(['history'], (data) => {
    let history = data.history || [];

    let domain;
    try { domain = new URL(url).hostname; } catch(e) { domain = url || 'unknown'; }

    const entry = {
      timestamp: new Date().toISOString(),
      url: url,
      domain: domain,
      findings: findings.map(f => ({
        key: f.key,
        masked_key: f.full_key ? f.full_key.substring(0, 4) + '****' + f.full_key.substring(f.full_key.length - 4) : f.key,
        risk: f.risk,
        pattern_matched: f.pattern_matched
      })),
      risk_summary: {
        total: findings.length,
        critical: findings.filter(f => f.risk === 'CRITICAL').length,
        high: findings.filter(f => f.risk === 'HIGH').length,
        medium: findings.filter(f => f.risk === 'MEDIUM').length
      }
    };

    if (securityResults) {
      entry.security_summary = {
        headers: (securityResults.headers || []).length,
        cookies: (securityResults.cookies || []).length,
        vulnerabilities: (securityResults.vulnerabilities || []).length,
        sensitiveFiles: (securityResults.sensitiveFiles || []).length,
        session: (securityResults.sessionState?.allIssues || securityResults.sessionState?.issues || []).length,
        oauth: (securityResults.oauthFlows?.issues || []).length,
        graphql: (securityResults.graphql?.issues || []).length,
        crypto: (securityResults.crypto?.issues || []).length,
        cloudStorage: (securityResults.cloudStorage?.issues || []).length,
        exfiltration: (securityResults.exfiltration?.issues || []).length,
        websocket: (securityResults.websockets?.issues || []).length,
        jsObfuscation: (securityResults.jsObfuscation?.issues || []).length
      };
    }

    // Add to beginning of history
    history.unshift(entry);

    // Keep only last 100 entries
    if (history.length > 100) {
      history = history.slice(0, 100);
    }

    chrome.storage.local.set({ history: history });
  });
}

// Check storage quota and warn if approaching limit
async function checkStorageQuota() {
  try {
    const bytesInUse = await chrome.storage.local.getBytesInUse(null);
    const quotaBytes = chrome.storage.local.QUOTA_BYTES || 10485760; // 10MB default
    const usagePercent = (bytesInUse / quotaBytes) * 100;

    if (usagePercent > 80) {
      console.warn(`Origami: Storage usage at ${usagePercent.toFixed(1)}% (${(bytesInUse / 1024).toFixed(0)}KB / ${(quotaBytes / 1024).toFixed(0)}KB)`);

      // Prune domain caches older than 1 day at 80%+
      const allData = await chrome.storage.local.get(null);
      const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      const toPrune = [];
      for (const key of Object.keys(allData)) {
        if (key.startsWith('domain_cache_')) {
          const entry = allData[key];
          if (entry && entry.cachedAt && entry.cachedAt < oneDayAgo) {
            toPrune.push(key);
          }
        }
      }
      if (toPrune.length > 0) {
        await chrome.storage.local.remove(toPrune);
        console.log(`Origami: Pruned ${toPrune.length} domain caches due to storage pressure`);
      }

      // Auto-prune history and AI caches if above 90%
      if (usagePercent > 90) {
        const data = await chrome.storage.local.get(['history']);
        let history = data.history || [];
        if (history.length > 50) {
          history = history.slice(0, 50);
          await chrome.storage.local.set({ history });
          console.log('Origami: Auto-pruned history to 50 entries due to storage pressure');
        }

        // Prune AI cache entries older than 3 days under severe pressure
        toPrune.length = 0;
        const threeDaysAgo = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString();
        for (const key of Object.keys(allData)) {
          if (key.startsWith('ai_cache_')) {
            const cache = allData[key];
            if (cache && typeof cache === 'object') {
              let pruned = false;
              for (const [fp, d] of Object.entries(cache)) {
                if (d.cachedAt && d.cachedAt < threeDaysAgo) {
                  delete cache[fp];
                  pruned = true;
                }
              }
              if (Object.keys(cache).length === 0) {
                toPrune.push(key);
              } else if (pruned) {
                await chrome.storage.local.set({ [key]: cache });
              }
            }
          }
        }
        if (toPrune.length > 0) {
          await chrome.storage.local.remove(toPrune);
        }
      }

      return { usagePercent, bytesInUse, quotaBytes, warning: true };
    }

    return { usagePercent, bytesInUse, quotaBytes, warning: false };
  } catch (error) {
    console.error('Origami: Storage quota check failed:', error);
    return null;
  }
}

// Store current findings for the tab
const tabFindings = new Map();

// Store security analysis results for each tab
const tabSecurityResults = new Map();

// Store resource inventory for each tab
const tabInventory = new Map();

// Active brute force scanner instance (one at a time)
let activeBruteForceScanner = null;
let bruteForceScanSenderId = null;
// Active web crawler instance (one at a time)
let activeCrawler = null;

// Store validation results for Google API keys
const apiValidationResults = new Map(); // key -> validation results

// Track which domain each tab is on (for domain-level caching)
const tabDomains = new Map(); // tabId -> hostname

// Resolve the domain for a tab, using cache or chrome.tabs.get()
async function getDomainForTab(tabId) {
  if (tabDomains.has(tabId)) return tabDomains.get(tabId);
  try {
    const tab = await chrome.tabs.get(tabId);
    if (tab && tab.url) {
      const domain = new URL(tab.url).hostname;
      tabDomains.set(tabId, domain);
      return domain;
    }
  } catch (e) { /* tab may not exist */ }
  return null;
}

// Stable fingerprint for matching AI assessments across scans
function findingFingerprint(finding, category) {
  return origamiFindingFingerprint(finding, category);
}

// Helper: Save findings to persistent storage
async function saveTabFindings(tabId, findings) {
  tabFindings.set(tabId, findings);

  // Also persist to chrome.storage.local to survive service worker restarts
  try {
    const storageKey = `tab_findings_${tabId}`;
    await chrome.storage.local.set({ [storageKey]: findings });

    // Cache AI assessments at domain level for persistence across navigation
    const domain = await getDomainForTab(tabId);
    if (domain) {
      const assessed = findings
        .filter(f => f.aiAssessment)
        .map(f => ({
          fingerprint: findingFingerprint(f, 'secrets'),
          aiAssessment: f.aiAssessment,
          severityOverride: f.severityOverride
        }));
      if (assessed.length > 0) {
        saveAIAssessmentCache(domain, assessed);
      }
    }
  } catch (error) {
    console.error('Error saving findings to storage:', error);
  }
}

// Helper: Load findings from persistent storage
async function loadTabFindings(tabId) {
  // Check memory first
  if (tabFindings.has(tabId)) {
    return tabFindings.get(tabId);
  }
  
  // If not in memory, try to load from storage
  try {
    const storageKey = `tab_findings_${tabId}`;
    const result = await chrome.storage.local.get(storageKey);
    const findings = result[storageKey] || [];
    
    if (findings.length > 0) {
      tabFindings.set(tabId, findings);
    }
    
    return findings;
  } catch (error) {
    console.error('Error loading findings from storage:', error);
    return [];
  }
}

// Helper: Save security results to persistent storage
async function saveTabSecurityResults(tabId, results) {
  tabSecurityResults.set(tabId, results);

  try {
    const storageKey = `tab_security_${tabId}`;
    await chrome.storage.local.set({ [storageKey]: results });

    // Cache AI assessments from security findings at domain level
    const domain = await getDomainForTab(tabId);
    if (domain) {
      const assessed = [];
      for (const [category, items] of Object.entries(results)) {
        if (Array.isArray(items)) {
          items.filter(f => f.aiAssessment).forEach(f => {
            assessed.push({
              fingerprint: findingFingerprint(f, category),
              aiAssessment: f.aiAssessment,
              severityOverride: f.severityOverride
            });
          });
        }
      }
      if (assessed.length > 0) {
        saveAIAssessmentCache(domain, assessed);
      }
    }
  } catch (error) {
    console.error('Error saving security results to storage:', error);
  }
}

// Helper: Load security results from persistent storage
async function loadTabSecurityResults(tabId) {
  // Check memory first
  if (tabSecurityResults.has(tabId)) {
    return tabSecurityResults.get(tabId);
  }
  
  // If not in memory, try to load from storage
  try {
    const storageKey = `tab_security_${tabId}`;
    const result = await chrome.storage.local.get(storageKey);
    const securityResults = result[storageKey] || null;
    
    if (securityResults) {
      tabSecurityResults.set(tabId, securityResults);
    }
    
    return securityResults;
  } catch (error) {
    console.error('Error loading security results from storage:', error);
    return null;
  }
}

// Helper: Save brute force state to persistent storage
async function saveBruteForceState(tabId, domain, state) {
  try {
    if (tabId) {
      const tabKey = `bruteforce_results_${tabId}`;
      await chrome.storage.local.set({ [tabKey]: state });
    }
    if (domain) {
      const domainKey = `bruteforce_cache_${domain}`;
      await chrome.storage.local.set({ [domainKey]: { ...state, cachedAt: Date.now() } });
    }
  } catch (error) {
    console.error('Error saving brute force state:', error);
  }
}

// Helper: Save crawler state to persistent storage
async function saveCrawlerState(tabId, domain, state) {
  try {
    if (tabId) {
      const tabKey = `crawler_results_${tabId}`;
      await chrome.storage.local.set({ [tabKey]: state });
    }
    if (domain) {
      const domainKey = `crawler_cache_${domain}`;
      await chrome.storage.local.set({ [domainKey]: { ...state, cachedAt: Date.now() } });
    }
  } catch (error) {
    console.error('Error saving crawler state:', error);
  }
}

// Helper: Save inventory to persistent storage (merges with existing)
async function saveTabInventory(tabId, inventory) {
  const existing = tabInventory.get(tabId);
  if (existing && existing.domain === inventory.domain) {
    // Same domain: merge resources
    const merged = {
      ...existing,
      timestamp: inventory.timestamp,
      url: inventory.url,
      resources: { ...existing.resources, ...inventory.resources },
      externalResources: { ...existing.externalResources }
    };
    // Merge external resources
    if (inventory.externalResources) {
      for (const [domain, resources] of Object.entries(inventory.externalResources)) {
        if (!merged.externalResources[domain]) {
          merged.externalResources[domain] = [];
        }
        const existingPaths = new Set(merged.externalResources[domain].map(r => r.path));
        for (const r of resources) {
          if (!existingPaths.has(r.path)) {
            merged.externalResources[domain].push(r);
          }
        }
      }
    }
    tabInventory.set(tabId, merged);
    inventory = merged;
  } else {
    // Different domain or no existing: replace
    tabInventory.set(tabId, inventory);
  }

  try {
    const storageKey = `tab_inventory_${tabId}`;
    await chrome.storage.local.set({ [storageKey]: inventory });
  } catch (error) {
    console.error('Error saving inventory to storage:', error);
  }

  // Also cache at domain level for navigation preservation
  if (inventory.domain) {
    saveDomainInventory(inventory.domain, inventory);
  }
}

// Helper: Load inventory from persistent storage
async function loadTabInventory(tabId) {
  if (tabInventory.has(tabId)) {
    return tabInventory.get(tabId);
  }

  try {
    const storageKey = `tab_inventory_${tabId}`;
    const result = await chrome.storage.local.get(storageKey);
    const inventory = result[storageKey] || null;
    if (inventory) {
      tabInventory.set(tabId, inventory);
    }
    return inventory;
  } catch (error) {
    console.error('Error loading inventory from storage:', error);
    return null;
  }
}

// Helper: Save domain-level inventory cache (survives tab navigation)
async function saveDomainInventory(domain, inventory) {
  if (!domain) return;
  try {
    const storageKey = `domain_inventory_${domain}`;
    await chrome.storage.local.set({
      [storageKey]: {
        ...inventory,
        cachedAt: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('Error saving domain inventory:', error);
  }
}

// Helper: Load domain-level inventory cache
async function loadDomainInventory(domain) {
  if (!domain) return null;
  try {
    const storageKey = `domain_inventory_${domain}`;
    const result = await chrome.storage.local.get(storageKey);
    return result[storageKey] || null;
  } catch (error) {
    console.error('Error loading domain inventory:', error);
    return null;
  }
}

// --- Domain-level caches for assessment persistence ---

// Save AI assessments to a domain-level cache (survives tab close/navigate)
async function saveAIAssessmentCache(domain, assessments) {
  if (!domain || !assessments || assessments.length === 0) return;
  try {
    const storageKey = `ai_cache_${domain}`;
    const existing = (await chrome.storage.local.get(storageKey))[storageKey] || {};

    for (const entry of assessments) {
      existing[entry.fingerprint] = {
        aiAssessment: entry.aiAssessment,
        severityOverride: entry.severityOverride || null,
        cachedAt: new Date().toISOString()
      };
    }

    // Cap at 200 entries per domain
    const entries = Object.entries(existing);
    if (entries.length > 200) {
      entries.sort((a, b) => (b[1].cachedAt || '').localeCompare(a[1].cachedAt || ''));
      await chrome.storage.local.set({ [storageKey]: Object.fromEntries(entries.slice(0, 200)) });
    } else {
      await chrome.storage.local.set({ [storageKey]: existing });
    }
  } catch (error) {
    console.error('Origami: Error saving AI assessment cache:', error);
  }
}

// Load AI assessment cache for a domain
async function loadAIAssessmentCache(domain) {
  if (!domain) return {};
  try {
    const storageKey = `ai_cache_${domain}`;
    const result = await chrome.storage.local.get(storageKey);
    return result[storageKey] || {};
  } catch (error) {
    console.error('Origami: Error loading AI assessment cache:', error);
    return {};
  }
}

// Merge cached AI assessments into Phase 2-3 issues before returning to popup
async function mergeAICacheIntoIssues(tabId, data, category) {
  if (!data) return;
  const domain = tabDomains.get(tabId);
  if (!domain) return;
  const aiCache = await loadAIAssessmentCache(domain);
  if (Object.keys(aiCache).length === 0) return;
  const items = Array.isArray(data) ? data : (data.issues || []);
  let merged = 0;
  items.forEach(f => {
    if (f.aiAssessment) return;
    const fp = findingFingerprint(f, category);
    const cached = aiCache[fp];
    if (cached) {
      f.aiAssessment = cached.aiAssessment;
      if (cached.severityOverride && !f.severityOverride) {
        f.severityOverride = cached.severityOverride;
      }
      merged++;
    }
  });
  if (merged > 0) console.log(`Origami: Merged ${merged} cached AI assessments into ${category} results`);
}

// Snapshot all tab data to a domain-level cache before it gets cleared
async function snapshotToDomainCache(tabId, domain) {
  if (!domain) return;
  const now = new Date().toISOString();

  try {
    const findings = await loadTabFindings(tabId);
    const secResults = await loadTabSecurityResults(tabId);

    // Only cache if there's meaningful data
    if ((!findings || findings.length === 0) && !secResults) return;

    // Gather specialized results from storage
    const specKeys = [
      `tab_crypto_${tabId}`, `tab_cloud_storage_${tabId}`,
      `tab_exfiltration_${tabId}`, `tab_websockets_${tabId}`,
      `tab_oauth_flows_${tabId}`, `tab_graphql_${tabId}`,
      `tab_surface_${tabId}`, `tab_chains_${tabId}`,
      `tab_js_obfuscation_${tabId}`
    ];
    const specData = await chrome.storage.local.get(specKeys);

    // Truncate large AI analysis text in domain cache (full version in ai_cache_)
    const compactFindings = (findings || []).map(f => {
      if (f.aiAssessment && f.aiAssessment.analysis && f.aiAssessment.analysis.length > 500) {
        return { ...f, aiAssessment: { ...f.aiAssessment, analysis: f.aiAssessment.analysis.substring(0, 500) + '...' } };
      }
      return f;
    });

    const compactSecurity = secResults ? JSON.parse(JSON.stringify(secResults)) : null;
    if (compactSecurity) {
      for (const items of Object.values(compactSecurity)) {
        if (Array.isArray(items)) {
          items.forEach(f => {
            if (f.aiAssessment && f.aiAssessment.analysis && f.aiAssessment.analysis.length > 500) {
              f.aiAssessment.analysis = f.aiAssessment.analysis.substring(0, 500) + '...';
            }
          });
        }
      }
    }

    const cacheEntry = {
      domain, cachedAt: now,
      findings: compactFindings,
      securityResults: compactSecurity,
      crypto: specData[`tab_crypto_${tabId}`] || null,
      cloudStorage: specData[`tab_cloud_storage_${tabId}`] || null,
      exfiltration: specData[`tab_exfiltration_${tabId}`] || null,
      websockets: specData[`tab_websockets_${tabId}`] || null,
      oauthFlows: specData[`tab_oauth_flows_${tabId}`] || null,
      graphql: specData[`tab_graphql_${tabId}`] || null,
      surface: specData[`tab_surface_${tabId}`] || null,
      chains: specData[`tab_chains_${tabId}`] || null,
      jsObfuscation: specData[`tab_js_obfuscation_${tabId}`] || null
    };

    await chrome.storage.local.set({ [`domain_cache_${domain}`]: cacheEntry });
    console.log('Origami: Domain cache saved for', domain);
  } catch (error) {
    console.error('Origami: Error saving domain cache:', error);
  }
}

// Load domain cache
async function loadDomainCache(domain) {
  if (!domain) return null;
  try {
    const storageKey = `domain_cache_${domain}`;
    const result = await chrome.storage.local.get(storageKey);
    return result[storageKey] || null;
  } catch (error) {
    console.error('Origami: Error loading domain cache:', error);
    return null;
  }
}

// Helper: Clear findings from both memory and storage
async function clearTabFindings(tabId) {
  tabFindings.delete(tabId);
  tabSecurityResults.delete(tabId);
  tabInventory.delete(tabId);

  try {
    const storageKey = `tab_findings_${tabId}`;
    const securityKey = `tab_security_${tabId}`;
    const inventoryKey = `tab_inventory_${tabId}`;
    const pluginResultsKey = `tab_plugin_results_${tabId}`;
    const oauthKey = `tab_oauth_flows_${tabId}`;
    const graphqlKey = `tab_graphql_${tabId}`;
    const surfaceKey = `tab_surface_${tabId}`;
    const chainsKey = `tab_chains_${tabId}`;
    const cryptoKey = `tab_crypto_${tabId}`;
    const cloudStorageKey = `tab_cloud_storage_${tabId}`;
    const exfiltrationKey = `tab_exfiltration_${tabId}`;
    const websocketsKey = `tab_websockets_${tabId}`;
    const jsObfuscationKey = `tab_js_obfuscation_${tabId}`;
    const bruteforceKey = `bruteforce_results_${tabId}`;
    const crawlerKey = `crawler_results_${tabId}`;
    await chrome.storage.local.remove([storageKey, securityKey, inventoryKey, pluginResultsKey, oauthKey, graphqlKey, surfaceKey, chainsKey, cryptoKey, cloudStorageKey, exfiltrationKey, websocketsKey, jsObfuscationKey, bruteforceKey, crawlerKey]);
  } catch (error) {
    console.error('Error clearing findings from storage:', error);
  }
}

// Helper: Reassess Google API key risk based on validation results.
// Default is LOW (exposure only risks billing). Upgrades:
//   LOW -> CRITICAL  when dangerous services are enabled (Gemini, Compute, Storage, Secrets, etc.)
//   LOW -> HIGH      when any other services are enabled (billing-impacting APIs)
async function reassessAPIKeyRisk(tabId, apiKey, newRisk, reason) {
  try {
    const findings = await loadTabFindings(tabId);
    if (!findings || findings.length === 0) return;

    let updated = false;
    const updatedFindings = findings.map(finding => {
      const normalizedKey = normalizeSecretKey(finding.full_key || finding.key);
      const isGoogleAPIKey = finding.pattern_matched === 'Google Cloud API Key' ||
        (finding.full_key || finding.key || '').startsWith('AIza');
      if (normalizedKey === apiKey && isGoogleAPIKey) {
        const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };
        const currentLevel = severityOrder[finding.risk] ?? 3;
        const newLevel = severityOrder[newRisk] ?? 3;
        // Only upgrade, never downgrade
        if (newLevel < currentLevel) {
          console.log(`Origami: Upgrading Google API key from ${finding.risk} to ${newRisk}:`, apiKey.substring(0, 8) + '****');
          updated = true;
          return { ...finding, risk: newRisk, upgrade_reason: reason };
        }
      }
      return finding;
    });

    if (updated) {
      await saveTabFindings(tabId, updatedFindings);
      const settings = await new Promise(resolve => {
        chrome.storage.sync.get(['settings'], data => resolve(data.settings || DEFAULT_SETTINGS));
      });
      if (settings.badge_enabled) {
        updateBadge(tabId, updatedFindings, settings);
      }
    }
  } catch (error) {
    console.error('Error reassessing API key risk:', error);
  }
}

// Handle messages from content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // Relay scan progress from content script to popup
  if (request.action === 'scanProgress') {
    chrome.runtime.sendMessage(request).catch(() => {
      // Popup may not be open - that's fine
    });
    return;
  }

  if (request.action === 'scanComplete') {
    const findings = request.findings || [];
    const url = request.url;
    const tabId = sender.tab?.id || request.tabId;

    console.log('Origami: Received scan results for tab', tabId, '- Found', findings.length, 'secrets');

    if (!tabId) return;

    // Get settings and whitelist
    chrome.storage.sync.get(['settings', 'whitelist'], async (data) => {
      const settings = data.settings || DEFAULT_SETTINGS;
      const whitelist = data.whitelist || DEFAULT_WHITELIST;

      // Deduplicate secrets first (merge duplicate secrets with different patterns)
      const deduplicatedFindings = deduplicateSecrets(findings);
      console.log('Origami: After deduplication:', deduplicatedFindings.length, 'unique secrets (from', findings.length, 'total matches)');

      // Filter findings based on whitelist
      const filteredFindings = filterFindings(deduplicatedFindings, url, whitelist);

      console.log('Origami: After filtering:', filteredFindings.length, 'secrets remain');

      // Merge cached AI assessments from previous visits to this domain
      if (url) {
        try {
          const domain = new URL(url).hostname;
          tabDomains.set(tabId, domain);
          const aiCache = await loadAIAssessmentCache(domain);
          if (Object.keys(aiCache).length > 0) {
            let merged = 0;
            filteredFindings.forEach(f => {
              const fp = findingFingerprint(f, 'secrets');
              const cached = aiCache[fp];
              if (cached && !f.aiAssessment) {
                f.aiAssessment = cached.aiAssessment;
                if (cached.severityOverride && !f.severityOverride) {
                  f.severityOverride = cached.severityOverride;
                }
                merged++;
              }
            });
            if (merged > 0) console.log(`Origami: Merged ${merged} cached AI assessments for ${domain}`);
          }
        } catch (e) { /* ignore URL parse errors */ }
      }

      // Store findings for this tab (even if empty) - now persisted to storage
      await saveTabFindings(tabId, filteredFindings);

      // Update badge
      updateBadge(tabId, filteredFindings, settings);

      // Send notification and webhook only if findings exist
      if (filteredFindings.length > 0) {
        sendNotification(filteredFindings, url, settings);

        // Send webhook
        const webhookSecResults = await loadTabSecurityResults(tabId);
        sendWebhook(filteredFindings, url, settings, webhookSecResults);

        // Add to history (include security results if available)
        const historySecResults = await loadTabSecurityResults(tabId);
        addToHistory(filteredFindings, url, settings, historySecResults);

        // Note: Auto-validation handled in popup for better fetch API access
      }

      // Notify MCP bridge of scan completion
      if (mcpBridge && mcpBridge.connected) {
        mcpBridge.notifyEvent('scanComplete', {
          url,
          tabId,
          findingsCount: filteredFindings.length,
          timestamp: new Date().toISOString(),
        });
      }

      // Respond after storage is written so callers can read back processed data
      sendResponse({ success: true });
    });

    return true; // Keep channel open for async response
  } else if (request.action === 'getTabFindings') {
    const tabId = request.tabId;
    
    // Load findings from storage if needed
    loadTabFindings(tabId).then(findings => {
      sendResponse({ findings: findings });
    });
    
    return true; // Keep channel open for async response
  } else if (request.action === 'updateTabFindings') {
    // Update findings in storage (used when AI assessments are added)
    const { tabId, findings } = request;
    
    saveTabFindings(tabId, findings).then(() => {
      sendResponse({ success: true });
    });
    
    return true; // Keep channel open for async response
  } else if (request.action === 'updateTabSecurityResults') {
    // Update security results in storage (used when AI assessments are added)
    const { tabId, results } = request;
    
    saveTabSecurityResults(tabId, results).then(() => {
      sendResponse({ success: true });
    });
    
    return true; // Keep channel open for async response
  } else if (request.action === 'clearTabFindings') {
    const tabId = request.tabId;
    
    clearTabFindings(tabId).then(() => {
      chrome.action.setBadgeText({ tabId: tabId, text: '' });
      sendResponse({ success: true });
    });
    
    return true; // Keep channel open for async response
  } else if (request.action === 'storeAPIValidationResults') {
    // Store validation results from popup
    const { apiKey, results, tabId } = request;
    apiValidationResults.set(apiKey, {
      timestamp: new Date().toISOString(),
      results: results,
      enabled_count: results.filter(r => r.status.includes('ENABLED')).length,
      total_count: results.length
    });

    // Reassess API key risk based on which services are enabled
    // Wrapped in async IIFE to await reassessment before responding
    (async () => {
      if (tabId) {
        const criticalServices = [
          'Vertex AI / AI Platform',
          'Generative AI (Gemini)',
          'Cloud Vision API',
          'Speech-to-Text API',
          'Video Intelligence API',
          'Compute Engine API',
          'Cloud Storage API',
          'Secret Manager API'
        ];

        const enabledResults = results.filter(r => r.status.includes('ENABLED'));
        const hasCriticalService = enabledResults.some(r => criticalServices.includes(r.service));
        const hasAnyService = enabledResults.length > 0;

        if (hasCriticalService) {
          await reassessAPIKeyRisk(tabId, apiKey, 'CRITICAL',
            'Critical GCP services enabled (Gemini/Vertex AI/Compute/Storage/Secrets)');
        } else if (hasAnyService) {
          await reassessAPIKeyRisk(tabId, apiKey, 'HIGH',
            'Billing-impacting GCP services enabled');
        }
      }
      sendResponse({ success: true });
    })();

    return true; // Keep channel open for async reassessment
  } else if (request.action === 'getAPIValidationResults') {
    // Get validation results for a specific key
    const { apiKey } = request;
    const results = apiValidationResults.get(apiKey) || null;
    sendResponse({ results: results });
  } else if (request.action === 'clearAPIValidationResults') {
    // Clear all validation results
    apiValidationResults.clear();
    sendResponse({ success: true });
  } else if (request.action === 'saveGoogleApiTestingSettings') {
    // Save Google API testing settings (selected services, preset, etc.)
    const { googleApiTesting } = request;
    chrome.storage.sync.get(['settings'], (data) => {
      const settings = data.settings || DEFAULT_SETTINGS;
      settings.googleApiTesting = { ...settings.googleApiTesting, ...googleApiTesting };
      chrome.storage.sync.set({ settings }, () => {
        sendResponse({ success: true });
      });
    });
    return true; // Keep channel open for async response
  } else if (request.action === 'getGoogleApiTestingSettings') {
    // Get Google API testing settings
    chrome.storage.sync.get(['settings'], (data) => {
      const settings = data.settings || DEFAULT_SETTINGS;
      sendResponse({ googleApiTesting: settings.googleApiTesting || DEFAULT_SETTINGS.googleApiTesting });
    });
    return true; // Keep channel open for async response
  } else if (request.action === 'saveDiscoveredProjects') {
    // Save discovered GCP project IDs
    const { projects } = request;
    chrome.storage.sync.get(['settings'], (data) => {
      const settings = data.settings || DEFAULT_SETTINGS;
      if (!settings.googleApiTesting) {
        settings.googleApiTesting = DEFAULT_SETTINGS.googleApiTesting;
      }
      settings.googleApiTesting.discoveredProjects = projects;
      chrome.storage.sync.set({ settings }, () => {
        console.log('Origami: Saved', projects.length, 'discovered GCP projects');
        sendResponse({ success: true });
      });
    });
    return true; // Keep channel open for async response
  } else if (request.action === 'securityAnalysisComplete') {
    // Store security analysis results
    const results = request.results || null;
    const url = request.url || sender.url;
    const tabId = sender.tab?.id;
    
    console.log('Origami Background: securityAnalysisComplete received', {
      hasResults: !!results,
      tabId: tabId,
      resultKeys: results ? Object.keys(results) : null
    });
    
    if (tabId && results) {
      console.log('Origami Background: Storing security results for tab', tabId, results);

      chrome.storage.sync.get(['settings'], async (data) => {
        const settings = data.settings || DEFAULT_SETTINGS;

        // Merge cached AI assessments from previous visits
        if (url) {
          try {
            const domain = new URL(url).hostname;
            tabDomains.set(tabId, domain);
            const aiCache = await loadAIAssessmentCache(domain);
            if (Object.keys(aiCache).length > 0) {
              let merged = 0;
              for (const [category, items] of Object.entries(results)) {
                if (Array.isArray(items)) {
                  items.forEach(f => {
                    const fp = findingFingerprint(f, category);
                    const cached = aiCache[fp];
                    if (cached && !f.aiAssessment) {
                      f.aiAssessment = cached.aiAssessment;
                      if (cached.severityOverride && !f.severityOverride) {
                        f.severityOverride = cached.severityOverride;
                      }
                      merged++;
                    }
                  });
                }
              }
              if (merged > 0) console.log(`Origami: Merged ${merged} cached AI assessments into security results`);
            }
          } catch (e) { /* ignore URL parse errors */ }
        }

        // Save results
        await saveTabSecurityResults(tabId, results);
        console.log('Origami Background: Security results saved for tab', tabId);
        
        // Update badge with both secret findings and security findings
        const secretFindings = await loadTabFindings(tabId);
        await updateBadge(tabId, secretFindings, settings, results);

        // Notify popup that results are ready
        try {
          chrome.runtime.sendMessage({
            action: 'securityAnalysisReady',
            tabId: tabId
          });
        } catch (e) {
          // Popup may not be open
        }

        sendResponse({ success: true });
      });
    } else {
      console.log('Origami Background: Cannot store - missing tabId or results');
      sendResponse({ success: false });
    }
    
    return true; // Keep channel open for async response
  } else if (request.action === 'getTabSecurityResults') {
    // Retrieve security analysis results for a tab
    const tabId = request.tabId;

    console.log('Origami Background: getTabSecurityResults requested for tab', tabId);

    loadTabSecurityResults(tabId).then(results => {
      console.log('Origami Background: Returning security results for tab', tabId, {
        hasResults: !!results,
        resultKeys: results ? Object.keys(results) : null
      });
      sendResponse({ results: results });
    });

    return true; // Keep channel open for async response
  } else if (request.action === 'getDomainCache') {
    // Return domain cache and AI assessment cache for a domain
    const { domain } = request;
    (async () => {
      try {
        const cache = await loadDomainCache(domain);
        const aiCache = await loadAIAssessmentCache(domain);
        sendResponse({ cache, aiCache });
      } catch (e) {
        sendResponse({ cache: null, aiCache: {}, error: e.message });
      }
    })();
    return true;
  } else if (request.action === 'cacheAIAssessment') {
    // Direct AI assessment cache save from popup
    const { domain, fingerprint, aiAssessment, severityOverride } = request;
    saveAIAssessmentCache(domain, [{ fingerprint, aiAssessment, severityOverride }])
      .then(() => sendResponse({ success: true }));
    return true;
  } else if (request.action === 'checkCVEs') {
    // Check technologies for CVEs and EOL status
    const { technologies } = request;

    console.log('Origami Background: Checking CVEs for technologies:', Object.keys(technologies));

    // Use async IIFE to properly handle async operations
    (async () => {
      try {
        // Get settings
        const data = await chrome.storage.sync.get(['settings']);
        const settings = data.settings || DEFAULT_SETTINGS;

        // Check if CVE checking is enabled
        if (!settings.cve_checking || !settings.cve_checking.enabled) {
          console.log('Origami Background: CVE checking is disabled');
          sendResponse({ vulnerabilities: {} });
          return;
        }

        console.log('Origami Background: CVE checking is enabled, starting check...');

        // CVEChecker is loaded via importScripts at the top of this file
        const checker = new CVEChecker();
        const vulnerabilities = await checker.checkTechnologies(technologies);

        console.log('Origami Background: CVE check complete:', {
          categoriesWithVulns: Object.keys(vulnerabilities),
          totalVulnerableTechs: Object.values(vulnerabilities).reduce((sum, arr) => sum + arr.length, 0)
        });

        sendResponse({ vulnerabilities: vulnerabilities });
      } catch (error) {
        console.error('Origami Background: CVE check failed:', error);
        console.error('Error details:', error.stack);
        sendResponse({ vulnerabilities: {}, error: error.message });
      }
    })();

    return true; // Keep channel open for async response
  } else if (request.action === 'clearCVECache') {
    // Clear CVE cache
    console.log('Origami Background: Clearing CVE cache');

    (async () => {
      try {
        const checker = new CVEChecker();
        await checker.clearCache();

        sendResponse({ success: true });
      } catch (error) {
        console.error('Origami Background: Cache clear failed:', error);
        sendResponse({ success: false, error: error.message });
      }
    })();

    return true; // Keep channel open for async response
  } else if (request.action === 'getCVECacheStats') {
    // Get CVE cache statistics
    console.log('Origami Background: Getting CVE cache stats');

    (async () => {
      try {
        const checker = new CVEChecker();
        const stats = await checker.getCacheStats();

        sendResponse({ stats: stats });
      } catch (error) {
        console.error('Origami Background: Cache stats failed:', error);
        sendResponse({ stats: null, error: error.message });
      }
    })();

    return true; // Keep channel open for async response
  } else if (request.action === 'llmAnalyze') {
    // High-level LLM analysis handler: reads LLM settings from storage, constructs
    // provider-specific API calls, and returns the raw response. Used by ChainPredictor,
    // PoCGenerator, and RuleGenerator so they don't need to know provider details.
    const { prompt, systemPrompt, options } = request;

    (async () => {
      let timeoutId;
      try {
        const data = await chrome.storage.sync.get(['settings']);
        const settings = data.settings || DEFAULT_SETTINGS;
        const llm = settings.llm || {};

        if (!llm.enabled) {
          sendResponse({ success: false, error: 'LLM not configured. Go to Settings to set up an AI provider.' });
          return;
        }

        const provider = llm.provider || 'ollama';
        const apiKey = llm.apiKey || '';
        const model = llm.model || '';
        const ollamaEndpoint = llm.endpoint || 'http://127.0.0.1:11434';
        const temperature = options?.temperature ?? llm.temperature ?? 0.3;
        const maxTokens = options?.maxTokens ?? llm.maxTokens ?? 8192;

        // Cloud providers require an API key
        if (['openai', 'anthropic', 'gemini'].includes(provider) && !apiKey) {
          sendResponse({ success: false, error: 'LLM not configured. Go to Settings to set up an AI provider.' });
          return;
        }

        let fetchEndpoint = '';
        let fetchHeaders = {};
        let fetchBody = {};

        if (provider === 'gemini') {
          fetchEndpoint = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;
          fetchHeaders = { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey };
          fetchBody = {
            systemInstruction: systemPrompt ? { parts: [{ text: systemPrompt }] } : undefined,
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: {
              temperature: temperature,
              maxOutputTokens: maxTokens
            },
            thinkingConfig: { thinkingBudget: 0 },
            safetySettings: [
              { category: 'HARM_CATEGORY_HARASSMENT', threshold: 'BLOCK_NONE' },
              { category: 'HARM_CATEGORY_HATE_SPEECH', threshold: 'BLOCK_NONE' },
              { category: 'HARM_CATEGORY_SEXUALLY_EXPLICIT', threshold: 'BLOCK_NONE' },
              { category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_NONE' }
            ]
          };
        } else if (provider === 'openai') {
          fetchEndpoint = 'https://api.openai.com/v1/chat/completions';
          fetchHeaders = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + apiKey
          };
          const messages = [];
          if (systemPrompt) messages.push({ role: 'system', content: systemPrompt });
          messages.push({ role: 'user', content: prompt });
          fetchBody = {
            model: model || 'gpt-4o',
            messages: messages,
            temperature: temperature,
            max_tokens: maxTokens
          };
        } else if (provider === 'anthropic') {
          fetchEndpoint = 'https://api.anthropic.com/v1/messages';
          fetchHeaders = {
            'Content-Type': 'application/json',
            'x-api-key': apiKey,
            'anthropic-version': '2023-06-01',
            'anthropic-dangerous-direct-browser-access': 'true'
          };
          fetchBody = {
            model: model || 'claude-sonnet-4-5-20250929',
            max_tokens: maxTokens,
            temperature: temperature || 0.3,
            messages: [{ role: 'user', content: prompt }]
          };
          if (systemPrompt) fetchBody.system = systemPrompt.trim();
        } else if (provider === 'ollama') {
          fetchEndpoint = ollamaEndpoint.replace(/\/+$/, '') + '/api/generate';
          fetchHeaders = { 'Content-Type': 'application/json' };
          const fullPrompt = systemPrompt ? (systemPrompt + '\n\n' + prompt) : prompt;
          fetchBody = {
            model: model || 'llama3.1:8b',
            prompt: fullPrompt,
            stream: false,
            options: {
              temperature: temperature,
              num_predict: maxTokens
            }
          };
        } else {
          sendResponse({ success: false, error: 'Unknown LLM provider: ' + provider });
          return;
        }

        // Detect local requests for CORS handling
        const isLocalRequest = fetchEndpoint.includes('localhost') || fetchEndpoint.includes('127.0.0.1');

        // Build clean headers
        const cleanHeaders = { ...fetchHeaders };
        delete cleanHeaders['Origin'];
        delete cleanHeaders['Referer'];

        const controller = new AbortController();
        timeoutId = setTimeout(() => controller.abort(), 120000);

        const fetchOptions = {
          method: 'POST',
          headers: cleanHeaders,
          body: JSON.stringify(fetchBody),
          signal: controller.signal
        };

        if (isLocalRequest) {
          fetchOptions.mode = 'cors';
          fetchOptions.credentials = 'omit';
          fetchOptions.referrerPolicy = 'no-referrer';
          fetchOptions.referrer = '';
        }

        const response = await fetch(fetchEndpoint, fetchOptions);
        clearTimeout(timeoutId);

        if (!response.ok) {
          const errorText = await response.text();
          if (isLocalRequest && response.status === 403) {
            sendResponse({
              success: false,
              error: 'Ollama rejected the request (403 Forbidden). Fix: run Ollama with OLLAMA_ORIGINS="chrome-extension://*" environment variable.'
            });
            return;
          }
          sendResponse({
            success: false,
            error: 'LLM API error (' + response.status + '): ' + errorText.substring(0, 500)
          });
          return;
        }

        const responseData = await response.json();
        sendResponse({ success: true, data: responseData });
      } catch (error) {
        if (timeoutId) clearTimeout(timeoutId);
        if (error.name === 'AbortError') {
          sendResponse({
            success: false,
            error: 'LLM request timed out after 120 seconds'
          });
        } else {
          const isLocal = (request.options?.endpoint || '').includes('localhost') ||
                          (request.options?.endpoint || '').includes('127.0.0.1');
          if (isLocal || error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
            sendResponse({
              success: false,
              error: 'Cannot connect to LLM. Make sure the provider is running and accessible. ' + error.message
            });
          } else {
            sendResponse({
              success: false,
              error: 'LLM request failed: ' + error.message
            });
          }
        }
      }
    })();

    return true; // Keep channel open for async response

  } else if (request.action === 'llmRequest') {
    // Proxy LLM requests through background to avoid CORS issues
    // (Chrome extension popups send Origin: chrome-extension://[id] which Ollama rejects)
    const { endpoint, method, headers, body } = request;

    (async () => {
      // SSRF protection: only allow requests to known LLM provider endpoints
      if (!isAllowedLLMEndpoint(endpoint)) {
        sendResponse({ success: false, error: 'Endpoint not allowed. Only known LLM provider endpoints are permitted.' });
        return;
      }

      // Detect if this is a local/Ollama request (localhost or 127.0.0.1)
      const isLocalRequest = endpoint.includes('localhost') || endpoint.includes('127.0.0.1');
      let timeoutId;

      try {
        // Build clean headers - remove Origin/Referer that local servers (Ollama) reject
        const cleanHeaders = { ...(headers || {}) };
        delete cleanHeaders['Origin'];
        delete cleanHeaders['Referer'];

        const controller = new AbortController();
        timeoutId = setTimeout(() => controller.abort(), 120000);

        const fetchOptions = {
          method: method || 'POST',
          headers: cleanHeaders,
          body: body ? JSON.stringify(body) : undefined,
          signal: controller.signal
        };

        // For local servers like Ollama, prevent Origin header from being sent
        // Chrome's fetch API auto-injects Origin: chrome-extension://[id] which Ollama rejects with 403
        if (isLocalRequest) {
          fetchOptions.mode = 'cors';
          fetchOptions.credentials = 'omit';
          fetchOptions.referrerPolicy = 'no-referrer';
          fetchOptions.referrer = '';
        }

        const response = await fetch(endpoint, fetchOptions);
        clearTimeout(timeoutId);

        if (!response.ok) {
          const errorText = await response.text();
          // Provide helpful error for Ollama 403 (Origin header rejection)
          if (isLocalRequest && response.status === 403) {
            sendResponse({
              success: false,
              status: response.status,
              error: `Ollama rejected the request (403 Forbidden). Fix: run Ollama with OLLAMA_ORIGINS="chrome-extension://*" environment variable. On macOS: launchctl setenv OLLAMA_ORIGINS "chrome-extension://*" then restart Ollama. On Linux: OLLAMA_ORIGINS="chrome-extension://*" ollama serve`
            });
            return;
          }
          sendResponse({
            success: false,
            status: response.status,
            error: errorText.substring(0, 500)
          });
          return;
        }

        const data = await response.json();
        sendResponse({ success: true, data });
      } catch (error) {
        if (timeoutId) clearTimeout(timeoutId);
        if (error.name === 'AbortError') {
          sendResponse({
            success: false,
            error: 'LLM request timed out after 120 seconds'
          });
        } else if (isLocalRequest && (error.message.includes('Failed to fetch') || error.message.includes('NetworkError'))) {
          sendResponse({
            success: false,
            error: `Cannot connect to Ollama. Make sure Ollama is running and accessible at ${endpoint}. If you get 403 errors, set OLLAMA_ORIGINS="chrome-extension://*" environment variable before starting Ollama.`
          });
        } else {
          sendResponse({
            success: false,
            error: error.message
          });
        }
      }
    })();

    return true; // Keep channel open for async response

  } else if (request.action === 'chatHistoryGet') {
    const { domain } = request;
    (async () => {
      try {
        const key = 'chat_history_' + domain;
        const data = await chrome.storage.local.get(key);
        sendResponse({ success: true, conversations: data[key] || [] });
      } catch (error) {
        console.error('Origami: chatHistoryGet error:', error.message);
        sendResponse({ success: false, conversations: [], error: error.message });
      }
    })();
    return true;

  } else if (request.action === 'chatHistorySave') {
    const { domain, conversation } = request;
    (async () => {
      try {
        const key = 'chat_history_' + domain;
        const data = await chrome.storage.local.get(key);
        const conversations = data[key] || [];

        // Trim conversation messages to max 50 pairs (100 messages)
        if (conversation.messages && conversation.messages.length > 100) {
          conversation.messages = conversation.messages.slice(-100);
        }

        // Check if this conversation already exists (update in place)
        const existingIdx = conversations.findIndex(c => c.id === conversation.id);
        if (existingIdx !== -1) {
          conversations[existingIdx] = conversation;
        } else {
          conversations.push(conversation);
        }

        // Keep max 5 conversations per domain (evict oldest)
        while (conversations.length > 5) {
          conversations.shift();
        }

        await chrome.storage.local.set({ [key]: conversations });
        sendResponse({ success: true });
      } catch (error) {
        console.error('Origami: chatHistorySave error:', error.message);
        sendResponse({ success: false, error: error.message });
      }
    })();
    return true;

  } else if (request.action === 'chatHistoryClear') {
    const { domain } = request;
    (async () => {
      try {
        const key = 'chat_history_' + domain;
        await chrome.storage.local.remove(key);
        sendResponse({ success: true });
      } catch (error) {
        console.error('Origami: chatHistoryClear error:', error.message);
        sendResponse({ success: false, error: error.message });
      }
    })();
    return true;

  } else if (request.action === 'validateSecret') {
    // SECURITY FIX: Block content scripts from using validateSecret as SSRF proxy
    if (sender.tab) {
      sendResponse({ status: 0, body: '', headers: {}, error: 'Unauthorized' });
      return;
    }
    const { url, method, headers, body } = request;

    (async () => {
      try {
        // SSRF protection: only allow requests to known API validation endpoints
        if (!isAllowedValidationEndpoint(url)) {
          sendResponse({ status: 0, body: '', headers: {}, error: 'Endpoint not allowed. Only known API provider endpoints are permitted for validation.' });
          return;
        }

        const cleanHeaders = { ...(headers || {}) };
        delete cleanHeaders['Origin'];
        delete cleanHeaders['Referer'];

        const fetchOptions = {
          method: method || 'GET',
          headers: cleanHeaders
        };

        if (body) {
          fetchOptions.body = typeof body === 'string' ? body : JSON.stringify(body);
        }

        const response = await fetch(url, fetchOptions);
        const responseBody = await response.text();

        const responseHeaders = {};
        response.headers.forEach((value, key) => {
          responseHeaders[key] = value;
        });

        sendResponse({
          status: response.status,
          body: responseBody,
          headers: responseHeaders
        });
      } catch (error) {
        sendResponse({
          status: 0,
          body: '',
          headers: {},
          error: error.message
        });
      }
    })();

    return true; // Keep channel open for async response

  } else if (request.action === 'repeaterRequest') {
    // Verify sender is the extension popup (not a content script or other page)
    if (sender.tab || (sender.url && !sender.url.startsWith(chrome.runtime.getURL('')))) {
      sendResponse({ error: 'Unauthorized: only the extension popup can use Repeater', status: 0 });
      return;
    }

    const { url, method, headers, body } = request;

    // URL protocol allowlist — only http: and https: are permitted
    try {
      const parsed = new URL(url);
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        sendResponse({ error: `Protocol "${parsed.protocol}" is not allowed. Use http: or https:`, status: 0 });
        return;
      }
    } catch (e) {
      sendResponse({ error: 'Invalid URL: ' + e.message, status: 0 });
      return;
    }

    (async () => {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 30000);

      try {
        const cleanHeaders = { ...(headers || {}) };
        delete cleanHeaders['Origin'];
        delete cleanHeaders['Referer'];
        delete cleanHeaders['User-Agent']; // forbidden fetch header — browser sets this automatically

        const fetchOptions = {
          method: method || 'GET',
          headers: cleanHeaders,
          signal: controller.signal,
          redirect: 'follow',
        };

        if (body && ['POST', 'PUT', 'PATCH'].includes(method)) {
          fetchOptions.body = body;
        }

        const startTime = Date.now();
        const response = await fetch(url, fetchOptions);

        const MAX_SIZE = 1 * 1024 * 1024;
        const bodyText = await response.text();
        const truncated = bodyText.length > MAX_SIZE;
        const responseBody = truncated ? bodyText.substring(0, MAX_SIZE) : bodyText;

        const elapsed = Date.now() - startTime;

        const responseHeaders = {};
        response.headers.forEach((value, key) => {
          responseHeaders[key] = value;
        });

        try {
          sendResponse({
            status: response.status,
            statusText: response.statusText,
            headers: responseHeaders,
            body: responseBody,
            timing: elapsed,
            truncated: truncated,
            size: bodyText.length,
          });
        } catch (e) {
          // Popup may have closed — ignore
        }
      } catch (error) {
        try {
          sendResponse({
            error: error.name === 'AbortError' ? 'Request timed out (30s)' : error.message,
            status: 0,
          });
        } catch (e) {
          // Popup may have closed — ignore
        }
      } finally {
        clearTimeout(timeout);
      }
    })();

    return true; // Keep channel open for async response

  // ========================================================================
  // HTTP History message handlers
  // ========================================================================
  } else if (request.action === 'httpHistoryEntry') {
    if (!httpCaptureEnabled) return;
    const entry = request.entry;
    if (!entry || !entry.url) return;
    entry.tabId = sender.tab?.id || 0;
    entry.tier = 1;
    addHttpHistoryEntry(entry).catch(e => {
      console.error('Origami: Failed to store HTTP history entry:', e);
    });
    return; // No response needed (fire-and-forget from content script)

  } else if (request.action === 'getHttpHistoryState') {
    sendResponse({ enabled: httpCaptureEnabled, scope: httpCaptureScope });
    return;

  } else if (request.action === 'getHttpHistory') {
    (async () => {
      try {
        const entries = await getHttpHistory(request.filters || {});
        const total = await getHttpHistoryCount();
        sendResponse({ entries, total });
      } catch (e) {
        sendResponse({ entries: [], total: 0, error: e.message });
      }
    })();
    return true;

  } else if (request.action === 'getHttpHistoryEntry') {
    (async () => {
      try {
        const entry = await getHttpHistoryEntry(request.id);
        sendResponse({ entry });
      } catch (e) {
        sendResponse({ entry: null, error: e.message });
      }
    })();
    return true;

  } else if (request.action === 'clearHttpHistory') {
    (async () => {
      try {
        await clearHttpHistory();
        sendResponse({ success: true });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;

  } else if (request.action === 'toggleHttpCapture') {
    httpCaptureEnabled = !!request.enabled;
    if (request.scope) httpCaptureScope = request.scope;

    // Persist to settings
    chrome.storage.sync.get(['settings'], (data) => {
      const settings = data.settings || DEFAULT_SETTINGS;
      if (!settings.httpHistory) settings.httpHistory = {};
      settings.httpHistory.enabled = httpCaptureEnabled;
      settings.httpHistory.captureScope = httpCaptureScope;
      chrome.storage.sync.set({ settings });
    });

    broadcastHttpCaptureState();
    sendResponse({ enabled: httpCaptureEnabled, scope: httpCaptureScope });
    return;

  } else if (request.action === 'enableFullCapture') {
    (async () => {
      try {
        const tabId = request.tabId;
        if (!tabId) { sendResponse({ success: false, error: 'No tabId' }); return; }
        await enableFullCapture(tabId);
        sendResponse({ success: true });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;

  } else if (request.action === 'disableFullCapture') {
    (async () => {
      try {
        await disableFullCapture(request.tabId || httpFullCaptureTabId);
        sendResponse({ success: true });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;

  } else if (request.action === 'toggleHttpHistoryPin') {
    (async () => {
      try {
        const result = await toggleHttpHistoryPin(request.id, request.pinned);
        sendResponse({ success: result });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;

  } else if (request.action === 'getHttpHistoryCount') {
    (async () => {
      try {
        const count = await getHttpHistoryCount();
        sendResponse({ count });
      } catch (e) {
        sendResponse({ count: 0, error: e.message });
      }
    })();
    return true;

  } else if (request.action === 'sqliRequest') {
    // Verify sender is the extension popup (not a content script or other page)
    if (!sender.url || !sender.url.startsWith(chrome.runtime.getURL(''))) {
      sendResponse({ error: 'Unauthorized: only the extension popup can use SQLi Tester', status: 0 });
      return;
    }

    const { url, method, headers, body } = request;

    // URL protocol allowlist — only http: and https: are permitted
    try {
      const parsed = new URL(url);
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        sendResponse({ error: `Protocol "${parsed.protocol}" is not allowed. Use http: or https:`, status: 0 });
        return;
      }
    } catch (e) {
      sendResponse({ error: 'Invalid URL: ' + e.message, status: 0 });
      return;
    }

    (async () => {
      const controller = new AbortController();
      const sqliTimeout = request.timeout || 10000;
      const timeout = setTimeout(() => controller.abort(), sqliTimeout);

      try {
        const cleanHeaders = { ...(headers || {}) };
        delete cleanHeaders['Origin'];
        delete cleanHeaders['Referer'];
        delete cleanHeaders['User-Agent']; // forbidden fetch header — browser sets this automatically

        const fetchOptions = {
          method: method || 'GET',
          headers: cleanHeaders,
          signal: controller.signal,
          redirect: 'follow',
        };

        if (body && ['POST', 'PUT', 'PATCH'].includes(method)) {
          fetchOptions.body = body;
        }

        const startTime = Date.now();
        const response = await fetch(url, fetchOptions);

        const MAX_SIZE = 512 * 1024;
        const bodyText = await response.text();
        const truncated = bodyText.length > MAX_SIZE;
        const responseBody = truncated ? bodyText.substring(0, MAX_SIZE) : bodyText;

        const elapsed = Date.now() - startTime;

        const responseHeaders = {};
        response.headers.forEach((value, key) => {
          responseHeaders[key] = value;
        });

        try {
          sendResponse({
            status: response.status,
            statusText: response.statusText,
            headers: responseHeaders,
            body: responseBody,
            timing: elapsed,
            truncated: truncated,
            size: bodyText.length,
          });
        } catch (e) {
          // Popup may have closed — ignore
        }
      } catch (error) {
        try {
          sendResponse({
            error: error.name === 'AbortError' ? `Request timed out (${sqliTimeout / 1000}s)` : error.message,
            status: 0,
          });
        } catch (e) {
          // Popup may have closed — ignore
        }
      } finally {
        clearTimeout(timeout);
      }
    })();

    return true; // Keep channel open for async response

  } else if (request.action === 'inventoryCollected') {
    const tabId = sender.tab?.id || request.tabId;
    const inventory = request.inventory;
    if (tabId && inventory) {
      saveTabInventory(tabId, inventory);
    }
    sendResponse({ success: true });

  } else if (request.action === 'inventoryIncremental') {
    const tabId = sender.tab?.id;
    if (tabId && request.resources) {
      saveTabInventory(tabId, {
        domain: request.domain,
        timestamp: request.timestamp,
        url: request.url,
        resources: request.resources,
        externalResources: request.externalResources || {}
      });
    }
    sendResponse({ success: true });

  } else if (request.action === 'getTabInventory') {
    const tabId = request.tabId;
    loadTabInventory(tabId).then(inventory => {
      sendResponse({ inventory: inventory });
    });
    return true;

  } else if (request.action === 'getDomainInventory') {
    const domain = request.domain;
    loadDomainInventory(domain).then(inventory => {
      sendResponse({ inventory: inventory });
    });
    return true;

  } else if (request.action === 'startBruteForceScan') {
    // Start a brute force directory/file scan
    const config = request.config;
    const bfTabId = request.tabId;
    let bfDomain;
    try { bfDomain = new URL(config.targetUrl).hostname; } catch (e) {}

    if (activeBruteForceScanner && activeBruteForceScanner.isScanning) {
      sendResponse({ error: 'A scan is already in progress' });
      return;
    }

    activeBruteForceScanner = new BruteForceScanner();
    const bfStartedAt = Date.now();

    // Build scan config with callbacks that relay to the popup
    const scanConfig = {
      targetUrl: config.targetUrl,
      scanMode: config.scanMode,
      wordlist: config.customWordlist || undefined,
      extensions: config.extensions,
      concurrency: config.concurrency,
      timeout: config.timeout,
      followRedirects: config.followRedirects,
      statusCodes: config.statusCodes,
      onProgress: (scanned, total, result) => {
        // Send progress to popup
        chrome.runtime.sendMessage({
          action: 'bruteForceScanProgress',
          scanned: scanned,
          total: total,
          result: result
        }).catch(() => { /* popup may be closed */ });

        // Persist every 10 results
        if (result && activeBruteForceScanner &&
            activeBruteForceScanner.results.length % 10 === 0) {
          saveBruteForceState(bfTabId, bfDomain, {
            domain: bfDomain,
            targetUrl: config.targetUrl,
            results: activeBruteForceScanner.results,
            scanActive: true,
            scannedCount: scanned,
            totalPaths: total,
            startedAt: bfStartedAt,
            completedAt: null
          });
        }
      },
      onResult: (result) => {
        // Individual result - already sent via onProgress
      },
      onComplete: (summary) => {
        // Persist completed state
        saveBruteForceState(bfTabId, bfDomain, {
          domain: bfDomain,
          targetUrl: config.targetUrl,
          results: summary.results,
          scanActive: false,
          scannedCount: summary.scanned,
          totalPaths: summary.total,
          startedAt: bfStartedAt,
          completedAt: Date.now()
        });

        // Auto-merge results into inventory (gated by toggle)
        if (config.autoInventory) {
          const matchCodes = new Set(config.statusCodes || [200]);
          const okResults = summary.results.filter(r => matchCodes.has(r.status));
          if (okResults.length > 0 && bfTabId && bfDomain) {
            const resources = {};
            okResults.forEach(result => {
              resources[result.path] = BruteForceScanner.toInventoryResource(result);
            });
            saveTabInventory(bfTabId, {
              domain: bfDomain,
              timestamp: Date.now(),
              url: config.targetUrl,
              resources: resources,
              externalResources: {}
            });
          }
        }

        // Notify popup of completion
        chrome.runtime.sendMessage({
          action: 'bruteForceScanComplete',
          scanned: summary.scanned,
          total: summary.total,
          cancelled: summary.cancelled,
          resultsCount: summary.results.length
        }).catch(() => { /* popup may be closed */ });

        activeBruteForceScanner = null;
      }
    };

    activeBruteForceScanner.startScan(scanConfig);
    sendResponse({ success: true });
    return; // synchronous response

  } else if (request.action === 'stopBruteForceScan') {
    if (activeBruteForceScanner) {
      activeBruteForceScanner.stopScan();
      activeBruteForceScanner = null;
    }
    sendResponse({ success: true });

  } else if (request.action === 'getBruteForceResults') {
    const tabKey = `bruteforce_results_${request.tabId}`;
    chrome.storage.local.get([tabKey], (data) => {
      if (data[tabKey]) {
        sendResponse({ state: data[tabKey] });
      } else if (request.domain) {
        const domainKey = `bruteforce_cache_${request.domain}`;
        chrome.storage.local.get([domainKey], (domainData) => {
          sendResponse({ state: domainData[domainKey] || null });
        });
      } else {
        sendResponse({ state: null });
      }
    });
    return true; // async

  } else if (request.action === 'isBruteForceScanActive') {
    sendResponse({ active: !!(activeBruteForceScanner && activeBruteForceScanner.isScanning) });

  } else if (request.action === 'startCrawl') {
    const config = request.config;
    const crawlTabId = request.tabId;
    let crawlDomain;
    try { crawlDomain = new URL(config.targetUrl).hostname; } catch (e) {}

    if (activeCrawler && activeCrawler.isScanning) {
      sendResponse({ error: 'A crawl is already in progress' });
      return;
    }

    activeCrawler = new WebCrawler();
    const crawlStartedAt = Date.now();

    const scanConfig = {
      targetUrl: config.targetUrl,
      maxDepth: config.maxDepth,
      followExternal: config.followExternal,
      concurrency: config.concurrency,
      timeout: config.timeout,
      onProgress: (crawled, discovered, result) => {
        chrome.runtime.sendMessage({
          action: 'crawlerProgress',
          crawled: crawled,
          discovered: discovered,
          result: result
        }).catch(() => { /* popup may be closed */ });

        // Persist every 10 results
        if (result && activeCrawler &&
            activeCrawler.results.length % 10 === 0) {
          saveCrawlerState(crawlTabId, crawlDomain, {
            domain: crawlDomain,
            targetUrl: config.targetUrl,
            results: activeCrawler.results,
            scanActive: true,
            crawledCount: crawled,
            discoveredCount: discovered,
            startedAt: crawlStartedAt,
            completedAt: null
          });
        }
      },
      onComplete: (summary) => {
        saveCrawlerState(crawlTabId, crawlDomain, {
          domain: crawlDomain,
          targetUrl: config.targetUrl,
          results: summary.results,
          scanActive: false,
          crawledCount: summary.crawled,
          discoveredCount: summary.discovered,
          startedAt: crawlStartedAt,
          completedAt: Date.now()
        });

        // Auto-merge all results into inventory (gated by toggle)
        if (config.autoInventory) {
          const matchCodes = new Set(config.statusCodes || [200, 301, 302, 403]);
          const toMerge = summary.results.filter(r => matchCodes.has(r.status));
          if (toMerge.length > 0 && crawlTabId && crawlDomain) {
            const resources = {};
            toMerge.forEach(result => {
              resources[result.path] = WebCrawler.toInventoryResource(result);
            });
            saveTabInventory(crawlTabId, {
              domain: crawlDomain,
              timestamp: Date.now(),
              url: config.targetUrl,
              resources: resources,
              externalResources: {}
            });
          }
        }

        chrome.runtime.sendMessage({
          action: 'crawlerComplete',
          crawled: summary.crawled,
          discovered: summary.discovered,
          cancelled: summary.cancelled,
          resultsCount: summary.results.length
        }).catch(() => { /* popup may be closed */ });

        activeCrawler = null;
      }
    };

    activeCrawler.startScan(scanConfig);
    sendResponse({ success: true });
    return;

  } else if (request.action === 'stopCrawl') {
    if (activeCrawler) {
      activeCrawler.stopScan();
      activeCrawler = null;
    }
    sendResponse({ success: true });

  } else if (request.action === 'getCrawlerResults') {
    const tabKey = `crawler_results_${request.tabId}`;
    chrome.storage.local.get([tabKey], (data) => {
      if (data[tabKey]) {
        sendResponse({ state: data[tabKey] });
      } else if (request.domain) {
        const domainKey = `crawler_cache_${request.domain}`;
        chrome.storage.local.get([domainKey], (domainData) => {
          sendResponse({ state: domainData[domainKey] || null });
        });
      } else {
        sendResponse({ state: null });
      }
    });
    return true; // async

  } else if (request.action === 'isCrawlerActive') {
    sendResponse({ active: !!(activeCrawler && activeCrawler.isScanning) });

  } else if (request.action === 'clearBruteForceResults') {
    const keysToRemove = [`bruteforce_results_${request.tabId}`];
    if (request.domain) keysToRemove.push(`bruteforce_cache_${request.domain}`);
    chrome.storage.local.remove(keysToRemove, () => {
      sendResponse({ success: true });
    });
    return true;

  } else if (request.action === 'clearCrawlerResults') {
    const keysToRemove = [`crawler_results_${request.tabId}`];
    if (request.domain) keysToRemove.push(`crawler_cache_${request.domain}`);
    chrome.storage.local.remove(keysToRemove, () => {
      sendResponse({ success: true });
    });
    return true;

  } else if (request.action === 'checkStorageQuota') {
    checkStorageQuota().then(quotaInfo => {
      sendResponse({ quota: quotaInfo });
    });
    return true; // Keep channel open for async response

  } else if (request.action === 'getPlugins') {
    chrome.storage.local.get(['origami_plugins'], (data) => {
      sendResponse({ plugins: data.origami_plugins || [] });
    });
    return true;

  } else if (request.action === 'savePlugin') {
    const { plugin } = request;
    chrome.storage.local.get(['origami_plugins'], (data) => {
      const plugins = data.origami_plugins || [];
      const existingIndex = plugins.findIndex(p => p.manifest.id === plugin.manifest.id);
      if (existingIndex >= 0) {
        plugins[existingIndex] = plugin;
      } else {
        plugins.push(plugin);
      }
      chrome.storage.local.set({ origami_plugins: plugins }, () => {
        console.log('Origami: Plugin saved:', plugin.manifest.id);
        sendResponse({ success: true });
      });
    });
    return true;

  } else if (request.action === 'removePlugin') {
    const { pluginId } = request;
    chrome.storage.local.get(['origami_plugins'], (data) => {
      const plugins = (data.origami_plugins || []).filter(p => p.manifest.id !== pluginId);
      chrome.storage.local.set({ origami_plugins: plugins }, () => {
        console.log('Origami: Plugin removed:', pluginId);
        sendResponse({ success: true });
      });
    });
    return true;

  } else if (request.action === 'togglePlugin') {
    const { pluginId, enabled } = request;
    chrome.storage.local.get(['origami_plugins'], (data) => {
      const plugins = data.origami_plugins || [];
      const plugin = plugins.find(p => p.manifest.id === pluginId);
      if (plugin) {
        plugin.enabled = enabled;
        chrome.storage.local.set({ origami_plugins: plugins }, () => {
          console.log('Origami: Plugin toggled:', pluginId, 'enabled:', enabled);
          sendResponse({ success: true });
        });
      } else {
        sendResponse({ success: false, error: 'Plugin not found' });
      }
    });
    return true;

  } else if (request.action === 'pluginResultsCollected') {
    // Store plugin results alongside security results
    const tabId = sender.tab?.id || request.tabId;
    if (tabId && request.results) {
      try {
        const storageKey = `tab_plugin_results_${tabId}`;
        chrome.storage.local.set({ [storageKey]: request.results });
      } catch (e) {
        console.error('Origami: Error storing plugin results:', e);
      }
    }
    sendResponse({ success: true });

  } else if (request.action === 'getTemplates') {
    chrome.storage.local.get(['origami_templates'], (data) => {
      sendResponse({ templates: data.origami_templates || [] });
    });
    return true;

  } else if (request.action === 'saveTemplate') {
    const { template } = request;
    chrome.storage.local.get(['origami_templates'], (data) => {
      const templates = data.origami_templates || [];
      const existingIndex = templates.findIndex(t => t.id === template.id);
      if (existingIndex >= 0) {
        templates[existingIndex] = template;
      } else {
        templates.push(template);
      }
      chrome.storage.local.set({ origami_templates: templates }, () => {
        console.log('Origami: Template saved:', template.id);
        sendResponse({ success: true });
      });
    });
    return true;

  } else if (request.action === 'removeTemplate') {
    const { templateId } = request;
    chrome.storage.local.get(['origami_templates'], (data) => {
      const templates = (data.origami_templates || []).filter(t => t.id !== templateId);
      chrome.storage.local.set({ origami_templates: templates }, () => {
        console.log('Origami: Template removed:', templateId);
        sendResponse({ success: true });
      });
    });
    return true;

  } else if (request.action === 'initBuiltinTemplates') {
    chrome.storage.local.get(['origami_templates'], (data) => {
      const existing = data.origami_templates || [];
      const hasBuiltins = existing.some(t => t.builtin);
      if (!hasBuiltins && request.builtins) {
        const merged = [...request.builtins, ...existing];
        chrome.storage.local.set({ origami_templates: merged }, () => {
          console.log('Origami: Initialized', request.builtins.length, 'builtin templates');
          sendResponse({ success: true, initialized: true });
        });
      } else {
        sendResponse({ success: true, initialized: false });
      }
    });
    return true;

  // --- Feature 7: OAuth/SAML Flow Capture ---
  } else if (request.action === 'oauthFlowCaptured') {
    const tabId = sender.tab?.id || request.tabId;
    if (tabId && request.flows) {
      try {
        const storageKey = `tab_oauth_flows_${tabId}`;
        chrome.storage.local.set({ [storageKey]: request.flows });
      } catch (e) {
        console.error('Origami: Error storing OAuth flows:', e);
      }
    }
    sendResponse({ success: true });

  } else if (request.action === 'getOAuthFlows') {
    const tabId = request.tabId;
    (async () => {
      try {
        const storageKey = `tab_oauth_flows_${tabId}`;
        const data = await chrome.storage.local.get(storageKey);
        sendResponse({ flows: data[storageKey] || null });
      } catch (e) {
        sendResponse({ flows: null, error: e.message });
      }
    })();
    return true;

  // --- Feature 4: GraphQL Proxy & Results ---
  } else if (request.action === 'graphqlProxy') {
    // SECURITY FIX: Block content scripts from using graphqlProxy as SSRF proxy
    if (sender.tab) {
      sendResponse({ error: 'Unauthorized' });
      return;
    }
    const { url, query, variables, headers: reqHeaders } = request;
    (async () => {
      try {
        // SSRF protection: only allow HTTPS requests to non-private hosts
        try {
          const parsed = new URL(url);
          if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
            sendResponse({ success: false, error: 'Only HTTP(S) URLs are allowed for GraphQL proxy.' });
            return;
          }
          const hostname = parsed.hostname.toLowerCase();
          const blockedHosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]'];
          if (blockedHosts.includes(hostname) || /^10\./.test(hostname) || /^172\.(1[6-9]|2\d|3[01])\./.test(hostname) ||
              /^192\.168\./.test(hostname) || /^169\.254\./.test(hostname) || /^127\./.test(hostname) || /^0\./.test(hostname) ||
              /^\d+$/.test(hostname) || /^0x/i.test(hostname)) {
            sendResponse({ success: false, error: 'GraphQL proxy cannot target private/internal addresses.' });
            return;
          }
        } catch (e) {
          sendResponse({ success: false, error: 'Invalid URL for GraphQL proxy.' });
          return;
        }

        const cleanHeaders = { 'Content-Type': 'application/json', ...(reqHeaders || {}) };
        delete cleanHeaders['Origin'];
        delete cleanHeaders['Referer'];
        const response = await fetch(url, {
          method: 'POST',
          headers: cleanHeaders,
          body: JSON.stringify({ query, variables }),
          credentials: 'omit',
          referrerPolicy: 'no-referrer'
        });
        const contentType = response.headers.get('content-type') || '';
        if (!contentType.includes('json')) {
          sendResponse({ success: false, error: 'Non-JSON response (likely blocked by WAF or not a GraphQL endpoint)', status: response.status });
          return;
        }
        const data = await response.json();
        sendResponse({ success: true, data, status: response.status });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;

  } else if (request.action === 'graphqlResultsCollected') {
    const tabId = sender.tab?.id || request.tabId;
    if (tabId && request.graphql) {
      try {
        const storageKey = `tab_graphql_${tabId}`;
        chrome.storage.local.set({ [storageKey]: request.graphql });
      } catch (e) {
        console.error('Origami: Error storing GraphQL results:', e);
      }
    }
    sendResponse({ success: true });

  } else if (request.action === 'getGraphQLResults') {
    const tabId = request.tabId;
    (async () => {
      try {
        const storageKey = `tab_graphql_${tabId}`;
        const data = await chrome.storage.local.get(storageKey);
        sendResponse({ graphql: data[storageKey] || null });
      } catch (e) {
        sendResponse({ graphql: null, error: e.message });
      }
    })();
    return true;

  // --- Feature 9: Attack Surface Evolution Tracker ---
  } else if (request.action === 'saveBaseline') {
    const { domain, baseline } = request;
    (async () => {
      try {
        const storageKey = `baseline_${domain}`;
        const data = await chrome.storage.local.get(storageKey);
        let baselines = data[storageKey] || [];
        baselines.unshift(baseline);
        // Keep last 5 baselines per domain
        if (baselines.length > 5) baselines = baselines.slice(0, 5);
        await chrome.storage.local.set({ [storageKey]: baselines });
        console.log('Origami: Baseline saved for', domain, '(' + baselines.length + ' total)');
        sendResponse({ success: true, count: baselines.length });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;

  } else if (request.action === 'getBaselines') {
    const { domain } = request;
    (async () => {
      try {
        const storageKey = `baseline_${domain}`;
        const data = await chrome.storage.local.get(storageKey);
        sendResponse({ baselines: data[storageKey] || [] });
      } catch (e) {
        sendResponse({ baselines: [], error: e.message });
      }
    })();
    return true;

  } else if (request.action === 'diffBaseline') {
    const { domain, currentSnapshot } = request;
    (async () => {
      try {
        const storageKey = `baseline_${domain}`;
        const data = await chrome.storage.local.get(storageKey);
        const baselines = data[storageKey] || [];
        if (baselines.length === 0) {
          sendResponse({ diff: null, message: 'No baselines saved for this domain' });
          return;
        }
        const lastBaseline = baselines[0];
        // Compute diff
        const diff = computeBaselineDiff(lastBaseline, currentSnapshot);
        sendResponse({ diff, baseline: lastBaseline });
      } catch (e) {
        sendResponse({ diff: null, error: e.message });
      }
    })();
    return true;

  } else if (request.action === 'surfaceSnapshotCaptured') {
    const tabId = sender.tab?.id || request.tabId;
    if (tabId && request.snapshot) {
      try {
        const storageKey = `tab_surface_${tabId}`;
        chrome.storage.local.set({ [storageKey]: request.snapshot });
      } catch (e) {
        console.error('Origami: Error storing surface snapshot:', e);
      }
    }
    sendResponse({ success: true });

  } else if (request.action === 'getSurfaceSnapshot') {
    const tabId = request.tabId;
    (async () => {
      try {
        const storageKey = `tab_surface_${tabId}`;
        const data = await chrome.storage.local.get(storageKey);
        sendResponse({ snapshot: data[storageKey] || null });
      } catch (e) {
        sendResponse({ snapshot: null, error: e.message });
      }
    })();
    return true;

  // --- Feature 5: Correlation Chains ---
  } else if (request.action === 'correlationChainsDetected') {
    const tabId = sender.tab?.id || request.tabId;
    if (tabId && request.chains) {
      try {
        const storageKey = `tab_chains_${tabId}`;
        chrome.storage.local.set({ [storageKey]: request.chains });
      } catch (e) {
        console.error('Origami: Error storing correlation chains:', e);
      }
    }
    sendResponse({ success: true });

  } else if (request.action === 'getCorrelationChains') {
    const tabId = request.tabId;
    (async () => {
      try {
        const storageKey = `tab_chains_${tabId}`;
        const data = await chrome.storage.local.get(storageKey);
        sendResponse({ chains: data[storageKey] || null });
      } catch (e) {
        sendResponse({ chains: null, error: e.message });
      }
    })();
    return true;

  // --- Crypto Auditor Results ---
  } else if (request.action === 'cryptoResultsCollected') {
    const tabId = sender.tab?.id || request.tabId;
    if (tabId && request.crypto) {
      try {
        const storageKey = `tab_crypto_${tabId}`;
        chrome.storage.local.set({ [storageKey]: request.crypto });
      } catch (e) {
        console.error('Origami: Error storing crypto results:', e);
      }
    }
    sendResponse({ success: true });

  } else if (request.action === 'getCryptoResults') {
    const tabId = request.tabId;
    (async () => {
      try {
        const storageKey = `tab_crypto_${tabId}`;
        const data = await chrome.storage.local.get(storageKey);
        const crypto = data[storageKey] || null;
        if (crypto) await mergeAICacheIntoIssues(tabId, crypto, 'crypto');
        sendResponse({ crypto });
      } catch (e) {
        sendResponse({ crypto: null, error: e.message });
      }
    })();
    return true;

  // --- Cloud Storage Mapper Results ---
  } else if (request.action === 'cloudStorageResultsCollected') {
    const tabId = sender.tab?.id || request.tabId;
    if (tabId && request.cloudStorage) {
      try {
        const storageKey = `tab_cloud_storage_${tabId}`;
        chrome.storage.local.set({ [storageKey]: request.cloudStorage });
      } catch (e) {
        console.error('Origami: Error storing cloud storage results:', e);
      }
    }
    sendResponse({ success: true });

  } else if (request.action === 'getCloudStorageResults') {
    const tabId = request.tabId;
    (async () => {
      try {
        const storageKey = `tab_cloud_storage_${tabId}`;
        const data = await chrome.storage.local.get(storageKey);
        const cloudStorage = data[storageKey] || null;
        if (cloudStorage) await mergeAICacheIntoIssues(tabId, cloudStorage, 'cloudStorage');
        sendResponse({ cloudStorage });
      } catch (e) {
        sendResponse({ cloudStorage: null, error: e.message });
      }
    })();
    return true;

  // --- Exfiltration Detector Results ---
  } else if (request.action === 'exfiltrationResultsCollected') {
    const tabId = sender.tab?.id || request.tabId;
    if (tabId && request.exfiltration) {
      try {
        const storageKey = `tab_exfiltration_${tabId}`;
        chrome.storage.local.set({ [storageKey]: request.exfiltration });
      } catch (e) {
        console.error('Origami: Error storing exfiltration results:', e);
      }
    }
    sendResponse({ success: true });

  } else if (request.action === 'getExfiltrationResults') {
    const tabId = request.tabId;
    (async () => {
      try {
        const storageKey = `tab_exfiltration_${tabId}`;
        const data = await chrome.storage.local.get(storageKey);
        const exfiltration = data[storageKey] || null;
        if (exfiltration) await mergeAICacheIntoIssues(tabId, exfiltration, 'exfiltration');
        sendResponse({ exfiltration });
      } catch (e) {
        sendResponse({ exfiltration: null, error: e.message });
      }
    })();
    return true;

  // --- WebSocket Auditor Results ---
  } else if (request.action === 'websocketResultsCollected') {
    const tabId = sender.tab?.id || request.tabId;
    if (tabId && request.websockets) {
      try {
        const storageKey = `tab_websockets_${tabId}`;
        chrome.storage.local.set({ [storageKey]: request.websockets });
      } catch (e) {
        console.error('Origami: Error storing WebSocket results:', e);
      }
    }
    sendResponse({ success: true });

  } else if (request.action === 'getWebSocketResults') {
    const tabId = request.tabId;
    (async () => {
      try {
        const storageKey = `tab_websockets_${tabId}`;
        const data = await chrome.storage.local.get(storageKey);
        const websockets = data[storageKey] || null;
        if (websockets) await mergeAICacheIntoIssues(tabId, websockets, 'websocket');
        sendResponse({ websockets });
      } catch (e) {
        sendResponse({ websockets: null, error: e.message });
      }
    })();
    return true;

  // --- JS Obfuscation Detector Results ---
  } else if (request.action === 'jsObfuscationResultsCollected') {
    const tabId = sender.tab?.id || request.tabId;
    if (tabId && request.jsObfuscation) {
      try {
        const storageKey = `tab_js_obfuscation_${tabId}`;
        chrome.storage.local.set({ [storageKey]: request.jsObfuscation });
      } catch (e) {
        console.error('Origami: Error storing JS obfuscation results:', e);
      }
    }
    sendResponse({ success: true });

  } else if (request.action === 'getJSObfuscationResults') {
    const tabId = request.tabId;
    (async () => {
      try {
        const storageKey = `tab_js_obfuscation_${tabId}`;
        const data = await chrome.storage.local.get(storageKey);
        const jsObfuscation = data[storageKey] || null;
        if (jsObfuscation) await mergeAICacheIntoIssues(tabId, jsObfuscation, 'jsObfuscation');
        sendResponse({ jsObfuscation });
      } catch (e) {
        sendResponse({ jsObfuscation: null, error: e.message });
      }
    })();
    return true;

  // --- Phase 2-3 AI Assessment Persistence ---
  } else if (request.action === 'updateExfiltrationResults') {
    const tabId = request.tabId;
    if (tabId && request.data) {
      (async () => {
        try {
          const storageKey = `tab_exfiltration_${tabId}`;
          const existing = (await chrome.storage.local.get(storageKey))[storageKey];
          if (existing) {
            existing.issues = request.data;
            await chrome.storage.local.set({ [storageKey]: existing });
          }
        } catch (e) { console.error('Origami: Error updating exfiltration results:', e); }
        sendResponse({ success: true });
      })();
      return true;
    }
    sendResponse({ success: true });

  } else if (request.action === 'updateCryptoResults') {
    const tabId = request.tabId;
    if (tabId && request.data) {
      (async () => {
        try {
          const storageKey = `tab_crypto_${tabId}`;
          const existing = (await chrome.storage.local.get(storageKey))[storageKey];
          if (existing) {
            existing.issues = request.data;
            await chrome.storage.local.set({ [storageKey]: existing });
          }
        } catch (e) { console.error('Origami: Error updating crypto results:', e); }
        sendResponse({ success: true });
      })();
      return true;
    }
    sendResponse({ success: true });

  } else if (request.action === 'updateCloudStorageResults') {
    const tabId = request.tabId;
    if (tabId && request.data) {
      (async () => {
        try {
          const storageKey = `tab_cloud_storage_${tabId}`;
          const existing = (await chrome.storage.local.get(storageKey))[storageKey];
          if (existing) {
            existing.issues = request.data;
            await chrome.storage.local.set({ [storageKey]: existing });
          }
        } catch (e) { console.error('Origami: Error updating cloud storage results:', e); }
        sendResponse({ success: true });
      })();
      return true;
    }
    sendResponse({ success: true });

  } else if (request.action === 'updateWebSocketResults') {
    const tabId = request.tabId;
    if (tabId && request.data) {
      (async () => {
        try {
          const storageKey = `tab_websockets_${tabId}`;
          const existing = (await chrome.storage.local.get(storageKey))[storageKey];
          if (existing) {
            existing.issues = request.data;
            await chrome.storage.local.set({ [storageKey]: existing });
          }
        } catch (e) { console.error('Origami: Error updating websocket results:', e); }
        sendResponse({ success: true });
      })();
      return true;
    }
    sendResponse({ success: true });

  } else if (request.action === 'updateJSObfuscationResults') {
    const tabId = request.tabId;
    if (tabId && request.data) {
      (async () => {
        try {
          const storageKey = `tab_js_obfuscation_${tabId}`;
          const existing = (await chrome.storage.local.get(storageKey))[storageKey];
          if (existing) {
            existing.issues = request.data;
            await chrome.storage.local.set({ [storageKey]: existing });
          }
        } catch (e) { console.error('Origami: Error updating JS obfuscation results:', e); }
        sendResponse({ success: true });
      })();
      return true;
    }
    sendResponse({ success: true });

  } else if (request.action === 'getMCPStatus') {
    sendResponse({
      enabled: mcpBridge.enabled,
      connected: mcpBridge.connected,
      wsUrl: mcpBridge.wsUrl,
      reconnectAttempts: mcpBridge.reconnectAttempts,
    });
    return false;

  } else if (request.action === 'storageGet') {
    // SECURITY FIX: Block content scripts from reading extension storage
    if (sender.tab) {
      sendResponse(null);
      return;
    }
    chrome.storage.local.get([request.key], (result) => {
      sendResponse({ data: result[request.key] || null });
    });
    return true;

  } else if (request.action === 'storageSet') {
    // SECURITY FIX: Block content scripts from writing extension storage
    if (sender.tab) {
      sendResponse({ success: false });
      return;
    }
    // Access control: only allow writing to specific safe storage keys
    // Block writes to security-critical keys (plugins, settings, whitelist) to prevent
    // injection of malicious plugins or tampering with security settings
    const allowedKeyPrefixes = ['tab_', 'chat_history_', 'ai_cache_', 'scan_', 'repeater_'];
    const allowedExactKeys = ['origami_last_scan', 'origami_scan_count'];
    const key = request.key;
    const isAllowed = allowedExactKeys.includes(key) || allowedKeyPrefixes.some(p => key.startsWith(p));
    if (!isAllowed) {
      console.warn('Origami: storageSet blocked for restricted key:', key);
      sendResponse({ success: false, error: 'Storage key not allowed: ' + key });
      return true;
    }
    chrome.storage.local.set({ [key]: request.value }, () => {
      sendResponse({ success: true });
    });
    return true;

  } else if (request.action === 'getAllFindings') {
    const tabId = request.tabId;
    (async () => {
      try {
        const allFindings = {};

        // Load security analysis results (headers, cookies, vulns, technologies, sensitiveFiles, etc.)
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

        // Load secrets/findings
        const findings = await loadTabFindings(tabId);
        if (findings && findings.length > 0) {
          allFindings.secrets = findings;
        }

        // Load crypto results
        const cryptoKey = `tab_crypto_${tabId}`;
        const cryptoData = await chrome.storage.local.get(cryptoKey);
        allFindings.crypto = cryptoData[cryptoKey] || null;

        // Load cloud storage results
        const cloudKey = `tab_cloud_storage_${tabId}`;
        const cloudData = await chrome.storage.local.get(cloudKey);
        allFindings.cloudStorage = cloudData[cloudKey] || null;

        // Load exfiltration results
        const exfilKey = `tab_exfiltration_${tabId}`;
        const exfilData = await chrome.storage.local.get(exfilKey);
        allFindings.exfiltration = exfilData[exfilKey] || null;

        // Load websocket results
        const wsKey = `tab_websockets_${tabId}`;
        const wsData = await chrome.storage.local.get(wsKey);
        allFindings.websockets = wsData[wsKey] || null;

        // Load JS obfuscation results
        const obfuscationKey = `tab_js_obfuscation_${tabId}`;
        const obfuscationData = await chrome.storage.local.get(obfuscationKey);
        allFindings.jsObfuscation = allFindings.jsObfuscation || obfuscationData[obfuscationKey] || null;

        // Load correlation chains
        const chainsKey = `tab_chains_${tabId}`;
        const chainsData = await chrome.storage.local.get(chainsKey);
        allFindings.correlationChains = chainsData[chainsKey] || null;

        sendResponse(allFindings);
      } catch (e) {
        console.error('Origami: getAllFindings error:', e.message);
        sendResponse(null);
      }
    })();
    return true;
  } else if (request.action === 'exportFindingsForMCP') {
    // Export all findings for the active tab as a JSON download for the MCP server
    const tabId = request.tabId;
    (async () => {
      try {
        const allFindings = { timestamp: new Date().toISOString() };

        // Get tab URL
        try {
          const tab = await chrome.tabs.get(tabId);
          allFindings.url = tab?.url || 'unknown';
        } catch (e) {
          allFindings.url = 'unknown';
        }

        // Load all results
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

        // Load secrets
        const findings = await loadTabFindings(tabId);
        if (findings && findings.length > 0) {
          allFindings.secrets = findings;
        }

        // Load specialized results
        const specKeys = [
          `tab_crypto_${tabId}`, `tab_cloud_storage_${tabId}`,
          `tab_exfiltration_${tabId}`, `tab_websockets_${tabId}`,
          `tab_js_obfuscation_${tabId}`
        ];
        const specData = await chrome.storage.local.get(specKeys);
        allFindings.crypto = allFindings.crypto || specData[`tab_crypto_${tabId}`] || null;
        allFindings.cloudStorage = allFindings.cloudStorage || specData[`tab_cloud_storage_${tabId}`] || null;
        allFindings.exfiltration = allFindings.exfiltration || specData[`tab_exfiltration_${tabId}`] || null;
        allFindings.websockets = allFindings.websockets || specData[`tab_websockets_${tabId}`] || null;
        allFindings.jsObfuscation = allFindings.jsObfuscation || specData[`tab_js_obfuscation_${tabId}`] || null;

        // Trigger download to ~/.origami/findings.json (matches MCP server default path)
        const jsonStr = JSON.stringify(allFindings, null, 2);
        const dataUrl = 'data:application/json;base64,' + btoa(unescape(encodeURIComponent(jsonStr)));
        const downloadId = await chrome.downloads.download({
          url: dataUrl,
          filename: '.origami/findings.json',
          conflictAction: 'overwrite',
          saveAs: false
        });

        sendResponse({ success: true, findingsCount: Object.keys(allFindings).length, downloadId });
      } catch (e) {
        console.error('Origami: exportFindingsForMCP error:', e.message);
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  // --- Report Malicious Site ---
  else if (request.action === 'getReportHistory') {
    chrome.storage.local.get(['origami_report_history'], (data) => {
      sendResponse({ history: data.origami_report_history || [] });
    });
    return true;

  } else if (request.action === 'saveReportHistory') {
    const { report } = request;
    chrome.storage.local.get(['origami_report_history'], (data) => {
      const history = data.origami_report_history || [];
      history.unshift(report);
      if (history.length > 200) history.length = 200;
      chrome.storage.local.set({ origami_report_history: history }, () => {
        sendResponse({ success: true, history: history });
      });
    });
    return true;

  } else if (request.action === 'clearReportHistory') {
    chrome.storage.local.set({ origami_report_history: [] }, () => {
      sendResponse({ success: true });
    });
    return true;
  }

  return true; // Keep channel open for async response
});

// Port-based streaming for AI Partner chat (OpenAI and Anthropic SSE streaming)
chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== 'ai-partner-stream') return;

  port.onMessage.addListener((msg) => {
    if (msg.action !== 'startStream') return;

    const { provider, endpoint, headers, body } = msg;

    (async () => {
      let timeoutId;
      try {
        // SSRF protection: only allow known LLM provider endpoints for streaming
        if (!isAllowedLLMEndpoint(endpoint)) {
          port.postMessage({ type: 'error', error: 'Endpoint not allowed. Only known LLM provider endpoints are permitted.' });
          return;
        }

        const isLocalRequest = endpoint.includes('localhost') || endpoint.includes('127.0.0.1');
        const isOpenAI = endpoint.includes('openai.com');
        const isAnthropic = endpoint.includes('anthropic.com');

        // Clean headers (same as llmRequest handler)
        const cleanHeaders = { ...(headers || {}) };
        delete cleanHeaders['Origin'];
        delete cleanHeaders['Referer'];

        const controller = new AbortController();
        timeoutId = setTimeout(() => controller.abort(), 120000);

        const requestBody = { ...body };
        if (isOpenAI || isAnthropic) {
          requestBody.stream = true;
        }

        const fetchOptions = {
          method: 'POST',
          headers: cleanHeaders,
          body: JSON.stringify(requestBody),
          signal: controller.signal
        };

        if (isLocalRequest) {
          fetchOptions.mode = 'cors';
          fetchOptions.credentials = 'omit';
          fetchOptions.referrerPolicy = 'no-referrer';
          fetchOptions.referrer = '';
        }

        const response = await fetch(endpoint, fetchOptions);

        if (!response.ok) {
          clearTimeout(timeoutId);
          const errorText = await response.text();
          port.postMessage({ type: 'error', error: 'HTTP ' + response.status + ': ' + errorText.substring(0, 500) });
          return;
        }

        // Streaming path for OpenAI and Anthropic
        if ((isOpenAI || isAnthropic) && response.body) {
          const reader = response.body.getReader();
          const decoder = new TextDecoder();
          let buffer = '';

          while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            // Keep the last potentially incomplete line in the buffer
            buffer = lines.pop() || '';

            for (const line of lines) {
              const trimmed = line.trim();

              if (isOpenAI) {
                if (!trimmed.startsWith('data: ')) continue;
                const payload = trimmed.slice(6);
                if (payload === '[DONE]') {
                  clearTimeout(timeoutId);
                  port.postMessage({ type: 'done' });
                  return;
                }
                try {
                  const parsed = JSON.parse(payload);
                  const content = parsed.choices?.[0]?.delta?.content;
                  if (content) {
                    port.postMessage({ type: 'chunk', text: content });
                  }
                } catch (_) {
                  // Skip malformed JSON lines
                }
              } else if (isAnthropic) {
                if (trimmed === 'event: message_stop') {
                  clearTimeout(timeoutId);
                  port.postMessage({ type: 'done' });
                  return;
                }
                if (!trimmed.startsWith('data: ')) continue;
                const payload = trimmed.slice(6);
                try {
                  const parsed = JSON.parse(payload);
                  if (parsed.type === 'content_block_delta' && parsed.delta?.type === 'text_delta') {
                    port.postMessage({ type: 'chunk', text: parsed.delta.text });
                  }
                } catch (_) {
                  // Skip malformed JSON lines
                }
              }
            }
          }

          // Stream ended without explicit done signal
          clearTimeout(timeoutId);
          port.postMessage({ type: 'done' });
          return;
        }

        // Non-streaming fallback for Gemini/Ollama
        clearTimeout(timeoutId);
        const data = await response.json();

        let fullText = '';
        if (endpoint.includes('generativelanguage.googleapis.com')) {
          fullText = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
        } else if (isLocalRequest || endpoint.includes('/api/generate')) {
          fullText = data.response || '';
        } else {
          fullText = JSON.stringify(data);
        }

        if (fullText) {
          port.postMessage({ type: 'chunk', text: fullText });
        }
        port.postMessage({ type: 'done' });

      } catch (error) {
        if (timeoutId) clearTimeout(timeoutId);
        const errorMsg = error.name === 'AbortError'
          ? 'Streaming request timed out after 120 seconds'
          : error.message;
        try {
          port.postMessage({ type: 'error', error: errorMsg });
        } catch (_) {
          // Port may already be disconnected
        }
      }
    })();
  });
});

// Baseline diff computation
function computeBaselineDiff(baseline, current) {
  const diff = { added: [], removed: [], changed: [], summary: {} };

  // Compare technologies
  const baseTech = new Set(Object.keys(baseline.technologies || {}));
  const currTech = new Set(Object.keys(current.technologies || {}));
  for (const t of currTech) {
    if (!baseTech.has(t)) diff.added.push({ type: 'technology', name: t });
  }
  for (const t of baseTech) {
    if (!currTech.has(t)) diff.removed.push({ type: 'technology', name: t });
  }
  // Version changes
  for (const t of currTech) {
    if (baseTech.has(t)) {
      const bv = baseline.technologies[t];
      const cv = current.technologies[t];
      if (bv !== cv) {
        diff.changed.push({ type: 'technology_version', name: t, from: bv, to: cv });
      }
    }
  }

  // Compare headers
  const baseHeaders = Object.keys(baseline.headers || {});
  const currHeaders = Object.keys(current.headers || {});
  for (const h of currHeaders) {
    if (!baseHeaders.includes(h)) diff.added.push({ type: 'header', name: h });
  }
  for (const h of baseHeaders) {
    if (!currHeaders.includes(h)) diff.removed.push({ type: 'header', name: h });
  }

  // Compare finding counts
  const baseFindingCount = baseline.findingSummary?.total || 0;
  const currFindingCount = current.findingSummary?.total || 0;
  diff.summary = {
    technologiesAdded: diff.added.filter(d => d.type === 'technology').length,
    technologiesRemoved: diff.removed.filter(d => d.type === 'technology').length,
    headersAdded: diff.added.filter(d => d.type === 'header').length,
    headersRemoved: diff.removed.filter(d => d.type === 'header').length,
    versionChanges: diff.changed.length,
    findingsDelta: currFindingCount - baseFindingCount
  };

  return diff;
}

// Periodic cleanup of stale tab data (prevents memory leaks)
const MAX_TAB_ENTRIES = 50;

async function cleanupStaleTabs() {
  try {
    const tabs = await chrome.tabs.query({});
    const activeTabIds = new Set(tabs.map(t => t.id));

    // Clean up in-memory entries for closed tabs
    for (const tabId of tabFindings.keys()) {
      if (!activeTabIds.has(tabId)) {
        tabFindings.delete(tabId);
      }
    }
    for (const tabId of tabSecurityResults.keys()) {
      if (!activeTabIds.has(tabId)) {
        tabSecurityResults.delete(tabId);
      }
    }
    for (const tabId of tabInventory.keys()) {
      if (!activeTabIds.has(tabId)) {
        tabInventory.delete(tabId);
      }
    }

    // Clean up stale storage entries
    const allData = await chrome.storage.local.get(null);
    const keysToRemove = [];
    for (const key of Object.keys(allData)) {
      const match = key.match(/^tab_(?:findings|security|inventory|plugin_results|oauth_flows|graphql|surface|chains|crypto|cloud_storage|exfiltration|websockets|js_obfuscation)_(\d+)$/);
      if (match && !activeTabIds.has(parseInt(match[1]))) {
        keysToRemove.push(key);
      }
    }
    // Clean up domain inventory entries older than 7 days
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    for (const key of Object.keys(allData)) {
      if (key.startsWith('domain_inventory_')) {
        const entry = allData[key];
        if (entry && entry.cachedAt && entry.cachedAt < sevenDaysAgo) {
          keysToRemove.push(key);
        }
      }
    }

    // Clean up domain cache entries older than 3 days
    const threeDaysAgo = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString();
    for (const key of Object.keys(allData)) {
      if (key.startsWith('domain_cache_')) {
        const entry = allData[key];
        if (entry && entry.cachedAt && entry.cachedAt < threeDaysAgo) {
          keysToRemove.push(key);
        }
      }
    }

    // Clean up feature state entries older than 7 days
    for (const key of Object.keys(allData)) {
      if (key.startsWith('feature_')) {
        const entry = allData[key];
        if (entry && entry.savedAt && entry.savedAt < Date.now() - 7 * 24 * 60 * 60 * 1000) {
          keysToRemove.push(key);
        }
      }
    }

    // Clean up brute force cache entries older than 7 days
    for (const key of Object.keys(allData)) {
      if (key.startsWith('bruteforce_cache_')) {
        const entry = allData[key];
        if (entry && entry.cachedAt && entry.cachedAt < Date.now() - 7 * 24 * 60 * 60 * 1000) {
          keysToRemove.push(key);
        }
      }
    }

    // Clean up brute force tab entries for closed tabs
    for (const key of Object.keys(allData)) {
      const bfMatch = key.match(/^bruteforce_results_(\d+)$/);
      if (bfMatch && !activeTabIds.has(parseInt(bfMatch[1]))) {
        keysToRemove.push(key);
      }
    }

    // Clean up AI assessment cache entries older than 14 days
    const fourteenDaysAgo = new Date(Date.now() - 14 * 24 * 60 * 60 * 1000).toISOString();
    for (const key of Object.keys(allData)) {
      if (key.startsWith('ai_cache_')) {
        const cache = allData[key];
        if (cache && typeof cache === 'object') {
          let pruned = false;
          for (const [fp, data] of Object.entries(cache)) {
            if (data.cachedAt && data.cachedAt < fourteenDaysAgo) {
              delete cache[fp];
              pruned = true;
            }
          }
          if (Object.keys(cache).length === 0) {
            keysToRemove.push(key);
          } else if (pruned) {
            await chrome.storage.local.set({ [key]: cache });
          }
        }
      }
    }

    // Clean up stale tabDomains entries
    for (const tabId of tabDomains.keys()) {
      if (!activeTabIds.has(tabId)) {
        tabDomains.delete(tabId);
      }
    }

    if (keysToRemove.length > 0) {
      await chrome.storage.local.remove(keysToRemove);
      console.log(`Origami: Cleaned up ${keysToRemove.length} stale storage entries`);
    }

    // Evict old HTTP History entries (IndexedDB)
    await evictHttpHistory();

  } catch (error) {
    console.error('Origami: Cleanup error:', error);
  }
}

// Run cleanup every 5 minutes
setInterval(cleanupStaleTabs, 5 * 60 * 1000);

// Clear findings when tab is closed (snapshot to domain cache first)
chrome.tabs.onRemoved.addListener(async (tabId) => {
  const domain = tabDomains.get(tabId);
  if (domain) {
    await snapshotToDomainCache(tabId, domain);
  }
  clearTabFindings(tabId);
  tabDomains.delete(tabId);
});

// Clear findings when navigating to a new page (snapshot to domain cache first)
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading') {
    // Snapshot current data to domain cache before clearing
    const domain = tabDomains.get(tabId);
    if (domain) {
      await snapshotToDomainCache(tabId, domain);
    }
    clearTabFindings(tabId);
    tabDomains.delete(tabId);
    chrome.action.setBadgeText({ tabId: tabId, text: '' });

    // Track new domain
    if (tab && tab.url) {
      try {
        const newDomain = new URL(tab.url).hostname;
        if (newDomain) tabDomains.set(tabId, newDomain);
      } catch (e) { /* ignore invalid URLs */ }
    }
  }
});

// Update badge when switching between tabs
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const tabId = activeInfo.tabId;
  const findings = await loadTabFindings(tabId);
  const securityResults = await loadTabSecurityResults(tabId);
  
  chrome.storage.sync.get(['settings'], (data) => {
    const settings = data.settings || DEFAULT_SETTINGS;
    updateBadge(tabId, findings, settings, securityResults);
  });
});

// Handle notification clicks - open the extension popup
chrome.notifications.onClicked.addListener(() => {
  // Get the current active tab and focus on it
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) {
      chrome.action.openPopup();
    }
  });
});

// ─── MCP Bridge Initialization ────────────────────────────────────────────────

// Initialize MCP bridge (reads settings and connects if enabled)
mcpBridge.init();

// Keep-alive alarm: prevents service worker termination while MCP bridge is active
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'origami-mcp-keepalive') {
    if (mcpBridge.enabled && !mcpBridge.connected) {
      mcpBridge.connect();
    }
  }
});

// Listen for MCP bridge setting changes
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'sync' && changes.settings) {
    const newSettings = changes.settings.newValue || {};
    const mcpSettings = newSettings.mcpBridge || {};
    const wasEnabled = mcpBridge.enabled;

    if (mcpSettings.enabled && !wasEnabled) {
      // MCP bridge was just enabled
      mcpBridge.enabled = true;
      mcpBridge.wsUrl = mcpSettings.wsUrl || 'ws://127.0.0.1:9340';
      mcpBridge.wsToken = mcpSettings.wsToken || '';
      mcpBridge.connect();
      chrome.alarms.create('origami-mcp-keepalive', { periodInMinutes: 0.4 });
      console.log('Origami MCP: Bridge enabled');
    } else if (!mcpSettings.enabled && wasEnabled) {
      // MCP bridge was just disabled
      mcpBridge.disconnect();
      chrome.alarms.clear('origami-mcp-keepalive');
      console.log('Origami MCP: Bridge disabled');
    } else if (mcpSettings.enabled && (mcpSettings.wsUrl !== mcpBridge.wsUrl || mcpSettings.wsToken !== mcpBridge.wsToken)) {
      // URL or token changed while enabled
      mcpBridge.disconnect();
      mcpBridge.enabled = true;
      mcpBridge.wsUrl = mcpSettings.wsUrl;
      mcpBridge.wsToken = mcpSettings.wsToken || '';
      mcpBridge.connect();
    }
  }
});

// Start keep-alive alarm if MCP bridge is already enabled
chrome.storage.sync.get(['settings'], (data) => {
  const settings = data.settings || DEFAULT_SETTINGS;
  if (settings.mcpBridge && settings.mcpBridge.enabled) {
    chrome.alarms.create('origami-mcp-keepalive', { periodInMinutes: 0.4 });
  }
});

// Notify MCP bridge on scan completion (so Claude Code can react to new data)
const originalOnMessageListener = chrome.runtime.onMessage.hasListeners;
// Hook into scan completion to notify MCP bridge
const _origScanCompleteHandler = true;

console.log('Origami background service worker initialized');

