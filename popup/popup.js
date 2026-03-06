// Origami Popup Script
// Handles UI interactions and communication with background script

let currentFindings = [];
let currentSettings = null;
let currentWhitelist = null;
let currentHistory = [];
let securityResults = null;
let currentPatterns = [];
let editingPattern = null;
let currentInventory = null;
let errorLog = [];  // Global error log
let securityResultsLoaded = false;  // Track if security results have been loaded/attempted

// Target override state (full-page mode tab targeting)
let _overrideTabId = null;
let _overrideTabUrl = null;
let _isFullPageMode = false;

async function getTargetTab() {
  if (_overrideTabId !== null) {
    try {
      const tab = await chrome.tabs.get(_overrideTabId);
      _overrideTabUrl = tab.url;
      return tab;
    } catch (e) {
      clearTargetOverride();
    }
  }
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab || null;
}

function getTargetTabCb(callback) {
  getTargetTab().then(tab => callback(tab ? [tab] : [])).catch(() => callback([]));
}

function setTargetOverride(tabId, tabUrl) {
  _overrideTabId = tabId;
  _overrideTabUrl = tabUrl;
  chrome.storage.session.set({ targetOverride: { tabId, tabUrl } });
  updateTargetOverrideUI();
}

function clearTargetOverride() {
  _overrideTabId = null;
  _overrideTabUrl = null;
  chrome.storage.session.remove('targetOverride');
  updateTargetOverrideUI();
}

function updateTargetOverrideUI() {
  const urlEl = document.getElementById('targetBarUrl');
  const clearBtn = document.getElementById('targetClearBtn');
  if (!urlEl) return;
  if (_overrideTabId !== null && _overrideTabUrl) {
    try {
      urlEl.textContent = new URL(_overrideTabUrl).hostname;
    } catch (e) {
      urlEl.textContent = _overrideTabUrl;
    }
    urlEl.classList.add('active');
    if (clearBtn) clearBtn.style.display = '';
  } else {
    urlEl.textContent = 'No target selected';
    urlEl.classList.remove('active');
    if (clearBtn) clearBtn.style.display = 'none';
  }
}

function showTabPicker() {
  chrome.tabs.query({}, (allTabs) => {
    const httpTabs = allTabs.filter(t => t.url && (t.url.startsWith('http://') || t.url.startsWith('https://')));
    let html = '<div class="tab-picker-list">';
    if (httpTabs.length === 0) {
      html += '<div style="padding: 16px; color: var(--text-tertiary);">No web pages open</div>';
    } else {
      httpTabs.forEach(t => {
        const isCurrent = t.id === _overrideTabId;
        let hostname = '';
        try { hostname = new URL(t.url).hostname; } catch(e) {}
        html += `<div class="tab-picker-item${isCurrent ? ' current' : ''}" data-tab-id="${t.id}" data-tab-url="${escapeHtml(t.url)}">
          <div style="flex:1;min-width:0">
            <div class="tab-picker-title">${escapeHtml(t.title || 'Untitled')}</div>
            <div class="tab-picker-url">${escapeHtml(hostname)}</div>
          </div>
        </div>`;
      });
    }
    html += '</div>';

    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `<div class="modal-content" style="max-height:400px">
      <div class="modal-header"><h3>Select Target Tab</h3>
        <button class="modal-close" title="Close">&times;</button>
      </div>
      <div class="modal-body">${html}</div>
    </div>`;
    document.body.appendChild(modal);

    modal.querySelector('.modal-close').addEventListener('click', () => modal.remove());
    modal.addEventListener('click', (e) => { if (e.target === modal) modal.remove(); });

    modal.querySelectorAll('.tab-picker-item').forEach(item => {
      item.addEventListener('click', () => {
        const tabId = parseInt(item.dataset.tabId, 10);
        const tabUrl = item.dataset.tabUrl;
        setTargetOverride(tabId, tabUrl);
        modal.remove();
        reloadAllDataForTarget();
      });
    });
  });
}

function reloadAllDataForTarget() {
  currentFindings = [];
  securityResults = null;
  currentInventory = null;
  securityResultsLoaded = false;

  const findingsContainer = document.getElementById('findingsList');
  if (findingsContainer) findingsContainer.innerHTML = '';
  const securityContainer = document.getElementById('securityContent');
  if (securityContainer) securityContainer.innerHTML = '';
  const inventoryContainer = document.getElementById('inventoryContent');
  if (inventoryContainer) inventoryContainer.innerHTML = '';

  const scoreDashboard = document.getElementById('scoreDashboard');
  if (scoreDashboard) scoreDashboard.style.display = 'none';

  loadCurrentFindings().catch(e => console.error('reload findings:', e));
  loadInventory().catch(e => console.error('reload inventory:', e));

  getTargetTab().then(tab => {
    if (tab) loadPhase2DataForTab(tab.id);
  });

  // Reset AI Partner if domain changed
  if (typeof chatManager !== 'undefined') chatManager = null;
}

// Feature state persistence helpers (domain-keyed via chrome.storage.local)
function saveFeatureState(featureKey, data) {
  getTargetTabCb((tabs) => {
    if (!tabs[0]?.url) return;
    let domain;
    try { domain = new URL(tabs[0].url).hostname; } catch (e) { return; }
    const storageKey = `feature_${featureKey}_${domain}`;
    chrome.storage.local.set({ [storageKey]: { data, savedAt: Date.now() } });
  });
}

function loadFeatureState(featureKey, callback) {
  getTargetTabCb((tabs) => {
    if (!tabs[0]?.url) { callback(null); return; }
    let domain;
    try { domain = new URL(tabs[0].url).hostname; } catch (e) { callback(null); return; }
    const storageKey = `feature_${featureKey}_${domain}`;
    chrome.storage.local.get([storageKey], (result) => {
      callback(result[storageKey]?.data || null);
    });
  });
}

// Error logging functions
function logError(error, context = '', additionalInfo = {}) {
  const errorEntry = {
    timestamp: new Date().toISOString(),
    message: error.message || String(error),
    stack: error.stack || '',
    context: context,
    url: window.location.href,
    ...additionalInfo
  };

  errorLog.push(errorEntry);
  console.error('Origami Error:', errorEntry);

  // Update error badge
  updateErrorBadge();

  // Keep only last 100 errors
  if (errorLog.length > 100) {
    errorLog.shift();
  }

  // Save to storage
  chrome.storage.local.set({ errorLog: errorLog });
}

function updateErrorBadge() {
  const badge = document.getElementById('errorBadge');
  const indicator = document.getElementById('errorIndicatorBtn');
  if (badge && indicator) {
    if (errorLog.length > 0) {
      badge.textContent = errorLog.length;
      indicator.style.display = 'inline-flex';
    } else {
      indicator.style.display = 'none';
    }
  }
}

function displayErrors() {
  const container = document.getElementById('errorsContainer');

  if (errorLog.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <p>${origamiIcon('checkCircle')} No errors logged</p>
        <p class="empty-hint">Errors and exceptions will appear here for debugging.</p>
      </div>
    `;
    return;
  }

  let html = '<div class="error-list">';

  // Display errors in reverse order (newest first)
  [...errorLog].reverse().forEach((error, index) => {
    const actualIndex = errorLog.length - 1 - index;
    html += `
      <div class="error-item">
        <div class="error-header">
          <span class="error-timestamp">${new Date(error.timestamp).toLocaleString()}</span>
          ${error.context ? `<span class="error-context">${escapeHtml(error.context)}</span>` : ''}
        </div>
        <div class="error-message">
          <strong>Error:</strong> ${escapeHtml(error.message)}
        </div>
        ${error.stack ? `
        <details class="error-stack">
          <summary>Stack Trace</summary>
          <pre>${escapeHtml(error.stack)}</pre>
        </details>` : ''}
        ${Object.keys(error).filter(k => !['timestamp', 'message', 'stack', 'context', 'url'].includes(k)).length > 0 ? `
        <details class="error-details">
          <summary>Additional Info</summary>
          <pre>${escapeHtml(JSON.stringify(
            Object.fromEntries(
              Object.entries(error).filter(([k]) => !['timestamp', 'message', 'stack', 'context', 'url'].includes(k))
            ), null, 2
          ))}</pre>
        </details>` : ''}
      </div>
    `;
  });

  html += '</div>';
  container.innerHTML = html;
}

function clearErrors() {
  if (!confirm('Clear all error logs?')) return;
  errorLog = [];
  chrome.storage.local.set({ errorLog: [] });
  displayErrors();
  updateErrorBadge();
  showMessage('Error logs cleared', 'success');
}

function exportErrors() {
  if (errorLog.length === 0) {
    showMessage('No errors to export', 'info');
    return;
  }

  const data = JSON.stringify(errorLog, null, 2);
  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `origami-errors-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showMessage('Error logs exported', 'success');
}

// Wrap existing errors in try-catch
window.addEventListener('error', (event) => {
  logError(event.error || new Error(event.message), 'Global error handler', {
    filename: event.filename,
    lineno: event.lineno,
    colno: event.colno
  });
});

window.addEventListener('unhandledrejection', (event) => {
  logError(event.reason || new Error('Unhandled Promise rejection'), 'Unhandled Promise', {
    promise: event.promise
  });
});

// Initialize popup
document.addEventListener('DOMContentLoaded', async () => {
  // Full-page mode detection: chrome.tabs.getCurrent() returns undefined in
  // popup overlays (not a tab) but returns the tab object in full-page mode
  const selfTab = await chrome.tabs.getCurrent();
  _isFullPageMode = !!selfTab;

  // Restore override from session storage
  try {
    const session = await chrome.storage.session.get('targetOverride');
    if (session.targetOverride?.tabId) {
      try {
        await chrome.tabs.get(session.targetOverride.tabId);
        _overrideTabId = session.targetOverride.tabId;
        _overrideTabUrl = session.targetOverride.tabUrl;
      } catch (e) {
        chrome.storage.session.remove('targetOverride');
      }
    }
  } catch (e) { /* session storage unavailable */ }

  // URL parameter override (used by Playwright tests and expand-to-fullpage)
  const params = new URLSearchParams(window.location.search);
  const targetParam = params.get('target');
  if (targetParam) {
    const tabId = parseInt(targetParam, 10);
    if (!isNaN(tabId)) {
      try {
        const tab = await chrome.tabs.get(tabId);
        setTargetOverride(tabId, tab.url);
        // Store target tab for MCP bridge -- prevents MCP from reading from the
        // popup tab (which has no findings) when popup is the active Chrome tab.
        chrome.storage.local.set({ mcp_context_tab: tabId });
      } catch (e) { /* tab doesn't exist, fall through */ }
    }
  }

  if (_isFullPageMode) document.body.classList.add('full-page-mode');
  updateTargetOverrideUI();

  // Target bar event listeners
  document.getElementById('targetPickerBtn')?.addEventListener('click', showTabPicker);
  document.getElementById('targetClearBtn')?.addEventListener('click', () => {
    clearTargetOverride();
    reloadAllDataForTarget();
  });

  // Kanji badge opens full-page mode (only in popup overlay, hidden in full-page)
  document.getElementById('kanjiBadge')?.addEventListener('click', async () => {
    if (_isFullPageMode) return;
    // In popup overlay mode, the active tab IS the intended target
    const [currentTab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const targetParam = currentTab?.id ? `?target=${currentTab.id}` : '';
    chrome.tabs.create({
      url: chrome.runtime.getURL(`popup/popup.html${targetParam}`)
    });
    window.close();
  });

  // Tab lifecycle: clear override if target tab is closed
  chrome.tabs.onRemoved.addListener((closedTabId) => {
    if (_overrideTabId === closedTabId) {
      clearTargetOverride();
      reloadAllDataForTarget();
    }
  });

  try { await loadSettings(); } catch(e) { console.error('loadSettings failed:', e); }
  try { await loadWhitelist(); } catch(e) { console.error('loadWhitelist failed:', e); }
  try { await loadHistory(); } catch(e) { console.error('loadHistory failed:', e); }
  try { await loadCurrentFindings(); } catch(e) { console.error('loadCurrentFindings failed:', e); }
  try { await loadPatterns(); } catch(e) { console.error('loadPatterns failed:', e); }
  try { await loadPromptTemplates(); } catch(e) { console.error('loadPromptTemplates failed:', e); }
  try { await loadErrorLog(); } catch(e) { console.error('loadErrorLog failed:', e); }
  try { await loadInventory(); } catch(e) { console.error('loadInventory failed:', e); }
  try { await loadPlugins(); } catch(e) { console.error('loadPlugins failed:', e); }

  try { setupEventListeners(); } catch(e) { console.error('setupEventListeners failed:', e); }
  try { setupTabs(); } catch(e) { console.error('setupTabs failed:', e); }
  try { setupScanProgressListener(); } catch(e) { console.error('setupScanProgressListener failed:', e); }
  try { initAIPartner(); } catch(e) { console.error('initAIPartner failed:', e); }
  try { restoreRepeaterFormState(); } catch(e) { console.error('restoreRepeaterFormState failed:', e); }
});

// Listen for scan progress updates from the content script
let _scanProgressListener = null;
function setupScanProgressListener() {
  _scanProgressListener = (message, sender, sendResponse) => {
    if (message.action === 'scanProgress') {
      updateScanProgress(message.phase, message.step, message.totalSteps);
    }
    if (message.action === 'securityAnalysisReady') {
      handleSecurityAnalysisReady(message.tabId);
    }
  };
  chrome.runtime.onMessage.addListener(_scanProgressListener);
}

window.addEventListener('unload', () => {
  if (_scanProgressListener) {
    chrome.runtime.onMessage.removeListener(_scanProgressListener);
  }
});

function updateScanProgress(phase, step, totalSteps) {
  const container = document.getElementById('scanProgressContainer');
  const fill = document.getElementById('scanProgressFill');
  const label = document.getElementById('scanProgressLabel');
  if (!container || !fill || !label) return;

  const pct = Math.round((step / totalSteps) * 100);
  container.style.display = 'flex';
  fill.style.width = pct + '%';
  label.textContent = phase;

  // Hide after completion
  if (step >= totalSteps) {
    setTimeout(() => {
      container.style.display = 'none';
    }, 1500);
  }
}

// Load error log from storage
async function loadErrorLog() {
  chrome.storage.local.get(['errorLog'], (data) => {
    if (data.errorLog && Array.isArray(data.errorLog)) {
      errorLog = data.errorLog;
      updateErrorBadge();
    }
  });
}

// Setup tab navigation
function setupTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabPanes = document.querySelectorAll('.tab-pane');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabName = btn.dataset.tab;

      // Update active states
      tabBtns.forEach(b => b.classList.remove('active'));
      tabPanes.forEach(p => p.classList.remove('active'));
      const errorBtn = document.getElementById('errorIndicatorBtn');
      if (errorBtn) errorBtn.classList.remove('active');

      btn.classList.add('active');
      document.getElementById(`${tabName}-tab`).classList.add('active');

      // Update report summary when switching to Reports tab
      if (tabName === 'reports') {
        updateReportSummary();
      }

      // Display errors when switching to Errors tab (via header badge)
      if (tabName === 'errors') {
        displayErrors();
      }

      // Load plugins when switching to Plugins tab
      if (tabName === 'plugins') {
        loadPlugins();
      }

      // Load templates when switching to Templates tab
      if (tabName === 'templates') {
        loadDetectionTemplates();
      }

      // Load inventory when switching to Inventory tab
      if (tabName === 'inventory') {
        loadInventory();
      }

      // Load CVE cache stats and refresh patterns when switching to Settings tab
      if (tabName === 'settings') {
        loadCVECacheStats();
        displayPatterns();
        updatePatternStats();
      }

      // Load repeater history and restore form state when switching to Repeater tab
      if (tabName === 'repeater') {
        loadRepeaterHistory();
        restoreRepeaterFormState();
      }

      // Load HTTP history when switching to History tab
      if (tabName === 'history') {
        loadHttpHistoryState();
        loadHttpHistory();
      }
    });
  });

  // Setup security sub-tabs
  setupSecuritySubTabs();

  // Setup attack lab sub-tabs
  setupAttackLabSubTabs();

  // Setup HTTP History sub-tabs and controls
  setupHttpHistory();

  // Setup collapsible settings sections
  setupCollapsibleSections();
}

function setupCollapsibleSections() {
  document.querySelectorAll('.settings-section-toggle').forEach(toggle => {
    toggle.addEventListener('click', () => {
      const sectionId = toggle.dataset.section;
      const content = document.getElementById(`${sectionId}-content`);
      if (content) {
        toggle.classList.toggle('collapsed');
        content.classList.toggle('collapsed');
      }
    });
  });
}

function autoUnfoldFindings(container) {
  container.querySelectorAll('.finding-details').forEach(details => {
    details.style.display = 'block';
  });
  container.querySelectorAll('.toggle-details-btn').forEach(btn => {
    btn.textContent = ' Hide Details';
  });
  container.querySelectorAll('.ai-assessment-collapsible-content').forEach(content => {
    content.style.display = 'block';
  });
  container.querySelectorAll('.toggle-ai-assessment-btn').forEach(btn => {
    btn.textContent = '\u25B2 Collapse';
  });
}

function autoUnfoldInventory() {
  const inventoryTree = document.getElementById('inventoryTree');
  if (inventoryTree) {
    toggleAllTreeNodes(false);
  }
}

// Setup security sub-tab navigation
function setupSecuritySubTabs() {
  const subTabBtns = document.querySelectorAll('.security-sub-tab-btn');
  const subTabPanes = document.querySelectorAll('.security-sub-tab-pane');

  subTabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabName = btn.dataset.securityTab;

      // Update active states
      subTabBtns.forEach(b => b.classList.remove('active'));
      subTabPanes.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      document.getElementById(`security-${tabName}-tab`).classList.add('active');

      // Load data for session and auth-flows sub-tabs on click
      if (tabName === 'session') {
        getTargetTab().then((tab) => {
          if (tab) loadSessionState(tab.id);
        });
      }
      if (tabName === 'auth-flows') {
        getTargetTab().then((tab) => {
          if (tab) loadAuthFlows(tab.id);
        });
      }
      if (tabName === 'crypto') {
        getTargetTab().then((tab) => {
          if (tab) loadCryptoResults(tab.id);
        });
      }
      if (tabName === 'cloud-storage') {
        getTargetTab().then((tab) => {
          if (tab) loadCloudStorageResults(tab.id);
        });
      }
      if (tabName === 'exfiltration') {
        getTargetTab().then((tab) => {
          if (tab) loadExfiltrationResults(tab.id);
        });
      }
      if (tabName === 'websocket') {
        getTargetTab().then((tab) => {
          if (tab) loadWebSocketResults(tab.id);
        });
      }
    });
  });
}

// Setup attack lab sub-tab navigation
function setupAttackLabSubTabs() {
  const subTabBtns = document.querySelectorAll('.attack-lab-sub-tab-btn');
  const subTabPanes = document.querySelectorAll('.attack-lab-sub-tab-pane');

  subTabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabName = btn.dataset.attackTab;
      subTabBtns.forEach(b => b.classList.remove('active'));
      subTabPanes.forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(`attack-lab-${tabName}-tab`).classList.add('active');
      if (tabName === 'cookies') {
        loadCookieEditorCookies();
      }
    });
  });

  setupSQLiTab();
}

// Setup event listeners
function setupEventListeners() {
  // Findings tab
  document.getElementById('scanNowBtn').addEventListener('click', scanCurrentPage);
  document.getElementById('aiAssessAllBtn').addEventListener('click', performBulkAIAssessment);
  document.getElementById('aiPartnerBtn').addEventListener('click', () => {
    openAIPartner().catch(e => {
      console.error('openAIPartner failed:', e);
      showMessage('AI Partner error: ' + e.message, 'error');
    });
  });
  document.getElementById('searchInput').addEventListener('input', filterFindings);
  document.getElementById('exportBtn').addEventListener('click', openReportModal);
  document.getElementById('clearFindingsBtn').addEventListener('click', clearFindings);
  
  // Settings tab
  document.getElementById('saveSettingsBtn').addEventListener('click', saveSettings);
  document.getElementById('resetSettingsBtn').addEventListener('click', resetSettings);
  document.getElementById('testWebhookBtn').addEventListener('click', testWebhook);
  document.getElementById('resetAIAssessConfigBtn').addEventListener('click', resetAIAssessmentConfig);

  // AI Assessment concurrency slider
  const aiConcurrencySlider = document.getElementById('aiAssessConcurrency');
  const aiConcurrencyValue = document.getElementById('aiAssessConcurrencyValue');
  if (aiConcurrencySlider && aiConcurrencyValue) {
    aiConcurrencySlider.addEventListener('input', () => {
      aiConcurrencyValue.textContent = aiConcurrencySlider.value;
    });
  }

  // Max AI Partner Iterations slider
  const aiMaxIterSlider = document.getElementById('aiMaxIterations');
  const aiMaxIterValue = document.getElementById('aiMaxIterationsValue');
  if (aiMaxIterSlider && aiMaxIterValue) {
    aiMaxIterSlider.addEventListener('input', () => {
      aiMaxIterValue.textContent = aiMaxIterSlider.value;
    });
  }

  // MCP Bridge
  const mcpTestBtn = document.getElementById('mcpBridgeTestBtn');
  if (mcpTestBtn) {
    mcpTestBtn.addEventListener('click', () => {
      chrome.runtime.sendMessage({ action: 'getMCPStatus' }, (resp) => {
        const statusEl = document.getElementById('mcpBridgeStatus');
        if (!statusEl) return;
        if (resp && resp.connected) {
          statusEl.style.color = '#4caf50';
          statusEl.textContent = 'Status: Connected to MCP server';
        } else if (resp && resp.enabled) {
          statusEl.style.color = '#ff9800';
          statusEl.textContent = 'Status: Enabled but not connected (reconnect attempt: ' + (resp.reconnectAttempts || 0) + ')';
        } else {
          statusEl.style.color = '#888';
          statusEl.textContent = 'Status: Disabled';
        }
      });
    });
  }

  // CVE Cache Management
  document.getElementById('refreshCacheStatsBtn').addEventListener('click', loadCVECacheStats);
  document.getElementById('clearCacheBtn').addEventListener('click', clearCVECache);

  // Whitelist
  document.getElementById('addDomainBtn').addEventListener('click', addWhitelistDomain);
  document.getElementById('addPatternBtn').addEventListener('click', addWhitelistPattern);
  
  // Scan History (both settings button and sub-tab button)
  document.getElementById('clearHistoryBtn').addEventListener('click', clearHistory);
  const clearScanHistBtn = document.getElementById('clearScanHistoryBtn');
  if (clearScanHistBtn) clearScanHistBtn.addEventListener('click', clearHistory);
  document.getElementById('historySearchInput').addEventListener('input', filterHistory);
  document.getElementById('historyRiskFilter').addEventListener('change', filterHistory);

  // Errors
  document.getElementById('clearErrorsBtn').addEventListener('click', clearErrors);
  document.getElementById('exportErrorsBtn').addEventListener('click', exportErrors);

  // Error indicator in header (shows errors tab)
  const errorIndicatorBtn = document.getElementById('errorIndicatorBtn');
  if (errorIndicatorBtn) {
    errorIndicatorBtn.addEventListener('click', () => {
      const tabBtns = document.querySelectorAll('.tab-btn');
      const tabPanes = document.querySelectorAll('.tab-pane');
      tabBtns.forEach(b => b.classList.remove('active'));
      tabPanes.forEach(p => p.classList.remove('active'));
      errorIndicatorBtn.classList.add('active');
      document.getElementById('errors-tab').classList.add('active');
      displayErrors();
    });
  }

  // Report Malicious Site
  document.getElementById('reportMaliciousBtn').addEventListener('click', showReportModal);
  document.getElementById('reportMaliciousCloseBtn').addEventListener('click', closeReportModal);
  document.getElementById('reportToAllBtn').addEventListener('click', reportToAllVendors);
  document.getElementById('clearReportHistoryBtn').addEventListener('click', clearReportHistory);
  document.querySelectorAll('.report-category-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.report-category-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
    });
  });

  // Plugins
  document.getElementById('importPluginBtn').addEventListener('click', () => {
    document.getElementById('pluginFileInput').click();
  });
  document.getElementById('pluginFileInput').addEventListener('change', handlePluginImport);

  // LLM Settings
  document.getElementById('llmProvider').addEventListener('change', handleLLMProviderChange);
  document.getElementById('testLLMBtn').addEventListener('click', testLLMConnection);
  
  // API Validation Modal
  document.getElementById('modalCloseBtn').addEventListener('click', closeAPIValidationModal);
  document.getElementById('apiValidationModal').addEventListener('click', (e) => {
    // Close modal if clicking on backdrop (outside modal-content)
    if (e.target.id === 'apiValidationModal') {
      closeAPIValidationModal();
    }
  });
  
  // LLM Analysis Modal
  document.getElementById('llmModalCloseBtn').addEventListener('click', closeLLMAnalysisModal);
  document.getElementById('llmAnalysisModal').addEventListener('click', (e) => {
    if (e.target.id === 'llmAnalysisModal') {
      closeLLMAnalysisModal();
    }
  });
  document.getElementById('llmPromptSelect').addEventListener('change', (e) => {
    const customGroup = document.getElementById('customQuestionGroup');
    customGroup.style.display = e.target.value === 'custom' ? 'block' : 'none';
  });
  document.getElementById('analyzeLLMBtn').addEventListener('click', executeLLMAnalysis);
  
  // Report Generation Modal
  document.getElementById('reportModalCloseBtn').addEventListener('click', closeReportModal);
  document.getElementById('reportModal').addEventListener('click', (e) => {
    if (e.target.id === 'reportModal') {
      closeReportModal();
    }
  });
  document.getElementById('includeLLM').addEventListener('change', (e) => {
    const llmOptions = document.getElementById('llmReportOptions');
    llmOptions.style.display = e.target.checked ? 'block' : 'none';
  });
  document.getElementById('generateReportBtn').addEventListener('click', generateEnhancedReport);
  
  // Reports Tab
  document.getElementById('reportIncludeLLM').addEventListener('change', (e) => {
    const llmOptions = document.getElementById('reportLLMOptions');
    llmOptions.style.display = e.target.checked ? 'block' : 'none';
  });
  document.getElementById('generateReportMainBtn').addEventListener('click', generateReportFromTab);
  
  // Prompt Template Management
  document.getElementById('addPromptTemplateBtn').addEventListener('click', () => openPromptTemplateEditor());
  document.getElementById('promptTemplateEditorCloseBtn').addEventListener('click', closePromptTemplateEditor);
  document.getElementById('cancelPromptTemplateBtn').addEventListener('click', closePromptTemplateEditor);
  document.getElementById('savePromptTemplateBtn').addEventListener('click', savePromptTemplate);
  document.getElementById('deletePromptTemplateBtn').addEventListener('click', deleteCurrentPromptTemplate);
  document.getElementById('promptTemplateEditorModal').addEventListener('click', (e) => {
    if (e.target.id === 'promptTemplateEditorModal') {
      closePromptTemplateEditor();
    }
  });
  
  // Pattern Management
  document.getElementById('addNewPatternBtn').addEventListener('click', () => openPatternEditor());
  document.getElementById('patternSearch').addEventListener('input', filterPatterns);
  document.getElementById('patternRiskFilter').addEventListener('change', filterPatterns);
  document.getElementById('patternTypeFilter').addEventListener('change', filterPatterns);
  document.getElementById('exportPatternsBtn').addEventListener('click', exportPatterns);
  document.getElementById('importPatternsBtn').addEventListener('click', importPatterns);
  document.getElementById('resetPatternsBtn').addEventListener('click', resetPatterns);
  
  // Pattern Editor Modal
  document.getElementById('patternEditorCloseBtn').addEventListener('click', closePatternEditor);
  document.getElementById('cancelPatternBtn').addEventListener('click', closePatternEditor);
  document.getElementById('testPatternBtn').addEventListener('click', testPattern);
  document.getElementById('savePatternBtn').addEventListener('click', savePattern);
  document.getElementById('deletePatternBtn').addEventListener('click', deleteCurrentPattern);
  document.getElementById('patternEditorModal').addEventListener('click', (e) => {
    if (e.target.id === 'patternEditorModal') {
      closePatternEditor();
    }
  });

  // Inventory tab
  document.getElementById('inventoryViewToggle').addEventListener('click', toggleInventoryView);
  document.getElementById('refreshInventoryBtn').addEventListener('click', refreshInventory);
  document.getElementById('expandAllBtn').addEventListener('click', () => toggleAllTreeNodes(false));
  document.getElementById('collapseAllBtn').addEventListener('click', () => toggleAllTreeNodes(true));
  document.getElementById('inventorySearch').addEventListener('input', filterInventoryTree);
  document.getElementById('inventoryTypeFilter').addEventListener('change', filterInventoryTree);
  document.getElementById('exportInventoryBtn').addEventListener('click', exportInventory);
  document.getElementById('closeDetailPanelBtn').addEventListener('click', () => {
    document.getElementById('resourceDetailPanel').style.display = 'none';
    document.querySelectorAll('.tree-node-header.selected').forEach(el => el.classList.remove('selected'));
  });

  // Toggle sensitive files sub-setting when auto-scan is toggled
  document.getElementById('autoScanEnabled').addEventListener('change', function() {
    document.getElementById('autoScanSensitiveFiles').disabled = !this.checked;
  });

  // Repeater tab event listeners
  setupRepeaterEventListeners();
}

// Legacy function - now integrated into scanCurrentPage
// Kept for backward compatibility if needed elsewhere
async function runSecurityAnalysis() {
  console.log('Origami: Security analysis now runs automatically with Unfold button');
}

// Helper function to calculate highest severity in a findings array
function getHighestSeverity(findings) {
  if (!findings || findings.length === 0) return null;

  const severityOrder = {
    'CRITICAL': 0,
    'HIGH': 1,
    'MEDIUM': 2,
    'LOW': 3,
    'INFO': 4,
    'NONE': 5
  };

  let highestSev = 'INFO';
  let highestScore = severityOrder['INFO'] !== undefined ? severityOrder['INFO'] : 4;

  findings.forEach(finding => {
    const sev = (finding.severityOverride?.overriddenSeverity || finding.aiAssessment?.suggestedSeverity || finding.severity || 'INFO').toUpperCase();
    const score = severityOrder[sev] !== undefined ? severityOrder[sev] : 4;

    if (score < highestScore) {
      highestScore = score;
      highestSev = sev;
    }
  });

  return highestSev;
}

// Update severity badge on sub-tab
function updateSubTabBadge(category, severity, count) {
  const badge = document.getElementById(`${category}-severity-badge`);
  if (!badge) return;

  if (severity && count > 0) {
    badge.textContent = count;
    badge.className = 'sub-tab-badge ' + severity.toLowerCase();
    badge.style.display = 'inline-flex';
  } else {
    badge.style.display = 'none';
  }
}

function updateInventoryBadge() {
  const badge = document.getElementById('inventory-count-badge');
  if (!badge) return;
  const resources = currentInventory?.resources;
  const count = resources ? Object.keys(resources).length : 0;
  if (count > 0) {
    badge.textContent = count;
    badge.style.display = 'inline-flex';
  } else {
    badge.style.display = 'none';
  }
}

function deduplicateSensitiveFiles(findings) {
  if (!findings || findings.length === 0) return [];

  const grouped = {};
  for (const finding of findings) {
    const key = finding.check || finding.message || 'unknown';
    if (!grouped[key]) {
      grouped[key] = [];
    }
    grouped[key].push(finding);
  }

  const deduplicated = [];
  for (const [key, group] of Object.entries(grouped)) {
    if (group.length === 1) {
      deduplicated.push(group[0]);
      continue;
    }

    const severityScore = {
      'CRITICAL': 1000,
      'HIGH': 100,
      'MEDIUM': 10,
      'LOW': 1,
      'INFO': 0,
      'NONE': -1
    };

    let best = group[0];
    for (const item of group) {
      const itemScore = severityScore[(item.severity || 'INFO').toUpperCase()] || 0;
      const bestScore = severityScore[(best.severity || 'INFO').toUpperCase()] || 0;
      if (itemScore > bestScore) {
        best = item;
      }
    }

    const paths = group.map(f => f.path || f.url || '').filter(Boolean);
    const merged = { ...best };
    if (paths.length > 1) {
      merged.message = (merged.message || merged.check || key) + ' (' + paths.join(', ') + ')';
    }
    deduplicated.push(merged);
  }

  return deduplicated;
}

// Display Security Results
function displaySecurityResults(results) {
  console.log('Origami: displaySecurityResults called with:', results);

  // Remove loading overlay and restore sub-tab structure
  const securityTab = document.getElementById('security-tab');
  if (securityTab) {
    const overlay = securityTab.querySelector('.security-loading-overlay');
    if (overlay) overlay.remove();
    const nav = securityTab.querySelector('.security-sub-tabs');
    const content = securityTab.querySelector('.security-sub-tab-content');
    if (nav) nav.style.display = '';
    if (content) content.style.display = '';
  }

  // Store findings for LLM analysis - Use a more robust approach
  if (!window.currentSecurityFindings) {
    window.currentSecurityFindings = {};
  }

  // Sort findings by severity (DESCENDING: CRITICAL first, INFO last)
  const sortBySeverity = (findings) => {
    const sorted = [...findings].sort((a, b) => {
      // Assign priority scores: higher number = higher severity = should appear first
      const severityScore = {
        'CRITICAL': 1000,
        'HIGH': 100,
        'MEDIUM': 10,
        'LOW': 1,
        'INFO': 0,
        'NONE': -1
      };

      const sevA = (a.severityOverride?.overriddenSeverity || a.aiAssessment?.suggestedSeverity || a.severity || 'INFO').toUpperCase();
      const sevB = (b.severityOverride?.overriddenSeverity || b.aiAssessment?.suggestedSeverity || b.severity || 'INFO').toUpperCase();

      const scoreA = severityScore[sevA] !== undefined ? severityScore[sevA] : 0;
      const scoreB = severityScore[sevB] !== undefined ? severityScore[sevB] : 0;

      // DESCENDING sort: higher score first
      return scoreB - scoreA;
    });
    console.log('Origami Security: Sorted:', sorted.map(f => ({ severity: f.severity, check: f.check })));
    return sorted;
  };

  const sortedHeaders = results.headers ? sortBySeverity(results.headers.filter(f => !f.error)) : [];
  const sortedCookies = results.cookies ? sortBySeverity(results.cookies.filter(f => !f.error)) : [];
  const sortedVulnerabilities = results.vulnerabilities ? sortBySeverity(results.vulnerabilities.filter(f => !f.error)) : [];
  const filteredSensitiveFiles = results.sensitiveFiles
    ? results.sensitiveFiles.filter(f => !f.error)
    : [];
  const sortedSensitiveFiles = sortBySeverity(deduplicateSensitiveFiles(filteredSensitiveFiles));

  // Keep full results for AI assessment and report generation
  window.currentSecurityFindings.headers = sortedHeaders;
  window.currentSecurityFindings.cookies = sortedCookies;
  window.currentSecurityFindings.vulnerabilities = sortedVulnerabilities;
  window.currentSecurityFindings.sensitiveFiles = sortedSensitiveFiles;

  // Filter for display: only show actionable findings (not OK/INFO)
  const isActionable = f => {
    if (f.error) return false;
    const effSev = (f.severityOverride?.overriddenSeverity || f.aiAssessment?.suggestedSeverity || f.risk || f.severity || 'INFO').toUpperCase();
    return effSev !== 'INFO' && effSev !== 'NONE' && effSev !== 'OK';
  };
  const displayHeaders = sortedHeaders.filter(isActionable);
  const displayCookies = sortedCookies.filter(isActionable);

  console.log('Origami: window.currentSecurityFindings set to:', window.currentSecurityFindings);
  console.log('Origami: Total security findings stored:',
    (window.currentSecurityFindings.headers?.length || 0) +
    (window.currentSecurityFindings.cookies?.length || 0) +
    (window.currentSecurityFindings.vulnerabilities?.length || 0) +
    (window.currentSecurityFindings.sensitiveFiles?.length || 0)
  );

  // Update badges on sub-tabs (using filtered counts for headers/cookies)
  updateSubTabBadge('headers', getHighestSeverity(displayHeaders), displayHeaders.length);
  updateSubTabBadge('cookies', getHighestSeverity(displayCookies), displayCookies.length);
  updateSubTabBadge('vulnerabilities', getHighestSeverity(sortedVulnerabilities), sortedVulnerabilities.length);

  // Headers Sub-Tab
  const headersContainer = document.getElementById('headersResults');
  if (displayHeaders.length > 0) {
    let headersHtml = '<div class="security-analysis-results">';

    // Summary for headers (use display-filtered findings for accurate counts)
    const headersSummary = getSummary({ headers: displayHeaders });
    headersHtml += '<div class="security-summary">';
    headersHtml += `<div class="summary-card"><div class="summary-label">Critical</div><div class="summary-value" style="color: var(--critical-color);">${headersSummary.critical}</div></div>`;
    headersHtml += `<div class="summary-card"><div class="summary-label">High</div><div class="summary-value" style="color: var(--high-color);">${headersSummary.high}</div></div>`;
    headersHtml += `<div class="summary-card"><div class="summary-label">Medium</div><div class="summary-value" style="color: var(--medium-color);">${headersSummary.medium}</div></div>`;
    headersHtml += `<div class="summary-card"><div class="summary-label">Low</div><div class="summary-value" style="color: var(--medium-color);">${headersSummary.low}</div></div>`;
    headersHtml += '</div>';

    headersHtml += '<div class="security-items">';
    displayHeaders.forEach((finding) => {
      const catIndex = sortedHeaders.indexOf(finding);
      headersHtml += renderSecurityItem(finding, 'headers', catIndex);
    });
    headersHtml += '</div></div>';
    headersContainer.innerHTML = headersHtml;
  } else {
    headersContainer.innerHTML = `
      <div class="empty-state">
        <p>✓ No security header issues found</p>
        <p class="empty-hint">All security headers are properly configured</p>
      </div>
    `;
  }

  // Cookies Sub-Tab
  const cookiesContainer = document.getElementById('cookiesResults');
  if (displayCookies.length > 0) {
    let cookiesHtml = '<div class="security-analysis-results">';

    // Summary for cookies (use display-filtered findings for accurate counts)
    const cookiesSummary = getSummary({ cookies: displayCookies });
    cookiesHtml += '<div class="security-summary">';
    cookiesHtml += `<div class="summary-card"><div class="summary-label">Critical</div><div class="summary-value" style="color: var(--critical-color);">${cookiesSummary.critical}</div></div>`;
    cookiesHtml += `<div class="summary-card"><div class="summary-label">High</div><div class="summary-value" style="color: var(--high-color);">${cookiesSummary.high}</div></div>`;
    cookiesHtml += `<div class="summary-card"><div class="summary-label">Medium</div><div class="summary-value" style="color: var(--medium-color);">${cookiesSummary.medium}</div></div>`;
    cookiesHtml += `<div class="summary-card"><div class="summary-label">Low</div><div class="summary-value" style="color: var(--medium-color);">${cookiesSummary.low}</div></div>`;
    cookiesHtml += '</div>';

    cookiesHtml += '<div class="security-items">';
    displayCookies.forEach((finding) => {
      const catIndex = sortedCookies.indexOf(finding);
      cookiesHtml += renderSecurityItem(finding, 'cookies', catIndex);
    });
    cookiesHtml += '</div></div>';
    cookiesContainer.innerHTML = cookiesHtml;
  } else {
    cookiesContainer.innerHTML = `
      <div class="empty-state">
        <p>✓ No cookie security issues found</p>
        <p class="empty-hint">All cookies have proper security flags</p>
      </div>
    `;
  }

  // Vulnerabilities Sub-Tab
  const vulnContainer = document.getElementById('vulnerabilitiesResults');
  if (sortedVulnerabilities.length > 0) {
    let vulnHtml = '<div class="security-analysis-results">';

    // Summary for vulnerabilities
    const vulnSummary = getSummary({ vulnerabilities: sortedVulnerabilities });
    vulnHtml += '<div class="security-summary">';
    vulnHtml += `<div class="summary-card"><div class="summary-label">Critical</div><div class="summary-value" style="color: var(--critical-color);">${vulnSummary.critical}</div></div>`;
    vulnHtml += `<div class="summary-card"><div class="summary-label">High</div><div class="summary-value" style="color: var(--high-color);">${vulnSummary.high}</div></div>`;
    vulnHtml += `<div class="summary-card"><div class="summary-label">Medium</div><div class="summary-value" style="color: var(--medium-color);">${vulnSummary.medium}</div></div>`;
    vulnHtml += `<div class="summary-card"><div class="summary-label">Low</div><div class="summary-value" style="color: var(--medium-color);">${vulnSummary.low}</div></div>`;
    vulnHtml += '</div>';

    vulnHtml += '<div class="security-items">';
    sortedVulnerabilities.forEach((finding, index) => {
      vulnHtml += renderSecurityItem(finding, 'vulnerabilities', index);
    });
    vulnHtml += '</div></div>';
    vulnContainer.innerHTML = vulnHtml;
  } else {
    vulnContainer.innerHTML = `
      <div class="empty-state">
        <p>✓ No vulnerabilities detected</p>
        <p class="empty-hint">No common vulnerabilities found in JavaScript code</p>
      </div>
    `;
  }

  // SCA Sub-Tab - Move technology stack here
  const scaContainer = document.getElementById('scaResults');
  if (results.technologies) {
    // First render technologies
    scaContainer.innerHTML = renderTechStack(results.technologies);

    // Then check for CVEs and EOL (async)
    checkAndDisplayCVEs(results.technologies, scaContainer);
  } else {
    scaContainer.innerHTML = `
      <div class="empty-state">
        <p>No technologies detected</p>
        <p class="empty-hint">Unable to fingerprint frameworks or libraries</p>
      </div>
    `;
  }

  // Exposed Files Sub-Tab
  const exposedFilesContainer = document.getElementById('exposedFilesResults');
  if (sortedSensitiveFiles.length > 0) {
    let filesHtml = '<div class="security-analysis-results">';

    const filesSummary = getSummary({ sensitiveFiles: sortedSensitiveFiles });
    filesHtml += '<div class="security-summary">';
    filesHtml += `<div class="summary-card"><div class="summary-label">Critical</div><div class="summary-value" style="color: var(--critical-color);">${filesSummary.critical}</div></div>`;
    filesHtml += `<div class="summary-card"><div class="summary-label">High</div><div class="summary-value" style="color: var(--high-color);">${filesSummary.high}</div></div>`;
    filesHtml += `<div class="summary-card"><div class="summary-label">Medium</div><div class="summary-value" style="color: var(--medium-color);">${filesSummary.medium}</div></div>`;
    filesHtml += `<div class="summary-card"><div class="summary-label">Low</div><div class="summary-value" style="color: var(--medium-color);">${filesSummary.low}</div></div>`;
    filesHtml += '</div>';

    filesHtml += '<div class="security-items">';
    sortedSensitiveFiles.forEach((finding, index) => {
      filesHtml += renderSecurityItem(finding, 'sensitiveFiles', index);
    });
    filesHtml += '</div></div>';
    exposedFilesContainer.innerHTML = filesHtml;

    const highestSev = getHighestSeverity(sortedSensitiveFiles);
    updateSubTabBadge('exposed-files', highestSev, sortedSensitiveFiles.length);
  } else {
    exposedFilesContainer.innerHTML = `
      <div class="empty-state">
        <p>No exposed files detected</p>
        <p class="empty-hint">No .git, .env, backup files, or source maps found</p>
      </div>
    `;
  }

  // Session Sub-Tab - render session state if available
  if (results.sessionState) {
    renderSessionState(results.sessionState);
  }

  // Auth Flows Sub-Tab - render OAuth/SAML flows if available
  if (results.oauthFlows) {
    renderAuthFlows(results.oauthFlows);
  }

  // Re-attach event listeners for all containers
  attachSecurityEventListeners(headersContainer);
  attachSecurityEventListeners(cookiesContainer);
  attachSecurityEventListeners(vulnContainer);
  attachSecurityEventListeners(exposedFilesContainer);

  updateScoreDashboard();
}

// Attach event listeners to security findings
function attachSecurityEventListeners(container) {
  if (!container) return;
  
  // Add event listeners for AI Assessment buttons
  container.querySelectorAll('.ai-assess-security-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const category = btn.dataset.findingCategory;
      const categoryIndex = parseInt(btn.dataset.findingIndex);
      if (!btn.disabled) {
        await performInlineAIAssessment(categoryIndex, 'security', false, category);
      }
    });
  });

  // Add refresh AI button listeners for security findings
  container.querySelectorAll('.refresh-ai-security-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const category = btn.dataset.findingCategory;
      const categoryIndex = parseInt(btn.dataset.findingIndex);
      await performInlineAIAssessment(categoryIndex, 'security', true, category);
    });
  });

  // Add event listeners for toggle details buttons
  container.querySelectorAll('.toggle-security-details-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const category = btn.dataset.findingCategory;
      const categoryIndex = parseInt(btn.dataset.findingIndex);
      const detailsDiv = document.getElementById(`security-details-${category}-${categoryIndex}`);
      if (detailsDiv) {
        if (detailsDiv.style.display === 'none') {
          detailsDiv.style.display = 'block';
          btn.textContent = ' Hide Details';
        } else {
          detailsDiv.style.display = 'none';
          btn.innerHTML = `${origamiIcon('clipboard')} Details`;
        }
      } else {
        btn.title = 'Details unavailable';
        btn.disabled = true;
      }
    });
  });

  // Severity override listeners for security findings
  container.querySelectorAll('.severity-override-select.security-override').forEach(select => {
    select.addEventListener('change', async (e) => {
      const category = e.target.dataset.findingCategory;
      const categoryIndex = parseInt(e.target.dataset.findingIndex);
      const newSeverity = e.target.value;

      if (newSeverity) {
        await handleSeverityOverride(categoryIndex, newSeverity, 'security', category);
        e.target.value = ''; // Reset dropdown
      }
    });
  });

  // Toggle AI assessment collapse/expand for security findings
  container.querySelectorAll('.toggle-ai-assessment-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation(); // Prevent header click from bubbling
      const category = btn.dataset.findingCategory;
      const categoryIndex = parseInt(btn.dataset.findingIndex);
      const type = btn.dataset.findingType;
      const contentDiv = type === 'secret'
        ? document.getElementById(`ai-assessment-content-${categoryIndex}`)
        : document.getElementById(`ai-assessment-content-security-${category}-${categoryIndex}`);

      if (contentDiv) {
        if (contentDiv.style.display === 'none') {
          contentDiv.style.display = 'block';
          btn.textContent = '▲ Collapse';
        } else {
          contentDiv.style.display = 'none';
          btn.textContent = '▼ Expand';
        }
      }
    });
  });

  // Toggle AI assessment by clicking header (alternative to button) for security findings
  container.querySelectorAll('.ai-assessment-header-collapsible').forEach(header => {
    header.addEventListener('click', (e) => {
      // Only trigger if not clicking the button itself
      if (!e.target.classList.contains('toggle-ai-assessment-btn')) {
        const btn = header.querySelector('.toggle-ai-assessment-btn');
        if (btn) btn.click();
      }
    });
  });
}

// Render single security item
function renderSecurityItem(item, category, categoryIndex) {
  const severity = (item.severity || 'info').toLowerCase();
  const llmEnabled = currentSettings?.llm?.enabled && currentSettings.llm.provider !== 'none';
  
  // Build severity display - show original, AI-assessed, and overridden if available
  const aiSeverity = item.aiAssessment?.suggestedSeverity;
  const hasAIAssessment = !!item.aiAssessment;
  const overriddenSeverity = item.severityOverride?.overriddenSeverity;
  const effectiveSeverity = (overriddenSeverity || item.aiAssessment?.suggestedSeverity || item.severity || 'info').toLowerCase();

  let severityBadges;
  if (overriddenSeverity) {
    // Show original (strikethrough) -> overridden
    const overriddenLower = overriddenSeverity.toLowerCase();
    severityBadges = `
      <span class="security-badge ${severity} severity-overridden" title="Original severity (overridden)" style="text-decoration: line-through; opacity: 0.6;">
        ${severity.toUpperCase()}
      </span>
      <span class="finding-risk-arrow">→</span>
      <span class="security-badge ${overriddenLower} severity-override-badge" title="Overridden by user on ${new Date(item.severityOverride.timestamp).toLocaleString()}">
        ${overriddenSeverity === 'NONE' ? 'FALSE POSITIVE' : overriddenSeverity} ${origamiIcon('wrench')}
      </span>
      <select class="severity-override-select security-override" data-finding-category="${category}" data-finding-index="${categoryIndex}" title="Override severity">
        <option value=""> Override...</option>
        <option value="NONE">False Positive</option>
        <option value="INFO">Info</option>
        <option value="LOW">Low</option>
        <option value="MEDIUM">Medium</option>
        <option value="HIGH">High</option>
        <option value="CRITICAL">Critical</option>
      </select>`;
  } else if (aiSeverity) {
    // Show original -> AI-assessed with specific severity
    const aiSeverityLower = aiSeverity.toLowerCase();
    severityBadges = `
      <span class="security-badge ${severity}" title="Original severity">
        ${severity.toUpperCase()}
      </span>
      <span class="finding-risk-arrow">→</span>
      <span class="security-badge ${aiSeverityLower} ai-severity" title="AI-assessed severity: ${item.aiAssessment.severityReasoning ? escapeHtml(item.aiAssessment.severityReasoning.substring(0, 100)) + '...' : 'AI recommendation'}">
        ${aiSeverity} ${origamiIcon('sparkles')}
      </span>
      <select class="severity-override-select security-override" data-finding-category="${category}" data-finding-index="${categoryIndex}" title="Override severity">
        <option value=""> Override...</option>
        <option value="NONE">False Positive</option>
        <option value="INFO">Info</option>
        <option value="LOW">Low</option>
        <option value="MEDIUM">Medium</option>
        <option value="HIGH">High</option>
        <option value="CRITICAL">Critical</option>
      </select>`;
  } else if (hasAIAssessment) {
    // Show AI assessed indicator even without specific severity recommendation
    severityBadges = `
      <span class="security-badge ${severity}" title="Original severity">
        ${severity.toUpperCase()}
      </span>
      <span class="ai-assessed-badge" title="AI assessed on ${new Date(item.aiAssessment.timestamp).toLocaleString()}" style="margin-left: 6px; font-size: 12px; opacity: 0.8;">
        ${origamiIcon('sparkles')}
      </span>
      <select class="severity-override-select security-override" data-finding-category="${category}" data-finding-index="${categoryIndex}" title="Override severity">
        <option value=""> Override...</option>
        <option value="NONE">False Positive</option>
        <option value="INFO">Info</option>
        <option value="LOW">Low</option>
        <option value="MEDIUM">Medium</option>
        <option value="HIGH">High</option>
        <option value="CRITICAL">Critical</option>
      </select>`;
  } else {
    // Show original only + override dropdown
    severityBadges = `
      <span class="security-badge ${severity}">
        ${severity.toUpperCase()}
      </span>
      <select class="severity-override-select security-override" data-finding-category="${category}" data-finding-index="${categoryIndex}" title="Override severity">
        <option value=""> Override...</option>
        <option value="NONE">False Positive</option>
        <option value="INFO">Info</option>
        <option value="LOW">Low</option>
        <option value="MEDIUM">Medium</option>
        <option value="HIGH">High</option>
        <option value="CRITICAL">Critical</option>
      </select>`;
  }

  let html = `<div class="security-item ${effectiveSeverity}" data-finding-category="${category}" data-finding-index="${categoryIndex}">`;
  html += '<div class="security-item-header">';
  html += `<div class="security-item-title">${escapeHtml(item.check)}</div>`;
  html += '<div class="security-item-actions">';
  html += severityBadges;

  if (llmEnabled && severity !== 'info') {
    html += `<button class="btn btn-primary btn-sm ai-assess-security-btn ${hasAIAssessment ? 'has-assessment' : ''}"
            data-finding-category="${category}" data-finding-index="${categoryIndex}"
            title="${hasAIAssessment ? 'View/Update AI Assessment' : 'Get AI Assessment'}">
      ${hasAIAssessment ? `${origamiIcon('sparkles')} AI Analysis` : `${origamiIcon('sparkles')} AI Assess`}
    </button>`;
  } else if (!llmEnabled && severity !== 'info') {
    html += `<button class="btn btn-secondary btn-sm ai-assess-security-btn" disabled
            title="Configure LLM in Settings to enable AI assessment">
      ${origamiIcon('sparkles')} AI Assess
    </button>`;
  }

  // Always show Details button for consistency
  html += `<button class="btn btn-secondary btn-sm toggle-security-details-btn" data-finding-category="${category}" data-finding-index="${categoryIndex}">
    ${origamiIcon('clipboard')} Details
  </button>`;
  
  html += '</div>';
  html += '</div>';
  html += `<div class="security-item-message">${escapeHtml(item.message)}</div>`;
  
  if (item.recommendation) {
    html += `<div class="security-item-recommendation">${origamiIcon('lightbulb')} ${escapeHtml(item.recommendation)}</div>`;
  }
  
  // Always show details section for consistency
  html += `<div class="security-details" id="security-details-${category}-${categoryIndex}" style="display: none;">`;
  
  // Basic information section - always shown
  html += '<div class="detail-section">';
  html += `<strong>Check:</strong> ${escapeHtml(item.check || 'Unknown')}`;
  html += `<br><strong>Severity:</strong> <span class="security-badge ${severity}">${severity.toUpperCase()}</span>`;
  if (item.status) html += `<br><strong>Status:</strong> ${escapeHtml(item.status)}`;
  if (item.source) html += `<br><strong>Source:</strong> ${escapeHtml(item.source)}`;
  if (item.timestamp) html += `<br><strong>Detected:</strong> ${new Date(item.timestamp).toLocaleString()}`;
  html += '</div>';
  
  // Message section
  if (item.message) {
    html += '<div class="detail-section">';
    html += '<strong>Details:</strong>';
    html += `<p>${escapeHtml(item.message)}</p>`;
    html += '</div>';
  }
  
  // Recommendation section
  if (item.recommendation) {
    html += '<div class="detail-section">';
    html += '<strong>Recommendation:</strong>';
    html += `<p>${origamiIcon('lightbulb')} ${escapeHtml(item.recommendation)}</p>`;
    html += '</div>';
  }
  
  // Code context section (if available)
  if (item.codeContext) {
    html += '<div class="detail-section">';
    html += '<strong>Code Context:</strong>';
    if (item.lineNumber) html += ` <em>(Line ${item.lineNumber})</em>`;
    html += `<pre class="code-context"><code>${highlightMatchInContext(item.codeContext, item.matchedText)}</code></pre>`;
    html += '</div>';
  }
  
  // Matched pattern/text section (if available)
  if (item.matchedText) {
    html += '<div class="detail-section">';
    html += '<strong>Matched Pattern:</strong>';
    html += `<pre class="matched-text"><code>${escapeHtml(item.matchedText)}</code></pre>`;
    html += '</div>';
  }
  
  // URI/Location section (if available)
  if (item.uri) {
    html += '<div class="detail-section">';
    html += `<strong>Location:</strong> <code>${escapeHtml(item.uri)}</code>`;
    html += '</div>';
  }
  
  // Additional fields that might exist
  if (item.value) {
    html += '<div class="detail-section">';
    html += `<strong>Value:</strong> <code>${escapeHtml(item.value)}</code>`;
    html += '</div>';
  }
  
  if (item.currentValue) {
    html += '<div class="detail-section">';
    html += `<strong>Current Value:</strong> <code>${escapeHtml(item.currentValue)}</code>`;
    html += '</div>';
  }
  
  if (item.expectedValue) {
    html += '<div class="detail-section">';
    html += `<strong>Expected Value:</strong> <code>${escapeHtml(item.expectedValue)}</code>`;
    html += '</div>';
  }

  // Sensitive file-specific detail sections
  if (item.details?.path) {
    html += '<div class="detail-section">';
    html += `<strong>Path:</strong> <code>${escapeHtml(item.details.path)}</code>`;
    html += '</div>';
  }

  if (item.details?.url) {
    html += '<div class="detail-section">';
    html += `<strong>URL:</strong> <code>${escapeHtml(item.details.url)}</code>`;
    html += '</div>';
  }

  if (item.details?.validation) {
    html += '<div class="detail-section">';
    html += `<strong>Validation:</strong> ${escapeHtml(item.details.validation)}`;
    html += '</div>';
  }

  if (item.details?.responsePreview) {
    html += '<div class="detail-section">';
    html += '<strong>Response Preview:</strong>';
    html += `<pre class="code-context"><code>${escapeHtml(item.details.responsePreview)}</code></pre>`;
    html += '</div>';
  }

  html += '</div>';

  // AI Assessment Section - Always create this, not just when hasDetails is true
  html += `<div class="ai-assessment-section" id="ai-assessment-security-${category}-${categoryIndex}">`;
  if (item.aiAssessment) {
    html += `
      <div class="ai-assessment-result">
        <div class="ai-assessment-header-collapsible" style="cursor: pointer; display: flex; justify-content: space-between; align-items: center; padding: 8px 0;">
          <div>
            <strong>${origamiIcon('sparkles')} AI Security Assessment</strong>
            <span class="ai-timestamp" style="margin-left: 8px; font-size: 11px; color: var(--text-secondary);">${new Date(item.aiAssessment.timestamp).toLocaleString()}</span>
          </div>
          <button class="btn btn-secondary btn-sm toggle-ai-assessment-btn" data-finding-category="${category}" data-finding-index="${categoryIndex}" data-finding-type="security" style="padding: 2px 8px; font-size: 12px;">
            ▼ Expand
          </button>
        </div>
        <div class="ai-assessment-collapsible-content" id="ai-assessment-content-security-${category}-${categoryIndex}" style="display: none;">
          <div class="ai-assessment-content">${formatAIAssessment(item.aiAssessment.analysis)}</div>
          <div class="ai-assessment-actions">
            <button class="btn btn-secondary btn-sm refresh-ai-security-btn" data-finding-category="${category}" data-finding-index="${categoryIndex}">
              ${origamiIcon('refresh')} Refresh Analysis
            </button>
          </div>
        </div>
      </div>`;
  }
  html += '</div>';
  
  html += '</div>';
  
  return html;
}

// Check and display CVEs for detected technologies
async function checkAndDisplayCVEs(technologies, container) {
  // Check if CVE checking is disabled
  if (currentSettings.cve_checking?.enabled === false) {
    console.log('CVE checking is disabled in settings');
    return;
  }

  // Cancellation token: the last call to start always wins.
  // If a newer call overwrites the token before this one resolves, we discard
  // our results instead of inserting a duplicate section.
  const callToken = Date.now() + Math.random();
  container._cveCheckToken = callToken;

  try {
    // Show loading indicator
    const loadingDiv = document.createElement('div');
    loadingDiv.className = 'cve-loading';
    loadingDiv.innerHTML = `
      <div class="security-section" style="margin-top: 16px;">
        <div class="security-section-header">
          <div class="security-section-title">${origamiIcon('search')} Checking for CVEs...</div>
        </div>
      </div>
    `;
    container.appendChild(loadingDiv);

    // Wrap sendMessage in a Promise with timeout
    const checkCVEsWithTimeout = new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('CVE check timed out after 10 seconds'));
      }, 10000); // 10 second timeout

      chrome.runtime.sendMessage(
        { action: 'checkCVEs', technologies: technologies },
        (response) => {
          clearTimeout(timeout);
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
          } else {
            resolve(response);
          }
        }
      );
    });

    // Wait for response or timeout
    const response = await checkCVEsWithTimeout;

    // Remove loading indicator
    if (loadingDiv && loadingDiv.parentNode) {
      loadingDiv.remove();
    }

    // A newer call has started — discard results to prevent duplicate sections.
    if (container._cveCheckToken !== callToken) return;

    if (response && response.vulnerabilities && Object.keys(response.vulnerabilities).length > 0) {
      // Store vulnerabilities globally for AI assessment access
      window.currentTechVulnerabilities = response.vulnerabilities;

      // Update technologies in securityResults with CVE data for score recalculation
      if (securityResults && securityResults.technologies) {
        securityResults.technologies = response.vulnerabilities;
      }
      updateScoreDashboard();

      // Remove any stale CVE section from a prior call before inserting fresh results.
      container.querySelectorAll('.cve-section, .cve-success').forEach(el => el.remove());

      // Prepend vulnerabilities section to container
      const vulnHtml = renderVulnerabilitiesSection(response.vulnerabilities);
      container.insertAdjacentHTML('afterbegin', vulnHtml);

      // Restore any cached SCA AI assessments
      setTimeout(() => restoreSCAAIAssessments(), 100);

      // Update tech stack to show badges
      const techStackHtml = renderTechStackWithCVEs(technologies, response.vulnerabilities);
      // Replace the existing tech stack section
      const techSection = container.querySelector('.security-section:last-child');
      if (techSection) {
        techSection.outerHTML = techStackHtml;
      }

      // Attach CVE event listeners
      attachCVEEventListeners(container);

      // Update SCA sub-tab badge with vulnerability count
      const totalVulns = Object.values(response.vulnerabilities).reduce((sum, techs) => {
        return sum + techs.reduce((s, tech) => s + (tech.vulnerabilities?.length || 0), 0);
      }, 0);
      if (totalVulns > 0) {
        const highestScaSev = Object.values(response.vulnerabilities).reduce((highest, techs) => {
          techs.forEach(tech => {
            (tech.vulnerabilities || []).forEach(v => {
              const sev = (v.severity || 'INFO').toUpperCase();
              const order = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0 };
              if ((order[sev] || 0) > (order[highest] || 0)) highest = sev;
            });
          });
          return highest;
        }, 'INFO');
        updateSubTabBadge('sca', highestScaSev, totalVulns);
      }
    } else if (response && response.error) {
      // Show error message to user
      showCVEError(container, response.error, technologies);
    } else {
      // No vulnerabilities found - show success message
      container.querySelectorAll('.cve-section, .cve-success').forEach(el => el.remove());
      const successDiv = document.createElement('div');
      successDiv.className = 'cve-success';
      successDiv.innerHTML = `
        <div class="security-section" style="margin-top: 16px; border-left: 3px solid var(--success-color, #28a745);">
          <div class="security-section-header">
            <div class="security-section-title">${origamiIcon('checkCircle')} No known vulnerabilities found</div>
          </div>
        </div>
      `;
      container.insertAdjacentElement('afterbegin', successDiv);
    }
  } catch (error) {
    console.error('Error checking CVEs:', error);
    // Remove loading indicator if still present
    const loadingDiv = container.querySelector('.cve-loading');
    if (loadingDiv && loadingDiv.parentNode) {
      loadingDiv.remove();
    }
    // Only show error if this call is still the active one
    if (container._cveCheckToken === callToken) {
      showCVEError(container, error.message, technologies);
    }
  }
}

// Show CVE error message with retry button
function showCVEError(container, errorMessage, technologies) {
  const errorDiv = document.createElement('div');
  errorDiv.className = 'cve-error';
  errorDiv.innerHTML = `
    <div class="security-section" style="margin-top: 16px; border-left: 3px solid var(--high-color, #fd7e14);">
      <div class="security-section-header">
        <div class="security-section-title">${origamiIcon('warning')} CVE check failed</div>
      </div>
      <div class="security-section-content" style="padding: 12px;">
        <p style="margin: 0 0 8px 0; color: var(--text-secondary); font-size: 12px;">
          ${escapeHtml(errorMessage)}
        </p>
        <p style="margin: 0 0 12px 0; color: var(--text-secondary); font-size: 11px;">
          This could be due to network issues or API unavailability. Please check your internet connection.
        </p>
        <button id="retryCVECheckBtn" class="btn btn-secondary" style="font-size: 12px; padding: 6px 12px;">
          ${origamiIcon('refresh')} Retry CVE Check
        </button>
      </div>
    </div>
  `;
  container.insertAdjacentElement('afterbegin', errorDiv);

  // Add retry button click handler
  document.getElementById('retryCVECheckBtn').addEventListener('click', () => {
    errorDiv.remove();
    checkAndDisplayCVEs(technologies, container);
  });
}

// Build a tooltip string for EOL badge hover
function buildEolTooltip(eolStatus) {
  const parts = [];

  if (eolStatus.status === 'EOL') {
    parts.push('End of Life');
  } else if (eolStatus.status === 'ENDING_SOON') {
    parts.push('Support ending within 3 months');
  } else if (eolStatus.status === 'ENDING_SOON_6MO') {
    parts.push('Support ending within 6 months');
  } else {
    parts.push('Supported');
  }

  if (typeof eolStatus.eolDate === 'boolean') {
    parts.push(eolStatus.eolDate ? 'Security support: Ended' : 'Security support: Active');
  } else if (eolStatus.eolDate) {
    parts.push(`EOL date: ${eolStatus.eolDate}`);
  }

  if (eolStatus.supportDate) {
    parts.push(`Active support: ${eolStatus.activeSupportEnded ? 'Ended' : eolStatus.supportDate}`);
  }

  if (eolStatus.supportStatus === 'security_only') {
    parts.push('Security updates only');
  } else if (eolStatus.supportStatus === 'extended_only') {
    parts.push('Extended support only');
  }

  if (eolStatus.lts) {
    parts.push('LTS release');
  }

  if (eolStatus.latestVersion) {
    parts.push(`Latest: ${eolStatus.latestVersion}`);
  }

  return parts.join(' | ');
}

// Render vulnerabilities section (top of SCA tab)
function renderVulnerabilitiesSection(vulnerabilities) {
  // Defensive dedup: remove duplicate (name, version) within each category
  for (const category of Object.keys(vulnerabilities)) {
    if (category.startsWith('_') || !Array.isArray(vulnerabilities[category])) continue;
    const seen = new Set();
    vulnerabilities[category] = vulnerabilities[category].filter(tech => {
      const key = `${tech.name}|${tech.version || ''}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  // Get severity filter settings
  const severityFilter = currentSettings.cve_checking?.severity_filter || 'all';
  const showEol = currentSettings.cve_checking?.show_eol_warnings !== false;

  // Check if LLM is enabled for AI Assess buttons
  const llmEnabled = currentSettings?.llm?.enabled && currentSettings.llm.provider !== 'none';

  // Helper function to check if a severity passes the filter
  const shouldShowSeverity = (severity) => {
    if (severityFilter === 'all') return true;
    if (severityFilter === 'critical_high') return ['CRITICAL', 'HIGH'].includes(severity);
    if (severityFilter === 'critical') return severity === 'CRITICAL';
    return true; // Default to showing all
  };

  // Count vulnerabilities by severity (only count those that pass filter)
  let criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;
  let totalVulns = 0;
  let eolCount = 0;
  let endingSoonCount = 0;
  let endingSoon6moCount = 0;

  Object.values(vulnerabilities).forEach(techArray => {
    techArray.forEach(tech => {
      if (tech.vulnerabilities) {
        tech.vulnerabilities.forEach(vuln => {
          if (shouldShowSeverity(vuln.severity)) {
            totalVulns++;
            if (vuln.severity === 'CRITICAL') criticalCount++;
            else if (vuln.severity === 'HIGH') highCount++;
            else if (vuln.severity === 'MEDIUM') mediumCount++;
            else if (vuln.severity === 'LOW') lowCount++;
          }
        });
      }
      if (showEol && tech.eolStatus) {
        if (tech.eolStatus.status === 'EOL') eolCount++;
        else if (tech.eolStatus.status === 'ENDING_SOON') endingSoonCount++;
        else if (tech.eolStatus.status === 'ENDING_SOON_6MO') endingSoon6moCount++;
      }
    });
  });

  let html = '<div class="security-section cve-section" style="border-left: 3px solid #dc3545;">';
  html += '<div class="security-section-header">';
  html += `<div class="security-section-title">${origamiIcon('alert')} Vulnerabilities & EOL</div>`;
  html += `<div class="severity-badges">`;
  if (criticalCount > 0) html += `<span class="security-badge critical">${criticalCount} Critical</span>`;
  if (highCount > 0) html += `<span class="security-badge high">${highCount} High</span>`;
  if (mediumCount > 0) html += `<span class="security-badge medium">${mediumCount} Medium</span>`;
  if (lowCount > 0) html += `<span class="security-badge low">${lowCount} Low</span>`;
  if (eolCount > 0) html += `<span class="security-badge eol-expired">${origamiIcon('warning')} ${eolCount} EOL</span>`;
  if (endingSoonCount > 0) html += `<span class="security-badge eol-ending-soon">${origamiIcon('hourglass')} ${endingSoonCount} Ending Soon</span>`;
  if (endingSoon6moCount > 0) html += `<span class="security-badge eol-ending-6mo">${endingSoon6moCount} Ending &lt;6mo</span>`;
  html += `</div>`;
  html += '</div>';

  // Render each vulnerable technology
  Object.keys(vulnerabilities).forEach(category => {
    vulnerabilities[category].forEach((tech, idx) => {
      const techId = `vuln-tech-${category}-${idx}`;

      html += `<div class="vuln-tech-item" id="${techId}">`;
      html += `<div class="vuln-tech-header">`;
      html += `<div>`;
      html += `<strong>${escapeHtml(tech.name)}</strong>`;
      if (tech.version) html += ` <span class="tech-version-inline">v${escapeHtml(tech.version)}</span>`;

      // EOL badge (only show if EOL warnings enabled)
      if (showEol && tech.eolStatus) {
        const eolTooltip = buildEolTooltip(tech.eolStatus);
        if (tech.eolStatus.status === 'EOL') {
          html += ` <span class="eol-badge eol-critical" title="${escapeHtml(eolTooltip)}">${origamiIcon('warning')} EOL</span>`;
        } else if (tech.eolStatus.status === 'ENDING_SOON') {
          html += ` <span class="eol-badge eol-warning-3mo" title="${escapeHtml(eolTooltip)}">${origamiIcon("hourglass")} Ending &lt;3mo</span>`;
        } else if (tech.eolStatus.status === 'ENDING_SOON_6MO') {
          html += ` <span class="eol-badge eol-warning-6mo" title="${escapeHtml(eolTooltip)}">${origamiIcon("hourglass")} Ending &lt;6mo</span>`;
        }
        if (tech.eolStatus.lts) {
          html += ` <span class="eol-badge eol-lts-badge" title="Long Term Support release">LTS</span>`;
        }
      }

      html += `</div>`;
      html += `<div class="vuln-tech-actions">`;

      // Add AI Assess button for ALL technologies in the vulnerabilities list
      // (If it's in the list, there's a security concern worth analyzing)
      const hasVulns = tech.vulnerabilities && tech.vulnerabilities.length > 0;
      const hasEOL = tech.eolStatus && tech.eolStatus.status; // Any EOL data
      const hasAIAssessment = tech.aiAssessment && tech.aiAssessment.analysis;

      // Debug logging
      console.log(`Origami SCA: ${tech.name} v${tech.version} - hasVulns: ${hasVulns}, hasEOL: ${hasEOL}, eolStatus:`, tech.eolStatus);

      // Show button for ANY technology in the vulnerabilities list
      if (llmEnabled) {
        html += `<button class="btn btn-primary btn-sm ai-assess-cve-btn ${hasAIAssessment ? 'has-assessment' : ''}"
                data-tech-name="${escapeHtml(tech.name)}"
                data-tech-version="${tech.version || ''}"
                data-tech-category="${category}"
                data-tech-index="${idx}"
                title="${hasAIAssessment ? 'View/Update AI Assessment' : 'Get AI Assessment'}">
          ${hasAIAssessment ? `${origamiIcon('sparkles')} AI Analysis` : `${origamiIcon('sparkles')} AI Assess`}
        </button>`;
      } else {
        html += `<button class="btn btn-secondary btn-sm ai-assess-cve-btn" disabled
                title="Configure LLM in Settings to enable AI assessment">
          ${origamiIcon('sparkles')} AI Assess
        </button>`;
      }

      html += `<button class="btn btn-secondary btn-sm toggle-vuln-details-btn" data-tech-id="${techId}">▼ Expand</button>`;
      html += `</div>`;
      html += `</div>`;

      // Vulnerability details (collapsed by default)
      html += `<div class="vuln-tech-details" id="${techId}-details" style="display: none;">`;

      if (tech.vulnerabilities && tech.vulnerabilities.length > 0) {
        tech.vulnerabilities.forEach((vuln, vulnIdx) => {
          // Only render vulnerabilities that pass the severity filter
          if (shouldShowSeverity(vuln.severity)) {
            html += `<div class="cve-item">`;
            html += `<div class="cve-header">`;
            html += `<span class="cve-id">${escapeHtml(vuln.id)}</span>`;
            html += `<span class="security-badge ${vuln.severity.toLowerCase()}">${vuln.severity}</span>`;
            if (vuln.score) html += `<span class="cvss-score">CVSS: ${vuln.score}</span>`;
            html += `</div>`;
            html += `<div class="cve-summary">${escapeHtml(vuln.summary)}</div>`;
            if (vuln.fixedVersion) {
              html += `<div class="cve-fix">${origamiIcon('lightbulb')} Fix: Upgrade to ${escapeHtml(vuln.fixedVersion)}+</div>`;
            }
            if (vuln.nvdUrl) {
              html += `<div class="cve-references">`;
              html += `<a href="${escapeHtml(vuln.nvdUrl)}" target="_blank" class="cve-link">${origamiIcon("document")}  NVD Details</a>`;
              html += `</div>`;
            }
            html += `</div>`;
          }
        });
      }

      // Only show EOL details if setting is enabled
      if (showEol && tech.eolStatus) {
        const eolStatus = tech.eolStatus;
        const eolStatusClass = eolStatus.status === 'EOL' ? 'eol-details-critical' :
          eolStatus.status === 'ENDING_SOON' ? 'eol-details-warning-3mo' :
          eolStatus.status === 'ENDING_SOON_6MO' ? 'eol-details-warning-6mo' : 'eol-details-ok';

        html += `<div class="eol-details ${eolStatusClass}">`;
        html += `<strong>End-of-Life Information:</strong>`;

        if (eolStatus.cycle) {
          html += `<br>Cycle: ${escapeHtml(String(eolStatus.cycle))}`;
        }

        // Show EOL date with contextual message
        if (typeof eolStatus.eolDate === 'boolean') {
          html += eolStatus.eolDate
            ? `<br>${origamiIcon('warning')} Security support: <strong>Ended</strong>`
            : `<br>${origamiIcon('shield')} Security support: <strong>Active</strong>`;
        } else if (eolStatus.eolDate) {
          const eolLabel = eolStatus.status === 'EOL' ? 'Security support ended' : 'Security support until';
          html += `<br>${eolStatus.status === 'EOL' ? origamiIcon('warning') : origamiIcon('shield')} ${eolLabel}: <strong>${escapeHtml(eolStatus.eolDate)}</strong>`;
        }

        // Show active support date if different from EOL date
        if (eolStatus.supportDate) {
          const supportLabel = eolStatus.activeSupportEnded ? 'Active support ended' : 'Active support until';
          html += `<br>${eolStatus.activeSupportEnded ? origamiIcon('alert') : origamiIcon('shield')} ${supportLabel}: <strong>${escapeHtml(eolStatus.supportDate)}</strong>`;
        } else if (eolStatus.activeSupportEnded) {
          html += `<br>${origamiIcon('alert')} Active support: <strong>Ended</strong> (security updates only)`;
        }

        // Show extended support info
        if (eolStatus.extendedSupportDate) {
          const extLabel = eolStatus.hasExtendedSupport ? 'Extended support until' : 'Extended support ended';
          html += `<br>${origamiIcon('shield')} ${extLabel}: <strong>${escapeHtml(eolStatus.extendedSupportDate)}</strong>`;
        }

        // Show LTS badge
        if (eolStatus.lts) {
          html += `<br><span class="eol-lts-inline">LTS</span> This is a Long Term Support release`;
        }

        // Upgrade recommendation
        if (eolStatus.latestVersion) {
          html += `<br>${origamiIcon('lightbulb')} Latest in this cycle: <strong>${escapeHtml(eolStatus.latestVersion)}</strong>`;
          if (eolStatus.latestReleaseDate) {
            html += ` (released ${escapeHtml(eolStatus.latestReleaseDate)})`;
          }
          if (eolStatus.status === 'EOL') {
            html += `<br>${origamiIcon('lightbulb')} <strong>Recommendation:</strong> Upgrade to a supported release cycle`;
          }
        }

        html += `</div>`;
      }

      // AI Assessment container
      html += `<div class="ai-assessment-container" id="ai-assessment-cve-${category}-${idx}"></div>`;

      html += `</div>`; // vuln-tech-details
      html += `</div>`; // vuln-tech-item
    });
  });

  html += '</div>';
  return html;
}

// Render tech stack with CVE/EOL badges
function renderTechStackWithCVEs(technologies, vulnerabilities) {
  // Helper function to get vulnerability info for a tech
  const getTechVulnInfo = (techName, techVersion) => {
    let info = { hasCVE: false, eolState: null, criticalCount: 0, highCount: 0, hasLTS: false };

    Object.values(vulnerabilities).forEach(techArray => {
      const match = techArray.find(t => t.name === techName && (!techVersion || t.version === techVersion));
      if (match) {
        if (match.vulnerabilities && match.vulnerabilities.length > 0) {
          info.hasCVE = true;
          match.vulnerabilities.forEach(vuln => {
            if (vuln.severity === 'CRITICAL') info.criticalCount++;
            if (vuln.severity === 'HIGH') info.highCount++;
          });
        }
        if (match.eolStatus && match.eolStatus.status) {
          info.eolState = match.eolStatus.status;
          info.hasLTS = match.eolStatus.lts || false;
        }
      }
    });

    // Backward compatibility
    info.hasEOL = info.eolState === 'EOL';

    return info;
  };

  let html = '<div class="security-section">';
  html += '<div class="security-section-header">';
  html += `<div class="security-section-title">${origamiIcon('wrench')} Technology Stack</div>`;

  const total = Object.values(technologies).reduce((sum, arr) => {
    return sum + (Array.isArray(arr) ? arr.length : 0);
  }, 0);
  html += `<span class="security-badge info">${total}</span>`;
  html += '</div>';

  // Frameworks
  if (technologies.frameworks && technologies.frameworks.length > 0) {
    html += '<div class="tech-category">Frontend Frameworks</div>';
    html += '<div class="tech-grid">';
    technologies.frameworks.forEach(item => {
      const vulnInfo = getTechVulnInfo(item.name, item.version);
      html += `<div class="tech-item${vulnInfo.hasCVE || vulnInfo.hasEOL || vulnInfo.eolState === 'ENDING_SOON' ? ' tech-item-vulnerable' : ''}">`;
      html += `<div class="tech-name">${escapeHtml(item.name)}`;
      if (vulnInfo.criticalCount > 0) html += ` <span class="cve-badge cve-critical">${vulnInfo.criticalCount}[C]</span>`;
      else if (vulnInfo.highCount > 0) html += ` <span class="cve-badge cve-high">${vulnInfo.highCount}[H]</span>`;
      else if (vulnInfo.hasCVE) html += ` <span class="cve-badge">${origamiIcon('warning')}</span>`;
      if (vulnInfo.eolState === 'EOL') html += ` <span class="eol-badge-mini eol-mini-critical">EOL</span>`;
      else if (vulnInfo.eolState === 'ENDING_SOON') html += ` <span class="eol-badge-mini eol-mini-3mo">Ending</span>`;
      else if (vulnInfo.eolState === 'ENDING_SOON_6MO') html += ` <span class="eol-badge-mini eol-mini-6mo">~6mo</span>`;
      if (vulnInfo.hasLTS) html += ` <span class="eol-badge-mini eol-mini-lts">LTS</span>`;
      html += `</div>`;
      if (item.version) html += `<div class="tech-version">v${escapeHtml(item.version)}</div>`;
      html += `</div>`;
    });
    html += '</div>';
  }

  // Libraries
  if (technologies.libraries && technologies.libraries.length > 0) {
    html += '<div class="tech-category">Libraries</div>';
    html += '<div class="tech-grid">';
    technologies.libraries.forEach(item => {
      const vulnInfo = getTechVulnInfo(item.name, item.version);
      html += `<div class="tech-item${vulnInfo.hasCVE || vulnInfo.hasEOL || vulnInfo.eolState === 'ENDING_SOON' ? ' tech-item-vulnerable' : ''}">`;
      html += `<div class="tech-name">${escapeHtml(item.name)}`;
      if (vulnInfo.criticalCount > 0) html += ` <span class="cve-badge cve-critical">${vulnInfo.criticalCount}[C]</span>`;
      else if (vulnInfo.highCount > 0) html += ` <span class="cve-badge cve-high">${vulnInfo.highCount}[H]</span>`;
      else if (vulnInfo.hasCVE) html += ` <span class="cve-badge">${origamiIcon('warning')}</span>`;
      if (vulnInfo.eolState === 'EOL') html += ` <span class="eol-badge-mini eol-mini-critical">EOL</span>`;
      else if (vulnInfo.eolState === 'ENDING_SOON') html += ` <span class="eol-badge-mini eol-mini-3mo">Ending</span>`;
      else if (vulnInfo.eolState === 'ENDING_SOON_6MO') html += ` <span class="eol-badge-mini eol-mini-6mo">~6mo</span>`;
      if (vulnInfo.hasLTS) html += ` <span class="eol-badge-mini eol-mini-lts">LTS</span>`;
      html += `</div>`;
      if (item.version) html += `<div class="tech-version">v${escapeHtml(item.version)}</div>`;
      html += `</div>`;
    });
    html += '</div>';
  }

  // Backend
  if (technologies.backend && technologies.backend.length > 0) {
    html += '<div class="tech-category">Backend</div>';
    html += '<div class="tech-grid">';
    technologies.backend.forEach(item => {
      const vulnInfo = getTechVulnInfo(item.name, item.version);
      html += `<div class="tech-item${vulnInfo.hasCVE || vulnInfo.hasEOL || vulnInfo.eolState === 'ENDING_SOON' ? ' tech-item-vulnerable' : ''}">`;
      html += `<div class="tech-name">${escapeHtml(item.name)}`;
      if (vulnInfo.criticalCount > 0) html += ` <span class="cve-badge cve-critical">${vulnInfo.criticalCount}[C]</span>`;
      else if (vulnInfo.highCount > 0) html += ` <span class="cve-badge cve-high">${vulnInfo.highCount}[H]</span>`;
      else if (vulnInfo.hasCVE) html += ` <span class="cve-badge">${origamiIcon('warning')}</span>`;
      if (vulnInfo.eolState === 'EOL') html += ` <span class="eol-badge-mini eol-mini-critical">EOL</span>`;
      else if (vulnInfo.eolState === 'ENDING_SOON') html += ` <span class="eol-badge-mini eol-mini-3mo">Ending</span>`;
      else if (vulnInfo.eolState === 'ENDING_SOON_6MO') html += ` <span class="eol-badge-mini eol-mini-6mo">~6mo</span>`;
      if (vulnInfo.hasLTS) html += ` <span class="eol-badge-mini eol-mini-lts">LTS</span>`;
      html += `</div>`;
      if (item.version) html += `<div class="tech-version">v${escapeHtml(item.version)}</div>`;
      html += `</div>`;
    });
    html += '</div>';
  }

  // CDN
  if (technologies.cdn && technologies.cdn.length > 0) {
    html += '<div class="tech-category">CDN & Infrastructure</div>';
    html += '<div class="tech-grid">';
    technologies.cdn.forEach(item => {
      html += `<div class="tech-item">`;
      html += `<div class="tech-name">${escapeHtml(item.name)}</div>`;
      if (item.version) html += `<div class="tech-version">v${escapeHtml(item.version)}</div>`;
      html += `</div>`;
    });
    html += '</div>';
  }

  // Analytics
  if (technologies.analytics && technologies.analytics.length > 0) {
    html += '<div class="tech-category">Analytics & Tracking</div>';
    html += '<div class="tech-grid">';
    technologies.analytics.forEach(item => {
      html += `<div class="tech-item">`;
      html += `<div class="tech-name">${escapeHtml(item.name)}</div>`;
      if (item.version) html += `<div class="tech-version">v${escapeHtml(item.version)}</div>`;
      html += `</div>`;
    });
    html += '</div>';
  }
  
  // Security
  if (technologies.security && technologies.security.length > 0) {
    html += '<div class="tech-category">Security Tools</div>';
    html += '<div class="tech-grid">';
    technologies.security.forEach(item => {
      html += `<div class="tech-item">`;
      html += `<div class="tech-name">${escapeHtml(item.name)}</div>`;
      if (item.version) html += `<div class="tech-version">v${escapeHtml(item.version)}</div>`;
      html += `</div>`;
    });
    html += '</div>';
  }

  // Build Tools
  if (technologies.buildTools && technologies.buildTools.length > 0) {
    html += '<div class="tech-category">Build Tools</div>';
    html += '<div class="tech-grid">';
    technologies.buildTools.forEach(item => {
      html += `<div class="tech-item">`;
      html += `<div class="tech-name">${escapeHtml(item.name)}</div>`;
      if (item.version) html += `<div class="tech-version">v${escapeHtml(item.version)}</div>`;
      html += `</div>`;
    });
    html += '</div>';
  }

  html += '</div>';

  return html;
}

// Attach event listeners for CVE section
function attachCVEEventListeners(container) {
  if (!container) return;

  // Toggle vulnerability details
  container.querySelectorAll('.toggle-vuln-details-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const techId = e.target.dataset.techId;
      const detailsDiv = document.getElementById(`${techId}-details`);

      if (detailsDiv) {
        if (detailsDiv.style.display === 'none') {
          detailsDiv.style.display = 'block';
          e.target.textContent = '▲ Collapse';
        } else {
          detailsDiv.style.display = 'none';
          e.target.textContent = '▼ Expand';
        }
      }
    });
  });

  // AI Assess CVE buttons
  container.querySelectorAll('.ai-assess-cve-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const techName = e.target.dataset.techName;
      const techVersion = e.target.dataset.techVersion;
      const category = e.target.dataset.techCategory;
      const techIndex = parseInt(e.target.dataset.techIndex);

      console.log('Origami: AI Assess CVE button clicked', { techName, techVersion, category, techIndex });

      await performCVEAIAssessment(techName, techVersion, category, techIndex);
    });
  });
}

// Render tech stack (original function for non-CVE display)
function renderTechStack(tech) {
  let html = '<div class="security-section">';
  html += '<div class="security-section-header">';
  html += `<div class="security-section-title">${origamiIcon('wrench')} Technology Stack</div>`;

  const total = Object.values(tech).reduce((sum, arr) => {
    return sum + (Array.isArray(arr) ? arr.length : 0);
  }, 0);
  html += `<span class="security-badge info">${total}</span>`;
  html += '</div>';

  // Frameworks
  if (tech.frameworks && tech.frameworks.length > 0) {
    html += '<div class="tech-category">Frontend Frameworks</div>';
    html += '<div class="tech-grid">';
    tech.frameworks.forEach(item => {
      html += `<div class="tech-item">`;
      html += `<div class="tech-name">${escapeHtml(item.name)}</div>`;
      if (item.version) html += `<div class="tech-version">v${escapeHtml(item.version)}</div>`;
      html += `</div>`;
    });
    html += '</div>';
  }

  // Libraries
  if (tech.libraries && tech.libraries.length > 0) {
    html += '<div class="tech-category">Libraries</div>';
    html += '<div class="tech-grid">';
    tech.libraries.forEach(item => {
      html += `<div class="tech-item">`;
      html += `<div class="tech-name">${escapeHtml(item.name)}</div>`;
      if (item.version) html += `<div class="tech-version">v${escapeHtml(item.version)}</div>`;
      html += `</div>`;
    });
    html += '</div>';
  }

  // Backend
  if (tech.backend && tech.backend.length > 0) {
    html += '<div class="tech-category">Backend</div>';
    html += '<div class="tech-grid">';
    tech.backend.forEach(item => {
      html += `<div class="tech-item">`;
      html += `<div class="tech-name">${escapeHtml(item.name)}</div>`;
      if (item.version) html += `<div class="tech-version">v${escapeHtml(item.version)}</div>`;
      html += `</div>`;
    });
    html += '</div>';
  }

  // CDN
  if (tech.cdn && tech.cdn.length > 0) {
    html += '<div class="tech-category">CDN & Infrastructure</div>';
    html += '<div class="tech-grid">';
    tech.cdn.forEach(item => {
      html += `<div class="tech-item">`;
      html += `<div class="tech-name">${escapeHtml(item.name)}</div>`;
      if (item.version) html += `<div class="tech-version">v${escapeHtml(item.version)}</div>`;
      html += `</div>`;
    });
    html += '</div>';
  }

  // Analytics
  if (tech.analytics && tech.analytics.length > 0) {
    html += '<div class="tech-category">Analytics & Tracking</div>';
    html += '<div class="tech-grid">';
    tech.analytics.forEach(item => {
      html += `<div class="tech-item">`;
      html += `<div class="tech-name">${escapeHtml(item.name)}</div>`;
      if (item.version) html += `<div class="tech-version">v${escapeHtml(item.version)}</div>`;
      html += `</div>`;
    });
    html += '</div>';
  }

  // Security
  if (tech.security && tech.security.length > 0) {
    html += '<div class="tech-category">Security Tools</div>';
    html += '<div class="tech-grid">';
    tech.security.forEach(item => {
      html += `<div class="tech-item">`;
      html += `<div class="tech-name">${escapeHtml(item.name)}</div>`;
      if (item.version) html += `<div class="tech-version">v${escapeHtml(item.version)}</div>`;
      html += `</div>`;
    });
    html += '</div>';
  }

  // Build Tools
  if (tech.buildTools && tech.buildTools.length > 0) {
    html += '<div class="tech-category">Build Tools</div>';
    html += '<div class="tech-grid">';
    tech.buildTools.forEach(item => {
      html += `<div class="tech-item">`;
      html += `<div class="tech-name">${escapeHtml(item.name)}</div>`;
      if (item.version) html += `<div class="tech-version">v${escapeHtml(item.version)}</div>`;
      html += `</div>`;
    });
    html += '</div>';
  }

  html += '</div>';

  return html;
}

// Get summary statistics
function getSummary(results) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  const allFindings = [
    ...(results.headers || []),
    ...(results.cookies || []),
    ...(results.vulnerabilities || []),
    ...(results.sensitiveFiles || [])
  ];

  allFindings.forEach(finding => {
    // Use effective severity (override > AI assessment > original)
    const effectiveSeverity = (finding.severityOverride?.overriddenSeverity ||
                               finding.aiAssessment?.suggestedSeverity ||
                               finding.severity ||
                               'info').toLowerCase();

    // Skip false positives (NONE severity)
    if (effectiveSeverity === 'none') return;

    if (summary.hasOwnProperty(effectiveSeverity)) {
      summary[effectiveSeverity]++;
    }
  });

  return summary;
}

// Load current page findings
async function loadCurrentFindings() {
  try {
    const tab = await getTargetTab();
    
    // Load secret findings
    chrome.runtime.sendMessage(
      { action: 'getTabFindings', tabId: tab.id },
      (response) => {
        if (chrome.runtime.lastError) {
          console.error('Origami: Failed to load findings:', chrome.runtime.lastError.message);
          return;
        }
        if (response && response.findings && response.findings.length > 0) {
          currentFindings = response.findings;
          displayFindings(currentFindings);
          const findingsContainer = document.getElementById('findingsContainer');
          if (findingsContainer) autoUnfoldFindings(findingsContainer);
        } else {
          // Fall back to domain cache for findings
          tryRestoreFromDomainCache(tab, 'findings');
        }
      }
    );
    
    // Load security analysis results with retry logic
    let retryCount = 0;
    const maxRetries = 2;
    
    const loadSecurityResults = () => {
      chrome.runtime.sendMessage(
        { action: 'getTabSecurityResults', tabId: tab.id },
        (response) => {
          if (chrome.runtime.lastError) {
            console.error('Origami: Failed to load security results:', chrome.runtime.lastError.message);
            securityResultsLoaded = true;
            return;
          }
          console.log('Origami Popup: Security results response:', response);
          if (response && response.results) {
            securityResults = response.results;
            securityResultsLoaded = true;
            console.log('Origami Popup: Displaying security results:', securityResults);
            displaySecurityResults(securityResults);
            const securityContainer = document.getElementById('security-tab');
            if (securityContainer) autoUnfoldFindings(securityContainer);

            // Verify window.currentSecurityFindings was set
            console.log('Origami Popup: After display, window.currentSecurityFindings:', window.currentSecurityFindings);
          } else {
            console.log('Origami Popup: No security results available yet (attempt ' + (retryCount + 1) + '/' + maxRetries + ')');

            // Show loading overlay in security tab (without destroying sub-tab structure)
            const container = document.getElementById('security-tab');
            // Skip loading overlay if SQLi (or other) findings are already injected
            if (securityResults && securityResults.vulnerabilities && securityResults.vulnerabilities.length > 0) {
              displaySecurityResults(securityResults);
              securityResultsLoaded = true;
              return;
            }
            if (retryCount === 0 && container && !container.querySelector('.security-loading-overlay')) {
              const overlay = document.createElement('div');
              overlay.className = 'security-loading-overlay';
              overlay.innerHTML = `
                <div class="empty-state">
                  <p>${origamiIcon('hourglass')} Auto-scan is running...</p>
                  <p class="empty-hint">Security analysis in progress. Results will appear automatically.</p>
                </div>
              `;
              // Hide sub-tabs and content while loading
              const nav = container.querySelector('.security-sub-tabs');
              const content = container.querySelector('.security-sub-tab-content');
              if (nav) nav.style.display = 'none';
              if (content) content.style.display = 'none';
              container.appendChild(overlay);
            }

            // Retry a few times in case security analysis is still running
            retryCount++;
            if (retryCount < maxRetries) {
              console.log('Origami Popup: Waiting for security analysis to complete...');
              setTimeout(loadSecurityResults, 1500);
            } else {
              // After max retries, try domain cache before showing empty state
              securityResultsLoaded = true;
              console.log('Origami Popup: Security analysis not available - trying domain cache');
              tryRestoreFromDomainCache(tab, 'security').then(restored => {
                // Don't show empty state if SQLi findings are already injected
                if (securityResults && securityResults.vulnerabilities && securityResults.vulnerabilities.length > 0) {
                  displaySecurityResults(securityResults);
                  return;
                }
                if (!restored && container) {
                  // Replace loading overlay with empty-state prompt
                  const existingOverlay = container.querySelector('.security-loading-overlay');
                  if (existingOverlay) existingOverlay.remove();
                  const emptyOverlay = document.createElement('div');
                  emptyOverlay.className = 'security-loading-overlay';
                  emptyOverlay.innerHTML = `
                    <div class="empty-state">
                      <p>Click "Unfold" to scan for:</p>
                      <ul class="feature-list">
                        <li>${origamiIcon('shield')} Security Headers (CSP, HSTS, X-Frame-Options)</li>
                        <li>${origamiIcon('cookie')} Cookie Security (HttpOnly, Secure, SameSite)</li>
                        <li>${origamiIcon('warning')} Vulnerabilities (XSS, SQLi, CSRF, etc.)</li>
                        <li>${origamiIcon('wrench')} Technology Stack (Frameworks, Libraries, CDN)</li>
                      </ul>
                    </div>
                  `;
                  // Keep sub-tabs hidden, show empty state
                  const nav = container.querySelector('.security-sub-tabs');
                  const content = container.querySelector('.security-sub-tab-content');
                  if (nav) nav.style.display = 'none';
                  if (content) content.style.display = 'none';
                  container.appendChild(emptyOverlay);
                }
              });
            }
          }
        }
      );
    };
    
    loadSecurityResults();
  } catch (error) {
    console.error('Error loading findings:', error);
  }
}

// Restore findings/security results from domain cache when tab data is empty
async function tryRestoreFromDomainCache(tab, dataType) {
  let hostname;
  try { hostname = new URL(tab.url).hostname; } catch (e) { return false; }

  return new Promise((resolve) => {
    chrome.runtime.sendMessage(
      { action: 'getDomainCache', domain: hostname },
      (response) => {
        if (chrome.runtime.lastError || !response || !response.cache) {
          resolve(false);
          return;
        }
        const cache = response.cache;

        if (dataType === 'findings' && cache.findings && cache.findings.length > 0) {
          currentFindings = cache.findings;
          displayFindings(currentFindings);
          const findingsContainer = document.getElementById('findingsContainer');
          if (findingsContainer) autoUnfoldFindings(findingsContainer);
          console.log(`Origami Popup: Restored ${currentFindings.length} cached findings for ${hostname}`);
          resolve(true);
          return;
        }

        if (dataType === 'security' && cache.securityResults) {
          securityResults = cache.securityResults;
          securityResultsLoaded = true;
          displaySecurityResults(securityResults);
          const securityContainer = document.getElementById('security-tab');
          if (securityContainer) autoUnfoldFindings(securityContainer);
          console.log(`Origami Popup: Restored cached security results for ${hostname}`);
          resolve(true);
          return;
        }

        resolve(false);
      }
    );
  });
}

async function handleSecurityAnalysisReady(readyTabId) {
  try {
    const tab = await getTargetTab();
    if (tab.id !== readyTabId) return;

    chrome.runtime.sendMessage(
      { action: 'getTabSecurityResults', tabId: tab.id },
      (response) => {
        if (response && response.results) {
          securityResultsLoaded = true;
          securityResults = response.results;
          displaySecurityResults(securityResults);
          const securityContainer = document.getElementById('security-tab');
          if (securityContainer) autoUnfoldFindings(securityContainer);
        }
      }
    );
  } catch (error) {
    console.error('Error handling security analysis ready:', error);
  }
}

// Scan current page (now includes security analysis)
async function scanCurrentPage() {
  const btn = document.getElementById('scanNowBtn');
  const icon = btn.querySelector('#origamiIcon');

  // Trigger unfold animation
  btn.classList.add('unfolding');

  // After animation completes, switch to scanning state
  setTimeout(() => {
    btn.classList.remove('unfolding');
    btn.classList.add('scanning');
  }, 1200);

  // Update button text (keeping SVG icon) - find text node with content
  const textNode = Array.from(btn.childNodes).find(node =>
    node.nodeType === Node.TEXT_NODE && node.textContent.trim().length > 0
  );
  if (textNode) {
    textNode.textContent = ' Scanning...';
  }
  btn.disabled = true;

  try {
    const tab = await getTargetTab();

    // Step 1: Scan for secrets
    chrome.tabs.sendMessage(
      tab.id,
      { action: 'scanNow' },
      (response) => {
        if (chrome.runtime.lastError) {
          showMessage('Error: Could not scan this page. Try reloading the page.', 'error');
          btn.classList.remove('scanning');
          btn.classList.remove('unfolding');
          if (textNode) textNode.textContent = ' Unfold';
          btn.disabled = false;
          return;
        }

        if (response && response.findings) {
          // Send raw findings to background for dedup, filtering, and storage
          // so both Unfold and cached-load paths produce identical processed data
          chrome.runtime.sendMessage({
            action: 'scanComplete',
            findings: response.findings,
            url: tab.url,
            tabId: tab.id
          }, () => {
            // Load the processed findings back from storage
            chrome.runtime.sendMessage(
              { action: 'getTabFindings', tabId: tab.id },
              (storedResponse) => {
                currentFindings = (storedResponse && storedResponse.findings) || response.findings;
                displayFindings(currentFindings);
                showMessage(`Found ${currentFindings.length} potential secret(s).`, 'success');

                // Step 2: Run security analysis
                chrome.tabs.sendMessage(
                  tab.id,
                  { action: 'runSecurityAnalysis' },
                  (secResponse) => {
                    securityResultsLoaded = true;
                    if (secResponse && secResponse.results) {
                      securityResults = secResponse.results;
                      displaySecurityResults(securityResults);

                      const totalSecrets = currentFindings.length;
                      const totalVulns = (securityResults.vulnerabilities || []).length;
                      showMessage(`Unfold complete! ${totalSecrets} secret(s), ${totalVulns} vulnerability/ies`, 'success');
                    }

                    btn.classList.remove('scanning');
                    btn.classList.remove('unfolding');
                    if (textNode) textNode.textContent = ' Unfold';
                    btn.disabled = false;
                  }
                );
              }
            );
          });
        } else {
          // No findings -- still run security analysis
          // Step 2: Run security analysis
          chrome.tabs.sendMessage(
            tab.id,
            { action: 'runSecurityAnalysis' },
            (secResponse) => {
              securityResultsLoaded = true;
              if (secResponse && secResponse.results) {
                securityResults = secResponse.results;
                displaySecurityResults(securityResults);

                const totalVulns = (securityResults.vulnerabilities || []).length;
                showMessage(`Unfold complete! 0 secret(s), ${totalVulns} vulnerability/ies`, 'success');
              }

              btn.classList.remove('scanning');
              btn.classList.remove('unfolding');
              if (textNode) textNode.textContent = ' Unfold';
              btn.disabled = false;
            }
          );
        }
      }
    );
  } catch (error) {
    console.error('Scan error:', error);
    showMessage('Failed to scan page', 'error');
    btn.classList.remove('scanning');
    btn.classList.remove('unfolding');
    const textNodeError = Array.from(btn.childNodes).find(node =>
      node.nodeType === Node.TEXT_NODE && node.textContent.trim().length > 0
    );
    if (textNodeError) textNodeError.textContent = ' Unfold';
    btn.disabled = false;
  }
}

// Normalize secret key by extracting the actual secret value
function normalizeSecretKey(secretValue) {
  if (!secretValue) return '';

  // Remove common variable assignments and quotes
  let normalized = secretValue
    .replace(/^.*?[=:]\s*["'`]?/, '')  // Remove "api_key = " or "apiKey: " etc.
    .replace(/["'`].*$/, '')            // Remove trailing quotes and anything after
    .trim();

  // If the original value looks like it contains the key inside, extract it
  // Pattern: Look for common API key patterns (AIza, sk_, pk_, etc.)
  const keyPatterns = [
    /AIza[A-Za-z0-9_-]{35}/,           // Google API keys
    /sk_(?:live|test)_[A-Za-z0-9]{24,}/,  // Stripe keys
    /pk_(?:live|test)_[A-Za-z0-9]{24,}/,  // Stripe public keys
    /(?:AKIA|ASIA)[A-Z0-9]{16}/,       // AWS Access keys (incl. STS)
    /ghp_[A-Za-z0-9]{36}/,             // GitHub tokens
    /xox[baprs]-[A-Za-z0-9-]+/         // Slack tokens
  ];

  for (const pattern of keyPatterns) {
    const match = secretValue.match(pattern);
    if (match) {
      normalized = match[0];
      break;
    }
  }

  return normalized;
}

// Display findings
function displayFindings(findings) {
  const container = document.getElementById('findingsContainer');

  if (!findings || findings.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <p>No secrets found on this page.</p>
        <p class="empty-hint">Origami automatically scans JavaScript files for hardcoded secrets.</p>
      </div>
    `;
    updateStats({ critical: 0, high: 0, medium: 0, total: 0 });
    return;
  }
  
  // Deduplicate findings by secret value, keeping highest severity
  const deduplicatedFindings = [];
  const secretMap = new Map();

  findings.forEach(finding => {
    // Use normalized key for deduplication
    const secretKey = normalizeSecretKey(finding.full_key || finding.key);

    if (secretMap.has(secretKey)) {
      // Secret already exists, merge patterns and keep higher severity
      const existing = secretMap.get(secretKey);
      const riskOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

      // Add pattern to the list
      if (!existing.patterns_matched) {
        existing.patterns_matched = [existing.pattern_matched];
      }
      if (!existing.patterns_matched.includes(finding.pattern_matched)) {
        existing.patterns_matched.push(finding.pattern_matched);
      }

      // Keep the finding with higher severity
      const currentSeverity = riskOrder[finding.risk] || 5;
      const existingSeverity = riskOrder[existing.risk] || 5;

      if (currentSeverity < existingSeverity) {
        // Current has higher severity, replace but keep patterns and merge assessments
        finding.patterns_matched = existing.patterns_matched;

        // Preserve AI assessment and severity override if existing has them but current doesn't
        if (!finding.aiAssessment && existing.aiAssessment) {
          finding.aiAssessment = existing.aiAssessment;
        }
        if (!finding.severityOverride && existing.severityOverride) {
          finding.severityOverride = existing.severityOverride;
        }

        secretMap.set(secretKey, finding);
      } else if (currentSeverity === existingSeverity) {
        // Same severity, keep existing but merge AI assessment from current if needed
        if (!existing.aiAssessment && finding.aiAssessment) {
          existing.aiAssessment = finding.aiAssessment;
        }
        if (!existing.severityOverride && finding.severityOverride) {
          existing.severityOverride = finding.severityOverride;
        }

        secretMap.set(secretKey, existing);
      } else {
        // Existing has higher severity, keep it but merge AI assessment from current if needed
        if (!existing.aiAssessment && finding.aiAssessment) {
          existing.aiAssessment = finding.aiAssessment;
        }
        if (!existing.severityOverride && finding.severityOverride) {
          existing.severityOverride = finding.severityOverride;
        }

        secretMap.set(secretKey, existing);
      }
    } else {
      // New secret
      secretMap.set(secretKey, finding);
    }
  });

  // Convert map back to array
  const uniqueFindings = Array.from(secretMap.values());

  // Update stats using effective severity (override > AI > original)
  const getEffectiveRisk = f => (
    f.severityOverride?.overriddenSeverity ||
    f.aiAssessment?.suggestedSeverity ||
    f.risk || 'LOW'
  ).toUpperCase();

  const stats = {
    critical: uniqueFindings.filter(f => getEffectiveRisk(f) === 'CRITICAL').length,
    high: uniqueFindings.filter(f => getEffectiveRisk(f) === 'HIGH').length,
    medium: uniqueFindings.filter(f => getEffectiveRisk(f) === 'MEDIUM').length,
    total: uniqueFindings.length
  };
  updateStats(stats);

  // Sort by effective risk level (considering overrides and AI assessments)
  // Use DESCENDING order: higher severity values come first (CRITICAL before MEDIUM)
  const sortedFindings = [...uniqueFindings].sort((a, b) => {
    // Assign priority scores: higher number = higher severity = should appear first
    const severityScore = {
      'CRITICAL': 1000,
      'HIGH': 100,
      'MEDIUM': 10,
      'LOW': 1,
      'INFO': 0,
      'NONE': -1
    };

    // Get effective severity for a (override > AI > original)
    const effectiveSevA = (a.severityOverride?.overriddenSeverity ||
                           a.aiAssessment?.suggestedSeverity ||
                           a.risk || 'LOW').toUpperCase();

    // Get effective severity for b (override > AI > original)
    const effectiveSevB = (b.severityOverride?.overriddenSeverity ||
                           b.aiAssessment?.suggestedSeverity ||
                           b.risk || 'LOW').toUpperCase();

    const scoreA = severityScore[effectiveSevA] || 0;
    const scoreB = severityScore[effectiveSevB] || 0;

    // DESCENDING sort: higher score first (b - a puts higher values first)
    return scoreB - scoreA;
  });

  console.log('Origami: After sort:', sortedFindings.map(f => ({ risk: f.risk, key: f.key?.substring(0, 20) })));

  // Update currentFindings to match sorted order so indices align correctly
  currentFindings = sortedFindings;

  // Build bulk actions bar
  const patternTypes = [...new Set(sortedFindings.map(f => f.pattern_matched).filter(Boolean))];
  const bulkActionsHtml = `
    <div class="bulk-actions-bar">
      <button class="btn btn-secondary btn-sm bulk-whitelist-domain-btn" title="Whitelist all findings from the current domain">
        Whitelist Domain
      </button>
      <select class="bulk-whitelist-pattern-select btn-sm" title="Whitelist all findings of a specific pattern type">
        <option value="">Whitelist by Pattern...</option>
        ${patternTypes.map(p => `<option value="${escapeHtml(p)}">${escapeHtml(p)}</option>`).join('')}
      </select>
    </div>
  `;

  // Display findings
  container.innerHTML = bulkActionsHtml + sortedFindings.map((finding, index) => {
    const isGoogleAPI = finding.pattern_matched === 'Google Cloud API Key' || finding.full_key?.startsWith('AIza');
    // Always show Test API button for Google API keys (uses API Testing tab settings)
    const testAPIButton = isGoogleAPI ?
      `<button class="btn btn-secondary btn-sm test-api-btn" data-secret="${escapeHtml(finding.full_key)}">
        ${origamiIcon('key')} Test API
      </button>` : '';

    // Show Validate button for secrets with known provider validators
    const canValidate = typeof SecretValidator !== 'undefined' && SecretValidator.detectProvider(finding.full_key, finding.pattern_matched);
    const validateButton = canValidate ?
      `<button class="btn btn-secondary btn-sm validate-secret-btn" data-secret="${escapeHtml(finding.full_key)}" data-pattern="${escapeHtml(finding.pattern_matched || '')}" data-finding-index="${index}">
        ${origamiIcon('key')} Validate
      </button>` : '';

    // AI Assessment button - always show with appropriate state
    const llmEnabled = currentSettings?.llm?.enabled && currentSettings.llm.provider !== 'none';
    const hasAIAssessmentCheck = !!finding.aiAssessment;
    const llmButton = llmEnabled ?
      `<button class="btn btn-primary btn-sm ai-assess-btn ${hasAIAssessmentCheck ? 'has-assessment' : ''}"
              data-finding-type="secret" data-finding-index="${index}"
              title="${hasAIAssessmentCheck ? 'View/Update AI Assessment' : 'Get AI Assessment'}">
        ${hasAIAssessmentCheck ? `${origamiIcon('sparkles')} AI Analysis` : `${origamiIcon('sparkles')} AI Assess`}
      </button>` :
      `<button class="btn btn-secondary btn-sm ai-assess-btn" disabled
              title="Configure LLM in Settings to enable AI assessment">
        ${origamiIcon('sparkles')} AI Assess
      </button>`;
    
    // Check if we have extended details
    const hasDetails = finding.codeContext || finding.lineNumber;
    
    // Build severity display - show original, AI-assessed, and overridden if available
    const aiSeverity = finding.aiAssessment?.suggestedSeverity;
    const hasAIAssessment = !!finding.aiAssessment;
    const overriddenSeverity = finding.severityOverride?.overriddenSeverity;
    const effectiveSeverity = overriddenSeverity || finding.risk;

    let severityDisplay = '';
    if (overriddenSeverity) {
      // Show original (strikethrough) -> overridden
      severityDisplay = `
        <span class="finding-risk ${finding.risk} severity-overridden" title="Original severity (overridden)" style="text-decoration: line-through; opacity: 0.6;">
          ${finding.risk}
        </span>
        <span class="finding-risk-arrow">→</span>
        <span class="finding-risk ${overriddenSeverity} severity-override-badge" title="Overridden by user on ${new Date(finding.severityOverride.timestamp).toLocaleString()}">
          ${overriddenSeverity === 'NONE' ? 'FALSE POSITIVE' : overriddenSeverity} ${origamiIcon('wrench')}
        </span>`;
    } else if (aiSeverity) {
      // Show original -> AI-assessed with specific severity
      severityDisplay = `
        <span class="finding-risk ${finding.risk}" title="Original severity">
          ${finding.risk}
        </span>
        <span class="finding-risk-arrow">→</span>
        <span class="finding-risk ${aiSeverity} ai-severity" title="AI-assessed severity: ${finding.aiAssessment.severityReasoning ? escapeHtml(finding.aiAssessment.severityReasoning.substring(0, 100)) + '...' : 'AI recommendation'}">
          ${aiSeverity} ${origamiIcon('sparkles')}
        </span>`;
    } else if (hasAIAssessment) {
      // Show AI assessed indicator even without specific severity recommendation
      severityDisplay = `
        <span class="finding-risk ${finding.risk}" title="Original severity">
          ${finding.risk}
        </span>
        <span class="ai-assessed-badge" title="AI assessed on ${new Date(finding.aiAssessment.timestamp).toLocaleString()}" style="margin-left: 6px; font-size: 12px; opacity: 0.8;">
          ${origamiIcon('sparkles')}
        </span>`;
    } else {
      // Show only original
      severityDisplay = `<span class="finding-risk ${finding.risk}">${finding.risk}</span>`;
    }
    
    return `
      <div class="finding-item" data-index="${index}">
        <div class="finding-header">
          <div class="finding-severity-container">
            ${severityDisplay}
            <select class="severity-override-select" data-finding-index="${index}" data-finding-type="secret" title="Override severity">
              <option value=""> Override...</option>
              <option value="NONE">False Positive</option>
              <option value="INFO">Info</option>
              <option value="LOW">Low</option>
              <option value="MEDIUM">Medium</option>
              <option value="HIGH">High</option>
              <option value="CRITICAL">Critical</option>
            </select>
          </div>
          <div class="finding-actions">
            ${testAPIButton}
            ${validateButton}
            ${llmButton}
            <button class="btn btn-secondary btn-sm copy-btn" data-secret="${escapeHtml(finding.full_key)}">
              ${origamiIcon('clipboard')} Copy
            </button>
            ${hasDetails ? `<button class="btn btn-secondary btn-sm toggle-details-btn" data-finding-index="${index}">
              ${origamiIcon('clipboard')} Details
            </button>` : ''}
          </div>
        </div>
        <div class="finding-pattern">
          ${finding.patterns_matched && finding.patterns_matched.length > 1 ?
            `Patterns (${finding.patterns_matched.length}): ${finding.patterns_matched.map(p => escapeHtml(p)).join(', ')}` :
            `Pattern: ${escapeHtml(finding.pattern_matched || 'Generic')}`
          }
        </div>
        <div class="finding-key" data-full="${escapeHtml(finding.full_key)}" title="Click to toggle full secret">
          ${escapeHtml(finding.key)}
        </div>
        <div class="finding-url" title="${escapeHtml(finding.url)}">${escapeHtml(finding.url)}</div>
        <div class="secret-validation-result" id="secret-validation-${index}" style="display: none;"></div>
        ${hasDetails ? `
        <div class="finding-details" id="finding-details-${index}" style="display: none;">
          <div class="detail-section">
            <strong>Source:</strong> ${escapeHtml(finding.source || finding.url)}
            ${finding.lineNumber ? `<br><strong>Line:</strong> ${finding.lineNumber}` : ''}
            ${finding.timestamp ? `<br><strong>Detected:</strong> ${new Date(finding.timestamp).toLocaleString()}` : ''}
          </div>
          ${finding.codeContext ? `
          <div class="detail-section">
            <div class="code-context-header-collapsible" style="cursor: pointer; display: flex; justify-content: space-between; align-items: center; padding: 4px 0;">
              <strong>Code Context:</strong>
              <button class="btn btn-secondary btn-sm toggle-code-context-btn" data-finding-index="${index}" style="padding: 2px 8px; font-size: 12px;">&#9660; Expand</button>
            </div>
            <div class="code-context-collapsible-content" id="code-context-content-${index}" style="display: none;">
              <pre class="code-context"><code>${highlightMatchInContext(finding.codeContext, finding.matchedText)}</code></pre>
            </div>
          </div>` : ''}
          ${finding.matchedText ? `
          <div class="detail-section">
            <strong>Matched Text:</strong>
            <pre class="matched-text"><code>${escapeHtml(finding.matchedText)}</code></pre>
          </div>` : ''}
          
          <!-- AI Assessment Section -->
          <div class="ai-assessment-section" id="ai-assessment-${index}">
            ${finding.aiAssessment ? `
            <div class="ai-assessment-result">
              <div class="ai-assessment-header-collapsible" style="cursor: pointer; display: flex; justify-content: space-between; align-items: center; padding: 8px 0;">
                <div>
                  <strong>${origamiIcon('sparkles')} AI Security Assessment</strong>
                  <span class="ai-timestamp" style="margin-left: 8px; font-size: 11px; color: var(--text-secondary);">${new Date(finding.aiAssessment.timestamp).toLocaleString()}</span>
                </div>
                <button class="btn btn-secondary btn-sm toggle-ai-assessment-btn" data-finding-index="${index}" data-finding-type="secret" style="padding: 2px 8px; font-size: 12px;">
                  ▼ Expand
                </button>
              </div>
              <div class="ai-assessment-collapsible-content" id="ai-assessment-content-${index}" style="display: none;">
                <div class="ai-assessment-content">${formatAIAssessment(finding.aiAssessment.analysis)}</div>
                <div class="ai-assessment-actions">
                  <button class="btn btn-secondary btn-sm refresh-ai-btn" data-finding-index="${index}" data-finding-type="secret">
                    ${origamiIcon('refresh')} Refresh Analysis
                  </button>
                </div>
              </div>
            </div>` : ''}
          </div>
        </div>` : ''}
      </div>
    `;
  }).join('');
  
  // Add event listeners
  container.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const secret = e.target.dataset.secret;
      copyToClipboard(secret);
      e.target.textContent = '✓ Copied!';
      setTimeout(() => {
        e.target.innerHTML = `${origamiIcon('clipboard')} Copy`;
      }, 2000);
    });
  });

  // Add Test API button listeners
  container.querySelectorAll('.test-api-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const apiKey = e.target.dataset.secret;
      await testGoogleAPIKey(apiKey);
    });
  });

  // Add Validate Secret button listeners
  container.querySelectorAll('.validate-secret-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const secret = btn.dataset.secret;
      const pattern = btn.dataset.pattern;
      const index = btn.dataset.findingIndex;
      await validateSecretInline(secret, pattern, index, btn);
    });
  });

  // Add AI Assessment button listeners
  container.querySelectorAll('.ai-assess-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const index = parseInt(e.target.dataset.findingIndex);
      const type = e.target.dataset.findingType;
      if (type === 'secret' && !btn.disabled) {
        await performInlineAIAssessment(index, 'secret');
      }
    });
  });
  
  // Add refresh AI button listeners
  container.querySelectorAll('.refresh-ai-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const index = parseInt(e.target.dataset.findingIndex);
      const type = e.target.dataset.findingType;
      await performInlineAIAssessment(index, type, true);
    });
  });
  
  // Toggle full secret display
  container.querySelectorAll('.finding-key').forEach(keyEl => {
    keyEl.addEventListener('click', () => {
      const fullSecret = keyEl.dataset.full;
      if (keyEl.classList.contains('expanded')) {
        keyEl.textContent = fullSecret.slice(0, 16) + '...' + fullSecret.slice(-10);
        keyEl.classList.remove('expanded');
      } else {
        keyEl.textContent = fullSecret;
        keyEl.classList.add('expanded');
      }
    });
  });
  
  // Toggle finding details
  container.querySelectorAll('.toggle-details-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const index = parseInt(e.target.dataset.findingIndex);
      const detailsDiv = document.getElementById(`finding-details-${index}`);
      if (detailsDiv) {
        if (detailsDiv.style.display === 'none') {
          detailsDiv.style.display = 'block';
          e.target.textContent = ' Hide Details';
        } else {
          detailsDiv.style.display = 'none';
          e.target.innerHTML = `${origamiIcon('clipboard')} Details`;
        }
      }
    });
  });
  
  // Severity override listeners
  container.querySelectorAll('.severity-override-select').forEach(select => {
    select.addEventListener('change', async (e) => {
      const index = parseInt(e.target.dataset.findingIndex);
      const newSeverity = e.target.value;
      const type = e.target.dataset.findingType || 'secret';

      if (newSeverity) {
        await handleSeverityOverride(index, newSeverity, type);
        e.target.value = ''; // Reset dropdown
      }
    });
  });

  // Toggle AI assessment collapse/expand
  container.querySelectorAll('.toggle-ai-assessment-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation(); // Prevent header click from bubbling
      const index = parseInt(e.target.dataset.findingIndex);
      const type = e.target.dataset.findingType;
      const contentDiv = document.getElementById(`ai-assessment-content-${type === 'secret' ? index : 'security-' + index}`);

      if (contentDiv) {
        if (contentDiv.style.display === 'none') {
          contentDiv.style.display = 'block';
          e.target.textContent = '▲ Collapse';
        } else {
          contentDiv.style.display = 'none';
          e.target.textContent = '▼ Expand';
        }
      }
    });
  });

  // Toggle AI assessment by clicking header (alternative to button)
  container.querySelectorAll('.ai-assessment-header-collapsible').forEach(header => {
    header.addEventListener('click', (e) => {
      // Only trigger if not clicking the button itself
      if (!e.target.classList.contains('toggle-ai-assessment-btn')) {
        const btn = header.querySelector('.toggle-ai-assessment-btn');
        if (btn) btn.click();
      }
    });
  });

  // Toggle code context collapse/expand
  container.querySelectorAll('.toggle-code-context-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const index = parseInt(e.target.dataset.findingIndex);
      const contentDiv = document.getElementById(`code-context-content-${index}`);
      if (contentDiv) {
        if (contentDiv.style.display === 'none') {
          contentDiv.style.display = 'block';
          e.target.innerHTML = '&#9650; Collapse';
        } else {
          contentDiv.style.display = 'none';
          e.target.innerHTML = '&#9660; Expand';
        }
      }
    });
  });

  container.querySelectorAll('.code-context-header-collapsible').forEach(header => {
    header.addEventListener('click', (e) => {
      if (!e.target.classList.contains('toggle-code-context-btn')) {
        const btn = header.querySelector('.toggle-code-context-btn');
        if (btn) btn.click();
      }
    });
  });

  // Bulk whitelist: domain
  const bulkDomainBtn = container.querySelector('.bulk-whitelist-domain-btn');
  if (bulkDomainBtn) {
    bulkDomainBtn.addEventListener('click', async () => {
      const tab = await getTargetTab();
      if (!tab?.url) return;
      try {
        const domain = new URL(tab.url).hostname;
        if (!currentWhitelist.domains.includes(domain)) {
          currentWhitelist.domains.push(domain);
          await chrome.storage.sync.set({ whitelist: currentWhitelist });
          displayWhitelist();
          showMessage(`Whitelisted domain: ${domain}. Rescan to apply.`, 'success');
        } else {
          showMessage(`Domain ${domain} is already whitelisted`, 'info');
        }
      } catch (e) {
        showMessage('Could not determine current domain', 'error');
      }
    });
  }

  // Bulk whitelist: by pattern type
  const bulkPatternSelect = container.querySelector('.bulk-whitelist-pattern-select');
  if (bulkPatternSelect) {
    bulkPatternSelect.addEventListener('change', async (e) => {
      const patternName = e.target.value;
      if (!patternName) return;

      // Find all unique values for this pattern and add them as whitelist patterns
      const matchingFindings = currentFindings.filter(f => f.pattern_matched === patternName);
      let added = 0;
      matchingFindings.forEach(f => {
        const val = f.full_key || f.key;
        if (val && !currentWhitelist.patterns.includes(val)) {
          currentWhitelist.patterns.push(val);
          added++;
        }
      });

      if (added > 0) {
        await chrome.storage.sync.set({ whitelist: currentWhitelist });
        displayWhitelist();
        showMessage(`Whitelisted ${added} values from "${patternName}". Rescan to apply.`, 'success');
      } else {
        showMessage('All values already whitelisted', 'info');
      }
      e.target.value = ''; // Reset select
    });
  }

  updateScoreDashboard();
}

// Update statistics
function updateStats(stats) {
  document.getElementById('criticalCount').textContent = stats.critical;
  document.getElementById('highCount').textContent = stats.high;
  document.getElementById('mediumCount').textContent = stats.medium;
  document.getElementById('totalCount').textContent = stats.total;
}

// Update security score dashboard
function updateScoreDashboard() {
  const dashboard = document.getElementById('scoreDashboard');
  if (!dashboard) return;

  // Don't calculate score until security results have been loaded/attempted.
  // Prevents showing a partial score (secrets-only) that jumps when security data arrives.
  if (!securityResultsLoaded) return;

  const hasFindings = currentFindings && currentFindings.length > 0;
  const hasSecurityResults = securityResults && (
    (securityResults.headers && securityResults.headers.length > 0) ||
    (securityResults.cookies && securityResults.cookies.length > 0) ||
    (securityResults.vulnerabilities && securityResults.vulnerabilities.length > 0) ||
    (securityResults.sensitiveFiles && securityResults.sensitiveFiles.length > 0) ||
    (securityResults.sessionState?.issues?.length > 0) ||
    (securityResults.oauthFlows?.issues?.length > 0) ||
    (securityResults.graphql?.issues?.length > 0) ||
    (securityResults.crypto?.issues?.length > 0) ||
    (securityResults.cloudStorage?.issues?.length > 0) ||
    (securityResults.exfiltration?.issues?.length > 0) ||
    (securityResults.websockets?.issues?.length > 0)
  );

  if (!hasFindings && !hasSecurityResults) {
    dashboard.style.display = 'none';
    return;
  }

  const secData = window.currentSecurityFindings || {};
  const data = {
    secrets: currentFindings || [],
    headers: secData.headers || securityResults?.headers || [],
    cookies: secData.cookies || securityResults?.cookies || [],
    vulnerabilities: secData.vulnerabilities || securityResults?.vulnerabilities || [],
    technologies: securityResults?.technologies || null,
    sensitiveFiles: secData.sensitiveFiles || securityResults?.sensitiveFiles || [],
    session: (securityResults?.sessionState?.allIssues?.length > 0
      ? securityResults.sessionState.allIssues
      : securityResults?.sessionState?.issues) || [],
    oauth: securityResults?.oauthFlows?.issues || [],
    graphql: securityResults?.graphql?.issues || [],
    crypto: securityResults?.crypto?.issues || [],
    cloudStorage: securityResults?.cloudStorage?.issues || [],
    exfiltration: securityResults?.exfiltration?.issues || [],
    websocket: securityResults?.websockets?.issues || []
  };

  const scoringConfig = currentSettings?.scoring_config || {
    types: { secrets: true, headers: true, cookies: true, vulnerabilities: true, sensitiveFiles: true, sca: true, session: true, oauth: true, graphql: true, crypto: true, cloudStorage: true, exfiltration: true, websocket: true },
    severities: { critical: true, high: true, medium: true, low: true }
  };
  const result = SecurityScorer.calculate(data, scoringConfig);

  // Update score number
  const scoreNumber = document.getElementById('scoreNumber');
  const scoreGrade = document.getElementById('scoreGrade');
  scoreNumber.textContent = result.score;
  scoreGrade.textContent = result.grade;

  // Set color based on score
  let scoreColor;
  if (result.score >= 80) scoreColor = '#22c55e';
  else if (result.score >= 55) scoreColor = '#ffc107';
  else if (result.score >= 40) scoreColor = '#fd7e14';
  else scoreColor = '#ef4444';

  // Color the score number to match
  scoreNumber.style.color = scoreColor;

  // Animate the horizontal bar
  const barFill = document.getElementById('scoreBarFill');
  const displayScore = Math.max(result.score, 2);
  barFill.style.width = displayScore + '%';
  barFill.style.backgroundColor = scoreColor;

  // Update breakdown chips
  const breakdownEl = document.getElementById('scoreBreakdown');
  const categories = [
    { key: 'secrets', label: 'Secrets' },
    { key: 'headers', label: 'Headers' },
    { key: 'cookies', label: 'Cookies' },
    { key: 'vulnerabilities', label: 'Vulns' },
    { key: 'sensitiveFiles', label: 'Files' },
    { key: 'sca', label: 'SCA' },
    { key: 'session', label: 'Session' },
    { key: 'oauth', label: 'OAuth' },
    { key: 'graphql', label: 'GraphQL' },
    { key: 'crypto', label: 'Crypto' },
    { key: 'cloudStorage', label: 'Cloud' },
    { key: 'exfiltration', label: 'Exfil' },
    { key: 'websocket', label: 'WS' }
  ];

  let breakdownHtml = '';
  categories.forEach(cat => {
    const info = result.breakdown[cat.key];
    let cls = 'good';
    if (info.deductions >= 25) cls = 'bad';
    else if (info.deductions > 0) cls = 'warn';

    breakdownHtml += `<div class="score-category ${cls}">` +
      `${cat.label} <span class="cat-count">${info.findings}</span></div>`;
  });
  breakdownEl.innerHTML = breakdownHtml;

  dashboard.style.display = 'block';
}

// Filter findings
function filterFindings() {
  const searchTerm = document.getElementById('searchInput').value.toLowerCase();
  
  if (!searchTerm) {
    displayFindings(currentFindings);
    return;
  }
  
  const filtered = currentFindings.filter(finding => 
    finding.full_key.toLowerCase().includes(searchTerm) ||
    finding.url.toLowerCase().includes(searchTerm) ||
    (finding.pattern_matched && finding.pattern_matched.toLowerCase().includes(searchTerm))
  );
  
  displayFindings(filtered);
}

// Open report modal (redirects to Reports tab)
function openReportModal() {
  if (!currentFindings || currentFindings.length === 0) {
    showMessage('No findings to export', 'info');
    return;
  }

  // Switch to Reports tab instead of opening modal
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabPanes = document.querySelectorAll('.tab-pane');

  tabBtns.forEach(btn => {
    if (btn.dataset.tab === 'reports') {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });

  tabPanes.forEach(pane => {
    if (pane.id === 'reports-tab') {
      pane.classList.add('active');
      // Update report summary when switching to Reports tab
      updateReportSummary();
    } else {
      pane.classList.remove('active');
    }
  });

  showMessage('Use the Reports tab to generate professional security reports', 'info');
}

// Close report modal
function closeReportModal() {
  const modal = document.getElementById('reportModal');
  modal.style.display = 'none';
}

// Populate LLM models for report
async function populateReportLLMModels() {
  const llmSettings = await getLLMSettings();
  const modelSelect = document.getElementById('reportLLMModel');
  
  modelSelect.innerHTML = '';
  
  if (llmSettings.provider === 'none' || !llmSettings.enabled) {
    modelSelect.innerHTML = '<option value="">LLM not configured</option>';
    modelSelect.disabled = true;
    document.getElementById('includeLLM').disabled = true;
    document.getElementById('includeLLM').checked = false;
    return;
  }
  
  document.getElementById('includeLLM').disabled = false;
  modelSelect.disabled = false;
  
  const models = LLMManager.getAvailableModels(llmSettings.provider);
  models.forEach(model => {
    const option = document.createElement('option');
    option.value = model.id;
    option.textContent = model.name;
    if (model.id === llmSettings.model) {
      option.selected = true;
    }
    modelSelect.appendChild(option);
  });
}

// Export findings (legacy - for backward compatibility)
function exportFindings() {
  openReportModal();
}

// Export as JSON
function exportAsJSON() {
  const data = JSON.stringify(currentFindings, null, 2);
  downloadFile(data, `origami-findings-${Date.now()}.json`, 'application/json');
  showMessage('Exported as JSON', 'success');
}

// Export as CSV
function exportAsCSV() {
  const headers = ['Risk', 'Pattern', 'Secret (truncated)', 'Full Secret', 'URL'];
  const rows = currentFindings.map(f => [
    f.risk,
    f.pattern_matched || 'Generic',
    f.key,
    f.full_key,
    f.url
  ]);
  
  const csv = [headers, ...rows]
    .map(row => row.map(cell => `"${cell.replace(/"/g, '""')}"`).join(','))
    .join('\n');
  
  downloadFile(csv, `origami-findings-${Date.now()}.csv`, 'text/csv');
  showMessage('Exported as CSV', 'success');
}

// Clear findings
async function clearFindings() {
  if (!confirm('Clear all findings for this page?')) return;
  
  const tab = await getTargetTab();
  chrome.runtime.sendMessage({ action: 'clearTabFindings', tabId: tab.id }, () => {
    currentFindings = [];
    displayFindings([]);
    showMessage('Findings cleared', 'success');
  });
}

// Load settings
async function loadSettings() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(['settings'], (data) => {
      currentSettings = data.settings || {
        notifications_enabled: true,
        badge_enabled: true,
        badge_count_filter: 'critical_high',
        badge_type_filter: {
          secrets: true, headers: true, cookies: true, vulnerabilities: true,
          sensitiveFiles: true, session: true, oauth: true, graphql: true,
          crypto: true, cloudStorage: true, exfiltration: true, websocket: true
        },
        auto_scan_enabled: true,
        auto_scan_sensitive_files: true,
        webhook: { enabled: false, url: '', method: 'POST', params: {} },
        custom_patterns: [],
        history_enabled: true,
        api_validation: {
          enabled: true,
          auto_test: false,
          use_referer: true,
          quick_test_only: true
        },
        vuln_scanning: {
          scan_libraries: false,
          scan_minified: false
        },
        cve_checking: {
          enabled: true,
          severity_filter: 'all',
          show_eol_warnings: true
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
        ai_assessment: {
          types: {
            secrets: true, headers: true, cookies: true, vulnerabilities: true,
            sca: true, exposedFiles: true, session: true, oauth: true,
            graphql: true, crypto: true, cloudStorage: true, exfiltration: true,
            websocket: true
          },
          severities: {
            critical: true,
            high: true,
            medium: false,
            low: false,
            info: false
          },
          skip_assessed: true
        },
        scoring_config: {
          types: { secrets: true, headers: true, cookies: true, vulnerabilities: true, sensitiveFiles: true, sca: true, session: true, oauth: true, graphql: true, crypto: true, cloudStorage: true, exfiltration: true, websocket: true },
          severities: { critical: true, high: true, medium: true, low: true }
        },
        analyzers: {
          session: true, oauth: true, graphql: true, crypto: true,
          cloudStorage: true, exfiltration: true, websocket: true,
          correlationEngine: true, surfaceTracker: true
        }
      };
      
      // Populate form
      document.getElementById('notificationsEnabled').checked = currentSettings.notifications_enabled;
      document.getElementById('badgeEnabled').checked = currentSettings.badge_enabled;
      document.getElementById('badgeCountFilter').value = currentSettings.badge_count_filter || 'critical_high';
      const badgeTypeFilter = currentSettings.badge_type_filter || { secrets: true, headers: true, cookies: true, vulnerabilities: true, sensitiveFiles: true, session: true, oauth: true, graphql: true, crypto: true, cloudStorage: true, exfiltration: true, websocket: true };
      document.getElementById('badgeTypeSecrets').checked = badgeTypeFilter.secrets !== false;
      document.getElementById('badgeTypeHeaders').checked = badgeTypeFilter.headers !== false;
      document.getElementById('badgeTypeCookies').checked = badgeTypeFilter.cookies !== false;
      document.getElementById('badgeTypeVulnerabilities').checked = badgeTypeFilter.vulnerabilities !== false;
      document.getElementById('badgeTypeSensitiveFiles').checked = badgeTypeFilter.sensitiveFiles !== false;
      document.getElementById('badgeTypeSession').checked = badgeTypeFilter.session !== false;
      document.getElementById('badgeTypeOAuth').checked = badgeTypeFilter.oauth !== false;
      document.getElementById('badgeTypeGraphQL').checked = badgeTypeFilter.graphql !== false;
      document.getElementById('badgeTypeCrypto').checked = badgeTypeFilter.crypto !== false;
      document.getElementById('badgeTypeCloudStorage').checked = badgeTypeFilter.cloudStorage !== false;
      document.getElementById('badgeTypeExfiltration').checked = badgeTypeFilter.exfiltration !== false;
      document.getElementById('badgeTypeWebSocket').checked = badgeTypeFilter.websocket !== false;
      document.getElementById('autoScanEnabled').checked = currentSettings.auto_scan_enabled !== false;
      document.getElementById('autoScanSensitiveFiles').checked = currentSettings.auto_scan_sensitive_files !== false;
      document.getElementById('autoScanSensitiveFiles').disabled = !document.getElementById('autoScanEnabled').checked;
      document.getElementById('webhookEnabled').checked = currentSettings.webhook?.enabled || false;
      document.getElementById('webhookUrl').value = currentSettings.webhook?.url || '';
      document.getElementById('webhookMethod').value = currentSettings.webhook?.method || 'POST';
      document.getElementById('webhookParams').value = JSON.stringify(currentSettings.webhook?.params || {}, null, 2);
      document.getElementById('historyEnabled').checked = currentSettings.history_enabled !== false;
      
      // API Validation settings (deprecated - now handled by API Testing tab)

      // Vulnerability Scanning settings
      const vulnScan = currentSettings.vuln_scanning || { scan_libraries: false, scan_minified: false };
      document.getElementById('scanLibrariesEnabled').checked = vulnScan.scan_libraries || false;
      document.getElementById('scanMinifiedEnabled').checked = vulnScan.scan_minified || false;

      // CVE/EOL Checking settings
      const cveChecking = currentSettings.cve_checking || {
        enabled: true,
        severity_filter: 'all',
        show_eol_warnings: true
      };
      document.getElementById('cveCheckingEnabled').checked = cveChecking.enabled !== false;
      document.getElementById('cveShowEolWarnings').checked = cveChecking.show_eol_warnings !== false;
      document.getElementById('cveSeverityFilter').value = cveChecking.severity_filter || 'all';

      // LLM settings
      const llm = currentSettings.llm || {};
      document.getElementById('llmProvider').value = llm.provider || 'none';
      if (llm.apiKey) {
        document.getElementById('llmApiKey').value = llm.apiKey;
      }
      if (llm.endpoint) {
        document.getElementById('ollamaEndpoint').value = llm.endpoint;
      }
      
      // Trigger provider change to update UI
      handleLLMProviderChange();
      
      // Set model after provider is set
      if (llm.model) {
        setTimeout(() => {
          document.getElementById('llmModel').value = llm.model;
        }, 100);
      }

      // AI Assessment settings
      const aiAssess = currentSettings.ai_assessment || {
        types: { secrets: true, headers: true, cookies: true, vulnerabilities: true, sca: true, exposedFiles: true, session: true, oauth: true, graphql: true, crypto: true, cloudStorage: true, exfiltration: true, websocket: true },
        severities: { critical: true, high: true, medium: false, low: false, info: false },
        skip_assessed: true
      };
      document.getElementById('aiAssessSecrets').checked = aiAssess.types.secrets !== false;
      document.getElementById('aiAssessHeaders').checked = aiAssess.types.headers !== false;
      document.getElementById('aiAssessCookies').checked = aiAssess.types.cookies !== false;
      document.getElementById('aiAssessVulnerabilities').checked = aiAssess.types.vulnerabilities !== false;
      document.getElementById('aiAssessSCA').checked = aiAssess.types.sca !== false;
      document.getElementById('aiAssessExposedFiles').checked = aiAssess.types.exposedFiles !== false;
      document.getElementById('aiAssessSession').checked = aiAssess.types.session !== false;
      document.getElementById('aiAssessOAuth').checked = aiAssess.types.oauth !== false;
      document.getElementById('aiAssessGraphQL').checked = aiAssess.types.graphql !== false;
      document.getElementById('aiAssessCrypto').checked = aiAssess.types.crypto !== false;
      document.getElementById('aiAssessCloudStorage').checked = aiAssess.types.cloudStorage !== false;
      document.getElementById('aiAssessExfiltration').checked = aiAssess.types.exfiltration !== false;
      document.getElementById('aiAssessWebSocket').checked = aiAssess.types.websocket !== false;
      document.getElementById('aiAssessCorrelationChains').checked = aiAssess.types.correlationChains !== false;
      document.getElementById('aiAssessCritical').checked = aiAssess.severities.critical === true;
      document.getElementById('aiAssessHigh').checked = aiAssess.severities.high === true;
      document.getElementById('aiAssessMedium').checked = aiAssess.severities.medium === true;
      document.getElementById('aiAssessLow').checked = aiAssess.severities.low === true;
      document.getElementById('aiAssessInfo').checked = aiAssess.severities.info === true;
      document.getElementById('aiAssessSkipAssessed').checked = aiAssess.skip_assessed !== false;

      // Concurrency slider
      const concSlider = document.getElementById('aiAssessConcurrency');
      const concValue = document.getElementById('aiAssessConcurrencyValue');
      if (concSlider) {
        concSlider.value = aiAssess.concurrent_assessments || 3;
        if (concValue) concValue.textContent = concSlider.value;
      }

      // Max AI Partner Iterations slider
      const maxIterSlider = document.getElementById('aiMaxIterations');
      const maxIterValue = document.getElementById('aiMaxIterationsValue');
      if (maxIterSlider) {
        maxIterSlider.value = llm.maxToolIterations || 30;
        if (maxIterValue) maxIterValue.textContent = maxIterSlider.value;
      }

      // Scoring config settings
      const scoringConfig = currentSettings.scoring_config || {
        types: { secrets: true, headers: true, cookies: true, vulnerabilities: true, sensitiveFiles: true, sca: true, session: true, oauth: true, graphql: true, crypto: true, cloudStorage: true, exfiltration: true, websocket: true },
        severities: { critical: true, high: true, medium: true, low: true }
      };
      document.getElementById('scoreSecrets').checked = scoringConfig.types.secrets !== false;
      document.getElementById('scoreHeaders').checked = scoringConfig.types.headers !== false;
      document.getElementById('scoreCookies').checked = scoringConfig.types.cookies !== false;
      document.getElementById('scoreVulnerabilities').checked = scoringConfig.types.vulnerabilities !== false;
      document.getElementById('scoreSensitiveFiles').checked = scoringConfig.types.sensitiveFiles !== false;
      document.getElementById('scoreSCA').checked = scoringConfig.types.sca !== false;
      document.getElementById('scoreSession').checked = scoringConfig.types.session !== false;
      document.getElementById('scoreOAuth').checked = scoringConfig.types.oauth !== false;
      document.getElementById('scoreGraphQL').checked = scoringConfig.types.graphql !== false;
      document.getElementById('scoreCrypto').checked = scoringConfig.types.crypto !== false;
      document.getElementById('scoreCloudStorage').checked = scoringConfig.types.cloudStorage !== false;
      document.getElementById('scoreExfiltration').checked = scoringConfig.types.exfiltration !== false;
      document.getElementById('scoreWebSocket').checked = scoringConfig.types.websocket !== false;
      document.getElementById('scoreCritical').checked = scoringConfig.severities.critical !== false;
      document.getElementById('scoreHigh').checked = scoringConfig.severities.high !== false;
      document.getElementById('scoreMedium').checked = scoringConfig.severities.medium !== false;
      document.getElementById('scoreLow').checked = scoringConfig.severities.low !== false;

      // MCP Bridge settings
      const mcpBridge = currentSettings.mcpBridge || { enabled: false, wsUrl: 'ws://127.0.0.1:9340' };
      const mcpEnabledEl = document.getElementById('mcpBridgeEnabled');
      const mcpUrlEl = document.getElementById('mcpBridgeUrl');
      const mcpTokenEl = document.getElementById('mcpBridgeToken');
      if (mcpEnabledEl) mcpEnabledEl.checked = mcpBridge.enabled || false;
      if (mcpUrlEl) mcpUrlEl.value = mcpBridge.wsUrl || 'ws://127.0.0.1:9340';
      if (mcpTokenEl) mcpTokenEl.value = mcpBridge.wsToken || '';

      // Analyzer toggles
      const analyzers = currentSettings.analyzers || { session: true, oauth: true, graphql: true, crypto: true, cloudStorage: true, exfiltration: true, websocket: true, correlationEngine: true, surfaceTracker: true };
      document.getElementById('analyzerSession').checked = analyzers.session !== false;
      document.getElementById('analyzerOAuth').checked = analyzers.oauth !== false;
      document.getElementById('analyzerGraphQL').checked = analyzers.graphql !== false;
      document.getElementById('analyzerCrypto').checked = analyzers.crypto !== false;
      document.getElementById('analyzerCloudStorage').checked = analyzers.cloudStorage !== false;
      document.getElementById('analyzerExfiltration').checked = analyzers.exfiltration !== false;
      document.getElementById('analyzerWebSocket').checked = analyzers.websocket !== false;
      document.getElementById('analyzerCorrelationEngine').checked = analyzers.correlationEngine !== false;
      document.getElementById('analyzerSurfaceTracker').checked = analyzers.surfaceTracker !== false;

      // Update AI Assess All button tooltip
      updateAIAssessButtonTooltip();

      resolve();
    });
  });
}

// Update AI Assess All button tooltip based on configuration
function updateAIAssessButtonTooltip() {
  const aiConfig = currentSettings.ai_assessment || {
    types: { secrets: true, headers: true, cookies: true, vulnerabilities: true, sca: true, exposedFiles: true, session: true, oauth: true, graphql: true, crypto: true, cloudStorage: true, exfiltration: true, websocket: true, correlationChains: true },
    severities: { critical: true, high: true, medium: false, low: false, info: false },
    skip_assessed: true
  };

  // Build types list
  const enabledTypes = [];
  if (aiConfig.types.secrets) enabledTypes.push('Secrets');
  if (aiConfig.types.headers) enabledTypes.push('Headers');
  if (aiConfig.types.cookies) enabledTypes.push('Cookies');
  if (aiConfig.types.vulnerabilities) enabledTypes.push('Vulnerabilities');
  if (aiConfig.types.sca) enabledTypes.push('Software Composition (CVE/EOL)');
  if (aiConfig.types.exposedFiles) enabledTypes.push('Exposed Files');
  if (aiConfig.types.session) enabledTypes.push('Session Analysis');
  if (aiConfig.types.oauth) enabledTypes.push('OAuth/SAML');
  if (aiConfig.types.graphql) enabledTypes.push('GraphQL');
  if (aiConfig.types.crypto) enabledTypes.push('Crypto Audit');
  if (aiConfig.types.cloudStorage) enabledTypes.push('Cloud Storage');
  if (aiConfig.types.exfiltration) enabledTypes.push('Exfiltration');
  if (aiConfig.types.websocket) enabledTypes.push('WebSocket');
  if (aiConfig.types.correlationChains) enabledTypes.push('Attack Chains');

  // Build severities list
  const enabledSeverities = [];
  if (aiConfig.severities.critical) enabledSeverities.push('Critical');
  if (aiConfig.severities.high) enabledSeverities.push('High');
  if (aiConfig.severities.medium) enabledSeverities.push('Medium');
  if (aiConfig.severities.low) enabledSeverities.push('Low');
  if (aiConfig.severities.info) enabledSeverities.push('Info');

  // Build tooltip
  let tooltip = 'AI Assess All findings systematically\n\n';
  tooltip += `Types: ${enabledTypes.join(', ') || 'None'}\n`;
  tooltip += `Severities: ${enabledSeverities.join(', ') || 'None'}\n`;
  tooltip += `Skip assessed: ${aiConfig.skip_assessed ? 'Yes' : 'No'}\n\n`;
  tooltip += 'Configure in Settings tab';

  const btn = document.getElementById('aiAssessAllBtn');
  if (btn) {
    btn.title = tooltip;
  }
}

// Save settings
function saveSettings() {
  try {
    const webhookParams = document.getElementById('webhookParams').value;
    let parsedParams = {};
    
    if (webhookParams.trim()) {
      parsedParams = JSON.parse(webhookParams);
    }
    
    // Preserve settings managed by other tabs (not present in main settings form)
    const preservedGoogleApiTesting = currentSettings.googleApiTesting;
    const preservedApiValidation = currentSettings.api_validation;

    currentSettings = {
      notifications_enabled: document.getElementById('notificationsEnabled').checked,
      badge_enabled: document.getElementById('badgeEnabled').checked,
      badge_count_filter: document.getElementById('badgeCountFilter').value,
      badge_type_filter: {
        secrets: document.getElementById('badgeTypeSecrets').checked,
        headers: document.getElementById('badgeTypeHeaders').checked,
        cookies: document.getElementById('badgeTypeCookies').checked,
        vulnerabilities: document.getElementById('badgeTypeVulnerabilities').checked,
        sensitiveFiles: document.getElementById('badgeTypeSensitiveFiles').checked,
        session: document.getElementById('badgeTypeSession').checked,
        oauth: document.getElementById('badgeTypeOAuth').checked,
        graphql: document.getElementById('badgeTypeGraphQL').checked,
        crypto: document.getElementById('badgeTypeCrypto').checked,
        cloudStorage: document.getElementById('badgeTypeCloudStorage').checked,
        exfiltration: document.getElementById('badgeTypeExfiltration').checked,
        websocket: document.getElementById('badgeTypeWebSocket').checked
      },
      auto_scan_enabled: document.getElementById('autoScanEnabled').checked,
      auto_scan_sensitive_files: document.getElementById('autoScanSensitiveFiles').checked,
      webhook: {
        enabled: document.getElementById('webhookEnabled').checked,
        url: document.getElementById('webhookUrl').value,
        method: document.getElementById('webhookMethod').value,
        params: parsedParams
      },
      custom_patterns: currentSettings.custom_patterns || [],
      history_enabled: document.getElementById('historyEnabled').checked,
      vuln_scanning: {
        scan_libraries: document.getElementById('scanLibrariesEnabled').checked,
        scan_minified: document.getElementById('scanMinifiedEnabled').checked
      },
      cve_checking: {
        enabled: document.getElementById('cveCheckingEnabled').checked,
        severity_filter: document.getElementById('cveSeverityFilter').value,
        show_eol_warnings: document.getElementById('cveShowEolWarnings').checked
      },
      llm: {
        enabled: document.getElementById('llmProvider').value !== 'none',
        provider: document.getElementById('llmProvider').value,
        model: document.getElementById('llmModel').value,
        apiKey: document.getElementById('llmApiKey').value,
        endpoint: document.getElementById('llmProvider').value === 'ollama' ? document.getElementById('ollamaEndpoint').value : null,
        temperature: 0.3,
        maxTokens: 2000,
        maxToolIterations: parseInt(document.getElementById('aiMaxIterations')?.value || '30', 10)
      },
      ai_assessment: {
        types: {
          secrets: document.getElementById('aiAssessSecrets').checked,
          headers: document.getElementById('aiAssessHeaders').checked,
          cookies: document.getElementById('aiAssessCookies').checked,
          vulnerabilities: document.getElementById('aiAssessVulnerabilities').checked,
          sca: document.getElementById('aiAssessSCA').checked,
          exposedFiles: document.getElementById('aiAssessExposedFiles').checked,
          session: document.getElementById('aiAssessSession').checked,
          oauth: document.getElementById('aiAssessOAuth').checked,
          graphql: document.getElementById('aiAssessGraphQL').checked,
          crypto: document.getElementById('aiAssessCrypto').checked,
          cloudStorage: document.getElementById('aiAssessCloudStorage').checked,
          exfiltration: document.getElementById('aiAssessExfiltration').checked,
          websocket: document.getElementById('aiAssessWebSocket').checked,
          correlationChains: document.getElementById('aiAssessCorrelationChains').checked
        },
        severities: {
          critical: document.getElementById('aiAssessCritical').checked,
          high: document.getElementById('aiAssessHigh').checked,
          medium: document.getElementById('aiAssessMedium').checked,
          low: document.getElementById('aiAssessLow').checked,
          info: document.getElementById('aiAssessInfo').checked
        },
        skip_assessed: document.getElementById('aiAssessSkipAssessed').checked,
        concurrent_assessments: parseInt(document.getElementById('aiAssessConcurrency')?.value || '3', 10)
      },
      scoring_config: {
        types: {
          secrets: document.getElementById('scoreSecrets').checked,
          headers: document.getElementById('scoreHeaders').checked,
          cookies: document.getElementById('scoreCookies').checked,
          vulnerabilities: document.getElementById('scoreVulnerabilities').checked,
          sensitiveFiles: document.getElementById('scoreSensitiveFiles').checked,
          sca: document.getElementById('scoreSCA').checked,
          session: document.getElementById('scoreSession').checked,
          oauth: document.getElementById('scoreOAuth').checked,
          graphql: document.getElementById('scoreGraphQL').checked,
          crypto: document.getElementById('scoreCrypto').checked,
          cloudStorage: document.getElementById('scoreCloudStorage').checked,
          exfiltration: document.getElementById('scoreExfiltration').checked,
          websocket: document.getElementById('scoreWebSocket').checked
        },
        severities: {
          critical: document.getElementById('scoreCritical').checked,
          high: document.getElementById('scoreHigh').checked,
          medium: document.getElementById('scoreMedium').checked,
          low: document.getElementById('scoreLow').checked
        }
      },
      analyzers: {
        session: document.getElementById('analyzerSession').checked,
        oauth: document.getElementById('analyzerOAuth').checked,
        graphql: document.getElementById('analyzerGraphQL').checked,
        crypto: document.getElementById('analyzerCrypto').checked,
        cloudStorage: document.getElementById('analyzerCloudStorage').checked,
        exfiltration: document.getElementById('analyzerExfiltration').checked,
        websocket: document.getElementById('analyzerWebSocket').checked,
        correlationEngine: document.getElementById('analyzerCorrelationEngine').checked,
        surfaceTracker: document.getElementById('analyzerSurfaceTracker').checked
      },
      mcpBridge: {
        enabled: document.getElementById('mcpBridgeEnabled')?.checked || false,
        wsUrl: document.getElementById('mcpBridgeUrl')?.value || 'ws://127.0.0.1:9340',
        wsToken: document.getElementById('mcpBridgeToken')?.value || ''
      },
      ...(preservedGoogleApiTesting && { googleApiTesting: preservedGoogleApiTesting }),
      ...(preservedApiValidation && { api_validation: preservedApiValidation })
    };
    
    chrome.storage.sync.set({ settings: currentSettings }, () => {
      // Update AI Assess All button tooltip
      updateAIAssessButtonTooltip();
      showMessage('Settings saved successfully!', 'success');
    });
  } catch (error) {
    showMessage('Error: Invalid JSON in webhook parameters', 'error');
  }
}

// Reset settings
function resetSettings() {
  if (!confirm('Reset all settings to defaults?')) return;

  const defaults = {
    notifications_enabled: true,
    badge_enabled: true,
    badge_count_filter: 'critical_high',
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
      websocket: true
    },
    auto_scan_enabled: true,
    auto_scan_sensitive_files: true,
    webhook: { enabled: false, url: '', method: 'POST', params: {} },
    custom_patterns: [],
    history_enabled: true,
    api_validation: {
      enabled: true,
      auto_test: false,
      use_referer: true,
      quick_test_only: true
    },
    vuln_scanning: {
      scan_libraries: false,
      scan_minified: false
    },
    cve_checking: {
      enabled: true,
      severity_filter: 'all',
      show_eol_warnings: true
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
    googleApiTesting: {
      selectedServices: {
        'youtube': true, 'maps-static': true, 'geolocation': true,
        'custom-search': true, 'firebase-auth': true, 'translation': true,
        'books': true, 'timezone': true, 'directions': true,
        'places': true, 'geocoding': true, 'distance-matrix': true,
        'elevation': true, 'pagespeed': true, 'fonts': true,
        'vertex-ai': true, 'gemini': true, 'vision': true,
        'speech': true, 'video-intelligence': true, 'natural-language': true,
        'text-to-speech': true, 'resource-manager': true, 'compute-engine': true,
        'cloud-storage': true, 'secret-manager': true, 'bigquery': true
      },
      activePreset: 'all',
      discoveredProjects: [],
      skipExpensiveTests: true,
      maxTestsPerScan: 27
    },
    ai_assessment: {
      types: {
        secrets: true,
        headers: true,
        cookies: true,
        vulnerabilities: true,
        sca: true,
        exposedFiles: true,
        session: true,
        oauth: true,
        graphql: true,
        crypto: true,
        cloudStorage: true,
        exfiltration: true,
        websocket: true
      },
      severities: {
        critical: true,
        high: true,
        medium: false,
        low: false,
        info: false
      },
      skip_assessed: true,
      concurrent_assessments: 3
    },
    scoring_config: {
      types: { secrets: true, headers: true, cookies: true, vulnerabilities: true, sensitiveFiles: true, sca: true, session: true, oauth: true, graphql: true, crypto: true, cloudStorage: true, exfiltration: true, websocket: true },
      severities: { critical: true, high: true, medium: true, low: true }
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
      surfaceTracker: true
    }
  };

  chrome.storage.sync.set({ settings: defaults }, () => {
    loadSettings();
    showMessage('Settings reset to defaults', 'success');
  });
}

// Reset AI Assessment configuration only
function resetAIAssessmentConfig() {
  const aiAssessDefaults = {
    types: {
      secrets: true,
      headers: true,
      cookies: true,
      vulnerabilities: true,
      sca: true,
      exposedFiles: true,
      session: true,
      oauth: true,
      graphql: true,
      crypto: true,
      cloudStorage: true,
      exfiltration: true,
      websocket: true,
      correlationChains: true
    },
    severities: {
      critical: true,
      high: true,
      medium: false,
      low: false,
      info: false
    },
    skip_assessed: true,
    concurrent_assessments: 3
  };

  // Update current settings
  currentSettings.ai_assessment = aiAssessDefaults;

  // Save to storage
  chrome.storage.sync.set({ settings: currentSettings }, () => {
    // Update UI
    document.getElementById('aiAssessSecrets').checked = true;
    document.getElementById('aiAssessHeaders').checked = true;
    document.getElementById('aiAssessCookies').checked = true;
    document.getElementById('aiAssessVulnerabilities').checked = true;
    document.getElementById('aiAssessSCA').checked = true;
    document.getElementById('aiAssessExposedFiles').checked = true;
    document.getElementById('aiAssessSession').checked = true;
    document.getElementById('aiAssessOAuth').checked = true;
    document.getElementById('aiAssessGraphQL').checked = true;
    document.getElementById('aiAssessCrypto').checked = true;
    document.getElementById('aiAssessCloudStorage').checked = true;
    document.getElementById('aiAssessExfiltration').checked = true;
    document.getElementById('aiAssessWebSocket').checked = true;
    document.getElementById('aiAssessCorrelationChains').checked = true;
    document.getElementById('aiAssessCritical').checked = true;
    document.getElementById('aiAssessHigh').checked = true;
    document.getElementById('aiAssessMedium').checked = false;
    document.getElementById('aiAssessLow').checked = false;
    document.getElementById('aiAssessInfo').checked = false;
    document.getElementById('aiAssessSkipAssessed').checked = true;
    const concSliderEl = document.getElementById('aiAssessConcurrency');
    if (concSliderEl) {
      concSliderEl.value = 3;
      const concValEl = document.getElementById('aiAssessConcurrencyValue');
      if (concValEl) concValEl.textContent = '3';
    }

    // Update AI Assess All button tooltip
    updateAIAssessButtonTooltip();

    showMessage('AI Assessment config reset to defaults', 'success');
  });
}

// Load CVE cache statistics
function loadCVECacheStats() {
  chrome.runtime.sendMessage({ action: 'getCVECacheStats' }, (response) => {
    if (response && response.stats) {
      document.getElementById('cacheEntries').textContent = response.stats.entries || '0';
      document.getElementById('cacheSize').textContent = response.stats.sizeMB || '0.00 MB';
    } else if (response && response.error) {
      document.getElementById('cacheEntries').textContent = 'Error';
      document.getElementById('cacheSize').textContent = 'Error';
      console.error('Failed to load cache stats:', response.error);
    }
  });
}

// Clear CVE cache
function clearCVECache() {
  if (!confirm('Clear all CVE cache data? This will force re-checking all technologies on next scan.')) {
    return;
  }

  chrome.runtime.sendMessage({ action: 'clearCVECache' }, (response) => {
    if (response && response.success) {
      showMessage(`CVE cache cleared successfully!`, 'success');
      // Reload cache stats to show 0 entries
      loadCVECacheStats();
    } else if (response && response.error) {
      showMessage(`Failed to clear cache: ${response.error}`, 'error');
    }
  });
}

// Test webhook
async function testWebhook() {
  const url = document.getElementById('webhookUrl').value;
  if (!url) {
    showMessage('Please enter a webhook URL', 'error');
    return;
  }
  
  const method = document.getElementById('webhookMethod').value;
  let params = {};
  
  try {
    const paramsText = document.getElementById('webhookParams').value;
    if (paramsText.trim()) {
      params = JSON.parse(paramsText);
    }
  } catch (e) {
    showMessage('Invalid JSON in custom parameters', 'error');
    return;
  }
  
  const testPayload = {
    timestamp: new Date().toISOString(),
    url: 'https://example.com/test',
    domain: 'example.com',
    findings: [
      {
        key: 'test_secret_12..._truncated',
        full_key: 'test_secret_1234567890',
        risk: 'MEDIUM',
        pattern_matched: 'Test Pattern'
      }
    ],
    summary: { total: 1, critical: 0, high: 0, medium: 1 },
    ...params
  };
  
  try {
    const response = await fetch(url, {
      method: method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(testPayload)
    });
    
    if (response.ok) {
      showMessage(`Webhook test successful! Status: ${response.status}`, 'success');
    } else {
      showMessage(`Webhook test failed. Status: ${response.status}`, 'error');
    }
  } catch (error) {
    showMessage(`Webhook test failed: ${error.message}`, 'error');
  }
}

// Load whitelist
async function loadWhitelist() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(['whitelist'], (data) => {
      currentWhitelist = data.whitelist || { domains: [], patterns: [] };
      displayWhitelist();
      resolve();
    });
  });
}

// Display whitelist
function displayWhitelist() {
  const domainsContainer = document.getElementById('whitelistedDomains');
  const patternsContainer = document.getElementById('whitelistedPatterns');
  
  domainsContainer.innerHTML = currentWhitelist.domains.map((domain, index) => `
    <div class="tag">
      <span>${escapeHtml(domain)}</span>
      <button class="tag-remove" data-type="domain" data-index="${index}">✕</button>
    </div>
  `).join('');
  
  patternsContainer.innerHTML = currentWhitelist.patterns.map((pattern, index) => `
    <div class="tag">
      <span>${escapeHtml(pattern)}</span>
      <button class="tag-remove" data-type="pattern" data-index="${index}">✕</button>
    </div>
  `).join('');
  
  // Add remove listeners
  document.querySelectorAll('.tag-remove').forEach(btn => {
    btn.addEventListener('click', removeWhitelistItem);
  });
}

// Add whitelist domain
function addWhitelistDomain() {
  const input = document.getElementById('whitelistDomainInput');
  const domain = input.value.trim();
  
  if (!domain) return;
  
  if (!currentWhitelist.domains.includes(domain)) {
    currentWhitelist.domains.push(domain);
    chrome.storage.sync.set({ whitelist: currentWhitelist }, () => {
      displayWhitelist();
      input.value = '';
      showMessage('Domain added to whitelist', 'success');
    });
  } else {
    showMessage('Domain already in whitelist', 'info');
  }
}

// Add whitelist pattern
function addWhitelistPattern() {
  const input = document.getElementById('whitelistPatternInput');
  const pattern = input.value.trim();
  
  if (!pattern) return;
  
  if (!currentWhitelist.patterns.includes(pattern)) {
    currentWhitelist.patterns.push(pattern);
    chrome.storage.sync.set({ whitelist: currentWhitelist }, () => {
      displayWhitelist();
      input.value = '';
      showMessage('Pattern added to whitelist', 'success');
    });
  } else {
    showMessage('Pattern already in whitelist', 'info');
  }
}

// Remove whitelist item
function removeWhitelistItem(e) {
  const type = e.target.dataset.type;
  const index = parseInt(e.target.dataset.index);
  
  if (type === 'domain') {
    currentWhitelist.domains.splice(index, 1);
  } else {
    currentWhitelist.patterns.splice(index, 1);
  }
  
  chrome.storage.sync.set({ whitelist: currentWhitelist }, () => {
    displayWhitelist();
    showMessage('Removed from whitelist', 'success');
  });
}


// Load history
async function loadHistory() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['history'], (data) => {
      currentHistory = data.history || [];
      displayHistory(currentHistory);
      resolve();
    });
  });
}

// Display history
function displayHistory(history) {
  const container = document.getElementById('historyContainer');
  
  if (!history || history.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <p>No history yet.</p>
        <p class="empty-hint">Scan results will appear here when history is enabled.</p>
      </div>
    `;
    return;
  }
  
  container.innerHTML = history.map((entry, index) => `
    <div class="history-item">
      <div class="history-header">
        <div class="history-domain">${escapeHtml(entry.domain)}</div>
        <div class="history-timestamp">${formatDate(entry.timestamp)}</div>
      </div>
      <div class="history-summary">
        ${entry.risk_summary.critical > 0 ? `<span class="critical">Critical: ${entry.risk_summary.critical}</span>` : ''}
        ${entry.risk_summary.high > 0 ? `<span class="high">High: ${entry.risk_summary.high}</span>` : ''}
        ${entry.risk_summary.medium > 0 ? `<span class="medium">Medium: ${entry.risk_summary.medium}</span>` : ''}
        <span>Total: ${entry.risk_summary.total}</span>
      </div>
      <div class="history-url" title="${escapeHtml(entry.url)}">${escapeHtml(entry.url)}</div>
      <div class="history-actions">
        <button class="btn btn-secondary btn-sm view-history-btn" data-index="${index}">View Details</button>
      </div>
    </div>
  `).join('');
  
  // Add view details listeners
  container.querySelectorAll('.view-history-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const index = parseInt(e.target.dataset.index);
      viewHistoryDetails(history[index]);
    });
  });
}

// Filter history
function filterHistory() {
  const searchTerm = document.getElementById('historySearchInput').value.toLowerCase();
  const riskFilter = document.getElementById('historyRiskFilter').value;
  
  let filtered = currentHistory;
  
  // Apply search filter
  if (searchTerm) {
    filtered = filtered.filter(entry => 
      entry.url.toLowerCase().includes(searchTerm) ||
      entry.domain.toLowerCase().includes(searchTerm)
    );
  }
  
  // Apply risk filter
  if (riskFilter !== 'all') {
    filtered = filtered.filter(entry => 
      entry.findings.some(f => f.risk === riskFilter)
    );
  }
  
  displayHistory(filtered);
}

// View history details
function viewHistoryDetails(entry) {
  // Switch to findings tab and display the history entry
  document.querySelector('[data-tab="findings"]').click();
  displayFindings(entry.findings);
  showMessage(`Showing ${entry.findings.length} finding(s) from ${entry.domain}`, 'info');
}

// Clear history
function clearHistory() {
  if (!confirm('Clear all history? This cannot be undone.')) return;
  
  chrome.storage.local.set({ history: [] }, () => {
    currentHistory = [];
    displayHistory([]);
    showMessage('History cleared', 'success');
  });
}

// Utility functions
function copyToClipboard(text) {
  navigator.clipboard.writeText(text).catch(err => {
    console.error('Failed to copy:', err);
  });
}

function downloadFile(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function highlightMatchInContext(codeContext, matchedText) {
  if (!codeContext || !matchedText) return escapeHtml(codeContext || '');
  const escapedContext = escapeHtml(codeContext);
  const escapedMatch = escapeHtml(matchedText);
  if (!escapedMatch) return escapedContext;
  const parts = escapedContext.split(escapedMatch);
  if (parts.length === 1) return escapedContext;
  return parts.join(`<mark class="code-highlight">${escapedMatch}</mark>`);
}

function formatDate(timestamp) {
  const date = new Date(timestamp);
  return date.toLocaleString();
}

function showMessage(text, type = 'info') {
  const container = document.querySelector('.tab-pane.active');
  const existingMessage = container.querySelector('.message');
  
  if (existingMessage) {
    existingMessage.remove();
  }
  
  const message = document.createElement('div');
  message.className = `message message-${type}`;
  message.textContent = text;
  
  container.insertBefore(message, container.firstChild);
  
  setTimeout(() => {
    message.remove();
  }, 3000);
}

// Secret Validation Functions
async function validateSecretInline(secret, patternName, index, btn) {
  const resultContainer = document.getElementById(`secret-validation-${index}`);
  if (!resultContainer) return;

  btn.disabled = true;
  btn.innerHTML = `${origamiIcon('key')} Validating...`;
  resultContainer.style.display = 'block';
  resultContainer.innerHTML = '<div class="loading" style="padding: 8px; font-size: 12px;">Validating secret...</div>';

  try {
    const result = await SecretValidator.validate(secret, patternName);

    if (!result) {
      resultContainer.innerHTML = '<div style="padding: 8px; font-size: 12px; color: var(--text-secondary);">No validator available for this secret type.</div>';
      btn.innerHTML = `${origamiIcon('key')} Validate`;
      btn.disabled = false;
      return;
    }

    let statusClass, statusLabel;
    if (result.valid === true) {
      statusClass = 'validation-active';
      statusLabel = 'ACTIVE';
    } else if (result.valid === false) {
      statusClass = 'validation-invalid';
      statusLabel = 'Invalid/Revoked';
    } else {
      statusClass = 'validation-inconclusive';
      statusLabel = 'Inconclusive';
    }

    const permissionsHtml = result.permissions && result.permissions.length > 0
      ? `<div class="validation-permissions" style="margin-top: 4px; font-size: 11px;">
          <strong>Permissions:</strong> ${result.permissions.map(p => `<code>${escapeHtml(p)}</code>`).join(', ')}
        </div>` : '';

    const detailsEntries = result.details ? Object.entries(result.details).filter(([_, v]) => v !== undefined && v !== null) : [];
    const detailsHtml = detailsEntries.length > 0
      ? `<div class="validation-details-toggle" style="margin-top: 4px;">
          <button class="btn btn-secondary btn-sm toggle-validation-details" data-index="${index}" style="padding: 2px 8px; font-size: 11px;">Details</button>
          <div class="validation-details-content" id="validation-details-${index}" style="display: none; margin-top: 4px; font-size: 11px; padding: 6px; background: var(--bg-tertiary); border-radius: 4px;">
            ${detailsEntries.map(([k, v]) => `<div><strong>${escapeHtml(k)}:</strong> ${escapeHtml(typeof v === 'object' ? JSON.stringify(v) : String(v))}</div>`).join('')}
          </div>
        </div>` : '';

    resultContainer.innerHTML = `
      <div class="secret-validation-inline" style="padding: 8px; margin-top: 4px; border-radius: 4px; border: 1px solid var(--border-color); background: var(--bg-secondary);">
        <div style="display: flex; align-items: center; gap: 8px;">
          <span class="${statusClass}" style="font-weight: 600; font-size: 12px;">${statusLabel}</span>
          <span style="font-size: 12px; color: var(--text-secondary);">${escapeHtml(result.provider ? SecretValidator.VALIDATORS[result.provider]?.name || result.provider : '')}</span>
          ${result.risk ? `<span class="finding-risk ${result.risk}" style="font-size: 10px; padding: 1px 6px;">${result.risk}</span>` : ''}
        </div>
        <div style="font-size: 12px; margin-top: 4px; color: var(--text-primary);">${escapeHtml(result.message || '')}</div>
        ${permissionsHtml}
        ${result.error ? `<div style="margin-top: 4px; font-size: 11px; color: var(--high-color);">Error: ${escapeHtml(result.error)}</div>` : ''}
        ${detailsHtml}
      </div>
    `;

    // Add details toggle listener
    const toggleBtn = resultContainer.querySelector('.toggle-validation-details');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => {
        const content = document.getElementById(`validation-details-${index}`);
        if (content) {
          content.style.display = content.style.display === 'none' ? 'block' : 'none';
        }
      });
    }

    btn.innerHTML = `${origamiIcon('key')} Validated`;
  } catch (error) {
    resultContainer.innerHTML = `<div style="padding: 8px; font-size: 12px; color: var(--high-color);">Validation error: ${escapeHtml(error.message)}</div>`;
    btn.innerHTML = `${origamiIcon('key')} Validate`;
  }

  btn.disabled = false;
}

// Google API Key Testing Functions
async function testGoogleAPIKey(apiKey) {
  // Show modal
  const modal = document.getElementById('apiValidationModal');
  const body = document.getElementById('apiValidationBody');
  modal.style.display = 'flex';
  body.innerHTML = '<div class="loading">Testing Google API key...</div>';

  try {
    console.log('Origami: Starting API validation for key:', apiKey.slice(0, 10) + '...');

    // Check if GoogleAPIValidator is available
    if (typeof GoogleAPIValidator === 'undefined') {
      console.error('Origami: GoogleAPIValidator not loaded!');
      body.innerHTML = '<div class="error">Validator not loaded. Please reload the extension.</div>';
      return;
    }

    // Get settings from new API Testing tab (not deprecated api_validation)
    const googleApiSettings = await new Promise((resolve) => {
      chrome.runtime.sendMessage({ action: 'getGoogleApiTestingSettings' }, response => {
        resolve(response?.googleApiTesting || null);
      });
    });

    // Determine which services to test based on API Testing tab configuration
    let selectedServices = [];
    if (googleApiSettings && googleApiSettings.selectedServices) {
      // Use services selected in API Testing tab
      selectedServices = Object.entries(googleApiSettings.selectedServices)
        .filter(([_, checked]) => checked)
        .map(([serviceId, _]) => serviceId);
    }

    // If no services selected, use All Services as fallback
    if (selectedServices.length === 0) {
      console.log('Origami: No services selected in API Testing tab, using All Services fallback');
      selectedServices = GOOGLE_API_PRESETS.all;
    }

    console.log('Origami: Testing services:', selectedServices);

    // Run validation with selected services
    const validator = new GoogleAPIValidator(apiKey);
    const discoveredProjects = googleApiSettings?.discoveredProjects || [];
    const results = await validator.runSelectedTests(selectedServices, discoveredProjects);

    console.log('Origami: Validation complete:', results);

    if (results && results.length > 0) {
      // Store results in background for caching (include tabId for risk upgrade)
      getTargetTabCb((tabs) => {
        if (tabs[0]) {
          chrome.runtime.sendMessage({
            action: 'storeAPIValidationResults',
            apiKey: apiKey,
            results: results,
            tabId: tabs[0].id
          });
        }
      });

      displayAPIValidationResults(results, apiKey);
    } else {
      body.innerHTML = '<div class="error">No results returned from validation</div>';
    }
  } catch (error) {
    console.error('Origami: Validation error:', error);
    body.innerHTML = `<div class="error">Error: ${escapeHtml(error.message)}<br><small>Check console for details</small></div>`;
  }
}

function displayAPIValidationResults(results, apiKey) {
  const body = document.getElementById('apiValidationBody');
  
  // Count enabled APIs
  const enabledCount = results.filter(r => r.status.includes('ENABLED')).length;
  const totalCount = results.length;
  
  // Build HTML
  let html = `
    <div class="api-validation-summary">
      <h4>API Key: ${escapeHtml(apiKey.slice(0, 10))}...${escapeHtml(apiKey.slice(-6))}</h4>
      <div class="api-validation-count">${enabledCount} / ${totalCount}</div>
      <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">
        APIs Enabled
      </div>
    </div>
  `;
  
  // Sort: ENABLED first, then DISABLED, then errors
  const sortedResults = [...results].sort((a, b) => {
    const aOrder = a.status.includes('ENABLED') ? 0 : (a.status === 'DISABLED' ? 1 : 2);
    const bOrder = b.status.includes('ENABLED') ? 0 : (b.status === 'DISABLED' ? 1 : 2);
    return aOrder - bOrder;
  });

  sortedResults.forEach(result => {
    const statusClass = result.status.includes('ENABLED') ? 'enabled' :
                       result.status === 'DISABLED' ? 'disabled' : 'error';

    html += `
      <div class="api-result-item ${statusClass}">
        <div class="api-result-header">
          <span class="api-result-service">${escapeHtml(result.service)}</span>
          <span class="api-result-status ${statusClass}">
            ${escapeHtml(result.status)}
          </span>
        </div>
        <div class="api-result-message">${escapeHtml(result.message)}</div>
      </div>
    `;
  });

  body.innerHTML = html;
}

function closeAPIValidationModal() {
  const modal = document.getElementById('apiValidationModal');
  modal.style.display = 'none';
}

// LLM Functions

// Handle LLM provider change
function handleLLMProviderChange() {
  const provider = document.getElementById('llmProvider').value;
  const apiKeyGroup = document.getElementById('apiKeyGroup');
  const apiKeyLabel = document.getElementById('apiKeyLabel');
  const apiKeyInput = document.getElementById('llmApiKey');
  const ollamaEndpointGroup = document.getElementById('ollamaEndpointGroup');
  const modelSelect = document.getElementById('llmModel');
  
  // Show/hide fields based on provider
  if (provider === 'openai') {
    apiKeyGroup.style.display = 'block';
    ollamaEndpointGroup.style.display = 'none';
    apiKeyLabel.textContent = 'OpenAI API Key:';
    apiKeyInput.placeholder = 'sk-...';
  } else if (provider === 'anthropic') {
    apiKeyGroup.style.display = 'block';
    ollamaEndpointGroup.style.display = 'none';
    apiKeyLabel.textContent = 'Anthropic API Key:';
    apiKeyInput.placeholder = 'sk-ant-...';
  } else if (provider === 'gemini') {
    apiKeyGroup.style.display = 'block';
    ollamaEndpointGroup.style.display = 'none';
    apiKeyLabel.textContent = 'Google Gemini API Key:';
    apiKeyInput.placeholder = 'AIza...';
  } else if (provider === 'ollama') {
    apiKeyGroup.style.display = 'none';
    ollamaEndpointGroup.style.display = 'block';
  } else {
    apiKeyGroup.style.display = 'none';
    ollamaEndpointGroup.style.display = 'none';
  }
  
  // Populate model dropdown
  populateLLMModels(provider);
}

// Populate LLM model dropdown
function populateLLMModels(provider) {
  const modelSelect = document.getElementById('llmModel');
  modelSelect.innerHTML = '';
  
  if (provider === 'none') {
    modelSelect.innerHTML = '<option value="">Select a provider first</option>';
    modelSelect.disabled = true;
    return;
  }
  
  modelSelect.disabled = false;
  
  // Get models from LLMManager
  const models = LLMManager.getAvailableModels(provider);
  
  if (models && models.length > 0) {
    models.forEach(model => {
      const option = document.createElement('option');
      option.value = model.id;
      option.textContent = model.name;
      modelSelect.appendChild(option);
    });
  } else {
    modelSelect.innerHTML = '<option value="">No models available</option>';
  }
}

// Test LLM connection
async function testLLMConnection() {
  const provider = document.getElementById('llmProvider').value;
  const model = document.getElementById('llmModel').value;
  const apiKey = document.getElementById('llmApiKey').value;
  const endpoint = provider === 'ollama' ? document.getElementById('ollamaEndpoint').value : null;
  const resultSpan = document.getElementById('llmTestResult');
  const btn = document.getElementById('testLLMBtn');

  if (provider === 'none') {
    resultSpan.innerHTML = `${origamiIcon('warning')} Please select a provider`;
    resultSpan.style.color = '#ffc107';
    return;
  }

  if (!model) {
    resultSpan.innerHTML = `${origamiIcon('warning')} Please select a model`;
    resultSpan.style.color = '#ffc107';
    return;
  }

  if ((provider === 'openai' || provider === 'anthropic' || provider === 'gemini') && !apiKey) {
    resultSpan.innerHTML = `${origamiIcon('warning')} API key required`;
    resultSpan.style.color = '#ffc107';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Testing...';
  resultSpan.textContent = '';

  try {
    console.log('Origami: Testing LLM connection...', { provider, model, endpoint });

    const llmManager = new LLMManager(provider, apiKey, endpoint);
    llmManager.setModel(model);
    
    const result = await llmManager.testConnection();
    
    console.log('Origami: Test connection result:', result);
    
    if (result.success) {
      resultSpan.innerHTML = `${origamiIcon('checkCircle')} Connection successful!`;
      resultSpan.style.color = '#28a745';
    } else {
      resultSpan.textContent = ' ' + result.error;
      resultSpan.style.color = '#dc3545';
      console.error('Origami: Connection test failed:', result.error);
    }
  } catch (error) {
    resultSpan.textContent = ' ' + error.message;
    resultSpan.style.color = '#dc3545';
    console.error('Origami: Connection test exception:', error);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Test Connection';
  }
}

// Get LLM settings (helper function for other features)
async function getLLMSettings() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(['settings'], (data) => {
      const settings = data.settings || {};
      resolve(settings.llm || {
        enabled: false,
        provider: 'none',
        model: null,
        apiKey: '',
        endpoint: null
      });
    });
  });
}

// LLM Analysis Functions

let currentLLMFinding = null;
let currentLLMFindingType = null;
let currentPromptTemplates = [];
let editingPromptTemplate = null;

// Open LLM analysis for secret finding
function openLLMAnalysisForSecret(finding) {
  currentLLMFinding = finding;
  currentLLMFindingType = 'secret';
  
  const modal = document.getElementById('llmAnalysisModal');
  const resultsDiv = document.getElementById('llmResults');
  
  // Clear previous results
  resultsDiv.innerHTML = '';
  document.getElementById('llmLoading').style.display = 'none';
  
  // Reset prompt selector to default
  document.getElementById('llmPromptSelect').value = 'vulnerability';
  document.getElementById('customQuestionGroup').style.display = 'none';
  document.getElementById('llmContextSelect').value = 'finding';
  
  // Show modal
  modal.style.display = 'flex';
}

// Open LLM analysis for security finding
function openLLMAnalysisForSecurity(finding) {
  currentLLMFinding = finding;
  currentLLMFindingType = 'security';
  
  const modal = document.getElementById('llmAnalysisModal');
  const resultsDiv = document.getElementById('llmResults');
  
  // Clear previous results
  resultsDiv.innerHTML = '';
  document.getElementById('llmLoading').style.display = 'none';
  
  // Reset prompt selector to default
  document.getElementById('llmPromptSelect').value = 'vulnerability';
  document.getElementById('customQuestionGroup').style.display = 'none';
  document.getElementById('llmContextSelect').value = 'finding';
  
  // Show modal
  modal.style.display = 'flex';
}

// Close LLM analysis modal
function closeLLMAnalysisModal() {
  const modal = document.getElementById('llmAnalysisModal');
  modal.style.display = 'none';
  currentLLMFinding = null;
  currentLLMFindingType = null;
}

// Execute LLM analysis
async function executeLLMAnalysis() {
  if (!currentLLMFinding) {
    showMessage('No finding selected', 'error');
    return;
  }
  
  const promptType = document.getElementById('llmPromptSelect').value;
  const contextLevel = document.getElementById('llmContextSelect').value;
  const customQuestion = document.getElementById('customQuestion').value;
  
  const loadingDiv = document.getElementById('llmLoading');
  const resultsDiv = document.getElementById('llmResults');
  const analyzeBtn = document.getElementById('analyzeLLMBtn');
  
  // Show loading
  loadingDiv.style.display = 'block';
  resultsDiv.innerHTML = '';
  analyzeBtn.disabled = true;
  
  try {
    // Check if LLM classes are available
    if (typeof LLMManager === 'undefined') {
      throw new Error('LLMManager not loaded. Please reload the extension.');
    }
    
    if (typeof SecurityPrompts === 'undefined') {
      throw new Error('SecurityPrompts not loaded. Please reload the extension.');
    }
    
    // Get LLM settings
    const llmSettings = await getLLMSettings();
    
    console.log('Origami: LLM settings:', { provider: llmSettings.provider, model: llmSettings.model, endpoint: llmSettings.endpoint });
    
    if (!llmSettings.enabled || llmSettings.provider === 'none') {
      throw new Error('LLM not configured. Please configure LLM settings first.');
    }
    
    // Create LLM manager
    const llmManager = new LLMManager(
      llmSettings.provider,
      llmSettings.apiKey,
      llmSettings.endpoint
    );
    llmManager.setModel(llmSettings.model);
    
    console.log('Origami: LLM Manager created successfully');
    
    // Prepare prompt based on finding type and user selection
    let promptData;
    
    if (promptType === 'custom') {
      if (!customQuestion.trim()) {
        throw new Error('Please enter a custom question');
      }
      promptData = SecurityPrompts.custom(customQuestion, JSON.stringify(currentLLMFinding, null, 2));
    } else if (currentLLMFindingType === 'secret') {
      // Secret-specific prompts
      promptData = SecurityPrompts.secretsAnalysis([currentLLMFinding]);
    } else {
      // Security finding prompts
      switch (promptType) {
        case 'vulnerability':
          promptData = SecurityPrompts.vulnerabilityAssessment(currentLLMFinding);
          break;
        case 'remediation':
          promptData = SecurityPrompts.remediationAdvice(currentLLMFinding);
          break;
        case 'exploit':
          promptData = SecurityPrompts.exploitRecommendations(currentLLMFinding);
          break;
        default:
          promptData = SecurityPrompts.vulnerabilityAssessment(currentLLMFinding);
      }
    }
    
    // Execute LLM analysis
    console.log('Origami: Executing LLM analysis with prompt type:', promptType);
    
    const systemPrompt = (promptType === 'exploit')
      ? SecurityPrompts.exploiterSystemPrompt()
      : SecurityPrompts.advisorSystemPrompt();

    const result = await llmManager.analyze(
      promptData.prompt,
      promptData.context,
      { ...promptData.options, systemPrompt }
    );
    
    console.log('Origami: LLM analysis complete:', result);
    
    // Display results
    displayLLMResults(result);
    
  } catch (error) {
    console.error('Origami: LLM Analysis error:', error);
    resultsDiv.innerHTML = `
      <div class="test-error">
        <strong>Error:</strong> ${escapeHtml(error.message)}
        <br><small>Check browser console (F12) for details.</small>
      </div>
    `;
  } finally {
    loadingDiv.style.display = 'none';
    analyzeBtn.disabled = false;
  }
}

// Display LLM analysis results
function displayLLMResults(result) {
  const resultsDiv = document.getElementById('llmResults');
  
  let html = '<div class="llm-response">';
  
  // Provider and model info
  html += `<div class="llm-meta">`;
  html += `<span class="llm-provider-badge">${result.provider.toUpperCase()}</span>`;
  html += `<span class="llm-model-badge">${result.model}</span>`;
  if (result.usage) {
    html += `<span class="llm-usage">Tokens: ${result.usage.total_tokens || result.usage.input_tokens + result.usage.output_tokens}</span>`;
  }
  html += `</div>`;
  
  // Response content (with basic markdown formatting)
  const formattedResponse = formatLLMResponse(result.response);
  html += `<div class="llm-content">${formattedResponse}</div>`;
  
  // Copy button
  html += `<button class="btn btn-secondary btn-sm" onclick="copyLLMResponse()">${origamiIcon('clipboard')} Copy Response</button>`;
  
  html += '</div>';
  
  resultsDiv.innerHTML = html;
  
  // Store response for copying
  window.lastLLMResponse = result.response;
}

// Format LLM response with basic markdown-like styling
function formatLLMResponse(text) {
  let formatted = escapeHtml(text);
  
  // Bold: **text**
  formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
  
  // Code blocks: ```code```
  formatted = formatted.replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>');
  
  // Inline code: `code`
  formatted = formatted.replace(/`([^`]+)`/g, '<code>$1</code>');
  
  // Numbered lists
  formatted = formatted.replace(/^(\d+)\.\s+(.+)$/gm, '<div class="list-item">$1. $2</div>');
  
  // Bullet lists
  formatted = formatted.replace(/^[-*]\s+(.+)$/gm, '<div class="list-item">• $1</div>');
  
  // Newlines
  formatted = formatted.replace(/\n/g, '<br>');
  
  return formatted;
}

// Copy LLM response
function copyLLMResponse() {
  if (window.lastLLMResponse) {
    copyToClipboard(window.lastLLMResponse);
    showMessage('LLM response copied to clipboard', 'success');
  }
}

// Report Generation Functions

// Generate enhanced report
async function generateEnhancedReport() {
  const options = {
    formats: {
      html: document.getElementById('exportHTML').checked,
      markdown: document.getElementById('exportMarkdown').checked,
      json: document.getElementById('exportJSON').checked
    },
    llm: {
      enabled: document.getElementById('includeLLM').checked,
      model: document.getElementById('reportLLMModel').value,
      includeSummary: document.getElementById('includeSummary').checked,
      includeRiskAnalysis: document.getElementById('includeRiskAnalysis').checked,
      includeRemediation: document.getElementById('includeRemediation').checked,
      includeCompliance: document.getElementById('includeCompliance').checked
    }
  };
  
  // Validate at least one format selected
  if (!options.formats.html && !options.formats.markdown && !options.formats.json) {
    showMessage('Please select at least one export format', 'error');
    return;
  }
  
  const btn = document.getElementById('generateReportBtn');
  btn.disabled = true;
  btn.textContent = 'Generating...';
  
  // Show progress
  showReportProgress(true);
  updateReportProgress(0, 'Preparing report data...');
  
  try {
    // Get current tab for URL
    const tab = await getTargetTab();
    
    // Gather all data
    updateReportProgress(10, 'Collecting findings...');
    const reportData = {
      secrets: currentFindings || [],
      securityAnalysis: securityResults,
      technologies: securityResults?.technologies,
      vulnerabilities: window.currentTechVulnerabilities || {},
      sensitiveFiles: securityResults?.sensitiveFiles || [],
      url: tab.url
    };

    // Add new analyzer data from securityResults
    if (securityResults) {
      reportData.sessionAnalysis = securityResults.sessionState || null;
      reportData.oauthAnalysis = securityResults.oauthFlows || null;
      reportData.graphqlAnalysis = securityResults.graphql || null;
    }

    // Load async analyzer data from background storage
    try {
      const enhancedTabId = tab.id;
      const [cryptoResp, cloudResp, exfilResp, wsResp] = await Promise.all([
        new Promise(r => chrome.runtime.sendMessage({ action: 'getCryptoResults', tabId: enhancedTabId }, r)),
        new Promise(r => chrome.runtime.sendMessage({ action: 'getCloudStorageResults', tabId: enhancedTabId }, r)),
        new Promise(r => chrome.runtime.sendMessage({ action: 'getExfiltrationResults', tabId: enhancedTabId }, r)),
        new Promise(r => chrome.runtime.sendMessage({ action: 'getWebSocketResults', tabId: enhancedTabId }, r))
      ]);
      if (cryptoResp?.crypto) reportData.cryptoAnalysis = cryptoResp.crypto;
      if (cloudResp?.cloudStorage) reportData.cloudStorageAnalysis = cloudResp.cloudStorage;
      if (exfilResp?.exfiltration) reportData.exfiltrationAnalysis = exfilResp.exfiltration;
      if (wsResp?.websockets) reportData.websocketAnalysis = wsResp.websockets;
    } catch (e) {
      console.warn('Origami: Failed to load some analyzer data for report:', e);
    }

    // Load SQLi Attack Lab findings from storage
    try {
      const sqliResp = await new Promise(r => chrome.storage.local.get(['sqli_last_scan'], r));
      const sqliData = sqliResp && sqliResp.sqli_last_scan;
      if (sqliData && Array.isArray(sqliData.results)) {
        const sqliTechNamesE = { B: 'boolean-based blind', E: 'error-based', T: 'time-based blind', U: 'UNION query', S: 'stacked queries' };
        const confirmedSqliE = sqliData.results.filter(f => f.confirmed);
        if (confirmedSqliE.length > 0) {
          const sqliVulnsE = confirmedSqliE.map(f => ({
            check: `SQL Injection (${sqliTechNamesE[f.technique] || f.technique}) - ${f.param}`,
            status: 'vulnerable',
            severity: sqliTechniqueToSeverity(f.technique),
            message: `Parameter "${f.param}" is injectable via ${sqliTechNamesE[f.technique] || f.technique}. DBMS: ${f.dbms || 'unknown'}.`,
            recommendation: 'Use parameterized queries (prepared statements). Never concatenate user-controlled input into SQL queries.',
            source: 'SQLi Attack Lab', uri: sqliData.url || '',
            timestamp: new Date().toISOString(), matchedText: f.payload || '',
            sqliData: { technique: f.technique, param: f.param, payload: f.payload, dbms: f.dbms }
          }));
          if (!reportData.securityAnalysis) reportData.securityAnalysis = {};
          if (!reportData.securityAnalysis.vulnerabilities) reportData.securityAnalysis.vulnerabilities = [];
          reportData.securityAnalysis.vulnerabilities.push(...sqliVulnsE);
        }
      }
    } catch (e) {
      console.warn('Origami: Failed to load SQLi findings for report:', e);
    }

    // Create report generator
    const generator = new ReportGenerator();
    generator.generate(reportData);
    
    // If LLM enabled, enhance report
    if (options.llm.enabled) {
      updateReportProgress(15, 'Initializing LLM...');
      
      const llmSettings = await getLLMSettings();
      
      if (!llmSettings.enabled || llmSettings.provider === 'none') {
        throw new Error('LLM not configured. Please configure LLM in Settings.');
      }
      
      const llmManager = new LLMManager(
        llmSettings.provider,
        llmSettings.apiKey,
        llmSettings.endpoint
      );
      
      const model = options.llm.model || llmSettings.model;
      llmManager.setModel(model);
      
      // Generate LLM insights with progress tracking
      await generator.generateWithLLM(llmManager, {
        ...options.llm,
        progressCallback: updateReportProgress
      });
      
      updateReportProgress(95, 'LLM analysis complete...');
    } else {
      updateReportProgress(50, 'Formatting report...');
    }
    
    // Generate and download reports
    let downloadCount = 0;
    
    if (options.formats.html) {
      updateReportProgress(96, 'Generating HTML report...');
      generator.download('html');
      downloadCount++;
    }
    
    if (options.formats.markdown) {
      updateReportProgress(97, 'Generating Markdown report...');
      generator.download('markdown');
      downloadCount++;
    }
    
    if (options.formats.json) {
      updateReportProgress(98, 'Generating JSON export...');
      generator.download('json');
      downloadCount++;
    }
    
    updateReportProgress(100, `Complete! Downloaded ${downloadCount} file(s).`);
    showMessage(`Report generated successfully! Downloaded ${downloadCount} file(s).`, 'success');
    
    setTimeout(() => {
      showReportProgress(false);
      closeReportModal();
      btn.disabled = false;
      btn.textContent = ' Generate Report';
    }, 2000);
    
  } catch (error) {
    console.error('Report generation error:', error);
    showMessage(`Report generation failed: ${error.message}`, 'error');
    showReportProgress(false);
    btn.disabled = false;
    btn.textContent = ' Generate Report';
  }
}

// Show/hide report progress
function showReportProgress(show) {
  const progressDiv = document.getElementById('reportProgress');
  progressDiv.style.display = show ? 'block' : 'none';
  
  if (!show) {
    updateReportProgress(0, '');
  }
}

// Update report progress
function updateReportProgress(percent, message) {
  const progressBar = document.getElementById('reportProgressBar');
  const progressText = document.getElementById('reportProgressText');
  
  progressBar.style.width = `${percent}%`;
  progressText.textContent = message;
}

// Pattern Management Functions

// Load patterns
async function loadPatterns() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['secret_patterns'], async (data) => {
      currentPatterns = data.secret_patterns;

      // If no patterns exist, initialize with defaults
      if (!currentPatterns || currentPatterns.length === 0) {
        currentPatterns = await initializeDefaultPatterns();
        chrome.storage.local.set({ secret_patterns: currentPatterns });
      } else {
        // Merge new patterns with existing ones (migration)
        const defaultPatterns = await initializeDefaultPatterns();
        const merged = mergePatterns(currentPatterns, defaultPatterns);
        if (merged.updated) {
          console.log('Origami: Merged new patterns:', merged.added);
          currentPatterns = merged.patterns;
          chrome.storage.local.set({ secret_patterns: currentPatterns });
        }
      }

      displayPatterns();
      resolve();
    });
  });
}

// Merge new default patterns with existing user patterns
function mergePatterns(existing, defaults) {
  const existingIds = new Set(existing.map(p => p.id));
  const added = [];
  let updated = false;

  // Add new patterns that don't exist
  defaults.forEach(defaultPattern => {
    if (!existingIds.has(defaultPattern.id)) {
      existing.push(defaultPattern);
      added.push(defaultPattern.name);
      updated = true;
    } else {
      // Update risk levels and regex for existing builtin patterns during migration
      const existingPattern = existing.find(p => p.id === defaultPattern.id);
      if (existingPattern) {
        if (existingPattern.risk !== defaultPattern.risk) {
          const oldRisk = existingPattern.risk;
          existingPattern.risk = defaultPattern.risk;
          updated = true;
          console.log(`Origami: Updated ${defaultPattern.name} risk from ${oldRisk} to ${defaultPattern.risk}`);
        }
        if (existingPattern.builtin && existingPattern.regex !== defaultPattern.regex) {
          existingPattern.regex = defaultPattern.regex;
          updated = true;
          console.log(`Origami: Updated ${defaultPattern.name} regex`);
        }
        if (existingPattern.description !== defaultPattern.description) {
          existingPattern.description = defaultPattern.description;
          updated = true;
        }
      }
    }
  });

  // Migration: remove retired patterns that are FP-prone
  const retiredPatterns = ['twilio-api'];
  retiredPatterns.forEach(id => {
    const idx = existing.findIndex(p => p.id === id);
    if (idx !== -1) {
      existing.splice(idx, 1);
      updated = true;
    }
  });

  // Migration: disable patterns that are FP-prone by default
  const disableByDefault = ['google-oauth2-client-id'];
  disableByDefault.forEach(id => {
    const pat = existing.find(p => p.id === id);
    if (pat && pat.enabled === true && pat.builtin) {
      pat.enabled = false;
      updated = true;
    }
  });

  return { patterns: existing, added, updated };
}

// Initialize default patterns from scanner.js
async function initializeDefaultPatterns() {
  const patterns = [
    // HIGH (previously CRITICAL - downgraded per user request)
    { id: 'aws-access-key', name: 'AWS Access Key', regex: '(?:AKIA|ASIA)[0-9A-Z]{16}', risk: 'HIGH', enabled: true, builtin: true, category: 'cloud', description: 'AWS Access Key ID (includes STS temporary credentials)' },
    { id: 'stripe-live-key', name: 'Stripe Live Key', regex: 'sk_live_[0-9a-zA-Z]{24,}', risk: 'HIGH', enabled: true, builtin: true, category: 'api', description: 'Stripe secret API key' },
    { id: 'github-token', name: 'GitHub Token', regex: '(?:gh[pousr]_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{22,})', risk: 'HIGH', enabled: true, builtin: true, category: 'api', description: 'GitHub personal access token (classic and fine-grained)' },
    { id: 'slack-token', name: 'Slack Token', regex: 'xox[baprs]-[0-9]{8,}-[0-9A-Za-z-]{18,}', risk: 'HIGH', enabled: true, builtin: true, category: 'api', description: 'Slack API token' },
    { id: 'generic-secret-40', name: 'Generic Secret (40 chars)', regex: '[A-Za-z0-9_-]{40}==?', risk: 'HIGH', enabled: false, builtin: true, category: 'generic', description: 'Generic 40-character secret (disabled by default due to false positives on hashes/identifiers)' },
    { id: 'jwt-token', name: 'JWT Token', regex: 'ey[A-Za-z0-9_]{10,}\\.ey[A-Za-z0-9_]{10,}\\.[A-Za-z0-9_-]{10,}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'crypto', description: 'JSON Web Token (session tokens can enable account takeover; validate claims and expiry)' },
    { id: 'azure-connection', name: 'Azure Connection String', regex: 'DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+', risk: 'HIGH', enabled: true, builtin: true, category: 'cloud', description: 'Azure storage connection string' },
    { id: 'private-key', name: 'Private Key Header', regex: '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', risk: 'HIGH', enabled: true, builtin: true, category: 'crypto', description: 'Private cryptographic key' },
    { id: 'slack-webhook', name: 'Slack Webhook', regex: 'https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}', risk: 'HIGH', enabled: true, builtin: true, category: 'api', description: 'Slack webhook URL' },
    { id: 'sendgrid-api', name: 'SendGrid API Key', regex: 'SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}', risk: 'HIGH', enabled: true, builtin: true, category: 'api', description: 'SendGrid API key' },
    { id: 'gitlab-token', name: 'GitLab Token', regex: 'glpat-[0-9a-zA-Z_-]{20}', risk: 'HIGH', enabled: true, builtin: true, category: 'api', description: 'GitLab personal access token' },
    // OAuth2 - High-value long-lived credentials
    { id: 'google-oauth2-refresh', name: 'Google OAuth2 Refresh Token', regex: '1//[0-9A-Za-z_-]{43,}', risk: 'HIGH', enabled: true, builtin: true, category: 'oauth2', description: 'Google OAuth2 refresh token (long-lived, can generate new access tokens)' },
    { id: 'google-oauth2-secret', name: 'Google OAuth2 Client Secret', regex: 'GOCSPX-[0-9A-Za-z_-]{28}', risk: 'HIGH', enabled: true, builtin: true, category: 'oauth2', description: 'Google OAuth2 client secret (app credentials)' },
    { id: 'gcp-service-account', name: 'GCP Service Account Key', regex: '"type"\\s*:\\s*"service_account"', risk: 'MEDIUM', enabled: true, builtin: true, category: 'cloud', description: 'GCP service account JSON key marker (indicates key file present; actual private key is the secret)' },
    // UUID/GUID as Client Credential (OAuth2, API secrets, SDK credentials, etc.)
    { id: 'client-secret-uuid', name: 'Client Credential (UUID)', regex: '(client[_-]?(?:secret|id)|clientSecret|clientID|CLIENT_SECRET|CLIENT_ID|api[_-]?(?:secret|key)|apiSecret|apiKey|secret[_-]?key|secretKey)["\']?\\s*[:=]\\s*["\'][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}["\']', risk: 'MEDIUM', enabled: true, builtin: true, category: 'oauth2', description: 'Client credential in UUID/GUID format (OAuth2, SDK client IDs, etc.)' },

    // MEDIUM (downgraded from HIGH)
    { id: 'google-api-key', name: 'Google Cloud API Key', regex: 'AIza[0-9A-Za-z-_]{35}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'cloud', description: 'Google Cloud Platform API key (exposure risks billing abuse and quota exhaustion; validate to check for overprivileged access)' },
    { id: 'google-oauth2-access', name: 'Google OAuth2 Access Token', regex: 'ya29\\.[0-9A-Za-z_-]{20,}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'oauth2', description: 'Google OAuth2 access token (short-lived ~1 hour)' },
    { id: 'google-oauth2-client-id', name: 'Google OAuth2 Client ID', regex: '[0-9]{8,21}-[a-z0-9]{32}\\.apps\\.googleusercontent\\.com', risk: 'MEDIUM', enabled: false, builtin: true, category: 'oauth2', description: 'Google OAuth2 client ID (public per RFC 6749 -- disabled by default, enable for reconnaissance)' },
    { id: 'quoted-base64', name: 'Quoted Base64', regex: '["\'](?=.*[A-Z])(?=.*[a-z])(?=.*[0-9+/])[A-Za-z0-9+/]{50,}={0,2}["\']', risk: 'MEDIUM', enabled: false, builtin: true, category: 'generic', description: 'Quoted base64 strings (disabled by default - false positives on minified CDN files, data URIs, build artifacts)' },
    { id: 'database-url', name: 'Database URL', regex: '(mongodb|mysql|postgresql|postgres|redis|amqp|mssql)://[^:]+:[^@]+@[^\\s]+', risk: 'MEDIUM', enabled: true, builtin: true, category: 'database', description: 'Database connection URL with credentials' },
    { id: 'api-key-pattern', name: 'API Key Pattern', regex: '(api[_-]?key|apiKey|apikey|api[_-]?secret|apiSecret)["\']?\\s*[:=]\\s*["\'][a-zA-Z0-9_-]{16,}["\']', risk: 'MEDIUM', enabled: true, builtin: true, category: 'api', description: 'Generic API key assignment pattern' },

    // MEDIUM
    { id: 'access-token', name: 'Access Token', regex: '(access[_-]?token|accessToken)["\']?\\s*[:=]\\s*["\'][a-zA-Z0-9_-]{20,}["\']', risk: 'MEDIUM', enabled: true, builtin: true, category: 'generic', description: 'Access token assignment' },

    // ===================================================================
    // New patterns sourced from Lovable.dev secret scanner
    // ===================================================================

    // HIGH - AI/ML Services
    { id: 'openai-api-key-v2', name: 'OpenAI API Key (Infix)', regex: 'sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}', risk: 'HIGH', enabled: true, builtin: true, category: 'ai', description: 'OpenAI API key with T3BlbkFJ infix (high confidence)' },
    { id: 'openai-project-key', name: 'OpenAI Project API Key', regex: 'sk-proj-[A-Za-z0-9\\-_]{20,}', risk: 'HIGH', enabled: true, builtin: true, category: 'ai', description: 'OpenAI project-scoped API key' },
    { id: 'anthropic-api-key', name: 'Anthropic API Key', regex: 'sk-ant-[a-zA-Z0-9\\-_]{20,}', risk: 'HIGH', enabled: true, builtin: true, category: 'ai', description: 'Anthropic Claude API key' },

    // HIGH - Cloud
    { id: 'aws-extended-key', name: 'AWS Extended Access Key', regex: '(A3T[A-Z0-9]|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}', risk: 'HIGH', enabled: true, builtin: true, category: 'cloud', description: 'AWS access key (STS, IAM role, or temporary credentials)' },
    { id: 'aws-mws-token', name: 'AWS MWS Token', regex: 'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', risk: 'HIGH', enabled: true, builtin: true, category: 'cloud', description: 'Amazon Marketplace Web Service auth token' },
    { id: 'azure-service-bus', name: 'Azure Service Bus Connection', regex: 'Endpoint=sb://[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[^;]+', risk: 'HIGH', enabled: true, builtin: true, category: 'cloud', description: 'Azure Service Bus connection string with shared access key' },

    // HIGH - DevOps
    { id: 'npm-access-token', name: 'NPM Access Token', regex: 'npm_[a-zA-Z0-9]{36}', risk: 'HIGH', enabled: true, builtin: true, category: 'devops', description: 'NPM registry access token (supply chain risk)' },

    // HIGH - Commerce/Payments
    { id: 'stripe-restricted-key', name: 'Stripe Restricted Key', regex: 'rk_live_[0-9a-zA-Z]{24,}', risk: 'HIGH', enabled: true, builtin: true, category: 'commerce', description: 'Stripe restricted live API key' },
    { id: 'square-access-token', name: 'Square Access Token', regex: 'sq0atp-[0-9A-Za-z\\-_]{22}', risk: 'HIGH', enabled: true, builtin: true, category: 'commerce', description: 'Square payment platform access token' },
    { id: 'square-oauth-secret', name: 'Square OAuth Secret', regex: 'sq0csp-[0-9A-Za-z\\-_]{43}', risk: 'HIGH', enabled: true, builtin: true, category: 'commerce', description: 'Square OAuth client secret' },
    { id: 'paypal-braintree-token', name: 'PayPal/Braintree Token', regex: 'access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}', risk: 'HIGH', enabled: true, builtin: true, category: 'commerce', description: 'PayPal/Braintree production access token' },
    { id: 'shopify-private-token', name: 'Shopify Private App Token', regex: 'shppa_[a-f0-9]{64}', risk: 'HIGH', enabled: true, builtin: true, category: 'commerce', description: 'Shopify private app access token' },
    { id: 'shopify-custom-token', name: 'Shopify Custom App Token', regex: 'shpca_[a-f0-9]{64}', risk: 'HIGH', enabled: true, builtin: true, category: 'commerce', description: 'Shopify custom app access token' },

    // HIGH - Social/Communication
    { id: 'slack-extended-token', name: 'Slack Extended Token', regex: 'xoxe\\.xoxp-1-[0-9a-zA-Z]{140,}', risk: 'HIGH', enabled: true, builtin: true, category: 'social', description: 'Slack extended user token (broad access)' },
    { id: 'slack-workspace-token', name: 'Slack Workspace Token', regex: 'xoxe-1-[0-9a-zA-Z]{140,}', risk: 'HIGH', enabled: true, builtin: true, category: 'social', description: 'Slack enterprise workspace token' },

    // HIGH - API
    { id: 'github-fine-pat', name: 'GitHub Fine-grained PAT', regex: 'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}', risk: 'HIGH', enabled: true, builtin: true, category: 'api', description: 'GitHub fine-grained personal access token' },

    // HIGH - Crypto
    { id: 'pgp-private-key', name: 'PGP Private Key', regex: '-----BEGIN PGP PRIVATE KEY BLOCK-----', risk: 'HIGH', enabled: true, builtin: true, category: 'crypto', description: 'PGP/GPG private key block' },

    // HIGH - Cloud (HashiCorp/Terraform/Databricks)
    { id: 'hashicorp-vault-service', name: 'HashiCorp Vault Service Token', regex: 'hvs\\.[a-zA-Z0-9_-]{24,}', risk: 'HIGH', enabled: true, builtin: true, category: 'cloud', description: 'HashiCorp Vault service token' },
    { id: 'hashicorp-vault-batch', name: 'HashiCorp Vault Batch Token', regex: 'hvb\\.[a-zA-Z0-9_-]{24,}', risk: 'HIGH', enabled: true, builtin: true, category: 'cloud', description: 'HashiCorp Vault batch token' },
    { id: 'terraform-cloud-token', name: 'Terraform Cloud Token', regex: '[a-zA-Z0-9]{14}\\.atlasv1\\.[a-zA-Z0-9_-]{60,}', risk: 'HIGH', enabled: true, builtin: true, category: 'cloud', description: 'Terraform Cloud/Enterprise API token' },
    { id: 'databricks-token', name: 'Databricks Token', regex: 'dapi[a-f0-9]{32}', risk: 'HIGH', enabled: true, builtin: true, category: 'cloud', description: 'Databricks personal access token' },

    // MEDIUM - AI/ML Services
    { id: 'huggingface-token', name: 'Hugging Face Token', regex: 'hf_[a-zA-Z0-9]{34,40}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'ai', description: 'Hugging Face API access token' },
    { id: 'groq-api-key', name: 'Groq API Key', regex: 'gsk_[a-zA-Z0-9]{50,56}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'ai', description: 'Groq cloud inference API key' },
    { id: 'replicate-api-token', name: 'Replicate API Token', regex: 'r8_[a-zA-Z0-9]{38,42}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'ai', description: 'Replicate ML platform API token' },
    { id: 'xai-api-key', name: 'xAI API Key', regex: 'xai-[a-zA-Z0-9]{60,68}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'ai', description: 'xAI (Grok) API key' },
    { id: 'perplexity-api-key', name: 'Perplexity API Key', regex: 'pplx-[a-f0-9]{64}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'ai', description: 'Perplexity AI API key' },
    { id: 'tavily-api-key', name: 'Tavily API Key', regex: 'tvly-[a-zA-Z0-9]{36,40}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'ai', description: 'Tavily AI search API key' },
    { id: 'langchain-api-key', name: 'LangChain API Key', regex: 'lc_[a-zA-Z0-9]{48,52}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'ai', description: 'LangChain/LangSmith API key' },

    // MEDIUM - DevOps/Infrastructure
    { id: 'vercel-api-token', name: 'Vercel API Token', regex: '(vercel_|vc_)[a-zA-Z0-9]{24,}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'devops', description: 'Vercel deployment platform API token' },
    { id: 'render-api-key', name: 'Render API Key', regex: 'rnd_[a-zA-Z0-9]{30,34}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'devops', description: 'Render cloud platform API key' },
    { id: 'flyio-api-token', name: 'Fly.io API Token', regex: 'fo1_[a-zA-Z0-9]{41,45}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'devops', description: 'Fly.io deployment platform API token' },

    // MEDIUM - Commerce/Payments
    { id: 'stripe-test-key', name: 'Stripe Test Key', regex: 'sk_test_[0-9a-zA-Z]{24,}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'commerce', description: 'Stripe test secret API key (can reveal account structure)' },

    // MEDIUM - Social/Communication
    { id: 'discord-bot-token', name: 'Discord Bot Token', regex: '[MN][a-zA-Z0-9]{23}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_-]{27}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'social', description: 'Discord bot authentication token' },
    { id: 'facebook-access-token', name: 'Facebook Access Token', regex: 'EAACEdEose0cBA[0-9A-Za-z]+', risk: 'MEDIUM', enabled: true, builtin: true, category: 'social', description: 'Facebook/Meta Graph API access token' },

    // MEDIUM - API/SaaS
    { id: 'linear-api-key', name: 'Linear API Key', regex: 'lin_api_[a-zA-Z0-9]{38,42}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'api', description: 'Linear project management API key' },
    { id: 'airtable-pat', name: 'Airtable PAT', regex: 'pat[a-zA-Z0-9]{14}\\.[a-zA-Z0-9]{64}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'api', description: 'Airtable personal access token' },
    { id: 'figma-pat', name: 'Figma PAT', regex: 'figd_[a-zA-Z0-9\\-_]{40,46}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'api', description: 'Figma personal access token' },
    { id: 'asana-pat', name: 'Asana PAT', regex: '1\\/[0-9]{16}:[a-f0-9]{32}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'api', description: 'Asana personal access token' },

    // MEDIUM - Cloud
    { id: 'planetscale-service-token', name: 'PlanetScale Service Token', regex: 'pscale_tkn_[a-zA-Z0-9_-]{40,46}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'cloud', description: 'PlanetScale database service token' },
    { id: 'planetscale-oauth-token', name: 'PlanetScale OAuth Token', regex: 'pscale_oauth_[a-zA-Z0-9_-]{40,46}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'cloud', description: 'PlanetScale database OAuth token' },

    // MEDIUM - Email/Marketing
    { id: 'mailchimp-api-key', name: 'Mailchimp API Key', regex: '[0-9a-f]{32}-us[0-9]{1,2}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'email', description: 'Mailchimp email marketing API key' },
    { id: 'mailgun-api-key', name: 'Mailgun API Key', regex: 'key-[0-9a-zA-Z]{32}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'email', description: 'Mailgun email service API key' },

    // MEDIUM - API
    { id: 'wakatime-api-key', name: 'WakaTime API Key', regex: 'waka_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'api', description: 'WakaTime coding activity API key' },

    // MEDIUM - DevOps
    { id: 'circleci-token', name: 'CircleCI Token', regex: 'circle-token\\s*[:=]\\s*[a-f0-9]{40}', risk: 'MEDIUM', enabled: true, builtin: true, category: 'devops', description: 'CircleCI API token' },

    // MEDIUM - Generic (context-based, entropy-filtered)
    { id: 'password-assignment', name: 'Password Assignment', regex: '(password|passwd|pwd|secret)["\']?\\s*[:=]\\s*["\'][^\'"]{8,}["\']', risk: 'MEDIUM', enabled: true, builtin: true, category: 'generic', description: 'Hardcoded password or secret assignment' },
    { id: 'basic-auth-url', name: 'Basic Auth in URL', regex: 'https?://[a-zA-Z0-9._-]+:[^@/\\s"\']{3,}@[a-zA-Z0-9.-]+', risk: 'MEDIUM', enabled: true, builtin: true, category: 'generic', description: 'Basic authentication credentials embedded in URL' },

    // MEDIUM - Cloud
    { id: 'firebase-config', name: 'Firebase Config', regex: '["\']AIza[0-9A-Za-z-_]{35}["\'][\\s\\S]{0,500}(?:firebaseapp\\.com|firebaseio\\.com)', risk: 'LOW', enabled: true, builtin: true, category: 'cloud', description: 'Firebase API key colocated with Firebase domain (intentionally client-side per Firebase design)' },

    // HIGH - Monitoring (server-side API keys grant write access to all Datadog services)
    { id: 'datadog-api-key', name: 'Datadog API Key', regex: '(DD_API_KEY|datadog_api_key)["\']?\\s*[:=]\\s*["\'][a-f0-9]{32,}["\']', risk: 'HIGH', enabled: true, builtin: true, category: 'api', description: 'Datadog API key (grants write access to metrics, events, and logs)' },

    // LOW - Monitoring (APP keys are read-only analytics)
    { id: 'datadog-app-key', name: 'Datadog APP Key', regex: '(DD_APP_KEY|datadog_app_key)["\']?\\s*[:=]\\s*["\'][a-f0-9]{32,}["\']', risk: 'LOW', enabled: true, builtin: true, category: 'api', description: 'Datadog APP key (read-only analytics access)' }
  ];
  
  return patterns;
}

// Display patterns
function displayPatterns() {
  const container = document.getElementById('patternsList');
  const filtered = filterPatternsArray(currentPatterns);
  
  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <p>No patterns match your filters.</p>
      </div>
    `;
    updatePatternStats();
    return;
  }
  
  container.innerHTML = filtered.map(pattern => renderPatternCard(pattern)).join('');
  
  // Add event listeners to pattern cards
  container.querySelectorAll('.toggle-pattern-checkbox').forEach(checkbox => {
    checkbox.addEventListener('change', (e) => {
      const id = e.target.dataset.patternId;
      togglePattern(id, e.target.checked);
    });
  });
  
  container.querySelectorAll('.edit-pattern-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const id = e.currentTarget.dataset.patternId;
      openPatternEditor(id);
    });
  });

  container.querySelectorAll('.duplicate-pattern-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const id = e.currentTarget.dataset.patternId;
      duplicatePattern(id);
    });
  });

  container.querySelectorAll('.delete-pattern-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const id = e.currentTarget.dataset.patternId;
      deletePattern(id);
    });
  });

  container.querySelectorAll('.toggle-pattern-details').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const id = e.currentTarget.dataset.patternId;
      togglePatternDetails(id);
    });
  });
  
  updatePatternStats();
}

// Filter patterns based on search and filters
function filterPatternsArray(patterns) {
  const search = document.getElementById('patternSearch').value.toLowerCase();
  const riskFilter = document.getElementById('patternRiskFilter').value;
  const typeFilter = document.getElementById('patternTypeFilter').value;
  
  return patterns.filter(p => {
    const matchesSearch = !search || 
      p.name.toLowerCase().includes(search) ||
      p.regex.toLowerCase().includes(search) ||
      (p.description && p.description.toLowerCase().includes(search));
    
    const matchesRisk = riskFilter === 'all' || p.risk === riskFilter;
    
    const matchesType = typeFilter === 'all' || 
      (typeFilter === 'builtin' && p.builtin) ||
      (typeFilter === 'custom' && !p.builtin);
    
    return matchesSearch && matchesRisk && matchesType;
  });
}

// Filter patterns (UI trigger)
function filterPatterns() {
  displayPatterns();
}

// Update pattern statistics
function updatePatternStats() {
  const total = currentPatterns.length;
  const enabled = currentPatterns.filter(p => p.enabled).length;
  const custom = currentPatterns.filter(p => !p.builtin).length;
  
  document.getElementById('totalPatterns').textContent = total;
  document.getElementById('enabledPatterns').textContent = enabled;
  document.getElementById('customPatternsCount').textContent = custom;
}

// Render pattern card
function renderPatternCard(pattern) {
  const riskColors = {
    CRITICAL: '#dc3545',
    HIGH: '#fd7e14',
    MEDIUM: '#ffc107'
  };
  
  const riskColor = riskColors[pattern.risk] || '#6b7280';
  
  return `
    <div class="pattern-card ${pattern.enabled ? '' : 'disabled'}" data-pattern-id="${pattern.id}">
      <div class="pattern-header">
        <div class="pattern-info">
          <h4>${escapeHtml(pattern.name)}</h4>
          <div class="pattern-badges">
            <span class="pattern-badge" style="background: ${riskColor}; color: white;">
              ${escapeHtml(pattern.risk || '')}
            </span>
            ${pattern.builtin ? '<span class="pattern-badge builtin">Built-in</span>' : '<span class="pattern-badge custom-badge">Custom</span>'}
            <span class="pattern-category">${escapeHtml(pattern.category || 'generic')}</span>
          </div>
        </div>
        <div class="pattern-actions">
          <label class="toggle-switch">
            <input type="checkbox" class="toggle-pattern-checkbox" data-pattern-id="${pattern.id}" ${pattern.enabled ? 'checked' : ''}>
            <span class="toggle-slider"></span>
          </label>
          <button class="btn-icon edit-pattern-btn" data-pattern-id="${pattern.id}" title="Edit">${origamiIcon('wrench')}</button>
          ${!pattern.builtin ? `
            <button class="btn-icon duplicate-pattern-btn" data-pattern-id="${pattern.id}" title="Duplicate">${origamiIcon('clipboard')}</button>
            <button class="btn-icon delete delete-pattern-btn" data-pattern-id="${pattern.id}" title="Delete">${origamiIcon('xCircle')}</button>
          ` : `
            <button class="btn-icon duplicate-pattern-btn" data-pattern-id="${pattern.id}" title="Duplicate">${origamiIcon('clipboard')}</button>
          `}
        </div>
      </div>
      
      <div class="pattern-body">
        <div class="pattern-regex">
          <code>${escapeHtml(pattern.regex)}</code>
        </div>
        ${pattern.description ? `
          <p class="pattern-description">${escapeHtml(pattern.description)}</p>
        ` : ''}
        <button class="btn-link toggle-pattern-details" data-pattern-id="${pattern.id}">
          Show Details ▼
        </button>
        <div id="details-${pattern.id}" class="pattern-details" style="display: none;"></div>
      </div>
    </div>
  `;
}

// Toggle pattern details
function togglePatternDetails(id) {
  const details = document.getElementById(`details-${id}`);
  const btn = document.querySelector(`[data-pattern-id="${id}"].toggle-pattern-details`);
  
  if (details.style.display === 'none') {
    const pattern = currentPatterns.find(p => p.id === id);
    details.innerHTML = `
      <div class="detail-section">
        <strong>Category:</strong> ${escapeHtml(pattern.category || 'generic')}
      </div>
      <div class="detail-section">
        <strong>Regular Expression:</strong> <code>${escapeHtml(pattern.regex)}</code>
      </div>
    `;
    details.style.display = 'block';
    btn.textContent = 'Hide Details ▲';
  } else {
    details.style.display = 'none';
    btn.textContent = 'Show Details ▼';
  }
}

// Toggle pattern enabled/disabled
async function togglePattern(id, enabled) {
  const pattern = currentPatterns.find(p => p.id === id);
  if (pattern) {
    pattern.enabled = enabled;
    await chrome.storage.local.set({ secret_patterns: currentPatterns });
    updatePatternStats();
  }
}

// Open pattern editor
function openPatternEditor(patternId = null) {
  const modal = document.getElementById('patternEditorModal');
  const title = document.getElementById('patternEditorTitle');
  const deleteBtn = document.getElementById('deletePatternBtn');
  
  // Reset form
  document.getElementById('patternName').value = '';
  document.getElementById('patternCategory').value = 'custom';
  document.getElementById('patternRegex').value = '';
  document.getElementById('patternRisk').value = 'MEDIUM';
  document.getElementById('patternDescription').value = '';
  document.getElementById('patternTestInput').value = '';
  document.getElementById('patternTestResults').innerHTML = '';
  document.getElementById('patternEnabled').checked = true;
  
  if (patternId) {
    // Editing existing pattern
    const pattern = currentPatterns.find(p => p.id === patternId);
    if (pattern) {
      editingPattern = pattern;
      title.textContent = 'Edit Pattern';
      document.getElementById('patternName').value = pattern.name;
      document.getElementById('patternCategory').value = pattern.category || 'custom';
      document.getElementById('patternRegex').value = pattern.regex;
      document.getElementById('patternRisk').value = pattern.risk;
      document.getElementById('patternDescription').value = pattern.description || '';
      document.getElementById('patternEnabled').checked = pattern.enabled;
      
      deleteBtn.style.display = pattern.builtin ? 'none' : 'inline-block';
    }
  } else {
    // Adding new pattern
    editingPattern = null;
    title.textContent = 'Add New Pattern';
    deleteBtn.style.display = 'none';
  }
  
  modal.style.display = 'flex';
}

// Close pattern editor
function closePatternEditor() {
  const modal = document.getElementById('patternEditorModal');
  modal.style.display = 'none';
  editingPattern = null;
}

// Test pattern
function testPattern() {
  const regex = document.getElementById('patternRegex').value;
  const testInput = document.getElementById('patternTestInput').value;
  const resultsDiv = document.getElementById('patternTestResults');
  
  if (!regex) {
    resultsDiv.innerHTML = `<div class="test-warning">${origamiIcon('warning')} Please enter a regex pattern</div>`;
    return;
  }

  if (!testInput) {
    resultsDiv.innerHTML = `<div class="test-warning">${origamiIcon('warning')} Please enter test input</div>`;
    return;
  }
  
  try {
    const pattern = new RegExp(regex, 'g');
    const matches = testInput.match(pattern);
    
    if (matches && matches.length > 0) {
      resultsDiv.innerHTML = `
        <div class="test-success">
          ${origamiIcon('checkCircle')} Found ${matches.length} match(es):
          <ul>
            ${matches.slice(0, 10).map(m => `<li><code>${escapeHtml(m)}</code></li>`).join('')}
            ${matches.length > 10 ? '<li>... and more</li>' : ''}
          </ul>
        </div>
      `;
    } else {
      resultsDiv.innerHTML = `
        <div class="test-warning">
          ${origamiIcon('warning')} No matches found. Check your regex or test input.
        </div>
      `;
    }
  } catch (error) {
    resultsDiv.innerHTML = `
      <div class="test-error">
        ${origamiIcon('xCircle')} Invalid regex: ${escapeHtml(error.message)}
      </div>
    `;
  }
}

// Save pattern
async function savePattern() {
  const name = document.getElementById('patternName').value.trim();
  const category = document.getElementById('patternCategory').value;
  const regex = document.getElementById('patternRegex').value.trim();
  const risk = document.getElementById('patternRisk').value;
  const description = document.getElementById('patternDescription').value.trim();
  const enabled = document.getElementById('patternEnabled').checked;
  
  // Validate
  const errors = [];
  
  if (!name) {
    errors.push('Pattern name is required');
  }
  
  if (!regex) {
    errors.push('Regular expression is required');
  } else {
    try {
      const testRegex = new RegExp(regex, 'g');
      // ReDoS safety check: test regex against a sample string with a timeout
      // Catastrophic backtracking patterns (e.g., (a+)+ ) can freeze the content script
      const sampleText = 'A'.repeat(50) + '!' + 'B'.repeat(50) + '!' + 'x'.repeat(100);
      const startTime = performance.now();
      testRegex.exec(sampleText);
      const elapsed = performance.now() - startTime;
      if (elapsed > 100) {
        errors.push(`Regex may cause performance issues (took ${Math.round(elapsed)}ms on test input). Avoid nested quantifiers like (a+)+`);
      }
    } catch (e) {
      errors.push('Invalid regular expression: ' + e.message);
    }
  }
  
  if (errors.length > 0) {
    showMessage('Validation errors: ' + errors.join(', '), 'error');
    return;
  }
  
  const pattern = {
    name,
    category,
    regex,
    risk,
    description,
    enabled,
    builtin: false
  };
  
  if (editingPattern) {
    // Update existing
    pattern.id = editingPattern.id;
    pattern.builtin = editingPattern.builtin;
    const index = currentPatterns.findIndex(p => p.id === editingPattern.id);
    if (index !== -1) {
      currentPatterns[index] = pattern;
    }
  } else {
    // Add new
    pattern.id = generatePatternId();
    currentPatterns.push(pattern);
  }
  
  await chrome.storage.local.set({ secret_patterns: currentPatterns });
  displayPatterns();
  closePatternEditor();
  showMessage('Pattern saved successfully', 'success');
}

// Delete current pattern (in editor)
async function deleteCurrentPattern() {
  if (!editingPattern) return;
  
  if (!confirm(`Delete pattern "${editingPattern.name}"? This cannot be undone.`)) {
    return;
  }
  
  await deletePattern(editingPattern.id);
  closePatternEditor();
}

// Delete pattern
async function deletePattern(id) {
  const pattern = currentPatterns.find(p => p.id === id);
  
  if (pattern && pattern.builtin) {
    showMessage('Cannot delete built-in patterns. You can disable them instead.', 'error');
    return;
  }
  
  if (!confirm(`Delete this pattern? This cannot be undone.`)) {
    return;
  }
  
  currentPatterns = currentPatterns.filter(p => p.id !== id);
  await chrome.storage.local.set({ secret_patterns: currentPatterns });
  displayPatterns();
  showMessage('Pattern deleted', 'success');
}

// Duplicate pattern
async function duplicatePattern(id) {
  const original = currentPatterns.find(p => p.id === id);
  if (!original) return;
  
  const duplicate = {
    ...original,
    id: generatePatternId(),
    name: original.name + ' (Copy)',
    builtin: false
  };
  
  currentPatterns.push(duplicate);
  await chrome.storage.local.set({ secret_patterns: currentPatterns });
  displayPatterns();
  showMessage('Pattern duplicated', 'success');
}

// Export patterns to JSON
async function exportPatterns() {
  const json = JSON.stringify(currentPatterns, null, 2);
  downloadFile(json, `origami-patterns-${Date.now()}.json`, 'application/json');
  showMessage('Patterns exported', 'success');
}

// Import patterns from JSON
async function importPatterns() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.json';
  
  input.onchange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    
    try {
      const text = await file.text();
      const imported = JSON.parse(text);
      
      if (!Array.isArray(imported)) {
        throw new Error('Invalid format - expected array of patterns');
      }
      
      const action = confirm('Merge with existing patterns?\n\nOK = Merge (add to existing)\nCancel = Replace all custom patterns');
      
      if (action) {
        // Merge: Add new patterns, skip duplicates
        let addedCount = 0;
        imported.forEach(imp => {
          if (!currentPatterns.find(p => p.id === imp.id)) {
            currentPatterns.push(imp);
            addedCount++;
          }
        });
        showMessage(`Imported ${addedCount} new pattern(s)`, 'success');
      } else {
        // Replace all custom patterns
        const builtins = currentPatterns.filter(p => p.builtin);
        const customs = imported.filter(p => !p.builtin);
        currentPatterns = [...builtins, ...customs];
        showMessage(`Imported ${customs.length} custom pattern(s)`, 'success');
      }
      
      await chrome.storage.local.set({ secret_patterns: currentPatterns });
      displayPatterns();
      
    } catch (error) {
      showMessage(`Failed to import patterns: ${error.message}`, 'error');
    }
  };
  
  input.click();
}

// Reset patterns to defaults
async function resetPatterns() {
  if (!confirm('Reset all patterns to defaults?\n\nThis will remove all custom patterns and restore built-in patterns to their default state.')) {
    return;
  }
  
  currentPatterns = await initializeDefaultPatterns();
  await chrome.storage.local.set({ secret_patterns: currentPatterns });
  displayPatterns();
  showMessage('Patterns reset to defaults', 'success');
}

// Generate unique pattern ID
function generatePatternId() {
  return 'pat-' + Date.now().toString(36) + '-' + Math.random().toString(36).substr(2, 9);
}

// Reports Tab Functions

// Update report summary statistics
function updateReportSummary() {
  const secretsCount = currentFindings?.length || 0;
  const vulnsCount = securityResults?.vulnerabilities?.length || 0;
  
  // Calculate severity counts
  let criticalCount = 0;
  let highCount = 0;
  
  const getEffectiveSev = f => (
    f.severityOverride?.overriddenSeverity ||
    f.aiAssessment?.suggestedSeverity ||
    f.risk || f.severity || 'INFO'
  ).toUpperCase();

  if (currentFindings) {
    criticalCount += currentFindings.filter(f => getEffectiveSev(f) === 'CRITICAL').length;
    highCount += currentFindings.filter(f => getEffectiveSev(f) === 'HIGH').length;
  }

  if (securityResults) {
    const allSecurityFindings = [
      ...(securityResults.headers || []),
      ...(securityResults.cookies || []),
      ...(securityResults.vulnerabilities || [])
    ];
    criticalCount += allSecurityFindings.filter(f => getEffectiveSev(f) === 'CRITICAL').length;
    highCount += allSecurityFindings.filter(f => getEffectiveSev(f) === 'HIGH').length;

    // Count new analyzer category findings
    const newCategorySources = [
      securityResults.sessionState?.issues || securityResults.sessionState?.allIssues || [],
      securityResults.oauthFlows?.issues || [],
      securityResults.graphql?.issues || [],
      securityResults.crypto?.issues || [],
      securityResults.cloudStorage?.issues || [],
      securityResults.exfiltration?.issues || [],
      securityResults.websockets?.issues || [],
      securityResults.sensitiveFiles || []
    ];
    for (const source of newCategorySources) {
      criticalCount += source.filter(f => getEffectiveSev(f) === 'CRITICAL').length;
      highCount += source.filter(f => getEffectiveSev(f) === 'HIGH').length;
    }
  }
  
  document.getElementById('reportSecretsCount').textContent = secretsCount;
  document.getElementById('reportVulnsCount').textContent = vulnsCount;
  document.getElementById('reportCriticalCount').textContent = criticalCount;
  document.getElementById('reportHighCount').textContent = highCount;
  
  // Populate template dropdown with custom templates
  populateReportTemplateDropdown();
}

// Populate report template dropdown with custom templates
function populateReportTemplateDropdown() {
  const select = document.getElementById('reportLLMTemplate');
  
  // Keep built-in options
  const builtinOptions = [
    '<option value="comprehensive">Comprehensive Security Report</option>',
    '<option value="executive">Executive Summary</option>',
    '<option value="technical">Technical Deep Dive</option>',
    '<option value="compliance">Compliance Assessment</option>'
  ];
  
  // Add custom templates
  const customOptions = currentPromptTemplates
    .filter(t => !t.builtin && t.category === 'report')
    .map(t => `<option value="${t.id}">${escapeHtml(t.name)}</option>`);
  
  if (customOptions.length > 0) {
    builtinOptions.push('<option value="custom">--- Custom Templates ---</option>');
    builtinOptions.push(...customOptions);
  }
  
  select.innerHTML = builtinOptions.join('');
}

// Generate report from Reports tab
async function generateReportFromTab() {
  // Validate at least one format is selected
  const htmlChecked = document.getElementById('reportFormatHTML').checked;
  const mdChecked = document.getElementById('reportFormatMarkdown').checked;
  const jsonChecked = document.getElementById('reportFormatJSON').checked;
  
  if (!htmlChecked && !mdChecked && !jsonChecked) {
    showMessage('Please select at least one export format', 'error');
    return;
  }
  
  // Build options object
  const options = {
    formats: {
      html: htmlChecked,
      markdown: mdChecked,
      json: jsonChecked
    },
    content: {
      secrets: document.getElementById('includeSecrets').checked,
      headers: document.getElementById('includeHeaders').checked,
      cookies: document.getElementById('includeCookies').checked,
      vulnerabilities: document.getElementById('includeVulnerabilities').checked,
      techStack: document.getElementById('includeTechStack').checked,
      apiTesting: document.getElementById('includeAPITesting').checked,
      session: document.getElementById('includeSession').checked,
      oauth: document.getElementById('includeOAuth').checked,
      graphql: document.getElementById('includeGraphQL').checked,
      crypto: document.getElementById('includeCrypto').checked,
      cloudStorage: document.getElementById('includeCloudStorage').checked,
      exfiltration: document.getElementById('includeExfiltration').checked,
      websocket: document.getElementById('includeWebSocket').checked,
      exposedFiles: document.getElementById('includeExposedFiles')?.checked !== false,
      correlationChains: document.getElementById('includeCorrelationChains')?.checked !== false
    },
    llm: {
      enabled: document.getElementById('reportIncludeLLM').checked,
      template: document.getElementById('reportLLMTemplate').value,
      includeSummary: document.getElementById('reportLLMSummary').checked,
      includeRiskAnalysis: document.getElementById('reportLLMRiskAnalysis').checked,
      includeRemediation: document.getElementById('reportLLMRemediation').checked,
      includeCompliance: document.getElementById('reportLLMCompliance').checked,
      individual: document.getElementById('reportLLMIndividual').checked
    }
  };
  
  const btn = document.getElementById('generateReportMainBtn');
  btn.disabled = true;
  btn.textContent = 'Generating...';
  
  // Show progress
  showReportMainProgress(true);
  updateReportMainProgress(0, 'Preparing report data...');
  
  try {
    const tab = await getTargetTab();
    
    // Filter data based on content selections
    updateReportMainProgress(10, 'Collecting findings...');
    const reportData = {
      secrets: options.content.secrets ? (currentFindings || []) : [],
      securityAnalysis: {},
      technologies: options.content.techStack ? securityResults?.technologies : null,
      vulnerabilities: options.content.techStack ? (window.currentTechVulnerabilities || {}) : {},
      url: tab.url
    };
    
    if (securityResults) {
      if (options.content.headers) reportData.securityAnalysis.headers = securityResults.headers;
      if (options.content.cookies) reportData.securityAnalysis.cookies = securityResults.cookies;
      if (options.content.vulnerabilities) reportData.securityAnalysis.vulnerabilities = securityResults.vulnerabilities;
      if (options.content.exposedFiles) reportData.sensitiveFiles = securityResults.sensitiveFiles || [];
    }

    // Add new analyzer data to report
    if (securityResults) {
      if (options.content.session !== false) reportData.sessionAnalysis = securityResults.sessionState || null;
      if (options.content.oauth !== false) reportData.oauthAnalysis = securityResults.oauthFlows || null;
      if (options.content.graphql !== false) reportData.graphqlAnalysis = securityResults.graphql || null;
    }

    // Load async analyzer data from background storage
    try {
      const reportTabId = tab.id;
      const [cryptoResp, cloudResp, exfilResp, wsResp] = await Promise.all([
        new Promise(r => chrome.runtime.sendMessage({ action: 'getCryptoResults', tabId: reportTabId }, r)),
        new Promise(r => chrome.runtime.sendMessage({ action: 'getCloudStorageResults', tabId: reportTabId }, r)),
        new Promise(r => chrome.runtime.sendMessage({ action: 'getExfiltrationResults', tabId: reportTabId }, r)),
        new Promise(r => chrome.runtime.sendMessage({ action: 'getWebSocketResults', tabId: reportTabId }, r))
      ]);
      if (options.content.crypto !== false && cryptoResp?.crypto) reportData.cryptoAnalysis = cryptoResp.crypto;
      if (options.content.cloudStorage !== false && cloudResp?.cloudStorage) reportData.cloudStorageAnalysis = cloudResp.cloudStorage;
      if (options.content.exfiltration !== false && exfilResp?.exfiltration) reportData.exfiltrationAnalysis = exfilResp.exfiltration;
      if (options.content.websocket !== false && wsResp?.websockets) reportData.websocketAnalysis = wsResp.websockets;
    } catch (e) {
      console.warn('Origami: Failed to load some analyzer data for report:', e);
    }

    // Load correlation chains
    if (options.content.correlationChains !== false) {
      try {
        const chainsResp = await new Promise(r => chrome.runtime.sendMessage({ action: 'getCorrelationChains', tabId: reportTabId }, r));
        if (chainsResp?.chains) {
          reportData.correlationChains = chainsResp.chains;
        }
      } catch (e) {
        console.warn('Origami: Failed to load correlation chains for report:', e);
      }
    }

    // Load SQLi Attack Lab findings from storage
    try {
      const sqliScanResp = await new Promise(r => chrome.storage.local.get(['sqli_last_scan'], r));
      const sqliData = sqliScanResp && sqliScanResp.sqli_last_scan;
      if (sqliData && Array.isArray(sqliData.results)) {
        const sqliTechNames = { B: 'boolean-based blind', E: 'error-based', T: 'time-based blind', U: 'UNION query', S: 'stacked queries' };
        const confirmedSqli = sqliData.results.filter(f => f.confirmed);
        if (confirmedSqli.length > 0) {
          const sqliVulns = confirmedSqli.map(f => ({
            check: `SQL Injection (${sqliTechNames[f.technique] || f.technique}) - ${f.param}`,
            status: 'vulnerable',
            severity: sqliTechniqueToSeverity(f.technique),
            message: `Parameter "${f.param}" is injectable via ${sqliTechNames[f.technique] || f.technique}. DBMS: ${f.dbms || 'unknown'}.`,
            recommendation: 'Use parameterized queries (prepared statements). Never concatenate user-controlled input into SQL queries.',
            source: 'SQLi Attack Lab',
            uri: sqliData.url || '',
            timestamp: new Date().toISOString(),
            matchedText: f.payload || '',
            sqliData: { technique: f.technique, param: f.param, payload: f.payload, dbms: f.dbms }
          }));
          if (!reportData.securityAnalysis) reportData.securityAnalysis = {};
          if (!reportData.securityAnalysis.vulnerabilities) reportData.securityAnalysis.vulnerabilities = [];
          reportData.securityAnalysis.vulnerabilities.push(...sqliVulns);
        }
      }
    } catch (e) {
      console.warn('Origami: Failed to load SQLi findings for report:', e);
    }

    // Test Google APIs if requested
    if (options.content.apiTesting && reportData.secrets.length > 0) {
      updateReportMainProgress(15, 'Testing Google APIs...');

      // Find all Google API keys in secrets
      const googleAPIKeys = reportData.secrets.filter(secret =>
        secret.pattern_matched && secret.pattern_matched.includes('Google')
      );

      if (googleAPIKeys.length > 0) {
        reportData.apiTestResults = [];
        const referer = currentSettings.api_validation?.use_referer ? tab.url : null;
        const quickTestOnly = currentSettings.api_validation?.quick_test_only !== false;

        for (let i = 0; i < googleAPIKeys.length; i++) {
          updateReportMainProgress(15 + (i / googleAPIKeys.length) * 10,
            `Testing API ${i + 1}/${googleAPIKeys.length}...`);

          try {
            const validator = new GoogleAPIValidator(googleAPIKeys[i].full_key, referer);
            const results = quickTestOnly ?
              await validator.runQuickTests() :
              await validator.runAllTests();

            reportData.apiTestResults.push({
              apiKey: googleAPIKeys[i].full_key,
              results: results
            });

            // Small delay to avoid rate limiting
            await new Promise(resolve => setTimeout(resolve, 500));
          } catch (error) {
            console.error(`Failed to test API key ${i}:`, error);
            reportData.apiTestResults.push({
              apiKey: googleAPIKeys[i].full_key,
              error: error.message
            });
          }
        }

        updateReportMainProgress(25, `API testing complete (${googleAPIKeys.length} keys tested)`);
      } else {
        updateReportMainProgress(15, 'No Google API keys found to test');
      }
    }

    // Create report generator
    const generator = new ReportGenerator();
    generator.generate(reportData);
    
    // If LLM enabled, enhance report
    if (options.llm.enabled) {
      updateReportMainProgress(15, 'Initializing LLM...');
      
      const llmSettings = await getLLMSettings();
      
      if (!llmSettings.enabled || llmSettings.provider === 'none') {
        throw new Error('LLM not configured. Please configure LLM in Settings.');
      }
      
      const llmManager = new LLMManager(
        llmSettings.provider,
        llmSettings.apiKey,
        llmSettings.endpoint
      );
      
      llmManager.setModel(llmSettings.model);
      
      // Get custom template if selected
      let templateOverride = null;
      if (options.llm.template === 'custom') {
        templateOverride = await getSelectedCustomTemplate();
      }
      
      // Generate LLM insights with progress tracking
      await generator.generateWithLLM(llmManager, {
        ...options.llm,
        templateOverride,
        progressCallback: updateReportMainProgress
      });
      
      updateReportMainProgress(95, 'LLM analysis complete...');
    } else {
      updateReportMainProgress(50, 'Formatting report...');
    }
    
    // Generate and download reports
    let downloadCount = 0;
    
    if (options.formats.html) {
      updateReportMainProgress(96, 'Generating HTML report...');
      generator.download('html');
      downloadCount++;
    }
    
    if (options.formats.markdown) {
      updateReportMainProgress(97, 'Generating Markdown report...');
      generator.download('markdown');
      downloadCount++;
    }
    
    if (options.formats.json) {
      updateReportMainProgress(98, 'Generating JSON export...');
      generator.download('json');
      downloadCount++;
    }
    
    updateReportMainProgress(100, `Complete! Downloaded ${downloadCount} file(s).`);
    showMessage(`Report generated successfully! Downloaded ${downloadCount} file(s).`, 'success');
    
    setTimeout(() => {
      showReportMainProgress(false);
      btn.disabled = false;
      btn.textContent = ' Generate Report';
    }, 2000);
    
  } catch (error) {
    console.error('Report generation error:', error);
    showMessage(`Report generation failed: ${error.message}`, 'error');
    showReportMainProgress(false);
    btn.disabled = false;
    btn.textContent = ' Generate Report';
  }
}

// Show/hide report progress
function showReportMainProgress(show) {
  const progressDiv = document.getElementById('reportMainProgress');
  progressDiv.style.display = show ? 'block' : 'none';
  
  if (!show) {
    updateReportMainProgress(0, '');
  }
}

// Update report progress
function updateReportMainProgress(percent, message) {
  const progressBar = document.getElementById('reportMainProgressBar');
  const progressText = document.getElementById('reportMainProgressText');
  
  progressBar.style.width = `${percent}%`;
  progressText.textContent = message;
}

// Get selected custom template
async function getSelectedCustomTemplate() {
  const templateId = document.getElementById('reportLLMTemplate').value;
  
  if (templateId === 'comprehensive' || templateId === 'executive' || 
      templateId === 'technical' || templateId === 'compliance') {
    // These are handled by default prompts in report generator
    return null;
  }
  
  if (templateId === 'custom') {
    // User wants to select a custom template - find first custom template
    const customTemplate = currentPromptTemplates.find(t => !t.builtin);
    return customTemplate || null;
  }
  
  // Look for specific template by ID
  return currentPromptTemplates.find(t => t.id === templateId) || null;
}

// Prompt Template Management Functions

// Load prompt templates
async function loadPromptTemplates() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(['prompt_templates'], (data) => {
      currentPromptTemplates = data.prompt_templates || getDefaultPromptTemplates();
      
      // If no templates exist, initialize with defaults
      if (!data.prompt_templates || data.prompt_templates.length === 0) {
        chrome.storage.sync.set({ prompt_templates: currentPromptTemplates });
      }
      
      displayPromptTemplates();
      resolve();
    });
  });
}

// Get default prompt templates
function getDefaultPromptTemplates() {
  return [
    {
      id: 'template-comprehensive',
      name: 'Comprehensive Security Report',
      category: 'report',
      description: 'Full security analysis with executive summary and detailed findings',
      prompt: `Analyze the security posture of {url} based on {findings_count} findings.

Critical Issues: {critical_count}
High Priority Issues: {high_count}

Provide:
1. Executive Summary
2. Risk Assessment
3. Critical Vulnerabilities Analysis
4. Remediation Priorities
5. Security Recommendations`,
      builtin: true
    },
    {
      id: 'template-executive',
      name: 'Executive Summary',
      category: 'report',
      description: 'High-level overview for management and stakeholders',
      prompt: `Create an executive summary for the security assessment of {url}.

Found {findings_count} total issues:
- {critical_count} Critical
- {high_count} High Priority

Focus on:
1. Key risks and business impact
2. Overall security posture rating
3. Top 3 priority actions
4. Resource requirements`,
      builtin: true
    },
    {
      id: 'template-technical',
      name: 'Technical Deep Dive',
      category: 'report',
      description: 'Detailed technical analysis for security teams',
      prompt: `Perform a detailed technical analysis of security findings for {url}.

Total findings: {findings_count}
Severity breakdown: {critical_count} critical, {high_count} high

Include:
1. Technical details of each vulnerability
2. Proof of concept where applicable
3. Attack vectors and exploitation scenarios
4. Specific remediation steps
5. Code examples for fixes`,
      builtin: true
    }
  ];
}

// Display prompt templates
function displayPromptTemplates() {
  const container = document.getElementById('promptTemplatesList');
  
  if (currentPromptTemplates.length === 0) {
    container.innerHTML = '<p class="info-text">No templates yet. Add your first template!</p>';
    return;
  }
  
  container.innerHTML = currentPromptTemplates.map(template => `
    <div class="template-item">
      <div class="template-header">
        <div>
          <strong>${escapeHtml(template.name)}</strong>
          <span class="template-category">${escapeHtml(template.category)}</span>
          ${template.builtin ? '<span class="template-badge">Built-in</span>' : ''}
        </div>
        <div class="template-actions">
          <button class="btn-icon edit-template-btn" data-template-id="${template.id}" title="Edit">${origamiIcon('wrench')}</button>
          ${!template.builtin ? `<button class="btn-icon delete delete-template-btn" data-template-id="${template.id}" title="Delete">${origamiIcon("wrench")} </button>` : ''}
        </div>
      </div>
      ${template.description ? `<p class="template-description">${escapeHtml(template.description)}</p>` : ''}
    </div>
  `).join('');
  
  // Add event listeners
  container.querySelectorAll('.edit-template-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const id = e.currentTarget.dataset.templateId;
      openPromptTemplateEditor(id);
    });
  });

  container.querySelectorAll('.delete-template-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const id = e.currentTarget.dataset.templateId;
      deletePromptTemplate(id);
    });
  });
}

// Open prompt template editor
function openPromptTemplateEditor(templateId = null) {
  const modal = document.getElementById('promptTemplateEditorModal');
  const title = document.getElementById('promptTemplateEditorTitle');
  const deleteBtn = document.getElementById('deletePromptTemplateBtn');
  
  // Reset form
  document.getElementById('promptTemplateName').value = '';
  document.getElementById('promptTemplateCategory').value = 'report';
  document.getElementById('promptTemplateDescription').value = '';
  document.getElementById('promptTemplatePrompt').value = '';
  
  if (templateId) {
    // Editing existing template
    const template = currentPromptTemplates.find(t => t.id === templateId);
    if (template) {
      editingPromptTemplate = template;
      title.textContent = 'Edit Prompt Template';
      document.getElementById('promptTemplateName').value = template.name;
      document.getElementById('promptTemplateCategory').value = template.category;
      document.getElementById('promptTemplateDescription').value = template.description || '';
      document.getElementById('promptTemplatePrompt').value = template.prompt;
      
      deleteBtn.style.display = template.builtin ? 'none' : 'inline-block';
    }
  } else {
    // Adding new template
    editingPromptTemplate = null;
    title.textContent = 'Add Prompt Template';
    deleteBtn.style.display = 'none';
  }
  
  modal.style.display = 'flex';
}

// Close prompt template editor
function closePromptTemplateEditor() {
  const modal = document.getElementById('promptTemplateEditorModal');
  modal.style.display = 'none';
  editingPromptTemplate = null;
}

// Save prompt template
async function savePromptTemplate() {
  const name = document.getElementById('promptTemplateName').value.trim();
  const category = document.getElementById('promptTemplateCategory').value;
  const description = document.getElementById('promptTemplateDescription').value.trim();
  const prompt = document.getElementById('promptTemplatePrompt').value.trim();
  
  // Validate
  if (!name) {
    showMessage('Template name is required', 'error');
    return;
  }
  
  if (!prompt) {
    showMessage('Prompt text is required', 'error');
    return;
  }
  
  const template = {
    name,
    category,
    description,
    prompt,
    builtin: false
  };
  
  if (editingPromptTemplate) {
    // Update existing
    template.id = editingPromptTemplate.id;
    template.builtin = editingPromptTemplate.builtin;
    const index = currentPromptTemplates.findIndex(t => t.id === editingPromptTemplate.id);
    if (index !== -1) {
      currentPromptTemplates[index] = template;
    }
  } else {
    // Add new
    template.id = 'template-' + Date.now().toString(36) + '-' + Math.random().toString(36).substr(2, 9);
    currentPromptTemplates.push(template);
  }
  
  await chrome.storage.sync.set({ prompt_templates: currentPromptTemplates });
  displayPromptTemplates();
  closePromptTemplateEditor();
  showMessage('Template saved successfully', 'success');
}

// Delete current prompt template (in editor)
async function deleteCurrentPromptTemplate() {
  if (!editingPromptTemplate) return;
  
  if (!confirm(`Delete template "${editingPromptTemplate.name}"? This cannot be undone.`)) {
    return;
  }
  
  await deletePromptTemplate(editingPromptTemplate.id);
  closePromptTemplateEditor();
}

// Delete prompt template
async function deletePromptTemplate(id) {
  const template = currentPromptTemplates.find(t => t.id === id);
  
  if (template && template.builtin) {
    showMessage('Cannot delete built-in templates', 'error');
    return;
  }
  
  if (!confirm('Delete this template? This cannot be undone.')) {
    return;
  }
  
  currentPromptTemplates = currentPromptTemplates.filter(t => t.id !== id);
  await chrome.storage.sync.set({ prompt_templates: currentPromptTemplates });
  displayPromptTemplates();
  showMessage('Template deleted', 'success');
}

// Inline AI Assessment Functions

// Perform inline AI assessment for a finding
async function performInlineAIAssessment(index, type, refresh = false, category = null, bulkMode = false) {
  console.log('Origami: performInlineAIAssessment called', { index, type, refresh, category, bulkMode });

  const llmSettings = await getLLMSettings();

  if (!llmSettings.enabled || llmSettings.provider === 'none') {
    if (!bulkMode) showMessage('Please configure LLM in Settings first', 'error');
    return;
  }

  let finding, assessmentContainer, assessBtn;

  if (type === 'secret') {
    finding = currentFindings[index];
    if (!bulkMode) {
      assessmentContainer = document.getElementById(`ai-assessment-${index}`);
      assessBtn = document.querySelector(`.ai-assess-btn[data-finding-index="${index}"]`);
    }
  } else if (type === 'security') {
    console.log('Origami: window.currentSecurityFindings:', window.currentSecurityFindings);

    if (!window.currentSecurityFindings) {
      if (!bulkMode) showMessage('Security findings not loaded. Please try again.', 'error');
      return;
    }

    if (!category) {
      console.error('Origami: category is required for security assessment lookup');
      if (!bulkMode) showMessage('Internal error: missing finding category', 'error');
      return;
    }

    const categoryFindings = window.currentSecurityFindings[category] || [];
    console.log('Origami: category:', category, 'categoryFindings length:', categoryFindings.length, 'looking for index:', index);

    finding = categoryFindings[index];
    if (!bulkMode) {
      assessmentContainer = document.getElementById(`ai-assessment-security-${category}-${index}`);
      assessBtn = document.querySelector(`.ai-assess-security-btn[data-finding-category="${category}"][data-finding-index="${index}"]`);
    }

    console.log('Origami: finding:', finding, 'container:', assessmentContainer, 'button:', assessBtn);
  }

  if (!finding) {
    console.error('Origami: Missing finding', { finding });
    if (!bulkMode) showMessage('Unable to perform AI assessment. Please try again.', 'error');
    return;
  }

  if (!bulkMode && !assessmentContainer) {
    console.error('Origami: Missing container', { assessmentContainer });
    showMessage('Unable to perform AI assessment. Please try again.', 'error');
    return;
  }
  
  // Update button to show loading state
  if (assessBtn) {
    assessBtn.classList.add('loading');
    assessBtn.disabled = true;
    const originalHTML = assessBtn.innerHTML;
    assessBtn.innerHTML = `<span class="btn-spinner"></span> Analyzing...`;
    assessBtn.dataset.originalHtml = originalHTML;
  }

  // Show loading state
  if (assessmentContainer) {
    assessmentContainer.innerHTML = `
      <div class="ai-assessment-loading">
        <div class="loading-spinner"></div>
        <span>Analyzing with AI...</span>
      </div>
    `;
  }
  
  try {
    const llmManager = new LLMManager(
      llmSettings.provider,
      llmSettings.apiKey,
      llmSettings.endpoint
    );
    llmManager.setModel(llmSettings.model);
    
    // Prepare comprehensive prompt with all finding details
    const prompt = buildFindingAssessmentPrompt(finding, type);
    const context = JSON.stringify({ finding }, null, 2);
    
    const result = await llmManager.analyze(prompt, context, {
      temperature: 0.3,
      maxTokens: 1500
    });
    
    // Parse AI-recommended severity from response with multiple fallback patterns
    // Note: AI responses may use markdown bold (**HIGH**) around severity values
    let severityMatch = result.response.match(/RECOMMENDED SEVERITY:\s*\*{0,2}(CRITICAL|HIGH|MEDIUM|LOW|INFO|NONE)\*{0,2}/i);

    // Fallback patterns if primary format not found
    if (!severityMatch) {
      severityMatch = result.response.match(/(?:severity|risk)\s*(?:level|recommendation|assessment)?:\s*\*{0,2}(CRITICAL|HIGH|MEDIUM|LOW|INFO|NONE)\*{0,2}/i);
    }
    if (!severityMatch) {
      severityMatch = result.response.match(/(?:suggested|recommended|revised)\s*(?:severity|risk)?\s*(?:level|is)?:?\s*\*{0,2}(CRITICAL|HIGH|MEDIUM|LOW|INFO|NONE)\*{0,2}/i);
    }
    if (!severityMatch) {
      // Fallback: find the LAST standalone severity (the first is likely the original/initial severity)
      const allMatches = [...result.response.matchAll(/\b(CRITICAL|HIGH|MEDIUM|LOW|INFO|NONE)\b/gi)];
      if (allMatches.length > 0) {
        severityMatch = allMatches[allMatches.length - 1];
      }
    }

    const suggestedSeverity = severityMatch ? severityMatch[1].toUpperCase() : null;

    // Log if severity extraction failed for debugging
    if (!suggestedSeverity) {
      console.warn('Origami: Failed to extract severity from AI response. First 200 chars:', result.response.substring(0, 200));
    } else {
      console.log('Origami: Extracted AI severity:', suggestedSeverity);
    }

    // Extract severity reasoning (text after the severity recommendation)
    let severityReasoning = null;
    if (severityMatch) {
      const reasoningStart = result.response.indexOf(severityMatch[0]) + severityMatch[0].length;
      severityReasoning = result.response.substring(reasoningStart).trim();
      // Extract first paragraph or up to 500 characters as reasoning
      const firstPara = severityReasoning.split('\n\n')[0];
      severityReasoning = firstPara.length > 500 ? firstPara.substring(0, 500) + '...' : firstPara;
    }
    
    // Automatically apply severity override if AI recommended a different severity
    const originalSeverity = (finding.severity || finding.risk || '').toUpperCase();
    if (suggestedSeverity && suggestedSeverity !== originalSeverity) {
      finding.severityOverride = {
        originalSeverity: originalSeverity,
        overriddenSeverity: suggestedSeverity,
        reason: `AI Assessment: ${severityReasoning || 'See AI analysis for details'}`,
        aiRecommended: true,
        timestamp: new Date().toISOString()
      };
    }
    
    // Store assessment with finding
    finding.aiAssessment = {
      analysis: result.response,
      timestamp: new Date().toISOString(),
      provider: llmSettings.provider,
      model: llmSettings.model,
      suggestedSeverity: suggestedSeverity,
      severityReasoning: severityReasoning
    };
    
    // In bulk mode, skip per-finding storage persistence and DOM rendering (caller handles refresh)
    if (bulkMode) {
      try {
        const bmTab = await getTargetTab();
        const bmDomain = new URL(bmTab.url).hostname;
        const bmFp = origamiFindingFingerprint(finding, type === 'secret' ? 'secrets' : (category || type));
        chrome.runtime.sendMessage({
          action: 'cacheAIAssessment',
          domain: bmDomain,
          fingerprint: bmFp,
          aiAssessment: finding.aiAssessment,
          severityOverride: finding.severityOverride || null
        });
      } catch (e) {
        console.error('Origami: Could not cache AI assessment in bulk mode:', e);
      }
      return finding.aiAssessment;
    }

    // Persist updated findings to storage
    const tab = await getTargetTab();

    // Store a reference to the finding object so we can find it after re-sort
    const assessedFinding = finding;

    if (type === 'secret') {
      await chrome.runtime.sendMessage({
        action: 'updateTabFindings',
        tabId: tab.id,
        findings: currentFindings
      });
      // Refresh display to show severity override (this re-sorts and re-renders)
      displayFindings(currentFindings);

      // After re-render, find the NEW index of the assessed finding (sort may have changed it)
      const newIndex = currentFindings.indexOf(assessedFinding);
      if (newIndex !== -1) {
        index = newIndex;
      }
    } else if (type === 'security') {
      // For security findings, we need to update the security results
      await chrome.runtime.sendMessage({
        action: 'updateTabSecurityResults',
        tabId: tab.id,
        results: window.currentSecurityFindings
      });
      // Refresh display to show severity override
      displaySecurityResults(window.currentSecurityFindings);

      // Phase 2-3 categories use separate storage keys; persist AI-assessed issues back
      const phase2Actions = {
        'exfiltration': 'updateExfiltrationResults',
        'crypto': 'updateCryptoResults',
        'cloudStorage': 'updateCloudStorageResults',
        'websocket': 'updateWebSocketResults'
      };
      if (category && phase2Actions[category] && window.currentSecurityFindings[category]) {
        chrome.runtime.sendMessage({
          action: phase2Actions[category],
          tabId: tab.id,
          data: window.currentSecurityFindings[category]
        });
      }
    }

    // Also save AI assessment directly to domain cache for persistence
    try {
      const domain = new URL(tab.url).hostname;
      const fp = origamiFindingFingerprint(finding, type === 'secret' ? 'secrets' : (category || type));
      chrome.runtime.sendMessage({
        action: 'cacheAIAssessment',
        domain: domain,
        fingerprint: fp,
        aiAssessment: finding.aiAssessment,
        severityOverride: finding.severityOverride || null
      });
    } catch (e) {
      console.error('Origami: Could not cache AI assessment:', e);
    }

    // Re-acquire DOM references after re-render (displayFindings destroys old DOM nodes)
    if (type === 'secret') {
      assessmentContainer = document.getElementById(`ai-assessment-${index}`);
      assessBtn = document.querySelector(`.ai-assess-btn[data-finding-index="${index}"]`);
    } else if (type === 'security') {
      assessmentContainer = document.getElementById(`ai-assessment-security-${category}-${index}`);
      assessBtn = document.querySelector(`.ai-assess-security-btn[data-finding-category="${category}"][data-finding-index="${index}"]`);
    }

    if (!assessmentContainer) {
      console.error('Origami: Assessment container not found after re-render for index', index, 'category', category);
      showMessage('AI assessment complete! Expand Details to view.', 'success');
      return;
    }

    // Display assessment with collapsible UI (expanded by default since user just requested it)
    const contentId = type === 'secret' ? `ai-assessment-content-${index}` : `ai-assessment-content-security-${category}-${index}`;
    assessmentContainer.innerHTML = `
      <div class="ai-assessment-result">
        <div class="ai-assessment-header-collapsible" style="cursor: pointer; display: flex; justify-content: space-between; align-items: center; padding: 8px 0;">
          <div>
            <strong>${origamiIcon('sparkles')} AI Security Assessment</strong>
            <span class="ai-timestamp" style="margin-left: 8px; font-size: 11px; color: var(--text-secondary);">${new Date().toLocaleString()}</span>
            ${suggestedSeverity && finding.severityOverride ? '<span style="margin-left: 8px; color: var(--success-color); font-size: 12px;">✓ Severity auto-applied</span>' : ''}
          </div>
          <button class="btn btn-secondary btn-sm toggle-ai-assessment-btn" data-finding-category="${category || ''}" data-finding-index="${index}" data-finding-type="${type}" style="padding: 2px 8px; font-size: 12px;">
            ▲ Collapse
          </button>
        </div>
        <div class="ai-assessment-collapsible-content" id="${contentId}" style="display: block;">
          ${suggestedSeverity ? `
          <div class="ai-severity-recommendation" style="margin: 8px 0; padding: 8px; background: rgba(16, 185, 129, 0.1); border-left: 3px solid #10b981; border-radius: 4px; color: var(--text-primary);">
            <strong>AI Recommended Severity:</strong>
            <span class="badge ${suggestedSeverity.toLowerCase()}">${suggestedSeverity}</span>
            ${severityReasoning ? `<p style="margin-top: 8px; font-size: 12px; color: var(--text-secondary);">${escapeHtml(severityReasoning)}</p>` : ''}
          </div>` : ''}
          <div class="ai-assessment-content">${formatAIAssessment(result.response)}</div>
          <div class="ai-assessment-actions">
            <button class="btn btn-secondary btn-sm refresh-ai-btn" data-finding-category="${category || ''}" data-finding-index="${index}" data-finding-type="${type}">
              ${origamiIcon('refresh')} Refresh Analysis
            </button>
            <button class="btn btn-secondary btn-sm copy-ai-btn">
              ${origamiIcon('clipboard')} Copy Analysis
            </button>
          </div>
        </div>
      </div>
    `;

    // Add event listeners to new buttons
    assessmentContainer.querySelector('.refresh-ai-btn').addEventListener('click', async (e) => {
      await performInlineAIAssessment(index, type, true, category);
    });

    assessmentContainer.querySelector('.copy-ai-btn').addEventListener('click', () => {
      copyToClipboard(result.response);
      showMessage('AI assessment copied to clipboard', 'success');
    });

    // Add toggle collapse/expand listener
    const toggleAIBtn = assessmentContainer.querySelector('.toggle-ai-assessment-btn');
    if (toggleAIBtn) {
      toggleAIBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const contentDiv = document.getElementById(contentId);
        if (contentDiv) {
          if (contentDiv.style.display === 'none') {
            contentDiv.style.display = 'block';
            e.target.textContent = '▲ Collapse';
          } else {
            contentDiv.style.display = 'none';
            e.target.textContent = '▼ Expand';
          }
        }
      });

      // Also allow clicking the header to toggle
      const headerDiv = assessmentContainer.querySelector('.ai-assessment-header-collapsible');
      if (headerDiv) {
        headerDiv.addEventListener('click', (e) => {
          if (!e.target.classList.contains('toggle-ai-assessment-btn')) {
            toggleAIBtn.click();
          }
        });
      }
    }

    // Update the AI Assess button to show it has assessment
    if (assessBtn) {
      assessBtn.classList.remove('loading');
      assessBtn.classList.add('has-assessment');
      assessBtn.disabled = false;
      assessBtn.innerHTML = `${origamiIcon('sparkles')} AI Analysis`;
      assessBtn.title = 'View/Update AI Assessment';
    }

    showMessage('AI assessment complete!', 'success');

    // Auto-expand Details section to show the AI assessment (use updated index)
    setTimeout(() => {
      let detailsDiv, toggleBtn;

      if (type === 'secret') {
        detailsDiv = document.getElementById(`finding-details-${index}`);
        toggleBtn = document.querySelector(`.toggle-details-btn[data-finding-index="${index}"]`);
      } else if (type === 'security') {
        detailsDiv = document.getElementById(`security-details-${category}-${index}`);
        toggleBtn = document.querySelector(`.toggle-security-details-btn[data-finding-category="${category}"][data-finding-index="${index}"]`);
      }

      if (detailsDiv && detailsDiv.style.display === 'none') {
        detailsDiv.style.display = 'block';
        if (toggleBtn) {
          toggleBtn.textContent = ' Hide Details';
        }
      }

      // Scroll to the AI assessment section (use fresh DOM reference)
      const freshContainer = type === 'secret'
        ? document.getElementById(`ai-assessment-${index}`)
        : document.getElementById(`ai-assessment-security-${category}-${index}`);
      if (freshContainer) {
        freshContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    }, 150);

  } catch (error) {
    console.error('AI assessment error:', error);
    if (bulkMode) throw error;
    assessmentContainer.innerHTML = `
      <div class="ai-assessment-error">
        <strong>${origamiIcon('warning')} Assessment Failed</strong>
        <p>${escapeHtml(error.message)}</p>
        <button class="btn btn-secondary btn-sm retry-ai-btn" data-finding-category="${category || ''}" data-finding-index="${index}" data-finding-type="${type}">
          ${origamiIcon('refresh')} Retry
        </button>
      </div>
    `;

    assessmentContainer.querySelector('.retry-ai-btn').addEventListener('click', async () => {
      await performInlineAIAssessment(index, type, false, category);
    });

    // Restore button state on error
    if (assessBtn) {
      assessBtn.classList.remove('loading');
      assessBtn.disabled = false;
      assessBtn.innerHTML = assessBtn.dataset.originalHtml || '${origamiIcon("sparkles")}  AI Assess';
    }
    
    showMessage('AI assessment failed: ' + error.message, 'error');
  }
}

// Perform AI assessment for CVE/SCA findings
function saveSCAAIAssessments() {
  if (!window.currentTechVulnerabilities) return;
  const assessments = {};
  for (const [cat, techs] of Object.entries(window.currentTechVulnerabilities)) {
    if (cat.startsWith('_') || !Array.isArray(techs)) continue;
    techs.forEach((tech, idx) => {
      if (tech.aiAssessment) {
        assessments[`${cat}:${idx}:${tech.name}`] = tech.aiAssessment;
      }
    });
  }
  if (Object.keys(assessments).length > 0) {
    saveFeatureState('sca_ai_assessments', assessments);
  }
}

function restoreSCAAIAssessments() {
  if (!window.currentTechVulnerabilities) return;
  loadFeatureState('sca_ai_assessments', (assessments) => {
    if (!assessments || !window.currentTechVulnerabilities) return;
    for (const [key, assessment] of Object.entries(assessments)) {
      const parts = key.split(':');
      const cat = parts[0];
      const idxStr = parts[1];
      const name = parts.slice(2).join(':');
      const idx = parseInt(idxStr);
      if (window.currentTechVulnerabilities[cat]?.[idx]) {
        const tech = window.currentTechVulnerabilities[cat][idx];
        if (tech.name === name && !tech.aiAssessment) {
          tech.aiAssessment = assessment;
          // Re-render the assessment in DOM if container exists
          const containerId = `ai-assessment-cve-${cat}-${idx}`;
          const container = document.getElementById(containerId);
          if (container && container.innerHTML.trim() === '') {
            const contentId = `ai-assessment-content-cve-${cat}-${idx}`;
            container.innerHTML = `
              <div class="ai-assessment-result">
                <div class="ai-assessment-header-collapsible" style="cursor: pointer; display: flex; justify-content: space-between; align-items: center; padding: 8px 0;">
                  <div>
                    <strong>${origamiIcon('sparkles')} AI Security Assessment</strong>
                    <span class="ai-timestamp" style="margin-left: 8px; font-size: 11px; color: var(--text-secondary);">${new Date(assessment.timestamp).toLocaleString()}</span>
                  </div>
                  <button class="btn btn-secondary btn-sm toggle-ai-assessment-btn" data-tech-category="${cat}" data-tech-index="${idx}" style="padding: 2px 8px; font-size: 12px;">
                    ▼ Expand
                  </button>
                </div>
                <div class="ai-assessment-collapsible-content" id="${contentId}" style="display: none;">
                  <div class="ai-assessment-content">${formatAIAssessment(assessment.analysis)}</div>
                  <div class="ai-assessment-actions">
                    <button class="btn btn-secondary btn-sm refresh-ai-cve-btn" data-tech-category="${cat}" data-tech-index="${idx}">
                      ${origamiIcon('refresh')} Refresh Analysis
                    </button>
                    <button class="btn btn-secondary btn-sm copy-ai-btn">
                      ${origamiIcon('clipboard')} Copy Analysis
                    </button>
                  </div>
                </div>
              </div>
            `;
          }
        }
      }
    }
  });
}

async function performCVEAIAssessment(techName, techVersion, category, techIndex, refresh = false) {
  console.log('Origami: performCVEAIAssessment called', { techName, techVersion, category, techIndex, refresh });

  const llmSettings = await getLLMSettings();

  if (!llmSettings.enabled || llmSettings.provider === 'none') {
    showMessage('Please configure LLM in Settings first', 'error');
    return;
  }

  // Find the technology object in window.currentTechVulnerabilities
  if (!window.currentTechVulnerabilities || !window.currentTechVulnerabilities[category]) {
    showMessage('CVE data not loaded. Please try again.', 'error');
    return;
  }

  const tech = window.currentTechVulnerabilities[category][techIndex];
  if (!tech) {
    showMessage('Technology not found. Please try again.', 'error');
    return;
  }

  const assessmentContainer = document.getElementById(`ai-assessment-cve-${category}-${techIndex}`);
  const assessBtn = document.querySelector(`.ai-assess-cve-btn[data-tech-category="${category}"][data-tech-index="${techIndex}"]`);

  if (!assessmentContainer) {
    showMessage('Unable to perform AI assessment. Please try again.', 'error');
    return;
  }

  // Update button to show loading state
  if (assessBtn) {
    assessBtn.classList.add('loading');
    assessBtn.disabled = true;
    const originalHTML = assessBtn.innerHTML;
    assessBtn.innerHTML = `<span class="btn-spinner"></span> Analyzing...`;
    assessBtn.dataset.originalHtml = originalHTML;
  }

  // Show loading state
  assessmentContainer.innerHTML = `
    <div class="ai-assessment-loading">
      <div class="loading-spinner"></div>
      <span>Analyzing vulnerabilities with AI...</span>
    </div>
  `;

  try {
    const llmManager = new LLMManager(
      llmSettings.provider,
      llmSettings.apiKey,
      llmSettings.endpoint
    );
    llmManager.setModel(llmSettings.model);

    // Build comprehensive prompt for CVE assessment
    const prompt = buildCVEAssessmentPrompt(tech);
    const context = JSON.stringify({
      technology: {
        name: tech.name,
        version: tech.version,
        vulnerabilities: tech.vulnerabilities,
        eolStatus: tech.eolStatus
      }
    }, null, 2);

    const result = await llmManager.analyze(prompt, context, {
      temperature: 0.3,
      maxTokens: 2000
    });

    // Store assessment with technology object
    tech.aiAssessment = {
      analysis: result.response,
      timestamp: new Date().toISOString(),
      provider: llmSettings.provider,
      model: llmSettings.model
    };

    // Persist updated vulnerabilities to window object
    // (This will be used by AI Assess All and report generation)
    window.currentTechVulnerabilities[category][techIndex] = tech;

    // Persist SCA AI assessments to storage
    saveSCAAIAssessments();

    // Display assessment with collapsible UI
    const contentId = `ai-assessment-content-cve-${category}-${techIndex}`;
    assessmentContainer.innerHTML = `
      <div class="ai-assessment-result">
        <div class="ai-assessment-header-collapsible" style="cursor: pointer; display: flex; justify-content: space-between; align-items: center; padding: 8px 0;">
          <div>
            <strong>${origamiIcon('sparkles')} AI Security Assessment</strong>
            <span class="ai-timestamp" style="margin-left: 8px; font-size: 11px; color: var(--text-secondary);">${new Date().toLocaleString()}</span>
          </div>
          <button class="btn btn-secondary btn-sm toggle-ai-assessment-btn" data-tech-category="${category}" data-tech-index="${techIndex}" style="padding: 2px 8px; font-size: 12px;">
            ▲ Collapse
          </button>
        </div>
        <div class="ai-assessment-collapsible-content" id="${contentId}" style="display: block;">
          <div class="ai-assessment-content">${formatAIAssessment(result.response)}</div>
          <div class="ai-assessment-actions">
            <button class="btn btn-secondary btn-sm refresh-ai-cve-btn" data-tech-category="${category}" data-tech-index="${techIndex}">
              ${origamiIcon('refresh')} Refresh Analysis
            </button>
            <button class="btn btn-secondary btn-sm copy-ai-btn">
              ${origamiIcon('clipboard')} Copy Analysis
            </button>
          </div>
        </div>
      </div>
    `;

    // Add event listeners to new buttons
    assessmentContainer.querySelector('.refresh-ai-cve-btn').addEventListener('click', async (e) => {
      await performCVEAIAssessment(techName, techVersion, category, techIndex, true);
    });

    assessmentContainer.querySelector('.copy-ai-btn').addEventListener('click', () => {
      copyToClipboard(result.response);
      showMessage('AI assessment copied to clipboard', 'success');
    });

    // Add toggle collapse/expand listener
    const toggleAIBtn = assessmentContainer.querySelector('.toggle-ai-assessment-btn');
    if (toggleAIBtn) {
      toggleAIBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const contentDiv = document.getElementById(contentId);
        if (contentDiv) {
          if (contentDiv.style.display === 'none') {
            contentDiv.style.display = 'block';
            e.target.textContent = '▲ Collapse';
          } else {
            contentDiv.style.display = 'none';
            e.target.textContent = '▼ Expand';
          }
        }
      });

      // Also allow clicking the header to toggle
      const headerDiv = assessmentContainer.querySelector('.ai-assessment-header-collapsible');
      if (headerDiv) {
        headerDiv.addEventListener('click', (e) => {
          if (!e.target.classList.contains('toggle-ai-assessment-btn')) {
            toggleAIBtn.click();
          }
        });
      }
    }

    // Update the AI Assess button to show it has assessment
    if (assessBtn) {
      assessBtn.classList.remove('loading');
      assessBtn.classList.add('has-assessment');
      assessBtn.disabled = false;
      assessBtn.innerHTML = '${origamiIcon("sparkles")}  AI Analysis';
      assessBtn.title = 'View/Update AI Assessment';
    }

    showMessage('AI assessment complete!', 'success');

    // Auto-expand vulnerability details to show the AI assessment
    setTimeout(() => {
      const techId = `vuln-tech-${category}-${techIndex}`;
      const detailsDiv = document.getElementById(`${techId}-details`);
      const toggleBtn = document.querySelector(`.toggle-vuln-details-btn[data-tech-id="${techId}"]`);

      if (detailsDiv && detailsDiv.style.display === 'none') {
        detailsDiv.style.display = 'block';
        if (toggleBtn) {
          toggleBtn.textContent = '▲ Collapse';
        }
      }

      // Scroll to the AI assessment section
      assessmentContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, 100);

  } catch (error) {
    console.error('AI CVE assessment error:', error);
    assessmentContainer.innerHTML = `
      <div class="ai-assessment-error">
        <strong>${origamiIcon('warning')} Assessment Failed</strong>
        <p>${escapeHtml(error.message)}</p>
        <button class="btn btn-secondary btn-sm retry-ai-cve-btn" data-tech-category="${category}" data-tech-index="${techIndex}">
          ${origamiIcon('refresh')} Retry
        </button>
      </div>
    `;

    assessmentContainer.querySelector('.retry-ai-cve-btn').addEventListener('click', async () => {
      await performCVEAIAssessment(techName, techVersion, category, techIndex);
    });

    // Restore button state on error
    if (assessBtn) {
      assessBtn.classList.remove('loading');
      assessBtn.disabled = false;
      assessBtn.innerHTML = assessBtn.dataset.originalHtml || '${origamiIcon("sparkles")}  AI Assess';
    }

    showMessage('AI assessment failed: ' + error.message, 'error');
  }
}

// Build prompt for CVE/SCA assessment
function buildCVEAssessmentPrompt(tech) {
  let prompt = `Analyze these software vulnerabilities and provide a comprehensive security assessment:

**Component:** ${tech.name}${tech.version ? ` v${tech.version}` : ''}
`;

  // Add vulnerability details
  if (tech.vulnerabilities && tech.vulnerabilities.length > 0) {
    prompt += `\n**Known Vulnerabilities:** ${tech.vulnerabilities.length}\n`;
    tech.vulnerabilities.forEach((vuln, idx) => {
      prompt += `\n${idx + 1}. **${vuln.id}** - ${vuln.severity}`;
      if (vuln.score) prompt += ` (CVSS: ${vuln.score})`;
      prompt += `\n   ${vuln.summary}`;
      if (vuln.fixedVersion) prompt += `\n   Fixed in: ${vuln.fixedVersion}`;
    });
  }

  // Add EOL information
  if (tech.eolStatus) {
    prompt += `\n\n**End-of-Life Status:** ${tech.eolStatus.status}`;
    if (typeof tech.eolStatus.eolDate === 'boolean') {
      prompt += `\n**Security Support:** ${tech.eolStatus.eolDate ? 'Ended' : 'Active'}`;
    } else if (tech.eolStatus.eolDate) {
      prompt += `\n**EOL Date:** ${tech.eolStatus.eolDate}`;
    }
    if (tech.eolStatus.supportDate) prompt += `\n**Active Support Until:** ${tech.eolStatus.supportDate}`;
    if (tech.eolStatus.activeSupportEnded) prompt += `\n**Active Support:** Ended (security updates only)`;
    if (tech.eolStatus.extendedSupportDate) prompt += `\n**Extended Support Until:** ${tech.eolStatus.extendedSupportDate}`;
    if (tech.eolStatus.lts) prompt += `\n**LTS Release:** Yes`;
    if (tech.eolStatus.latestVersion) prompt += `\n**Latest Version:** ${tech.eolStatus.latestVersion}`;
    if (tech.eolStatus.supportStatus) prompt += `\n**Support Level:** ${tech.eolStatus.supportStatus}`;
  }

  prompt += `\n\nProvide:
1. **Risk Assessment**: What is the overall security risk of using this component version?
2. **Priority Vulnerabilities**: Which CVEs should be addressed first and why?
3. **Exploitability**: How easily exploitable are these vulnerabilities in a real-world scenario?
4. **Business Impact**: What could happen if these vulnerabilities are exploited?
5. **Upgrade Recommendation**: Should this component be upgraded immediately? What version?
6. **Workarounds**: If immediate upgrade isn't possible, what mitigations can be applied?
7. **Attack Scenarios**: Describe realistic attack scenarios that exploit these vulnerabilities
8. **Remediation Priority**: Rate the urgency (CRITICAL, HIGH, MEDIUM, LOW) and provide a timeline recommendation

Be specific and practical in your recommendations.`;

  return prompt;
}

// Perform bulk AI assessment on all findings
async function performBulkAIAssessment() {
  console.log('Origami: performBulkAIAssessment started');

  // Check if LLM is enabled
  const llmSettings = await getLLMSettings();
  if (!llmSettings.enabled || llmSettings.provider === 'none') {
    showMessage('Please configure LLM in Settings first', 'error');
    return;
  }

  // Get AI assessment configuration
  const aiConfig = currentSettings.ai_assessment || {
    types: { secrets: true, headers: true, cookies: true, vulnerabilities: true, sca: true, exposedFiles: true, session: true, oauth: true, graphql: true, crypto: true, cloudStorage: true, exfiltration: true, websocket: true, correlationChains: true },
    severities: { critical: true, high: true, medium: false, low: false, info: false },
    skip_assessed: true
  };

  console.log('Origami: AI Assessment config:', aiConfig);

  // Helper function to check if severity should be assessed
  const shouldAssessSeverity = (severity) => {
    const sev = (severity || 'info').toLowerCase();
    return aiConfig.severities[sev] === true;
  };

  // Gather secrets to assess (if enabled)
  let secretsToAssess = [];
  if (aiConfig.types.secrets) {
    secretsToAssess = currentFindings.filter(f => {
      // Skip if already assessed (if configured)
      if (aiConfig.skip_assessed && f.aiAssessment) return false;

      // Check severity
      return shouldAssessSeverity(f.risk);
    });
  }

  // Gather security findings to assess
  let headersToAssess = [];
  let cookiesToAssess = [];
  let vulnsToAssess = [];
  let exposedFilesToAssess = [];
  let cryptoToAssess = [];
  let cloudStorageToAssess = [];
  let exfiltrationToAssess = [];
  let websocketToAssess = [];
  let sessionToAssess = [];
  let oauthToAssess = [];
  let graphqlToAssess = [];

  if (window.currentSecurityFindings) {
    // Headers
    if (aiConfig.types.headers && window.currentSecurityFindings.headers) {
      headersToAssess = window.currentSecurityFindings.headers.filter(f => {
        if (aiConfig.skip_assessed && f.aiAssessment) return false;
        return shouldAssessSeverity(f.severity);
      });
    }

    // Cookies
    if (aiConfig.types.cookies && window.currentSecurityFindings.cookies) {
      cookiesToAssess = window.currentSecurityFindings.cookies.filter(f => {
        if (aiConfig.skip_assessed && f.aiAssessment) return false;
        return shouldAssessSeverity(f.severity);
      });
    }

    // Vulnerabilities
    if (aiConfig.types.vulnerabilities && window.currentSecurityFindings.vulnerabilities) {
      vulnsToAssess = window.currentSecurityFindings.vulnerabilities.filter(f => {
        if (aiConfig.skip_assessed && f.aiAssessment) return false;
        return shouldAssessSeverity(f.severity);
      });
    }

    // Exposed Files
    if (aiConfig.types.exposedFiles && window.currentSecurityFindings.sensitiveFiles) {
      exposedFilesToAssess = window.currentSecurityFindings.sensitiveFiles.filter(f => {
        if (aiConfig.skip_assessed && f.aiAssessment) return false;
        return shouldAssessSeverity(f.severity);
      });
    }

    // Crypto findings
    if (aiConfig.types.crypto && window.currentSecurityFindings.crypto) {
      cryptoToAssess = (window.currentSecurityFindings.crypto || []).filter(f => {
        if (aiConfig.skip_assessed && f.aiAssessment) return false;
        return shouldAssessSeverity(f.severity);
      });
    }

    // Cloud storage findings
    if (aiConfig.types.cloudStorage && window.currentSecurityFindings.cloudStorage) {
      cloudStorageToAssess = (window.currentSecurityFindings.cloudStorage || []).filter(f => {
        if (aiConfig.skip_assessed && f.aiAssessment) return false;
        return shouldAssessSeverity(f.severity);
      });
    }

    // Exfiltration findings
    if (aiConfig.types.exfiltration && window.currentSecurityFindings.exfiltration) {
      exfiltrationToAssess = (window.currentSecurityFindings.exfiltration || []).filter(f => {
        if (aiConfig.skip_assessed && f.aiAssessment) return false;
        return shouldAssessSeverity(f.severity);
      });
    }

    // WebSocket findings
    if (aiConfig.types.websocket && window.currentSecurityFindings.websocket) {
      websocketToAssess = (window.currentSecurityFindings.websocket || []).filter(f => {
        if (aiConfig.skip_assessed && f.aiAssessment) return false;
        return shouldAssessSeverity(f.severity);
      });
    }

    // Session findings
    if (aiConfig.types.session && window.currentSecurityFindings.session) {
      sessionToAssess = (window.currentSecurityFindings.session || []).filter(f => {
        if (aiConfig.skip_assessed && f.aiAssessment) return false;
        return shouldAssessSeverity(f.severity);
      });
    }

    // OAuth/SAML findings
    if (aiConfig.types.oauth && window.currentSecurityFindings.oauth) {
      oauthToAssess = (window.currentSecurityFindings.oauth || []).filter(f => {
        if (aiConfig.skip_assessed && f.aiAssessment) return false;
        return shouldAssessSeverity(f.severity);
      });
    }

    // GraphQL findings
    if (aiConfig.types.graphql && window.currentSecurityFindings.graphql) {
      graphqlToAssess = (window.currentSecurityFindings.graphql || []).filter(f => {
        if (aiConfig.skip_assessed && f.aiAssessment) return false;
        return shouldAssessSeverity(f.severity);
      });
    }
  }

  // Gather correlation chain findings to assess
  let chainsToAssess = [];
  if (aiConfig.types.correlationChains) {
    try {
      const activeTab = await getTargetTab();
      const chainsResp = await new Promise(r => chrome.runtime.sendMessage({ action: 'getCorrelationChains', tabId: activeTab.id }, r));
      if (chainsResp?.chains && Array.isArray(chainsResp.chains)) {
        chainsToAssess = chainsResp.chains.filter((chain, idx) => {
          if (aiConfig.skip_assessed && chain.aiAssessment) return false;
          return shouldAssessSeverity(chain.severity);
        }).map((chain, idx) => {
          // Find the original index in the full chains array
          const originalIdx = chainsResp.chains.indexOf(chain);
          return { chain, idx: originalIdx };
        });
        // Store chains for assessment updates
        window._correlationChainsForAssess = chainsResp.chains;
      }
    } catch (e) {
      console.warn('Origami: Failed to load correlation chains for assessment:', e);
    }
  }

  // Gather SCA findings to assess (CVE/EOL vulnerabilities)
  let scaToAssess = [];
  if (aiConfig.types.sca && window.currentTechVulnerabilities) {
    // Flatten all categories and filter technologies with vulnerabilities or EOL
    Object.keys(window.currentTechVulnerabilities).forEach(category => {
      const techsInCategory = window.currentTechVulnerabilities[category];
      techsInCategory.forEach((tech, idx) => {
        // Check if has vulnerabilities or EOL status
        const hasVulns = tech.vulnerabilities && tech.vulnerabilities.length > 0;
        const hasEOL = tech.eolStatus && (tech.eolStatus.status === 'EOL' || tech.eolStatus.status === 'ENDING_SOON' || tech.eolStatus.status === 'ENDING_SOON_6MO');

        if (hasVulns || hasEOL) {
          // Skip if already assessed
          if (aiConfig.skip_assessed && tech.aiAssessment) return;

          // For technologies with vulnerabilities, check severity filter
          // For EOL-only technologies, always include (treat as HIGH severity)
          let shouldInclude = false;

          if (hasVulns) {
            // Check if any vulnerability matches severity filter
            shouldInclude = tech.vulnerabilities.some(vuln =>
              shouldAssessSeverity(vuln.severity)
            );
          } else if (hasEOL) {
            // EOL without CVEs - treat as HIGH severity concern
            shouldInclude = shouldAssessSeverity('HIGH');
          }

          if (shouldInclude) {
            scaToAssess.push({
              tech,
              category,
              idx,
              techName: tech.name,
              techVersion: tech.version
            });
          }
        }
      });
    });
  }

  const securityToAssess = [...headersToAssess, ...cookiesToAssess, ...vulnsToAssess, ...exposedFilesToAssess];
  const advancedToAssess = [...cryptoToAssess, ...cloudStorageToAssess, ...exfiltrationToAssess, ...websocketToAssess, ...sessionToAssess, ...oauthToAssess, ...graphqlToAssess];
  const allSecurityToAssess = [...securityToAssess, ...advancedToAssess];
  const totalToAssess = secretsToAssess.length + allSecurityToAssess.length + scaToAssess.length + chainsToAssess.length;

  if (totalToAssess === 0) {
    showMessage('No findings match your AI Assessment configuration. Adjust settings in Settings tab.', 'info');
    return;
  }

  // Disable button during processing
  const assessAllBtn = document.getElementById('aiAssessAllBtn');
  const originalBtnText = assessAllBtn.innerHTML;
  assessAllBtn.disabled = true;
  assessAllBtn.innerHTML = '<span class="btn-spinner"></span> Processing...';

  let completed = 0;
  let failed = 0;

  try {
    // Build unified task list for concurrent processing
    const assessmentTasks = [];

    for (let i = 0; i < currentFindings.length; i++) {
      if (secretsToAssess.includes(currentFindings[i])) {
        assessmentTasks.push({ type: 'secret', index: i, category: null, label: `secret ${i}` });
      }
    }

    if (window.currentSecurityFindings) {
      const securityCategories = ['headers', 'cookies', 'vulnerabilities', 'sensitiveFiles', 'crypto', 'cloudStorage', 'exfiltration', 'websocket', 'session', 'oauth', 'graphql'];
      for (const cat of securityCategories) {
        const findings = window.currentSecurityFindings[cat] || [];
        for (let i = 0; i < findings.length; i++) {
          if (allSecurityToAssess.includes(findings[i])) {
            assessmentTasks.push({ type: 'security', index: i, category: cat, label: `${cat} ${i}` });
          }
        }
      }
    }

    for (let i = 0; i < scaToAssess.length; i++) {
      const { techName, techVersion, category, idx } = scaToAssess[i];
      assessmentTasks.push({ type: 'sca', techName, techVersion, category, techIdx: idx, label: `SCA ${techName}` });
    }

    for (let i = 0; i < chainsToAssess.length; i++) {
      const { chain, idx } = chainsToAssess[i];
      assessmentTasks.push({ type: 'chain', chainIdx: idx, chain, label: `Chain ${chain.title || idx}` });
    }

    // Concurrent assessment with configurable pool size
    const concurrencyLimit = aiConfig.concurrent_assessments || parseInt(document.getElementById('aiAssessConcurrency')?.value || '3', 10);

    async function executeAssessment(task) {
      try {
        if (task.type === 'secret') {
          await performInlineAIAssessment(task.index, 'secret', false, null, true);
        } else if (task.type === 'security') {
          await performInlineAIAssessment(task.index, 'security', false, task.category, true);
        } else if (task.type === 'sca') {
          await performCVEAIAssessment(task.techName, task.techVersion, task.category, task.techIdx);
        } else if (task.type === 'chain') {
          await performChainAIAssessment(task.chain, task.chainIdx);
        }
        completed++;
      } catch (error) {
        console.error(`Failed to assess ${task.label}:`, error);
        failed++;
      }
      assessAllBtn.innerHTML = `<span class="btn-spinner"></span> Analyzing ${completed + failed}/${totalToAssess}...`;
      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    // Promise pool: keeps `limit` assessments running concurrently
    async function runPool(tasks, limit) {
      const queue = [...tasks];
      const running = [];

      async function runNext() {
        if (queue.length === 0) return;
        const task = queue.shift();
        const promise = executeAssessment(task).then(() => {
          running.splice(running.indexOf(promise), 1);
        });
        running.push(promise);
        if (running.length >= limit) {
          await Promise.race(running);
        }
        await runNext();
      }

      const starters = [];
      for (let i = 0; i < Math.min(limit, tasks.length); i++) {
        starters.push(runNext());
      }
      await Promise.all(starters);
      await Promise.all(running);
    }

    await runPool(assessmentTasks, concurrencyLimit);

    // Persist and refresh UI once after all bulk assessments
    const tab = await getTargetTab();
    if (secretsToAssess.length > 0) {
      await chrome.runtime.sendMessage({ action: 'updateTabFindings', tabId: tab.id, findings: currentFindings });
      displayFindings(currentFindings);
    }
    if (allSecurityToAssess.length > 0 && window.currentSecurityFindings) {
      await chrome.runtime.sendMessage({ action: 'updateTabSecurityResults', tabId: tab.id, results: window.currentSecurityFindings });
      const phase2Actions = { 'exfiltration': 'updateExfiltrationResults', 'crypto': 'updateCryptoResults', 'cloudStorage': 'updateCloudStorageResults', 'websocket': 'updateWebSocketResults' };
      for (const cat of Object.keys(phase2Actions)) {
        if (window.currentSecurityFindings[cat]) {
          chrome.runtime.sendMessage({ action: phase2Actions[cat], tabId: tab.id, data: window.currentSecurityFindings[cat] });
        }
      }
      displaySecurityResults(window.currentSecurityFindings);
    }
    if (chainsToAssess.length > 0 && window._correlationChainsForAssess) {
      const chainsKey = `tab_chains_${tab.id}`;
      await chrome.storage.local.set({ [chainsKey]: window._correlationChainsForAssess });
    }

    // Show completion message
    if (failed === 0) {
      showMessage(`✓ Bulk AI assessment complete! ${completed} findings analyzed.`, 'success');
    } else {
      showMessage(`Bulk AI assessment completed with ${failed} errors. ${completed} findings analyzed successfully.`, 'warning');
    }

  } catch (error) {
    console.error('Bulk AI assessment error:', error);
    showMessage('Bulk AI assessment failed: ' + error.message, 'error');
  } finally {
    // Re-enable button
    assessAllBtn.disabled = false;
    assessAllBtn.innerHTML = originalBtnText;
  }
}

// AI assessment for a single correlation chain (bulk mode only)
async function performChainAIAssessment(chain, chainIdx) {
  const llmSettings = await getLLMSettings();
  if (!llmSettings.enabled || llmSettings.provider === 'none') return;

  const llmManager = new LLMManager(
    llmSettings.provider,
    llmSettings.apiKey,
    llmSettings.endpoint
  );
  llmManager.setModel(llmSettings.model);

  const prompt = `Analyze this attack chain found during security testing. Assess whether this chain represents a real exploitable path or is a theoretical/low-risk combination. Consider the severity of each step and the overall chain impact.

Chain: ${chain.title || 'Unnamed chain'}
Severity: ${chain.severity}
Steps: ${(chain.steps || chain.findings || []).map((s, i) => `${i + 1}. [${s.severity || s.risk || 'UNKNOWN'}] ${s.description || s.title || s.finding || JSON.stringify(s)}`).join('\n')}

Provide:
1. Whether this chain is practically exploitable
2. Key risk factors
3. Recommended mitigations
4. RECOMMENDED SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW|INFO>`;

  const context = JSON.stringify({ chain }, null, 2);
  const result = await llmManager.analyze(prompt, context, {
    temperature: 0.3,
    maxTokens: 1500
  });

  let severityMatch = result.response.match(/RECOMMENDED SEVERITY:\s*\*{0,2}(CRITICAL|HIGH|MEDIUM|LOW|INFO|NONE)\*{0,2}/i);
  if (!severityMatch) {
    severityMatch = result.response.match(/(?:severity|risk)\s*(?:level|recommendation|assessment)?:\s*\*{0,2}(CRITICAL|HIGH|MEDIUM|LOW|INFO|NONE)\*{0,2}/i);
  }

  const assessment = {
    analysis: result.response,
    suggestedSeverity: severityMatch ? severityMatch[1].toUpperCase() : null,
    timestamp: new Date().toISOString(),
    model: llmSettings.model || llmSettings.provider
  };

  // Update chain in stored array
  if (window._correlationChainsForAssess && window._correlationChainsForAssess[chainIdx]) {
    window._correlationChainsForAssess[chainIdx].aiAssessment = assessment;
  }
}

// Handle severity override
async function handleSeverityOverride(index, newSeverity, type = 'secret', category = null) {
  try {
    const tab = await getTargetTab();

    if (type === 'secret') {
      // Update secret finding
      if (!currentFindings[index]) {
        showMessage('Finding not found', 'error');
        return;
      }

      const finding = currentFindings[index];
      finding.severityOverride = {
        originalSeverity: finding.risk,
        overriddenSeverity: newSeverity,
        reason: '',
        aiRecommended: finding.aiAssessment?.suggestedSeverity || null,
        timestamp: new Date().toISOString()
      };

      // Save updated findings to storage
      await chrome.runtime.sendMessage({
        action: 'updateTabFindings',
        tabId: tab.id,
        findings: currentFindings
      });

      // Refresh display
      displayFindings(currentFindings);
      showMessage(`Severity overridden to ${newSeverity}`, 'success');

    } else if (type === 'security') {
      // Update security finding
      if (!window.currentSecurityFindings) {
        showMessage('Security findings not loaded', 'error');
        return;
      }

      if (!category) {
        showMessage('Internal error: missing finding category', 'error');
        return;
      }

      const categoryFindings = window.currentSecurityFindings[category] || [];
      if (!categoryFindings[index]) {
        showMessage('Security finding not found', 'error');
        return;
      }

      const finding = categoryFindings[index];
      finding.severityOverride = {
        originalSeverity: finding.severity,
        overriddenSeverity: newSeverity,
        reason: '',
        aiRecommended: finding.aiAssessment?.suggestedSeverity || null,
        timestamp: new Date().toISOString()
      };
      
      // Save updated security results to storage
      await chrome.runtime.sendMessage({
        action: 'updateTabSecurityResults',
        tabId: tab.id,
        results: window.currentSecurityFindings
      });
      
      // Refresh display
      displaySecurityResults(window.currentSecurityFindings);
      showMessage(`Severity overridden to ${newSeverity}`, 'success');
    }
    
  } catch (error) {
    console.error('Error overriding severity:', error);
    showMessage('Failed to override severity', 'error');
  }
}

// Build comprehensive assessment prompt
function buildFindingAssessmentPrompt(finding, type) {
  const adversarialPreamble = `You are assessing this finding from an attacker's perspective. Ask: "If I found this right now, what would I actually do with it?" Be accurate, not alarmist. Downgrade theoretical risks that require unrealistic conditions.

Severity criteria (apply strictly):
- CRITICAL: Directly exploitable now with high-privilege impact (admin credentials, cloud keys with broad scope, authentication bypass)
- HIGH: Real finding with a clear exploitation path but limited blast radius, or strong indicators of exploitability pending confirmation
- MEDIUM: Finding exists but requires additional conditions to exploit (valid account, internal access, other credentials), or is a publishable/analytics key with no privilege
- LOW: Exploitable only with significant prerequisites or real-world impact is negligible
- INFO: Theoretical, test/placeholder value, analytics data, or requires attacker capabilities that make other attack vectors far easier
- NONE: Confirmed false positive`;

  if (type === 'secret') {
    return `${adversarialPreamble}

**Finding Type:** ${finding.pattern_matched || 'Unknown'}
**Initial Risk Level:** ${finding.risk} (automated — may need adjustment)
${finding.source ? `**Source:** ${finding.source}` : ''}
${finding.lineNumber ? `**Line Number:** ${finding.lineNumber}` : ''}
${finding.uri ? `**Location:** ${finding.uri}` : ''}
${finding.patternContext ? `\n**Context Flag:** Detected inside a ${finding.patternContext === 'pattern_definition' ? 'pattern/rule definition object (likely another scanner\'s detection rules, NOT an actual secret)' : finding.patternContext}` : ''}

${finding.codeContext ? `**Code Context:**
\`\`\`
${finding.codeContext}
\`\`\`
` : ''}

**Step 1 — False positive check (rule out before escalating):**
- Is the match inside a regex literal (\`/pattern/\`) or RegExp constructor? → Detection pattern, not a secret
- Is it in a pattern definition array/object (keys like "name:", "regex:", "confidence:")? → Another scanner's rule
- Is it in documentation, a comment, or example code? → Not a real secret
- Is it a test fixture, mock value, or placeholder (e.g., "test-key-12345", "EXAMPLE", "YOUR_KEY_HERE")? → Not real
- Is it inside minified code from a security library? → Detection pattern

**Step 2 — Attacker exploitation analysis (only if NOT a false positive):**
- Does the key/token have a valid format that would be accepted by the target service?
- What specific actions can an attacker take with it right now?
- Does the domain/source context suggest this is a real production credential vs. an analytics/CDN publishable key?

Provide:
1. **False Positive Assessment**: Real secret or false positive? Cite the specific evidence from the code context.
2. **Attacker Capability**: If real, what can an attacker do with this credential right now? Be specific.
3. **Immediate Actions**: What to do now.
4. **Remediation**: How to prevent recurrence.
5. **Detection Confidence**: 0-100% confidence this is a real, exploitable secret.
6. **RECOMMENDED SEVERITY: [CRITICAL|HIGH|MEDIUM|LOW|INFO|NONE]** — one line, then your reasoning. Use INFO or NONE for false positives, analytics keys, and publishable client-side tokens.`;
  } else if (finding.details && (finding.details.path || finding.details.url || finding.details.responsePreview)) {
    return `${adversarialPreamble}

**Finding:** ${finding.check}
**Severity:** ${finding.severity || 'Unknown'}
**Status:** ${finding.status || 'Detected'}
${finding.details.path ? `**Path:** ${finding.details.path}` : ''}
${finding.details.url ? `**URL:** ${finding.details.url}` : ''}
${finding.details.validation ? `**Validation:** ${finding.details.validation}` : ''}
${finding.uri ? `**Endpoint:** ${finding.uri}` : ''}

${finding.details.responsePreview ? `**Response Preview:**
\`\`\`
${finding.details.responsePreview}
\`\`\`
` : ''}

**Finding Details:** ${finding.message}
${finding.recommendation ? `\n**Existing Recommendation:** ${finding.recommendation}` : ''}

Attacker perspective — what is actually exposed and what does an attacker gain from it?

Provide:
1. **Exploitability**: Is this genuinely exposed or a soft-404/redirect? What does the response contain?
2. **Attacker Gain**: What credentials, source code, or internal details are revealed? What's the exploitation chain?
3. **Proof of Concept**: How to verify and exploit further.
4. **Remediation**: Specific access-restriction steps.
5. **RECOMMENDED SEVERITY: [CRITICAL|HIGH|MEDIUM|LOW|INFO|NONE]** — one line, then reasoning. Downgrade to INFO if the response is a generic error page or redirect with no sensitive content.`;
  } else {
    return `${adversarialPreamble}

**Vulnerability:** ${finding.check}
**Severity:** ${finding.severity || 'Unknown'}
**Status:** ${finding.status || 'Detected'}
${finding.source ? `**Source:** ${finding.source}` : ''}
${finding.lineNumber ? `**Line Number:** ${finding.lineNumber}` : ''}
${finding.uri ? `**Endpoint:** ${finding.uri}` : ''}

${finding.codeContext ? `**Code Context:**
\`\`\`
${finding.codeContext}
\`\`\`
` : ''}

**Finding Details:** ${finding.message}
${finding.recommendation ? `\n**Existing Recommendation:** ${finding.recommendation}` : ''}

Attacker perspective — can this be exploited against a real user on this site right now?

Provide:
1. **Exploitability**: Is exploitation realistic without special conditions (no auth, no internal access, no other credentials)?
2. **Attack Chain**: Walk through the specific steps an attacker would take from this finding to impact.
3. **Business Impact**: Actual data or account compromise achievable, not theoretical worst-case.
4. **Proof of Concept**: Concrete verification steps or payload.
5. **Remediation**: Specific, actionable fix.
6. **RECOMMENDED SEVERITY: [CRITICAL|HIGH|MEDIUM|LOW|INFO|NONE]** — one line, then reasoning. Downgrade if exploitation requires conditions that are unrealistic (valid account, internal network, other compromised credentials).`;
  }
}

// Format AI assessment for display
function formatAIAssessment(text) {
  if (!text) return '';
  
  let formatted = escapeHtml(text);
  
  // Convert markdown-style formatting
  formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
  formatted = formatted.replace(/\*(.*?)\*/g, '<em>$1</em>');
  formatted = formatted.replace(/`([^`]+)`/g, '<code>$1</code>');
  
  // Convert code blocks
  formatted = formatted.replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>');
  
  // Convert lists
  formatted = formatted.replace(/^(\d+)\.\s+(.+)$/gm, '<div class="ai-list-item"><strong>$1.</strong> $2</div>');
  formatted = formatted.replace(/^[-*]\s+(.+)$/gm, '<div class="ai-list-item">• $1</div>');
  
  // Convert headers
  formatted = formatted.replace(/^##\s+(.+)$/gm, '<h4>$1</h4>');
  formatted = formatted.replace(/^#\s+(.+)$/gm, '<h3>$1</h3>');
  
  // Convert newlines
  formatted = formatted.replace(/\n\n/g, '<br><br>');
  formatted = formatted.replace(/\n/g, '<br>');

  return formatted;
}

// ========================================
// API Testing Tab Logic
// ========================================

// Preset configurations for Google API testing
const GOOGLE_API_PRESETS = {
  quick: ['youtube', 'geocoding', 'translation', 'books', 'fonts'],
  'ai-ml': ['vertex-ai', 'gemini', 'vision', 'speech', 'video-intelligence', 'natural-language', 'text-to-speech'],
  infrastructure: ['resource-manager', 'compute-engine', 'cloud-storage', 'secret-manager', 'bigquery'],
  firebase: ['firebase-auth', 'firebase-realtime-db', 'firebase-firestore', 'firebase-storage'],
  all: [
    // Original APIs (15)
    'youtube', 'maps-static', 'geolocation', 'custom-search', 'firebase-auth', 'translation', 'books',
    'timezone', 'directions', 'places', 'geocoding', 'distance-matrix', 'elevation', 'pagespeed', 'fonts',
    // AI/ML APIs (7)
    'vertex-ai', 'gemini', 'vision', 'speech', 'video-intelligence', 'natural-language', 'text-to-speech',
    // Infrastructure APIs (5)
    'resource-manager', 'compute-engine', 'cloud-storage', 'secret-manager', 'bigquery',
    // Firebase Exploitation (3 + firebase-auth already above)
    'firebase-realtime-db', 'firebase-firestore', 'firebase-storage'
  ]
};

// Initialize API Testing tab
function initializeAPITestingTab() {
  // Load available API keys
  loadAvailableGoogleAPIKeys();

  // Category collapse/expand handlers
  const categoryHeaders = document.querySelectorAll('.category-header');
  categoryHeaders.forEach(header => {
    header.addEventListener('click', () => {
      const category = header.dataset.category;
      const servicesDiv = document.querySelector(`.category-services[data-category="${category}"]`);
      const icon = header.querySelector('.category-icon');

      if (servicesDiv.classList.contains('collapsed')) {
        servicesDiv.classList.remove('collapsed');
        header.classList.remove('collapsed');
        icon.textContent = '▼';
      } else {
        servicesDiv.classList.add('collapsed');
        header.classList.add('collapsed');
        icon.textContent = '▶';
      }
    });
  });

  // Preset selection handler
  const presetSelect = document.getElementById('googlePreset');
  if (presetSelect) {
    presetSelect.addEventListener('change', (e) => {
      const preset = e.target.value;
      applyGoogleAPIPreset(preset);
    });
  }

  // Service checkbox handlers (for marking as custom when manually changed)
  const serviceCheckboxes = document.querySelectorAll('.service-checkbox input[type="checkbox"]');
  serviceCheckboxes.forEach(checkbox => {
    checkbox.addEventListener('change', () => {
      // Mark preset as custom if user manually changes checkboxes
      const currentPreset = presetSelect.value;
      if (currentPreset !== 'custom') {
        const selectedServices = getSelectedGoogleServices();
        const presetServices = GOOGLE_API_PRESETS[currentPreset] || [];

        // Check if current selection matches the preset
        const matches = selectedServices.length === presetServices.length &&
          selectedServices.every(s => presetServices.includes(s));

        if (!matches) {
          presetSelect.value = 'custom';
        }
      }
    });
  });

  // Save Settings button
  const saveSettingsBtn = document.getElementById('saveApiTestingSettingsBtn');
  if (saveSettingsBtn) {
    saveSettingsBtn.addEventListener('click', () => {
      saveGoogleAPISettings();
      // Show saved indicator
      const indicator = document.getElementById('settingsSavedIndicator');
      if (indicator) {
        indicator.style.display = 'block';
        setTimeout(() => {
          indicator.style.display = 'none';
        }, 2000);
      }
    });
  }

  // Run Selected Tests button
  const runTestsBtn = document.getElementById('runSelectedTestsBtn');
  if (runTestsBtn) {
    runTestsBtn.addEventListener('click', runGoogleAPITests);
  }

  // Refresh Keys button
  const refreshKeysBtn = document.getElementById('refreshKeysBtn');
  if (refreshKeysBtn) {
    refreshKeysBtn.addEventListener('click', loadAvailableGoogleAPIKeys);
  }

  // Clear Projects button
  const clearProjectsBtn = document.getElementById('clearProjectsBtn');
  if (clearProjectsBtn) {
    clearProjectsBtn.addEventListener('click', clearDiscoveredProjects);
  }

  // Skip expensive tests checkbox
  const skipExpensiveCheckbox = document.getElementById('skipExpensiveTests');
  if (skipExpensiveCheckbox) {
    skipExpensiveCheckbox.addEventListener('change', () => {
      // Settings saved manually via Save button now
    });
  }

  // Load saved settings
  loadGoogleAPISettings();

  // Restore persisted API test results
  loadFeatureState('api_test_results', (data) => {
    if (data && Array.isArray(data) && data.length > 0) {
      displayTestResults(data);
    }
  });
}

// Apply a preset configuration
function applyGoogleAPIPreset(preset) {
  const services = GOOGLE_API_PRESETS[preset] || [];

  // Uncheck all checkboxes first
  const allCheckboxes = document.querySelectorAll('.service-checkbox input[type="checkbox"]');
  allCheckboxes.forEach(checkbox => {
    checkbox.checked = false;
  });

  // Check the ones in the preset
  services.forEach(serviceId => {
    const checkbox = document.querySelector(`input[data-service="${serviceId}"]`);
    if (checkbox) {
      checkbox.checked = true;
    }
  });

  // Save to storage
  saveGoogleAPISettings();
}

// Get currently selected Google services
function getSelectedGoogleServices() {
  const checkboxes = document.querySelectorAll('.service-checkbox input[type="checkbox"]:checked');
  return Array.from(checkboxes).map(cb => cb.dataset.service);
}

// Save Google API settings to storage
function saveGoogleAPISettings() {
  const selectedServices = getSelectedGoogleServices();
  const preset = document.getElementById('googlePreset')?.value || 'custom';
  const skipExpensive = document.getElementById('skipExpensiveTests')?.checked ?? true;

  const googleApiTesting = {
    selectedServices: {},
    activePreset: preset,
    skipExpensiveTests: skipExpensive
  };

  // Build selectedServices object
  const allCheckboxes = document.querySelectorAll('.service-checkbox input[type="checkbox"]');
  allCheckboxes.forEach(checkbox => {
    const serviceId = checkbox.dataset.service;
    googleApiTesting.selectedServices[serviceId] = checkbox.checked;
  });

  // Save to background storage
  chrome.runtime.sendMessage({
    action: 'saveGoogleApiTestingSettings',
    googleApiTesting
  }, response => {
    console.log('Origami: Saved Google API testing settings');
  });
}

// Load available Google API keys into dropdown
async function loadAvailableGoogleAPIKeys() {
  const tab = await getTargetTab();
  if (!tab) return;

  chrome.runtime.sendMessage({ action: 'getTabFindings', tabId: tab.id }, response => {
    const findings = response?.findings || [];
    const googleKeys = findings.filter(f =>
      (f.pattern_matched && f.pattern_matched.includes('Google')) ||
      (f.key && f.key.startsWith('AIza'))
    );

    const select = document.getElementById('googleApiKeySelect');
    if (!select) return;

    if (googleKeys.length === 0) {
      select.innerHTML = '<option value="">No Google API keys found - Run "Unfold" first</option>';
      return;
    }

    select.innerHTML = googleKeys.map((key, index) => {
      const displayKey = key.key.substring(0, 20) + '...' + key.key.substring(key.key.length - 4);
      const pattern = key.pattern_matched || 'Google API Key';
      return `<option value="${index}">${pattern} (${displayKey})</option>`;
    }).join('');

    // Store keys in a global variable for later use
    window.availableGoogleAPIKeys = googleKeys;
  });
}

// Load Google API settings from storage
function loadGoogleAPISettings() {
  chrome.runtime.sendMessage({
    action: 'getGoogleApiTestingSettings'
  }, response => {
    if (response && response.googleApiTesting) {
      const settings = response.googleApiTesting;

      // Apply preset
      const presetSelect = document.getElementById('googlePreset');
      if (presetSelect && settings.activePreset) {
        presetSelect.value = settings.activePreset;
      }

      // Apply selected services
      if (settings.selectedServices) {
        Object.entries(settings.selectedServices).forEach(([serviceId, checked]) => {
          const checkbox = document.querySelector(`input[data-service="${serviceId}"]`);
          if (checkbox) {
            checkbox.checked = checked;
          }
        });
      }

      // Apply skip expensive tests
      const skipExpensiveCheckbox = document.getElementById('skipExpensiveTests');
      if (skipExpensiveCheckbox && settings.skipExpensiveTests !== undefined) {
        skipExpensiveCheckbox.checked = settings.skipExpensiveTests;
      }

      // Load discovered projects
      if (settings.discoveredProjects) {
        displayDiscoveredProjects(settings.discoveredProjects);
      }
    } else {
      // No saved settings - apply "All Services" preset as default
      const presetSelect = document.getElementById('googlePreset');
      if (presetSelect) {
        presetSelect.value = 'all';
        applyGoogleAPIPreset('all');
      }
    }
  });
}

// Run Google API tests
async function runGoogleAPITests() {
  const selectedServices = getSelectedGoogleServices();

  if (selectedServices.length === 0) {
    showMessage('Please select at least one service to test', 'error');
    return;
  }

  // Get selected API key from dropdown
  const keySelect = document.getElementById('googleApiKeySelect');
  if (!keySelect || !keySelect.value) {
    showMessage('Please select an API key to test', 'error');
    return;
  }

  const selectedIndex = parseInt(keySelect.value);
  if (!window.availableGoogleAPIKeys || !window.availableGoogleAPIKeys[selectedIndex]) {
    showMessage('Selected API key not found. Click "Refresh" to reload keys.', 'error');
    return;
  }

  const googleApiKey = window.availableGoogleAPIKeys[selectedIndex];
  const apiKey = googleApiKey.key;

  // Show progress
  const progressDiv = document.getElementById('testProgress');
  const progressFill = document.getElementById('progressFill');
  const progressText = document.getElementById('progressText');
  const runBtn = document.getElementById('runSelectedTestsBtn');
  const resultsDiv = document.getElementById('testResults');

  runBtn.disabled = true;
  progressDiv.style.display = 'flex';
  resultsDiv.style.display = 'none';

  // Get discovered projects and Firebase configs
  chrome.runtime.sendMessage({ action: 'getGoogleApiTestingSettings' }, async settingsResponse => {
    const discoveredProjects = settingsResponse?.googleApiTesting?.discoveredProjects || [];

    // Initialize validator
    const validator = new GoogleAPIValidator(apiKey);

    // If any firebase services are selected, fetch Firebase configs for projectId
    const firebaseServices = ['firebase-auth', 'firebase-realtime-db', 'firebase-firestore', 'firebase-storage'];
    const hasFirebaseTests = selectedServices.some(s => firebaseServices.includes(s));

    if (hasFirebaseTests) {
      // Get current tab to fetch Firebase configs
      const tab = await getTargetTab();
      if (tab?.id) {
        const configResponse = await new Promise(resolve => {
          chrome.runtime.sendMessage({ action: 'getFirebaseConfigs', tabId: tab.id }, resolve);
        });
        const fbConfigs = configResponse?.firebaseConfigs || [];
        if (fbConfigs.length > 0) {
          // Use the first config's projectId as the Firebase project ID
          const fbProjectId = fbConfigs[0].projectId;
          if (fbProjectId) {
            validator._firebaseProjectId = fbProjectId;
            console.log('Origami: Using Firebase projectId from page config:', fbProjectId);
          }
        }
      }
    }

    // Run tests
    progressText.textContent = `Testing ${selectedServices.length} service(s)...`;
    progressFill.style.width = '10%';

    try {
      const results = await validator.runSelectedTests(selectedServices, discoveredProjects);

      // Check if Resource Manager discovered new projects
      const resourceManagerResult = results.find(r => r.service === 'Cloud Resource Manager');
      if (resourceManagerResult && resourceManagerResult.discoveredProjects && resourceManagerResult.discoveredProjects.length > 0) {
        // Save discovered projects
        const projects = resourceManagerResult.discoveredProjects.map(p => ({
          projectId: p.projectId,
          projectName: p.projectName,
          discovered: new Date().toISOString()
        }));

        chrome.runtime.sendMessage({
          action: 'saveDiscoveredProjects',
          projects
        }, () => {
          displayDiscoveredProjects(projects);
        });
      }

      // Display results
      progressFill.style.width = '100%';
      progressText.textContent = 'Tests completed!';

      setTimeout(() => {
        progressDiv.style.display = 'none';
        displayTestResults(results);
        saveFeatureState('api_test_results', results);
        runBtn.disabled = false;
      }, 1000);

    } catch (error) {
      console.error('API testing error:', error);
      progressDiv.style.display = 'none';
      showMessage(`Test error: ${error.message}`, 'error');
      runBtn.disabled = false;
    }
  });
}

// Display test results
function displayTestResults(results) {
  const resultsDiv = document.getElementById('testResults');
  const resultsContainer = document.getElementById('resultsContainer');

  resultsContainer.innerHTML = '';

  // Sort: ENABLED first, then DISABLED/SKIPPED, then errors
  const sortedResults = [...results].sort((a, b) => {
    const aOrder = (a.status === 'ENABLED' || a.status.includes('ENABLED')) ? 0
      : (a.status === 'DISABLED' || a.status === 'SKIPPED') ? 1 : 2;
    const bOrder = (b.status === 'ENABLED' || b.status.includes('ENABLED')) ? 0
      : (b.status === 'DISABLED' || b.status === 'SKIPPED') ? 1 : 2;
    return aOrder - bOrder;
  });

  sortedResults.forEach(result => {
    const resultItem = document.createElement('div');
    resultItem.className = 'result-item';

    // Determine status class
    let statusClass = 'error';
    if (result.status === 'ENABLED' || result.status.includes('ENABLED')) {
      statusClass = 'enabled';
    } else if (result.status === 'DISABLED' || result.status === 'SKIPPED') {
      statusClass = 'disabled';
    }

    resultItem.classList.add(statusClass);

    // Build result HTML
    const impactBadge = result.impact ? `<span class="badge ${result.impact.toLowerCase()}">${result.impact}</span>` : '';
    const costIndicator = result.cost ? getCostIndicator(result.cost) : '';

    // Build Firebase-specific detail lines
    let extraDetails = '';
    if (result.projectId) {
      extraDetails += `<div class="result-message">Project: ${escapeHtml(result.projectId)}</div>`;
    }
    if (result.details?.accessLevel) {
      const accessColors = { OPEN: 'critical', AUTHENTICATED: 'high', SECURED: 'low' };
      extraDetails += `<div class="result-message">Access: <span class="badge ${accessColors[result.details.accessLevel] || 'info'}">${escapeHtml(result.details.accessLevel)}</span></div>`;
    }
    if (result.details?.databaseUrl) {
      extraDetails += `<div class="result-message" style="word-break: break-all;"><code>${escapeHtml(result.details.databaseUrl)}</code></div>`;
    }
    if (result.details?.topLevelKeys && result.details.topLevelKeys.length > 0) {
      const keyTags = result.details.topLevelKeys.slice(0, 10).map(k => `<code>${escapeHtml(k)}</code>`).join(' ');
      extraDetails += `<div class="result-message">Keys: ${keyTags}${result.details.topLevelKeys.length > 10 ? ' ...' : ''}</div>`;
    }
    if (result.details?.collections && result.details.collections.length > 0) {
      const colTags = result.details.collections.slice(0, 10).map(c => `<code>${escapeHtml(c)}</code>`).join(' ');
      extraDetails += `<div class="result-message">Collections: ${colTags}</div>`;
    }
    if (result.details?.sampleFiles && result.details.sampleFiles.length > 0) {
      const fileTags = result.details.sampleFiles.map(f => `<code>${escapeHtml(f)}</code>`).join(' ');
      extraDetails += `<div class="result-message">Files: ${fileTags}</div>`;
    }
    if (result.anonymousToken) {
      const truncated = result.anonymousToken.substring(0, 20) + '...' + result.anonymousToken.substring(result.anonymousToken.length - 10);
      extraDetails += `<div class="result-message">Token: <code>${escapeHtml(truncated)}</code> <button class="btn btn-sm copy-token-btn" style="font-size:10px;padding:1px 6px;margin-left:4px;">Copy</button></div>`;
    }

    resultItem.innerHTML = `
      <div>
        <div class="result-service">${escapeHtml(result.service)}</div>
        <div class="result-message">${escapeHtml(result.message || '')}</div>
        ${extraDetails}
      </div>
      <div style="display: flex; flex-direction: column; gap: 6px; align-items: flex-end;">
        <span class="result-status ${statusClass}">${escapeHtml(result.status)}</span>
        ${impactBadge}
        ${costIndicator}
      </div>
    `;

    resultsContainer.appendChild(resultItem);

    // Attach copy handler for anonymous token (avoids inline onclick injection)
    if (result.anonymousToken) {
      const copyBtn = resultItem.querySelector('.copy-token-btn');
      if (copyBtn) {
        copyBtn.addEventListener('click', () => {
          navigator.clipboard.writeText(result.anonymousToken);
          copyBtn.textContent = 'Copied';
          setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
        });
      }
    }
  });

  resultsDiv.style.display = 'block';
}

// Get cost indicator
function getCostIndicator(cost) {
  const costMap = {
    'VERY_HIGH': '$$$$',
    'HIGH': '$$$',
    'MEDIUM': '$$',
    'LOW': '$'
  };
  return `<span class="badge cost-${cost.toLowerCase().replace('_', '-')}">${costMap[cost] || ''}</span>`;
}

// Display discovered GCP projects
function displayDiscoveredProjects(projects) {
  const projectsList = document.getElementById('projectsList');
  const projectCount = document.getElementById('projectCount');
  const clearBtn = document.getElementById('clearProjectsBtn');

  if (!projects || projects.length === 0) {
    projectsList.innerHTML = '<p class="info-text">No projects discovered yet. Enable "Cloud Resource Manager" to discover projects.</p>';
    projectCount.textContent = '0';
    clearBtn.style.display = 'none';
    return;
  }

  projectCount.textContent = projects.length.toString();
  clearBtn.style.display = 'block';

  projectsList.innerHTML = projects.map(project => `
    <div class="project-item">
      <div class="project-info">
        <div class="project-id">${project.projectId}</div>
        ${project.projectName ? `<div class="project-name">${project.projectName}</div>` : ''}
        <div class="project-meta">Discovered: ${new Date(project.discovered).toLocaleString()}</div>
      </div>
    </div>
  `).join('');
}

// Clear discovered projects
function clearDiscoveredProjects() {
  if (confirm('Clear all discovered projects from cache?')) {
    chrome.runtime.sendMessage({
      action: 'saveDiscoveredProjects',
      projects: []
    }, () => {
      displayDiscoveredProjects([]);
      showMessage('Cleared discovered projects', 'success');
    });
  }
}

// ==================== Inventory Tab ====================

const DOMAIN_CATEGORIES = {
  // CDN
  'cdn.jsdelivr.net': { label: 'CDN', cls: 'cat-cdn' },
  'cdnjs.cloudflare.com': { label: 'CDN', cls: 'cat-cdn' },
  'unpkg.com': { label: 'CDN', cls: 'cat-cdn' },
  'stackpath.bootstrapcdn.com': { label: 'CDN', cls: 'cat-cdn' },
  'maxcdn.bootstrapcdn.com': { label: 'CDN', cls: 'cat-cdn' },
  'ajax.googleapis.com': { label: 'CDN', cls: 'cat-cdn' },
  'cdn.cloudflare.com': { label: 'CDN', cls: 'cat-cdn' },
  'cdn.bootcdn.net': { label: 'CDN', cls: 'cat-cdn' },
  'code.jquery.com': { label: 'CDN', cls: 'cat-cdn' },
  'cdn.tailwindcss.com': { label: 'CDN', cls: 'cat-cdn' },
  'esm.sh': { label: 'CDN', cls: 'cat-cdn' },
  // CDN suffix matches
  'akamaized.net': { label: 'CDN', cls: 'cat-cdn', suffix: true },
  'cloudfront.net': { label: 'CDN', cls: 'cat-cdn', suffix: true },
  'fastly.net': { label: 'CDN', cls: 'cat-cdn', suffix: true },
  'akamaihd.net': { label: 'CDN', cls: 'cat-cdn', suffix: true },
  'azureedge.net': { label: 'CDN', cls: 'cat-cdn', suffix: true },
  'cloudflare.com': { label: 'CDN', cls: 'cat-cdn', suffix: true },
  // Analytics
  'www.google-analytics.com': { label: 'Analytics', cls: 'cat-analytics' },
  'www.googletagmanager.com': { label: 'Analytics', cls: 'cat-analytics' },
  'googletagmanager.com': { label: 'Analytics', cls: 'cat-analytics' },
  'analytics.google.com': { label: 'Analytics', cls: 'cat-analytics' },
  'clarity.ms': { label: 'Analytics', cls: 'cat-analytics', suffix: true },
  'hotjar.com': { label: 'Analytics', cls: 'cat-analytics', suffix: true },
  'segment.io': { label: 'Analytics', cls: 'cat-analytics', suffix: true },
  'segment.com': { label: 'Analytics', cls: 'cat-analytics', suffix: true },
  'amplitude.com': { label: 'Analytics', cls: 'cat-analytics', suffix: true },
  'mixpanel.com': { label: 'Analytics', cls: 'cat-analytics', suffix: true },
  'plausible.io': { label: 'Analytics', cls: 'cat-analytics', suffix: true },
  'matomo.cloud': { label: 'Analytics', cls: 'cat-analytics', suffix: true },
  'heapanalytics.com': { label: 'Analytics', cls: 'cat-analytics', suffix: true },
  // Ads
  'pagead2.googlesyndication.com': { label: 'Ads', cls: 'cat-ads' },
  'googleads.g.doubleclick.net': { label: 'Ads', cls: 'cat-ads' },
  'ad.doubleclick.net': { label: 'Ads', cls: 'cat-ads' },
  'connect.facebook.net': { label: 'Ads', cls: 'cat-ads' },
  'doubleclick.net': { label: 'Ads', cls: 'cat-ads', suffix: true },
  'googlesyndication.com': { label: 'Ads', cls: 'cat-ads', suffix: true },
  'adnxs.com': { label: 'Ads', cls: 'cat-ads', suffix: true },
  'criteo.com': { label: 'Ads', cls: 'cat-ads', suffix: true },
  // Payment
  'js.stripe.com': { label: 'Payment', cls: 'cat-payment' },
  'checkout.stripe.com': { label: 'Payment', cls: 'cat-payment' },
  'www.paypal.com': { label: 'Payment', cls: 'cat-payment' },
  'www.paypalobjects.com': { label: 'Payment', cls: 'cat-payment' },
  'js.braintreegateway.com': { label: 'Payment', cls: 'cat-payment' },
  'square.com': { label: 'Payment', cls: 'cat-payment', suffix: true },
  // Fonts
  'fonts.googleapis.com': { label: 'Fonts', cls: 'cat-fonts' },
  'fonts.gstatic.com': { label: 'Fonts', cls: 'cat-fonts' },
  'use.fontawesome.com': { label: 'Fonts', cls: 'cat-fonts' },
  'kit.fontawesome.com': { label: 'Fonts', cls: 'cat-fonts' },
  'use.typekit.net': { label: 'Fonts', cls: 'cat-fonts' },
  // Social
  'platform.twitter.com': { label: 'Social', cls: 'cat-social' },
  'platform.linkedin.com': { label: 'Social', cls: 'cat-social' },
  'widgets.pinterest.com': { label: 'Social', cls: 'cat-social' },
  'www.instagram.com': { label: 'Social', cls: 'cat-social' },
  'platform.instagram.com': { label: 'Social', cls: 'cat-social' },
  // Auth
  'accounts.google.com': { label: 'Auth', cls: 'cat-auth' },
  'login.microsoftonline.com': { label: 'Auth', cls: 'cat-auth' },
  'auth0.com': { label: 'Auth', cls: 'cat-auth', suffix: true },
  'cognito-idp.amazonaws.com': { label: 'Auth', cls: 'cat-auth' },
  // Maps
  'maps.googleapis.com': { label: 'Maps', cls: 'cat-maps' },
  'maps.gstatic.com': { label: 'Maps', cls: 'cat-maps' },
  'api.mapbox.com': { label: 'Maps', cls: 'cat-maps' },
  // Monitoring
  'sentry.io': { label: 'Monitoring', cls: 'cat-monitoring', suffix: true },
  'browser.sentry-cdn.com': { label: 'Monitoring', cls: 'cat-monitoring' },
  'bam.nr-data.net': { label: 'Monitoring', cls: 'cat-monitoring' },
  'js-agent.newrelic.com': { label: 'Monitoring', cls: 'cat-monitoring' },
  'newrelic.com': { label: 'Monitoring', cls: 'cat-monitoring', suffix: true },
  'rum.datadog.com': { label: 'Monitoring', cls: 'cat-monitoring' }
};

function getDomainCategory(domain) {
  if (!domain) return null;
  const exact = DOMAIN_CATEGORIES[domain];
  if (exact && !exact.suffix) return { label: exact.label, cls: exact.cls };

  for (const [key, val] of Object.entries(DOMAIN_CATEGORIES)) {
    if (val.suffix && (domain === key || domain.endsWith('.' + key))) {
      return { label: val.label, cls: val.cls };
    }
  }
  return null;
}

let inventoryCachedFromDomain = false;
let inventoryViewMode = 'tree';
let flatViewSortColumn = 'name';
let flatViewSortAsc = true;

async function loadInventory() {
  return new Promise((resolve) => {
    getTargetTabCb((tabs) => {
      if (!tabs[0]) { resolve(); return; }
      const tab = tabs[0];
      chrome.runtime.sendMessage(
        { action: 'getTabInventory', tabId: tab.id },
        (response) => {
          if (response && response.inventory) {
            currentInventory = response.inventory;
            inventoryCachedFromDomain = false;
            displayInventoryTree();
            updateInventoryBadge();
            resolve();
          } else {
            // Fall back to domain cache
            let hostname;
            try { hostname = new URL(tab.url).hostname; } catch (e) { resolve(); return; }
            chrome.runtime.sendMessage(
              { action: 'getDomainInventory', domain: hostname },
              (domainResponse) => {
                if (domainResponse && domainResponse.inventory) {
                  currentInventory = domainResponse.inventory;
                  inventoryCachedFromDomain = true;
                  displayInventoryTree();
                  updateInventoryBadge();
                }
                resolve();
              }
            );
          }
        }
      );
    });
  });
}

async function refreshInventory() {
  const tab = await getTargetTab();
  if (!tab) return;

  const btn = document.getElementById('refreshInventoryBtn');
  btn.disabled = true;
  btn.textContent = 'Scanning...';

  const treeContainer = document.getElementById('inventoryTree');
  treeContainer.innerHTML = `
    <div class="inventory-loading">
      <div class="loading-spinner"></div>
      <p>Collecting resources...</p>
      <p class="empty-hint">Probing discovered URLs for status codes</p>
    </div>`;

  chrome.tabs.sendMessage(tab.id, { action: 'collectResources' }, (response) => {
    btn.disabled = false;
    btn.textContent = 'Refresh';

    if (chrome.runtime.lastError) {
      showMessage('Could not collect resources. Try reloading the page.', 'error');
      displayInventoryTree();
      updateInventoryBadge();
      return;
    }

    if (response && response.results) {
      currentInventory = response.results;
      chrome.runtime.sendMessage({
        action: 'inventoryCollected',
        tabId: tab.id,
        inventory: currentInventory
      });
      displayInventoryTree();
      updateInventoryBadge();
      showMessage('Resource inventory updated', 'success');
    }
  });
}

function buildResourceTree(inventory) {
  if (!inventory || !inventory.resources) return null;

  const root = {
    name: inventory.domain,
    path: '/',
    type: 'directory',
    children: {},
    resourceCount: Object.keys(inventory.resources).length
  };

  for (const [path, info] of Object.entries(inventory.resources)) {
    const parts = path.split('/').filter(Boolean);
    let current = root;

    if (parts.length === 0) {
      // Root path "/"
      current.resourceInfo = info;
      continue;
    }

    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      const isLast = i === parts.length - 1;

      if (!current.children[part]) {
        current.children[part] = {
          name: part,
          path: '/' + parts.slice(0, i + 1).join('/'),
          type: isLast ? 'file' : 'directory',
          children: {}
        };
      }

      if (isLast) {
        current.children[part].resourceInfo = info;
        current.children[part].type = 'file';
      }

      current = current.children[part];
    }
  }

  return root;
}

function buildExternalResourceTree(domain, resources) {
  if (!resources || !Array.isArray(resources) || resources.length === 0) return null;

  const root = {
    name: domain,
    path: '/',
    type: 'directory',
    children: {},
    isExternal: true,
    externalDomain: domain,
    resourceCount: resources.length
  };

  for (const resource of resources) {
    const path = resource.path || '/';
    const parts = path.split('/').filter(Boolean);
    let current = root;

    if (parts.length === 0) {
      current.resourceInfo = resource;
      continue;
    }

    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      const isLast = i === parts.length - 1;

      if (!current.children[part]) {
        current.children[part] = {
          name: part,
          path: '/' + parts.slice(0, i + 1).join('/'),
          type: isLast ? 'file' : 'directory',
          children: {},
          isExternal: true,
          externalDomain: domain
        };
      }

      if (isLast) {
        current.children[part].resourceInfo = resource;
        current.children[part].type = 'file';
      }

      current = current.children[part];
    }
  }

  return root;
}

function getResourceTypeIcon(type) {
  const icons = {
    'directory': '\uD83D\uDCC1',
    'document': '\uD83D\uDCC4',
    'script': '\u2699',
    'stylesheet': '\uD83C\uDFA8',
    'image': '\uD83D\uDDBC',
    'fetch': '\u21C4',
    'media': '\u25B6',
    'iframe': '\u25A1',
    'font': 'F',
    'link': '\u2192',
    'form': '\u2610',
    'preload': '\u21E3',
    'other': '\u25CB'
  };
  return icons[type] || icons['other'];
}

function getStatusClass(status) {
  if (!status) return '';
  if (status >= 200 && status < 300) return 'status-2xx';
  if (status >= 300 && status < 400) return 'status-3xx';
  if (status >= 400 && status < 500) return 'status-4xx';
  if (status >= 500) return 'status-5xx';
  return '';
}

function formatSize(bytes) {
  if (!bytes || bytes === 0) return '';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function findSecurityFindingsForPath(path) {
  const findings = [];

  function extractPathname(urlStr) {
    if (!urlStr) return null;
    try {
      if (urlStr.startsWith('http')) {
        return new URL(urlStr).pathname;
      }
      if (urlStr.startsWith('/')) {
        return urlStr.split('?')[0].split('#')[0];
      }
    } catch (e) {}
    return null;
  }

  function pathMatches(findingPath, resourcePath) {
    if (!findingPath || !resourcePath) return false;
    const clean = findingPath.split('?')[0].split('#')[0];
    return clean === resourcePath;
  }

  // Check secret findings
  if (currentFindings && currentFindings.length > 0) {
    currentFindings.forEach(secret => {
      const secretPath = extractPathname(secret.uri) ||
                         extractPathname(secret.url) ||
                         extractPathname(secret.source);
      if (pathMatches(secretPath, path)) {
        findings.push({ type: 'secret', severity: secret.risk || 'MEDIUM', detail: secret.pattern_matched || secret.key });
      }
    });
  }

  // Check sensitive files
  if (securityResults && securityResults.sensitiveFiles) {
    securityResults.sensitiveFiles.forEach(f => {
      if (f.details && f.details.path === path) {
        findings.push({ type: 'sensitive-file', severity: f.severity || 'HIGH', detail: f.check });
      }
    });
  }

  // Check vulnerability findings
  if (securityResults && securityResults.vulnerabilities) {
    securityResults.vulnerabilities.forEach(v => {
      const vulnPath = extractPathname(v.uri) ||
                       extractPathname(v.details?.url) ||
                       extractPathname(v.details?.uri);
      if (pathMatches(vulnPath, path)) {
        findings.push({ type: 'vulnerability', severity: v.severity || 'MEDIUM', detail: v.check || v.message });
      }
    });
  }

  return findings;
}

function computeSubtreeFindings(node) {
  const severityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0 };
  let count = 0;
  let highestValue = -1;
  let highestName = '';
  let summaries = [];

  const direct = findSecurityFindingsForPath(node.path);
  count += direct.length;
  for (const f of direct) {
    const val = severityOrder[f.severity] || 0;
    if (val > highestValue) {
      highestValue = val;
      highestName = f.severity;
    }
    summaries.push(`[${f.severity}] ${f.detail || f.type}`);
  }

  for (const key of Object.keys(node.children)) {
    const sub = computeSubtreeFindings(node.children[key]);
    count += sub.count;
    const subVal = severityOrder[sub.highest] || 0;
    if (subVal > highestValue) {
      highestValue = subVal;
      highestName = sub.highest;
    }
    summaries = summaries.concat(sub.summaries);
  }

  return { count, highest: highestName, summaries };
}

function renderTreeNode(node, depth, filterText, filterType) {
  const childKeys = Object.keys(node.children);
  const isLeaf = childKeys.length === 0;
  const info = node.resourceInfo || {};
  const findings = findSecurityFindingsForPath(node.path);

  // Apply filters
  if (isLeaf) {
    if (filterText && !node.name.toLowerCase().includes(filterText) && !node.path.toLowerCase().includes(filterText)) {
      return '';
    }
    if (filterType && filterType !== 'all' && info.type !== filterType) {
      return '';
    }
  }

  let icon;
  if (node.isExternal && node.name === node.externalDomain) {
    icon = '\uD83C\uDF10';
  } else {
    icon = node.type === 'directory' ? getResourceTypeIcon('directory') : getResourceTypeIcon(info.type);
  }

  let statusBadge = '';
  if (info.status) {
    const statusCls = getStatusClass(info.status);
    statusBadge = `<span class="tree-status ${statusCls}">${info.status}</span>`;
  }

  let findingBadge = '';
  const isDirectory = childKeys.length > 0;
  if (isDirectory) {
    const subtree = computeSubtreeFindings(node);
    if (subtree.count > 0 && subtree.highest) {
      const tooltipLines = subtree.summaries.slice(0, 10);
      if (subtree.summaries.length > 10) {
        tooltipLines.push(`... and ${subtree.summaries.length - 10} more`);
      }
      const tooltip = escapeHtml(tooltipLines.join('\n'));
      findingBadge = `<span class="tree-finding-badge ${subtree.highest.toLowerCase()}" title="${tooltip}">${subtree.count}</span>`;
    }
  } else if (findings.length > 0) {
    const severityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0 };
    const highestSeverity = findings.reduce((highest, f) => {
      return (severityOrder[f.severity] || 0) > (severityOrder[highest] || 0) ? f.severity : highest;
    }, findings[0].severity);
    const tooltipLines = findings.map(f => `[${f.severity}] ${f.detail || f.type}`);
    const tooltip = escapeHtml(tooltipLines.join('\n'));
    findingBadge = `<span class="tree-finding-badge ${highestSeverity.toLowerCase()}" title="${tooltip}">${findings.length}</span>`;
  }

  const sizeStr = formatSize(info.size);
  const sizeHtml = sizeStr ? `<span class="tree-size">${sizeStr}</span>` : '';
  const domainAttr = node.externalDomain ? ` data-domain="${escapeHtml(node.externalDomain)}"` : '';

  // Build children HTML
  let childrenHtml = '';
  if (childKeys.length > 0) {
    const sortedKeys = childKeys.sort((a, b) => {
      const aIsDir = Object.keys(node.children[a].children).length > 0;
      const bIsDir = Object.keys(node.children[b].children).length > 0;
      if (aIsDir && !bIsDir) return -1;
      if (!aIsDir && bIsDir) return 1;
      return a.localeCompare(b);
    });

    const childContent = sortedKeys.map(key =>
      renderTreeNode(node.children[key], depth + 1, filterText, filterType)
    ).join('');

    // If filter is active and no children match, hide directory unless it itself matches
    if ((filterText || (filterType && filterType !== 'all')) && !childContent.trim()) {
      return '';
    }

    const collapsed = depth > 0 ? ' collapsed' : '';
    childrenHtml = `<div class="tree-children${collapsed}">${childContent}</div>`;
  }

  const toggleClass = isLeaf ? 'tree-toggle leaf' : `tree-toggle${depth > 0 ? ' collapsed' : ''}`;

  let categoryBadge = '';
  if (node.isExternal && node.name === node.externalDomain) {
    const cat = getDomainCategory(node.externalDomain);
    if (cat) categoryBadge = `<span class="tree-category-badge ${cat.cls}">${cat.label}</span>`;
  }

  let actionsHtml = '';
  if (isLeaf && info.type) {
    const nodeUrl = getResourceFullUrl(node.path, node.externalDomain || undefined);
    actionsHtml = `<span class="inv-row-actions"><button class="inv-action-btn" data-action="repeater" data-url="${escapeHtml(nodeUrl)}" title="Send to Repeater">&#8634;</button><button class="inv-action-btn" data-action="browser" data-url="${escapeHtml(nodeUrl)}" title="Open in Browser">&#8599;</button></span>`;
  }

  return `<div class="tree-node" data-path="${escapeHtml(node.path)}"${domainAttr}>
    <div class="tree-node-header" data-path="${escapeHtml(node.path)}"${domainAttr}>
      <span class="${toggleClass}">&#9660;</span>
      <span class="tree-icon">${icon}</span>
      <span class="tree-label ${node.type === 'directory' ? 'directory' : ''}">${escapeHtml(node.name)}</span>${categoryBadge}
      <span class="tree-meta">${statusBadge}${findingBadge}${sizeHtml}</span>${actionsHtml}
    </div>
    ${childrenHtml}
  </div>`;
}

function toggleInventoryView() {
  inventoryViewMode = inventoryViewMode === 'tree' ? 'flat' : 'tree';
  const label = document.getElementById('viewToggleLabel');
  const expandBtn = document.getElementById('expandAllBtn');
  const collapseBtn = document.getElementById('collapseAllBtn');
  if (inventoryViewMode === 'flat') {
    label.textContent = 'Tree View';
    if (expandBtn) expandBtn.style.display = 'none';
    if (collapseBtn) collapseBtn.style.display = 'none';
  } else {
    label.textContent = 'Flat View';
    if (expandBtn) expandBtn.style.display = '';
    if (collapseBtn) collapseBtn.style.display = '';
  }
  displayInventoryTree();
  updateInventoryBadge();
}

function displayInventoryFlat() {
  const container = document.getElementById('inventoryTree');
  if (!currentInventory || !currentInventory.resources || Object.keys(currentInventory.resources).length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <p>No resource inventory available.</p>
        <p class="empty-hint">Click "Unfold" to scan and collect page resources.</p>
      </div>`;
    return;
  }

  const filterText = (document.getElementById('inventorySearch').value || '').toLowerCase();
  const filterType = document.getElementById('inventoryTypeFilter').value;
  const domain = currentInventory.domain || '';

  // Gather all resources into flat array
  const allResources = [];

  for (const [path, info] of Object.entries(currentInventory.resources)) {
    allResources.push({ path, domain, isExternal: false, ...info });
  }

  if (currentInventory.externalResources) {
    for (const [extDomain, resources] of Object.entries(currentInventory.externalResources)) {
      if (!Array.isArray(resources)) continue;
      for (const r of resources) {
        allResources.push({ ...r, domain: extDomain, isExternal: true });
      }
    }
  }

  // Apply filters
  const filtered = allResources.filter(r => {
    if (filterText) {
      const searchable = (r.path || '').toLowerCase() + ' ' + (r.domain || '').toLowerCase();
      if (!searchable.includes(filterText)) return false;
    }
    if (filterType && filterType !== 'all' && r.type !== filterType) return false;
    return true;
  });

  // Sort
  const col = flatViewSortColumn;
  const asc = flatViewSortAsc;
  filtered.sort((a, b) => {
    let va, vb;
    switch (col) {
      case 'name': va = a.path || ''; vb = b.path || ''; break;
      case 'type': va = a.type || ''; vb = b.type || ''; break;
      case 'status': va = a.status || 0; vb = b.status || 0; break;
      case 'size': va = a.size || 0; vb = b.size || 0; break;
      case 'duration': va = a.duration || 0; vb = b.duration || 0; break;
      default: va = a.path || ''; vb = b.path || '';
    }
    if (typeof va === 'string') {
      const cmp = va.localeCompare(vb);
      return asc ? cmp : -cmp;
    }
    return asc ? va - vb : vb - va;
  });

  const sortIndicator = (colName) => {
    if (col !== colName) return '';
    return asc ? ' \u25B2' : ' \u25BC';
  };

  let html = '';
  if (inventoryCachedFromDomain) {
    const cachedTime = currentInventory.cachedAt || currentInventory.timestamp;
    const label = cachedTime ? `Cached from ${new Date(cachedTime).toLocaleString()}` : 'Cached from previous visit';
    html += `<div class="cached-inventory-notice">${label} -- click Refresh for live data</div>`;
  }

  html += `<table class="inventory-flat-table">
    <thead>
      <tr>
        <th class="flat-th" data-sort="name">Name${sortIndicator('name')}</th>
        <th class="flat-th" data-sort="type">Type${sortIndicator('type')}</th>
        <th class="flat-th" data-sort="status">Status${sortIndicator('status')}</th>
        <th class="flat-th flat-size" data-sort="size">Size${sortIndicator('size')}</th>
        <th class="flat-th flat-duration" data-sort="duration">Time${sortIndicator('duration')}</th>
        <th class="flat-th flat-actions"></th>
      </tr>
    </thead>
    <tbody>`;

  for (const r of filtered) {
    const icon = getResourceTypeIcon(r.type);
    const statusCls = r.status ? getStatusClass(r.status) : '';
    const statusHtml = r.status ? `<span class="tree-status ${statusCls}">${r.status}</span>` : '';
    const findings = !r.isExternal ? findSecurityFindingsForPath(r.path) : [];
    let findingBadge = '';
    if (findings.length > 0) {
      const severityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0 };
      const highest = findings.reduce((h, f) => (severityOrder[f.severity] || 0) > (severityOrder[h] || 0) ? f.severity : h, findings[0].severity);
      findingBadge = `<span class="tree-finding-badge ${highest.toLowerCase()}">${findings.length}</span>`;
    }
    let domainLabel = '';
    if (r.isExternal) {
      const cat = getDomainCategory(r.domain);
      const catBadge = cat ? `<span class="tree-category-badge ${cat.cls}">${cat.label}</span>` : '';
      domainLabel = `<span class="flat-domain-label">${escapeHtml(r.domain)}</span>${catBadge}`;
    }

    const rowUrl = getResourceFullUrl(r.path, r.isExternal ? r.domain : undefined);
    html += `<tr class="flat-row" data-path="${escapeHtml(r.path)}" data-domain="${r.isExternal ? escapeHtml(r.domain) : ''}">
      <td class="flat-td flat-name"><span class="tree-icon">${icon}</span> ${escapeHtml(r.path)}${findingBadge}${domainLabel}</td>
      <td class="flat-td">${escapeHtml(r.type || '')}</td>
      <td class="flat-td">${statusHtml}</td>
      <td class="flat-td flat-size">${formatSize(r.size)}</td>
      <td class="flat-td flat-duration">${r.duration !== undefined ? r.duration + 'ms' : ''}</td>
      <td class="flat-td flat-actions-cell"><span class="inv-row-actions"><button class="inv-action-btn" data-action="repeater" data-url="${escapeHtml(rowUrl)}" title="Send to Repeater">&#8634;</button><button class="inv-action-btn" data-action="browser" data-url="${escapeHtml(rowUrl)}" title="Open in Browser">&#8599;</button></span></td>
    </tr>`;
  }

  html += '</tbody></table>';
  container.innerHTML = html;

  // Update stats
  const totalResources = Object.keys(currentInventory.resources).length;
  const externalDomains = currentInventory.externalResources ? Object.keys(currentInventory.externalResources).length : 0;
  let findingsCount = 0;
  for (const path of Object.keys(currentInventory.resources)) {
    findingsCount += findSecurityFindingsForPath(path).length;
  }
  document.getElementById('inventoryTotalResources').textContent = totalResources;
  document.getElementById('inventoryExternalDomains').textContent = externalDomains;
  document.getElementById('inventoryFindings').textContent = findingsCount;

  // Wire sort headers
  container.querySelectorAll('.flat-th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const sortCol = th.dataset.sort;
      if (flatViewSortColumn === sortCol) {
        flatViewSortAsc = !flatViewSortAsc;
      } else {
        flatViewSortColumn = sortCol;
        flatViewSortAsc = true;
      }
      displayInventoryFlat();
    });
  });

  // Wire row clicks
  container.querySelectorAll('.flat-row').forEach(row => {
    row.addEventListener('click', () => {
      container.querySelectorAll('.flat-row.selected').forEach(el => el.classList.remove('selected'));
      row.classList.add('selected');
      showResourceDetail(row.dataset.path, row.dataset.domain || undefined);
    });
  });

  // Wire inventory action buttons
  container.querySelectorAll('.inv-action-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      var url = btn.dataset.url;
      if (btn.dataset.action === 'repeater') sendToRepeater(url);
      else if (btn.dataset.action === 'browser') openResourceInBrowser(url);
    });
  });
}

function displayInventoryTree() {
  if (inventoryViewMode === 'flat') {
    displayInventoryFlat();
    return;
  }

  const container = document.getElementById('inventoryTree');

  if (!currentInventory || !currentInventory.resources || Object.keys(currentInventory.resources).length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <p>No resource inventory available.</p>
        <p class="empty-hint">Click "Unfold" to scan and collect page resources.</p>
      </div>`;
    document.getElementById('inventoryTotalResources').textContent = '0';
    document.getElementById('inventoryExternalDomains').textContent = '0';
    document.getElementById('inventoryFindings').textContent = '0';
    return;
  }

  const tree = buildResourceTree(currentInventory);
  if (!tree) return;

  const filterText = (document.getElementById('inventorySearch').value || '').toLowerCase();
  const filterType = document.getElementById('inventoryTypeFilter').value;

  let html = '';
  if (inventoryCachedFromDomain) {
    const cachedTime = currentInventory.cachedAt || currentInventory.timestamp;
    const label = cachedTime ? `Cached from ${new Date(cachedTime).toLocaleString()}` : 'Cached from previous visit';
    html += `<div class="cached-inventory-notice">${label} -- click Refresh for live data</div>`;
  }

  html += renderTreeNode(tree, 0, filterText, filterType);

  // Add external resources as hierarchical domain branches
  if (currentInventory.externalResources) {
    const externalDomains = Object.keys(currentInventory.externalResources);
    if (externalDomains.length > 0) {
      html += '<div class="tree-domain-separator"></div>';
      for (const domain of externalDomains.sort()) {
        const resources = currentInventory.externalResources[domain];
        if (!Array.isArray(resources) || resources.length === 0) continue;

        const extTree = buildExternalResourceTree(domain, resources);
        if (!extTree) continue;
        const extHtml = renderTreeNode(extTree, 0, filterText, filterType);
        if (extHtml.trim()) {
          html += extHtml;
        }
      }
    }
  }

  container.innerHTML = html;

  // Update stats
  const totalResources = Object.keys(currentInventory.resources).length;
  const externalDomains = currentInventory.externalResources ? Object.keys(currentInventory.externalResources).length : 0;
  let findingsCount = 0;
  for (const path of Object.keys(currentInventory.resources)) {
    findingsCount += findSecurityFindingsForPath(path).length;
  }

  document.getElementById('inventoryTotalResources').textContent = totalResources;
  document.getElementById('inventoryExternalDomains').textContent = externalDomains;
  document.getElementById('inventoryFindings').textContent = findingsCount;

  // Wire up tree interaction
  wireTreeHandlers(container);

  // Auto-expand tree on initial popup load
  autoUnfoldInventory();
}

function wireTreeHandlers(container) {
  container.querySelectorAll('.tree-node-header').forEach(header => {
    header.addEventListener('click', (e) => {
      const node = header.parentElement;
      const children = node.querySelector(':scope > .tree-children');
      const toggle = header.querySelector('.tree-toggle');

      if (children && !toggle.classList.contains('leaf')) {
        children.classList.toggle('collapsed');
        toggle.classList.toggle('collapsed');
      }

      // Select and show detail
      container.querySelectorAll('.tree-node-header.selected').forEach(el => el.classList.remove('selected'));
      header.classList.add('selected');

      const path = header.dataset.path;
      const domain = header.dataset.domain;
      showResourceDetail(path, domain);
    });
  });

  container.querySelectorAll('.inv-action-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      var url = btn.dataset.url;
      if (btn.dataset.action === 'repeater') sendToRepeater(url);
      else if (btn.dataset.action === 'browser') openResourceInBrowser(url);
    });
  });
}

function getResourceFullUrl(path, externalDomain) {
  if (externalDomain) return 'https://' + externalDomain + path;
  return (currentInventory.url ? new URL(currentInventory.url).origin : '') + path;
}

async function sendToRepeater(url) {
  document.querySelector('[data-tab="repeater"]').click();

  var cookieUrl = /^https?:\/\//i.test(url) ? url : 'https://' + url;
  var cookies = await new Promise(function(resolve) {
    chrome.cookies.getAll({ url: cookieUrl }, resolve);
  });

  setTimeout(function () {
    var methodEl = document.getElementById('repeater-method');
    if (methodEl) methodEl.value = 'GET';

    var urlEl = document.getElementById('repeater-url');
    if (urlEl) urlEl.value = url;

    var headersContainer = document.getElementById('repeater-headers-container');
    if (headersContainer) headersContainer.textContent = '';

    function addRow(key, value) {
      if (typeof addRepeaterHeader === 'function') addRepeaterHeader();
      var rows = headersContainer.querySelectorAll('.repeater-header-row');
      var lastRow = rows[rows.length - 1];
      if (lastRow) {
        var k = lastRow.querySelector('.repeater-header-key');
        var v = lastRow.querySelector('.repeater-header-value');
        if (k) k.value = key;
        if (v) v.value = value;
      }
    }

    if (cookies && cookies.length > 0) {
      var cookieStr = cookies.map(function(c) { return c.name + '=' + c.value; }).join('; ');
      addRow('Cookie', cookieStr);
    }

    addRow('User-Agent', navigator.userAgent);
    addRow('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8');
    addRow('Accept-Language', navigator.language || 'en-US,en;q=0.5');

    var bodyEl = document.getElementById('repeater-body');
    if (bodyEl) bodyEl.value = '';

    if (typeof toggleRepeaterBodyVisibility === 'function') {
      toggleRepeaterBodyVisibility();
    }

    showMessage('URL and session loaded in Repeater', 'success');
  }, 50);
}

function openResourceInBrowser(url) {
  chrome.tabs.create({ url: url, active: true });
}

function showResourceDetail(path, externalDomain) {
  const panel = document.getElementById('resourceDetailPanel');
  const title = document.getElementById('resourceDetailTitle');
  const body = document.getElementById('resourceDetailBody');

  let info = null;
  if (externalDomain && currentInventory.externalResources) {
    const domainResources = currentInventory.externalResources[externalDomain];
    if (Array.isArray(domainResources)) {
      info = domainResources.find(r => r.path === path);
    }
  } else if (currentInventory && currentInventory.resources) {
    info = currentInventory.resources[path];
  }

  if (!info) {
    panel.style.display = 'none';
    return;
  }

  const fullUrl = getResourceFullUrl(path, externalDomain);

  title.textContent = path;

  let html = `
    <div class="detail-row"><span class="detail-key">URL</span><span class="detail-value">${escapeHtml(fullUrl)} <button class="btn-copy-url" data-url="${escapeHtml(fullUrl)}" title="Copy URL">Copy</button></span></div>
    <div class="detail-row"><span class="detail-key">Type</span><span class="detail-value">${escapeHtml(info.type || 'unknown')}</span></div>`;

  if (info.status) {
    html += `<div class="detail-row"><span class="detail-key">Status</span><span class="detail-value"><span class="tree-status ${getStatusClass(info.status)}">${info.status}</span></span></div>`;
  }
  if (info.size) {
    html += `<div class="detail-row"><span class="detail-key">Size</span><span class="detail-value">${formatSize(info.size)}</span></div>`;
  }
  if (info.mimeType) {
    html += `<div class="detail-row"><span class="detail-key">MIME</span><span class="detail-value">${escapeHtml(info.mimeType)}</span></div>`;
  }
  if (info.duration !== undefined) {
    html += `<div class="detail-row"><span class="detail-key">Load time</span><span class="detail-value">${info.duration}ms</span></div>`;
  }
  if (info.source) {
    html += `<div class="detail-row"><span class="detail-key">Source</span><span class="detail-value">${escapeHtml(info.source)}</span></div>`;
  }

  // Show related findings
  if (!externalDomain) {
    const findings = findSecurityFindingsForPath(path);
    if (findings.length > 0) {
      html += '<div class="detail-findings">';
      html += `<div class="detail-row"><span class="detail-key">Findings</span><span class="detail-value">${findings.length} issue${findings.length > 1 ? 's' : ''}</span></div>`;
      findings.forEach(f => {
        html += `<div class="detail-row" style="margin-left: 8px;">
          <span class="tree-finding-badge ${f.severity.toLowerCase()}">${escapeHtml(f.severity)}</span>
          <span class="detail-value">${escapeHtml(f.detail || f.type)}</span>
        </div>`;
      });
      html += '</div>';
    }
  }

  html += `<div class="detail-actions">
    <button class="btn-detail-action" data-action="repeater" data-url="${escapeHtml(fullUrl)}">Send to Repeater</button>
    <button class="btn-detail-action" data-action="browser" data-url="${escapeHtml(fullUrl)}">Open in Browser</button>
  </div>`;

  body.innerHTML = html;
  panel.style.display = 'block';

  const copyBtn = body.querySelector('.btn-copy-url');
  if (copyBtn) {
    copyBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const url = copyBtn.dataset.url;
      copyToClipboard(url);
      copyBtn.textContent = 'Copied';
      copyBtn.classList.add('copied');
      setTimeout(() => {
        copyBtn.textContent = 'Copy';
        copyBtn.classList.remove('copied');
      }, 1500);
    });
  }

  body.querySelectorAll('.btn-detail-action').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      var url = btn.dataset.url;
      if (btn.dataset.action === 'repeater') sendToRepeater(url);
      else if (btn.dataset.action === 'browser') openResourceInBrowser(url);
    });
  });
}

function toggleAllTreeNodes(collapse) {
  const container = document.getElementById('inventoryTree');
  container.querySelectorAll('.tree-children').forEach(el => {
    if (collapse) {
      el.classList.add('collapsed');
    } else {
      el.classList.remove('collapsed');
    }
  });
  container.querySelectorAll('.tree-toggle').forEach(el => {
    if (el.classList.contains('leaf')) return;
    if (collapse) {
      el.classList.add('collapsed');
    } else {
      el.classList.remove('collapsed');
    }
  });
}

function filterInventoryTree() {
  displayInventoryTree();
  updateInventoryBadge();
}

function exportInventory() {
  if (!currentInventory || !currentInventory.resources || Object.keys(currentInventory.resources).length === 0) {
    showMessage('No inventory data to export', 'error');
    return;
  }

  const resourcesWithFindings = {};
  for (const [path, info] of Object.entries(currentInventory.resources)) {
    const findings = findSecurityFindingsForPath(path);
    resourcesWithFindings[path] = {
      ...info,
      findings: findings.length > 0 ? findings : undefined
    };
  }

  const exportData = {
    exportType: 'origami-inventory',
    version: '1.0',
    domain: currentInventory.domain,
    url: currentInventory.url,
    timestamp: currentInventory.timestamp,
    exportedAt: new Date().toISOString(),
    stats: {
      totalResources: Object.keys(currentInventory.resources).length,
      externalDomains: currentInventory.externalResources
        ? Object.keys(currentInventory.externalResources).length
        : 0,
      findingsCount: Object.values(resourcesWithFindings)
        .reduce((sum, r) => sum + (r.findings ? r.findings.length : 0), 0)
    },
    resources: resourcesWithFindings,
    externalResources: currentInventory.externalResources || {}
  };

  const domain = currentInventory.domain || 'unknown';
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const filename = `origami-inventory-${domain}-${timestamp}.json`;

  downloadFile(
    JSON.stringify(exportData, null, 2),
    filename,
    'application/json'
  );

  showMessage('Inventory exported', 'success');
}

// ============================================================================
// Plugin Management
// ============================================================================

let currentPlugins = [];

async function loadPlugins() {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ action: 'getPlugins' }, (response) => {
      currentPlugins = (response && response.plugins) || [];
      displayPlugins();
      updatePluginStats();
      resolve();
    });
  });
}

function displayPlugins() {
  const container = document.getElementById('pluginsContainer');
  if (!container) return;

  if (currentPlugins.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <p>No plugins installed</p>
        <p class="empty-hint">Import a plugin JSON file to extend Origami with custom analyzers.</p>
      </div>
    `;
    return;
  }

  let html = '';
  currentPlugins.forEach(plugin => {
    const manifest = plugin.manifest;
    const isEnabled = plugin.enabled !== false;
    const disabledClass = isEnabled ? '' : ' disabled';

    html += `
      <div class="plugin-card${disabledClass}" data-plugin-id="${escapeHtml(manifest.id)}">
        <div class="plugin-card-header">
          <div class="plugin-card-info">
            <div class="plugin-card-name">${escapeHtml(manifest.name)}</div>
            <div class="plugin-card-meta">
              <span>v${escapeHtml(manifest.version)}</span>
              ${manifest.author ? `<span>by ${escapeHtml(manifest.author)}</span>` : ''}
              <span class="plugin-category-badge">${escapeHtml(manifest.resultCategory)}</span>
            </div>
          </div>
          <div class="plugin-card-actions">
            <label class="plugin-toggle" title="${isEnabled ? 'Disable' : 'Enable'} plugin">
              <input type="checkbox" ${isEnabled ? 'checked' : ''} data-plugin-toggle="${escapeHtml(manifest.id)}">
              <span class="plugin-toggle-slider"></span>
            </label>
            <button class="plugin-remove-btn" data-plugin-remove="${escapeHtml(manifest.id)}" title="Remove plugin">Remove</button>
          </div>
        </div>
        ${manifest.description ? `<div class="plugin-card-description">${escapeHtml(manifest.description)}</div>` : ''}
      </div>
    `;
  });

  container.innerHTML = html;

  // Wire up toggle and remove handlers
  container.querySelectorAll('[data-plugin-toggle]').forEach(toggle => {
    toggle.addEventListener('change', (e) => {
      const pluginId = e.target.dataset.pluginToggle;
      const enabled = e.target.checked;
      togglePlugin(pluginId, enabled);
    });
  });

  container.querySelectorAll('[data-plugin-remove]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const pluginId = e.target.dataset.pluginRemove;
      removePlugin(pluginId);
    });
  });
}

function updatePluginStats() {
  const totalEl = document.getElementById('pluginsTotalCount');
  const enabledEl = document.getElementById('pluginsEnabledCount');
  if (totalEl) totalEl.textContent = currentPlugins.length;
  if (enabledEl) enabledEl.textContent = currentPlugins.filter(p => p.enabled !== false).length;
}

function handlePluginImport(event) {
  const file = event.target.files[0];
  if (!file) return;

  // Reset file input so the same file can be re-imported
  event.target.value = '';

  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      const pluginData = JSON.parse(e.target.result);

      // Determine structure: could be { manifest, code } or just the manifest
      let manifest, code;
      if (pluginData.manifest) {
        manifest = pluginData.manifest;
        code = pluginData.code || '';
      } else {
        manifest = pluginData;
        code = '';
      }

      // Validate manifest
      const requiredFields = ['id', 'name', 'version', 'analyzerClass', 'resultCategory'];
      const missing = requiredFields.filter(f => !manifest[f]);
      if (missing.length > 0) {
        showMessage('Invalid plugin: missing fields: ' + missing.join(', '), 'error');
        return;
      }

      // Validate id format
      if (!/^[a-z0-9][a-z0-9-]*[a-z0-9]$/.test(manifest.id)) {
        showMessage('Invalid plugin id format. Use lowercase alphanumeric with hyphens.', 'error');
        return;
      }

      // Validate version format
      if (!/^\d+\.\d+\.\d+$/.test(manifest.version)) {
        showMessage('Invalid version format. Use semver (e.g., 1.0.0).', 'error');
        return;
      }

      // Check for duplicate
      const existingPlugin = currentPlugins.find(p => p.manifest.id === manifest.id);
      if (existingPlugin) {
        if (!confirm(`Plugin "${manifest.name}" already exists. Replace it?`)) {
          return;
        }
      }

      const plugin = {
        manifest: manifest,
        code: code,
        enabled: true,
        importedAt: new Date().toISOString()
      };

      chrome.runtime.sendMessage({ action: 'savePlugin', plugin }, (response) => {
        if (response && response.success) {
          showMessage(`Plugin "${manifest.name}" imported successfully`, 'success');
          loadPlugins();
        } else {
          showMessage('Failed to save plugin', 'error');
        }
      });
    } catch (err) {
      showMessage('Invalid JSON file: ' + err.message, 'error');
    }
  };

  reader.onerror = () => {
    showMessage('Failed to read file', 'error');
  };

  reader.readAsText(file);
}

function togglePlugin(pluginId, enabled) {
  chrome.runtime.sendMessage({ action: 'togglePlugin', pluginId, enabled }, (response) => {
    if (response && response.success) {
      // Update local state
      const plugin = currentPlugins.find(p => p.manifest.id === pluginId);
      if (plugin) {
        plugin.enabled = enabled;
      }
      updatePluginStats();

      // Update card visual state
      const card = document.querySelector(`.plugin-card[data-plugin-id="${pluginId}"]`);
      if (card) {
        if (enabled) {
          card.classList.remove('disabled');
        } else {
          card.classList.add('disabled');
        }
      }
    }
  });
}

function removePlugin(pluginId) {
  const plugin = currentPlugins.find(p => p.manifest.id === pluginId);
  const pluginName = plugin ? plugin.manifest.name : pluginId;

  if (!confirm(`Remove plugin "${pluginName}"?`)) return;

  chrome.runtime.sendMessage({ action: 'removePlugin', pluginId }, (response) => {
    if (response && response.success) {
      showMessage(`Plugin "${pluginName}" removed`, 'success');
      loadPlugins();
    } else {
      showMessage('Failed to remove plugin', 'error');
    }
  });
}

// Initialize API Testing tab when DOM loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeAPITestingTab);
} else {
  initializeAPITestingTab();
}

// ========================================
// Phase 2-3: Advanced Feature Rendering
// ========================================

// --- Inventory Sub-Tab Navigation ---
function setupInventorySubTabs() {
  const subTabBtns = document.querySelectorAll('.inventory-sub-tab-btn');
  const subTabPanes = document.querySelectorAll('.inventory-sub-tab-pane');

  subTabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabName = btn.dataset.inventoryTab;
      subTabBtns.forEach(b => b.classList.remove('active'));
      subTabPanes.forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      const pane = document.getElementById(`inventory-${tabName}-tab`);
      if (pane) pane.classList.add('active');

      if (tabName === 'evolution') {
        loadBaselineInfo();
      }
      if (tabName === 'bruteforce') {
        initBruteForceTarget();
        loadBruteForceResults();
      }
      if (tabName === 'crawler') {
        initCrawlerTarget();
        loadCrawlerResults();
      }
    });
  });
}

// --- Brute Force Scanner UI Logic ---

let bfScanActive = false;
let bfResults = [];

function initBruteForceTarget() {
  const targetInput = document.getElementById('bfTargetUrl');
  if (targetInput && !targetInput.value) {
    getTargetTabCb((tabs) => {
      if (tabs[0] && tabs[0].url) {
        try {
          const origin = new URL(tabs[0].url).origin;
          targetInput.value = origin;
        } catch (e) { /* ignore invalid URLs */ }
      }
    });
  }
}

function loadBruteForceResults() {
  getTargetTabCb((tabs) => {
    if (!tabs[0]) return;
    const tab = tabs[0];
    let domain;
    try { domain = new URL(tab.url).hostname; } catch (e) { return; }

    chrome.runtime.sendMessage({
      action: 'getBruteForceResults',
      tabId: tab.id,
      domain: domain
    }, (response) => {
      if (chrome.runtime.lastError || !response?.state) return;
      const state = response.state;

      // Restore results
      if (state.results && state.results.length > 0) {
        displayBruteForceResults(state.results);
        const resultsContainer = document.getElementById('bfResultsContainer');
        if (resultsContainer) resultsContainer.style.display = 'block';
      }

      // Restore progress bar
      if (state.scannedCount && state.totalPaths) {
        const progressContainer = document.getElementById('bfProgressContainer');
        if (progressContainer) progressContainer.style.display = 'block';
        updateBruteForceProgress(state.scannedCount, state.totalPaths);
      }

      // Restore target URL
      const targetInput = document.getElementById('bfTargetUrl');
      if (targetInput && state.targetUrl && !targetInput.value) {
        targetInput.value = state.targetUrl;
      }

      // Check if scan is still running in background
      if (state.scanActive) {
        chrome.runtime.sendMessage({ action: 'isBruteForceScanActive' }, (resp) => {
          if (chrome.runtime.lastError) return;
          if (resp?.active) {
            bfScanActive = true;
            const startBtn = document.getElementById('bfStartBtn');
            const stopBtn = document.getElementById('bfStopBtn');
            if (startBtn) startBtn.style.display = 'none';
            if (stopBtn) stopBtn.style.display = 'inline-flex';
          }
        });
      }
    });
  });
}

function setupBruteForceScanner() {
  // Wordlist type toggle
  const wordlistRadios = document.querySelectorAll('input[name="bfWordlistType"]');
  const customTextarea = document.getElementById('bfCustomWordlist');
  if (wordlistRadios.length && customTextarea) {
    wordlistRadios.forEach(radio => {
      radio.addEventListener('change', () => {
        customTextarea.style.display = radio.value === 'custom' && radio.checked ? 'block' : 'none';
      });
    });
  }

  // Concurrency slider
  const concurrencySlider = document.getElementById('bfConcurrency');
  const concurrencyValue = document.getElementById('bfConcurrencyValue');
  if (concurrencySlider && concurrencyValue) {
    concurrencySlider.addEventListener('input', () => {
      concurrencyValue.textContent = concurrencySlider.value;
    });
  }

  // Timeout slider
  const timeoutSlider = document.getElementById('bfTimeout');
  const timeoutValue = document.getElementById('bfTimeoutValue');
  if (timeoutSlider && timeoutValue) {
    timeoutSlider.addEventListener('input', () => {
      timeoutValue.textContent = timeoutSlider.value;
    });
  }

  // Start button
  const startBtn = document.getElementById('bfStartBtn');
  if (startBtn) {
    startBtn.addEventListener('click', startBruteForceScan);
  }

  // Stop button
  const stopBtn = document.getElementById('bfStopBtn');
  if (stopBtn) {
    stopBtn.addEventListener('click', stopBruteForceScan);
  }

  // Add All to Inventory button
  const addAllBtn = document.getElementById('bfAddAllBtn');
  if (addAllBtn) {
    addAllBtn.addEventListener('click', () => {
      addBruteForceToInventory(bfResults);
    });
  }

  // Clear Results button
  const clearBtn = document.getElementById('bfClearResultsBtn');
  if (clearBtn) {
    clearBtn.addEventListener('click', clearBruteForceResults);
  }
}

function clearBruteForceResults() {
  bfResults = [];
  const resultsContainer = document.getElementById('bfResultsContainer');
  const resultsBody = document.getElementById('bfResultsBody');
  const resultsCount = document.getElementById('bfResultsCount');
  const progressContainer = document.getElementById('bfProgressContainer');
  if (resultsContainer) resultsContainer.style.display = 'none';
  if (resultsBody) resultsBody.innerHTML = '';
  if (resultsCount) resultsCount.textContent = '0';
  if (progressContainer) progressContainer.style.display = 'none';

  getTargetTabCb((tabs) => {
    if (!tabs[0]) return;
    let domain;
    try { domain = new URL(tabs[0].url).hostname; } catch (e) {}
    chrome.runtime.sendMessage({
      action: 'clearBruteForceResults',
      tabId: tabs[0].id,
      domain: domain
    });
  });
}

function collectBruteForceConfig() {
  const targetUrl = (document.getElementById('bfTargetUrl')?.value || '').trim();
  if (!targetUrl) {
    showMessage('Please enter a target URL', 'error');
    return null;
  }

  try {
    new URL(targetUrl);
  } catch (e) {
    showMessage('Invalid target URL', 'error');
    return null;
  }

  const wordlistType = document.querySelector('input[name="bfWordlistType"]:checked')?.value || 'builtin';
  let customWordlist = null;
  if (wordlistType === 'custom') {
    const text = (document.getElementById('bfCustomWordlist')?.value || '').trim();
    if (!text) {
      showMessage('Custom wordlist is empty', 'error');
      return null;
    }
    customWordlist = text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
  }

  const scanMode = document.querySelector('input[name="bfScanMode"]:checked')?.value || 'both';

  const extensionsRaw = (document.getElementById('bfExtensions')?.value || '').trim();
  const extensions = extensionsRaw
    ? extensionsRaw.split(',').map(e => e.trim()).filter(e => e)
    : [];

  const concurrency = parseInt(document.getElementById('bfConcurrency')?.value || '10', 10);
  const timeout = parseInt(document.getElementById('bfTimeout')?.value || '5000', 10);
  const followRedirects = document.getElementById('bfFollowRedirects')?.checked || false;

  const statusCodes = [];
  document.querySelectorAll('.bf-status-code:checked').forEach(cb => {
    statusCodes.push(parseInt(cb.value, 10));
  });
  if (statusCodes.length === 0) {
    showMessage('Select at least one status code to match', 'error');
    return null;
  }

  const autoInventory = document.getElementById('bfAutoInventory')?.checked || false;

  return {
    targetUrl,
    scanMode,
    wordlistType,
    customWordlist,
    extensions,
    concurrency,
    timeout,
    followRedirects,
    statusCodes,
    autoInventory
  };
}

function startBruteForceScan() {
  if (bfScanActive) return;

  const config = collectBruteForceConfig();
  if (!config) return;

  bfScanActive = true;
  bfResults = [];

  // Update UI state
  const startBtn = document.getElementById('bfStartBtn');
  const stopBtn = document.getElementById('bfStopBtn');
  const progressContainer = document.getElementById('bfProgressContainer');
  const resultsContainer = document.getElementById('bfResultsContainer');
  const resultsBody = document.getElementById('bfResultsBody');
  const resultsCount = document.getElementById('bfResultsCount');

  if (startBtn) startBtn.style.display = 'none';
  if (stopBtn) stopBtn.style.display = 'inline-flex';
  if (progressContainer) progressContainer.style.display = 'block';
  if (resultsContainer) resultsContainer.style.display = 'block';
  if (resultsBody) resultsBody.innerHTML = '';
  if (resultsCount) resultsCount.textContent = '0';

  updateBruteForceProgress(0, 0);

  // Send message to background to start scan (include tabId for persistence)
  getTargetTabCb((tabs) => {
    const tabId = tabs[0]?.id;
    chrome.runtime.sendMessage({
      action: 'startBruteForceScan',
      config: config,
      tabId: tabId
    }, (response) => {
      if (chrome.runtime.lastError) {
        showMessage('Failed to start scan: ' + chrome.runtime.lastError.message, 'error');
        resetBruteForceUI();
        return;
      }
      if (response && response.error) {
        showMessage('Scan error: ' + response.error, 'error');
        resetBruteForceUI();
      }
    });
  });
}

function stopBruteForceScan() {
  chrome.runtime.sendMessage({ action: 'stopBruteForceScan' }, () => {
    resetBruteForceUI();
    showMessage('Brute force scan stopped', 'info');
  });
}

function resetBruteForceUI() {
  bfScanActive = false;
  const startBtn = document.getElementById('bfStartBtn');
  const stopBtn = document.getElementById('bfStopBtn');
  if (startBtn) startBtn.style.display = 'inline-flex';
  if (stopBtn) stopBtn.style.display = 'none';
}

function updateBruteForceProgress(scanned, total) {
  const fill = document.getElementById('bfProgressFill');
  const text = document.getElementById('bfProgressText');
  const percent = document.getElementById('bfProgressPercent');

  const pct = total > 0 ? Math.round((scanned / total) * 100) : 0;

  if (fill) fill.style.width = pct + '%';
  if (text) text.textContent = scanned + ' / ' + total;
  if (percent) percent.textContent = pct + '%';
}

function displayBruteForceResult(result) {
  if (!result) return;

  bfResults.push(result);

  const resultsBody = document.getElementById('bfResultsBody');
  const resultsCount = document.getElementById('bfResultsCount');
  const resultsContainer = document.getElementById('bfResultsContainer');

  if (resultsContainer) resultsContainer.style.display = 'block';
  if (resultsCount) resultsCount.textContent = bfResults.length;

  if (!resultsBody) return;

  const tr = document.createElement('tr');

  // Determine status class
  const statusClass = 'bf-status-' + result.status;

  // Format size
  let sizeStr = '-';
  if (result.size >= 0) {
    if (result.size > 1024 * 1024) {
      sizeStr = (result.size / (1024 * 1024)).toFixed(1) + ' MB';
    } else if (result.size > 1024) {
      sizeStr = (result.size / 1024).toFixed(1) + ' KB';
    } else {
      sizeStr = result.size + ' B';
    }
  }

  // Format content type
  const contentType = (result.contentType || 'unknown').split(';')[0].trim();

  const resultIndex = bfResults.length - 1;
  const loginBadge = result.isLoginPage ? '<span class="login-badge">Login</span>' : '';

  tr.innerHTML = `
    <td class="bf-path-cell" title="${escapeHtml(result.url)}">${escapeHtml(result.path)}${loginBadge}</td>
    <td><span class="bf-status-badge ${statusClass}">${result.status}</span></td>
    <td class="bf-size-cell">${sizeStr}</td>
    <td class="bf-type-cell" title="${escapeHtml(contentType)}">${escapeHtml(contentType)}</td>
    <td><button class="bf-action-btn" data-bf-index="${resultIndex}" onclick="addSingleBruteForceResult(${resultIndex})">+ Add</button></td>
  `;

  resultsBody.appendChild(tr);
}

function displayBruteForceResults(results) {
  const resultsBody = document.getElementById('bfResultsBody');
  if (resultsBody) resultsBody.innerHTML = '';
  bfResults = [];

  if (results && results.length > 0) {
    results.forEach(r => displayBruteForceResult(r));
  }
}

function addSingleBruteForceResult(index) {
  const result = bfResults[index];
  if (!result) return;

  addBruteForceToInventory([result]);

  // Update button state
  const btn = document.querySelector(`button[data-bf-index="${index}"]`);
  if (btn) {
    btn.textContent = 'Added';
    btn.classList.add('bf-added');
    btn.disabled = true;
  }
}
// Expose for inline onclick
if (typeof window !== 'undefined') {
  window.addSingleBruteForceResult = addSingleBruteForceResult;
}

function addBruteForceToInventory(results) {
  if (!results || results.length === 0) {
    showMessage('No results to add', 'info');
    return;
  }

  // Only add 200-status results by default for "Add All", or any status for single add
  const toAdd = results.length === 1
    ? results
    : results.filter(r => r.status === 200);

  if (toAdd.length === 0) {
    showMessage('No HTTP 200 results to add to inventory', 'info');
    return;
  }

  getTargetTabCb((tabs) => {
    if (!tabs[0]) return;
    const tab = tabs[0];
    let domain;
    try {
      domain = new URL(tab.url).hostname;
    } catch (e) {
      showMessage('Could not determine domain', 'error');
      return;
    }

    // Build resources object in inventory format
    const resources = {};
    toAdd.forEach(result => {
      resources[result.path] = {
        path: result.path,
        type: 'bruteforce',
        status: result.status,
        size: result.size >= 0 ? result.size : undefined,
        mimeType: (result.contentType || 'unknown').split(';')[0].trim(),
        source: 'bruteforce',
        url: result.url,
        discoveredAt: result.timestamp || Date.now()
      };
    });

    // Send incremental inventory update to background
    chrome.runtime.sendMessage({
      action: 'inventoryCollected',
      tabId: tab.id,
      inventory: {
        domain: domain,
        timestamp: Date.now(),
        url: tab.url,
        resources: resources,
        externalResources: {}
      }
    }, () => {
      if (chrome.runtime.lastError) {
        showMessage('Failed to update inventory: ' + chrome.runtime.lastError.message, 'error');
        return;
      }
      showMessage(toAdd.length + ' path(s) added to inventory', 'info');

      // Refresh inventory display
      loadInventory();
      updateInventoryBadge();
    });
  });
}

// Listen for brute force progress/result messages from background
function handleBruteForceMessage(message) {
  if (message.action === 'bruteForceScanProgress') {
    updateBruteForceProgress(message.scanned, message.total);
    if (message.result) {
      displayBruteForceResult(message.result);
    }
  } else if (message.action === 'bruteForceScanComplete') {
    resetBruteForceUI();
    updateBruteForceProgress(message.scanned, message.total);
    if (message.cancelled) {
      showMessage('Scan cancelled. Found ' + (message.resultsCount || 0) + ' paths.', 'info');
    } else {
      showMessage('Scan complete. Found ' + (message.resultsCount || 0) + ' paths out of ' + message.total + ' probed.', 'info');
    }
  }
}

// --- Web Crawler UI Logic ---

let crawlActive = false;
let crawlResults = [];
let activeCrawlerStatusCodes = [200, 301, 302, 403];

function initCrawlerTarget() {
  const targetInput = document.getElementById('crawlerTargetUrl');
  if (targetInput && !targetInput.value) {
    getTargetTabCb((tabs) => {
      if (tabs[0] && tabs[0].url) {
        try {
          targetInput.value = tabs[0].url;
        } catch (e) { /* ignore invalid URLs */ }
      }
    });
  }
}

function loadCrawlerResults() {
  getTargetTabCb((tabs) => {
    if (!tabs[0]) return;
    const tab = tabs[0];
    let domain;
    try { domain = new URL(tab.url).hostname; } catch (e) { return; }

    chrome.runtime.sendMessage({
      action: 'getCrawlerResults',
      tabId: tab.id,
      domain: domain
    }, (response) => {
      if (chrome.runtime.lastError || !response?.state) return;
      const state = response.state;

      // Restore results
      if (state.results && state.results.length > 0) {
        displayCrawlerResults(state.results);
        const resultsContainer = document.getElementById('crawlerResultsContainer');
        if (resultsContainer) resultsContainer.style.display = 'block';
      }

      // Restore progress bar
      if (state.crawledCount !== undefined && state.discoveredCount !== undefined) {
        const progressContainer = document.getElementById('crawlerProgressContainer');
        if (progressContainer) progressContainer.style.display = 'block';
        updateCrawlerProgress(state.crawledCount, state.discoveredCount);
      }

      // Restore target URL
      const targetInput = document.getElementById('crawlerTargetUrl');
      if (targetInput && state.targetUrl && !targetInput.value) {
        targetInput.value = state.targetUrl;
      }

      // Check if crawl is still running in background
      if (state.scanActive) {
        chrome.runtime.sendMessage({ action: 'isCrawlerActive' }, (resp) => {
          if (chrome.runtime.lastError) return;
          if (resp?.active) {
            crawlActive = true;
            const startBtn = document.getElementById('crawlerStartBtn');
            const stopBtn = document.getElementById('crawlerStopBtn');
            if (startBtn) startBtn.style.display = 'none';
            if (stopBtn) stopBtn.style.display = 'inline-flex';
          }
        });
      }
    });
  });
}

function setupCrawler() {
  // Max Depth slider
  const depthSlider = document.getElementById('crawlerMaxDepth');
  const depthValue = document.getElementById('crawlerMaxDepthValue');
  if (depthSlider && depthValue) {
    depthSlider.addEventListener('input', () => {
      depthValue.textContent = depthSlider.value;
    });
  }

  // Concurrency slider
  const concurrencySlider = document.getElementById('crawlerConcurrency');
  const concurrencyValue = document.getElementById('crawlerConcurrencyValue');
  if (concurrencySlider && concurrencyValue) {
    concurrencySlider.addEventListener('input', () => {
      concurrencyValue.textContent = concurrencySlider.value;
    });
  }

  // Timeout slider
  const timeoutSlider = document.getElementById('crawlerTimeout');
  const timeoutValue = document.getElementById('crawlerTimeoutValue');
  if (timeoutSlider && timeoutValue) {
    timeoutSlider.addEventListener('input', () => {
      timeoutValue.textContent = timeoutSlider.value;
    });
  }

  // Start button
  const startBtn = document.getElementById('crawlerStartBtn');
  if (startBtn) {
    startBtn.addEventListener('click', startCrawl);
  }

  // Stop button
  const stopBtn = document.getElementById('crawlerStopBtn');
  if (stopBtn) {
    stopBtn.addEventListener('click', stopCrawl);
  }

  // Add All to Inventory button
  const addAllBtn = document.getElementById('crawlerAddAllBtn');
  if (addAllBtn) {
    addAllBtn.addEventListener('click', () => {
      addCrawlerToInventory(crawlResults);
    });
  }

  // Clear Results button
  const clearBtn = document.getElementById('crawlerClearResultsBtn');
  if (clearBtn) {
    clearBtn.addEventListener('click', clearCrawlerResults);
  }
}

function clearCrawlerResults() {
  crawlResults = [];
  const resultsContainer = document.getElementById('crawlerResultsContainer');
  const resultsBody = document.getElementById('crawlerResultsBody');
  const resultsCount = document.getElementById('crawlerResultsCount');
  const progressContainer = document.getElementById('crawlerProgressContainer');
  if (resultsContainer) resultsContainer.style.display = 'none';
  if (resultsBody) resultsBody.innerHTML = '';
  if (resultsCount) resultsCount.textContent = '0';
  if (progressContainer) progressContainer.style.display = 'none';

  getTargetTabCb((tabs) => {
    if (!tabs[0]) return;
    let domain;
    try { domain = new URL(tabs[0].url).hostname; } catch (e) {}
    chrome.runtime.sendMessage({
      action: 'clearCrawlerResults',
      tabId: tabs[0].id,
      domain: domain
    });
  });
}

function collectCrawlerConfig() {
  const targetUrl = (document.getElementById('crawlerTargetUrl')?.value || '').trim();
  if (!targetUrl) {
    showMessage('Please enter a start URL', 'error');
    return null;
  }

  try {
    new URL(targetUrl);
  } catch (e) {
    showMessage('Invalid start URL', 'error');
    return null;
  }

  const maxDepth = parseInt(document.getElementById('crawlerMaxDepth')?.value || '2', 10);
  const followExternal = document.getElementById('crawlerFollowExternal')?.checked || false;
  const concurrency = parseInt(document.getElementById('crawlerConcurrency')?.value || '10', 10);
  const timeout = parseInt(document.getElementById('crawlerTimeout')?.value || '5000', 10);

  const autoInventory = document.getElementById('crawlerAutoInventory')?.checked || false;

  const statusCodes = [];
  document.querySelectorAll('.crawler-status-code:checked').forEach(cb => {
    statusCodes.push(parseInt(cb.value, 10));
  });
  if (statusCodes.length === 0) {
    showMessage('Select at least one status code to match', 'error');
    return null;
  }

  return {
    targetUrl,
    maxDepth,
    followExternal,
    concurrency,
    timeout,
    autoInventory,
    statusCodes
  };
}

function startCrawl() {
  if (crawlActive) return;

  const config = collectCrawlerConfig();
  if (!config) return;

  activeCrawlerStatusCodes = config.statusCodes;
  crawlActive = true;
  crawlResults = [];

  const startBtn = document.getElementById('crawlerStartBtn');
  const stopBtn = document.getElementById('crawlerStopBtn');
  const progressContainer = document.getElementById('crawlerProgressContainer');
  const resultsContainer = document.getElementById('crawlerResultsContainer');
  const resultsBody = document.getElementById('crawlerResultsBody');
  const resultsCount = document.getElementById('crawlerResultsCount');

  if (startBtn) startBtn.style.display = 'none';
  if (stopBtn) stopBtn.style.display = 'inline-flex';
  if (progressContainer) progressContainer.style.display = 'block';
  if (resultsContainer) resultsContainer.style.display = 'block';
  if (resultsBody) resultsBody.innerHTML = '';
  if (resultsCount) resultsCount.textContent = '0';

  updateCrawlerProgress(0, 0);

  getTargetTabCb((tabs) => {
    const tabId = tabs[0]?.id;
    chrome.runtime.sendMessage({
      action: 'startCrawl',
      config: config,
      tabId: tabId
    }, (response) => {
      if (chrome.runtime.lastError) {
        showMessage('Failed to start crawl: ' + chrome.runtime.lastError.message, 'error');
        resetCrawlerUI();
        return;
      }
      if (response && response.error) {
        showMessage('Crawl error: ' + response.error, 'error');
        resetCrawlerUI();
      }
    });
  });
}

function stopCrawl() {
  chrome.runtime.sendMessage({ action: 'stopCrawl' }, () => {
    resetCrawlerUI();
    showMessage('Crawl stopped', 'info');
  });
}

function resetCrawlerUI() {
  crawlActive = false;
  const startBtn = document.getElementById('crawlerStartBtn');
  const stopBtn = document.getElementById('crawlerStopBtn');
  if (startBtn) startBtn.style.display = 'inline-flex';
  if (stopBtn) stopBtn.style.display = 'none';
}

function updateCrawlerProgress(crawled, discovered) {
  const fill = document.getElementById('crawlerProgressFill');
  const text = document.getElementById('crawlerProgressText');
  const percent = document.getElementById('crawlerProgressPercent');

  // For crawlers, progress is crawled vs discovered (frontier size)
  const pct = discovered > 0 ? Math.round((crawled / discovered) * 100) : 0;

  if (fill) fill.style.width = pct + '%';
  if (text) text.textContent = crawled + ' / ' + discovered + ' discovered';
  if (percent) percent.textContent = pct + '%';

  // Update stats
  if (crawlResults.length > 0) {
    const maxDepth = Math.max(...crawlResults.map(r => r.depth || 0));
    const externalCount = crawlResults.filter(r => r.isExternal).length;
    const maxDepthEl = document.getElementById('crawlerMaxDepthReached');
    const externalEl = document.getElementById('crawlerExternalCount');
    if (maxDepthEl) maxDepthEl.textContent = maxDepth;
    if (externalEl) externalEl.textContent = externalCount;
  }
}

function displayCrawlerResult(result) {
  if (!result) return;
  if (!activeCrawlerStatusCodes.includes(result.status)) return;

  // Dedup by finalUrl (or url fallback) to prevent visual duplicates
  const deduKey = result.finalUrl || result.url;
  if (deduKey && crawlResults.some(r => (r.finalUrl || r.url) === deduKey)) return;

  crawlResults.push(result);

  const resultsBody = document.getElementById('crawlerResultsBody');
  const resultsCount = document.getElementById('crawlerResultsCount');
  const resultsContainer = document.getElementById('crawlerResultsContainer');

  if (resultsContainer) resultsContainer.style.display = 'block';
  if (resultsCount) resultsCount.textContent = crawlResults.length;

  if (!resultsBody) return;

  const tr = document.createElement('tr');

  // Determine depth badge class
  const depthClass = result.isExternal ? 'external' : 'internal';

  // Format content type
  const contentType = (result.contentType || 'unknown').split(';')[0].trim();

  // Display path relative to origin for internal, full URL for external
  const displayUrl = result.isExternal ? result.url : result.path;

  const resultIndex = crawlResults.length - 1;

  // Status class
  const statusClass = 'bf-status-' + result.status;

  const loginBadge = result.isLoginPage ? '<span class="login-badge">Login</span>' : '';

  tr.innerHTML = `
    <td class="crawler-url-cell" title="${escapeHtml(result.url)}">${escapeHtml(displayUrl)}${loginBadge}</td>
    <td><span class="bf-status-badge ${statusClass}">${result.status}</span></td>
    <td><span class="crawler-depth-badge ${depthClass}">${result.depth}</span></td>
    <td class="crawler-type-cell" title="${escapeHtml(contentType)}">${escapeHtml(contentType)}</td>
    <td><button class="crawler-action-btn" data-crawler-index="${resultIndex}" onclick="addSingleCrawlerResult(${resultIndex})">+ Add</button></td>
  `;

  resultsBody.appendChild(tr);
}

function displayCrawlerResults(results) {
  const resultsBody = document.getElementById('crawlerResultsBody');
  if (resultsBody) resultsBody.innerHTML = '';
  crawlResults = [];

  if (results && results.length > 0) {
    results.forEach(r => displayCrawlerResult(r));
  }
}

function addSingleCrawlerResult(index) {
  const result = crawlResults[index];
  if (!result) return;

  addCrawlerToInventory([result]);

  const btn = document.querySelector(`button[data-crawler-index="${index}"]`);
  if (btn) {
    btn.textContent = 'Added';
    btn.classList.add('crawler-added');
    btn.disabled = true;
  }
}
// Expose for inline onclick
if (typeof window !== 'undefined') {
  window.addSingleCrawlerResult = addSingleCrawlerResult;
}

function addCrawlerToInventory(results) {
  if (!results || results.length === 0) {
    showMessage('No results to add', 'info');
    return;
  }

  // For "Add All", only add results matching selected status codes; single add = any status
  const toAdd = results.length === 1
    ? results
    : results.filter(r => activeCrawlerStatusCodes.includes(r.status));

  if (toAdd.length === 0) {
    showMessage('No successful results to add to inventory', 'info');
    return;
  }

  getTargetTabCb((tabs) => {
    if (!tabs[0]) return;
    const tab = tabs[0];
    let domain;
    try {
      domain = new URL(tab.url).hostname;
    } catch (e) {
      showMessage('Could not determine domain', 'error');
      return;
    }

    const resources = {};
    toAdd.forEach(result => {
      resources[result.path] = {
        path: result.path,
        type: 'crawler',
        status: result.status,
        size: result.size >= 0 ? result.size : undefined,
        mimeType: (result.contentType || 'unknown').split(';')[0].trim(),
        source: 'crawler',
        url: result.url,
        depth: result.depth,
        discoveredAt: result.timestamp || Date.now()
      };
    });

    chrome.runtime.sendMessage({
      action: 'inventoryCollected',
      tabId: tab.id,
      inventory: {
        domain: domain,
        timestamp: Date.now(),
        url: tab.url,
        resources: resources,
        externalResources: {}
      }
    }, () => {
      if (chrome.runtime.lastError) {
        showMessage('Failed to update inventory: ' + chrome.runtime.lastError.message, 'error');
        return;
      }
      showMessage(toAdd.length + ' URL(s) added to inventory', 'info');
      loadInventory();
      updateInventoryBadge();
    });
  });
}

function handleCrawlerMessage(message) {
  if (message.action === 'crawlerProgress') {
    updateCrawlerProgress(message.crawled, message.discovered);
    if (message.result) {
      displayCrawlerResult(message.result);
    }
  } else if (message.action === 'crawlerComplete') {
    resetCrawlerUI();
    updateCrawlerProgress(message.crawled, message.discovered);
    if (message.cancelled) {
      showMessage('Crawl cancelled. Found ' + (message.resultsCount || 0) + ' URLs.', 'info');
    } else {
      showMessage('Crawl complete. Found ' + (message.resultsCount || 0) + ' URLs from ' + message.discovered + ' discovered.', 'info');
    }
  }
}

// --- Feature 5: Correlation Chains Rendering ---

async function loadCorrelationChains(tabId) {
  if (!tabId) {
    try {
      const tab = await getTargetTab();
      tabId = tab.id;
    } catch (e) {
      console.error('Origami: Could not get active tab for chains:', e);
      return;
    }
  }

  chrome.runtime.sendMessage({ action: 'getCorrelationChains', tabId }, (response) => {
    if (chrome.runtime.lastError) {
      console.error('Origami: Failed to load correlation chains:', chrome.runtime.lastError.message);
      return;
    }
    renderCorrelationChains(response?.chains);
  });
}

function renderCorrelationChains(chains) {
  const container = document.getElementById('chainsContainer');
  const totalEl = document.getElementById('chainsTotal');
  const highestEl = document.getElementById('chainsHighestSeverity');
  const autoEl = document.getElementById('chainsAutoDetected');

  if (!container) return;

  if (!chains || !Array.isArray(chains) || chains.length === 0) {
    if (totalEl) totalEl.textContent = '0';
    if (highestEl) highestEl.textContent = '--';
    if (autoEl) autoEl.textContent = '0';
    container.innerHTML = `
      <div class="empty-state">
        <p>No attack chains detected yet.</p>
        <p class="empty-hint">Run "Unfold" to detect attack chains. Correlation Engine analyzes findings for exploitable chains.</p>
      </div>
    `;
    return;
  }

  // Update stats
  if (totalEl) totalEl.textContent = chains.length;
  if (autoEl) autoEl.textContent = chains.filter(c => c.autoDetected !== false).length;

  const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };
  let highestSev = 'INFO';
  chains.forEach(chain => {
    const sev = (chain.severity || 'INFO').toUpperCase();
    if ((severityOrder[sev] || 4) < (severityOrder[highestSev] || 4)) {
      highestSev = sev;
    }
  });
  if (highestEl) highestEl.textContent = highestSev;

  let html = '';
  chains.forEach((chain, idx) => {
    const severity = (chain.severity || 'MEDIUM').toLowerCase();
    const severityUpper = severity.toUpperCase();
    const findingCount = Array.isArray(chain.findings) ? chain.findings.length : 0;
    const hasNarrative = chain.aiNarrative || chain.prediction?.narrative;

    html += `<div class="chain-card security-item ${severity}" data-chain-index="${idx}">`;
    html += `<div class="chain-header security-item-header">`;
    html += `<div class="security-item-title">${escapeHtml(chain.name || chain.id || 'Unnamed Chain')}</div>`;
    html += `<div class="security-item-actions">`;
    html += `<span class="security-badge ${severity}">${severityUpper}</span>`;
    if (findingCount > 0) {
      html += `<span class="security-badge info">${findingCount} findings</span>`;
    }
    html += `</div>`;
    html += `</div>`;

    if (chain.description) {
      html += `<div class="security-item-message">${escapeHtml(chain.description)}</div>`;
    }

    // Linked findings
    if (Array.isArray(chain.findings) && chain.findings.length > 0) {
      html += `<div class="chain-findings" style="margin-top: 8px;">`;
      html += `<strong>Linked Findings:</strong>`;
      html += `<ul style="margin: 4px 0 0 16px; padding: 0;">`;
      chain.findings.forEach(finding => {
        const fName = finding.check || finding.name || finding.templateId || 'Finding';
        const fSev = (finding.severity || 'INFO').toLowerCase();
        html += `<li style="margin-bottom: 2px;">`;
        html += `<span class="security-badge ${fSev}" style="font-size: 10px; padding: 1px 6px;">${fSev.toUpperCase()}</span> `;
        html += `${escapeHtml(fName)}`;
        html += `</li>`;
      });
      html += `</ul></div>`;
    }

    // Attack flow
    if (Array.isArray(chain.attackFlow) && chain.attackFlow.length > 0) {
      html += `<div class="chain-attack-flow" style="margin-top: 8px;">`;
      html += `<strong>Attack Flow:</strong>`;
      html += `<ol style="margin: 4px 0 0 16px; padding: 0;">`;
      chain.attackFlow.forEach(step => {
        html += `<li style="margin-bottom: 2px;">${escapeHtml(step)}</li>`;
      });
      html += `</ol></div>`;
    }

    // AI narrative
    if (hasNarrative) {
      const narrativeText = chain.aiNarrative || chain.prediction?.narrative || '';
      html += `<div class="chain-narrative" style="margin-top: 8px; border-top: 1px solid var(--border-color); padding-top: 8px;">`;
      html += `<details>`;
      html += `<summary style="cursor: pointer;"><strong>AI Exploitation Narrative</strong></summary>`;
      html += `<div class="ai-assessment-content" style="margin-top: 6px;">${formatAIAssessment(narrativeText)}</div>`;
      html += `</details>`;
      html += `</div>`;
    }

    // Remediation
    if (Array.isArray(chain.remediation) && chain.remediation.length > 0) {
      html += `<div style="margin-top: 8px;">`;
      html += `<details>`;
      html += `<summary style="cursor: pointer;"><strong>Remediation</strong></summary>`;
      html += `<ul style="margin: 4px 0 0 16px;">`;
      chain.remediation.forEach(step => {
        html += `<li>${escapeHtml(step)}</li>`;
      });
      html += `</ul></details></div>`;
    }

    html += `</div>`;
  });

  container.innerHTML = html;
}

// --- Feature 8: Session State Rendering ---

async function loadSessionState(tabId) {
  if (!tabId) {
    try {
      const tab = await getTargetTab();
      tabId = tab.id;
    } catch (e) {
      console.error('Origami: Could not get active tab for session state:', e);
      return;
    }
  }

  // Session state is stored inside the security results (from analyzer-coordinator)
  chrome.runtime.sendMessage({ action: 'getTabSecurityResults', tabId }, (response) => {
    if (chrome.runtime.lastError) {
      console.error('Origami: Failed to load session state:', chrome.runtime.lastError.message);
      return;
    }
    const sessionState = response?.results?.sessionState || null;
    renderSessionState(sessionState);
  });
}

function renderSessionState(sessionState) {
  const container = document.getElementById('sessionResults');
  if (!container) return;

  if (!sessionState) {
    container.innerHTML = `
      <div class="empty-state">
        <p>No session state data.</p>
        <p class="empty-hint">Run "Unfold" to analyze JWTs, session cookies, and OAuth state.</p>
      </div>
    `;
    return;
  }

  const tokens = sessionState.tokens || [];
  const cookies = sessionState.cookies || [];
  const oauthState = sessionState.oauthState;
  const allIssues = sessionState.allIssues || [];

  // Update badge (respect severity overrides)
  if (allIssues.length > 0) {
    const getEffSev = (i) => (i.severityOverride?.overriddenSeverity || i.aiAssessment?.suggestedSeverity || i.severity || 'INFO').toUpperCase();
    const actionableIssues = allIssues.filter(i => getEffSev(i) !== 'NONE');
    if (actionableIssues.length > 0) {
      const highestSev = actionableIssues.reduce((highest, issue) => {
        const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };
        const issueSev = getEffSev(issue);
        return (severityOrder[issueSev] || 4) < (severityOrder[highest] || 4) ? issueSev : highest;
      }, 'INFO');
      updateSubTabBadge('session', highestSev, actionableIssues.length);
    } else {
      updateSubTabBadge('session', null, 0);
    }
  }

  let html = '';

  // JWT Tokens
  if (tokens.length > 0) {
    html += `<div class="security-section" style="margin-bottom: 12px;">`;
    html += `<div class="security-section-header"><div class="security-section-title">JWT Tokens (${tokens.length})</div></div>`;

    tokens.forEach((token, idx) => {
      const hasIssues = Array.isArray(token.issues) && token.issues.length > 0;
      const severity = hasIssues ? 'high' : 'info';

      html += `<div class="security-item ${severity}" style="margin-bottom: 8px;">`;
      html += `<div class="security-item-header">`;
      html += `<div class="security-item-title">JWT #${idx + 1} (${escapeHtml(token.source)})</div>`;
      html += `<span class="security-badge ${severity}">${hasIssues ? token.issues.length + ' ISSUES' : 'OK'}</span>`;
      html += `</div>`;

      html += `<div style="padding: 8px 0; font-size: 12px;">`;
      html += `<div><strong>Source:</strong> ${escapeHtml(token.source)} (${escapeHtml(token.storageKey || '')})</div>`;
      html += `<div><strong>Token:</strong> <code style="word-break: break-all; font-size: 11px;">${escapeHtml(token.truncatedToken || '')}</code></div>`;

      if (token.header) {
        html += `<div><strong>Algorithm:</strong> ${escapeHtml(token.header.alg || 'unknown')}</div>`;
        if (token.header.typ) html += `<div><strong>Type:</strong> ${escapeHtml(token.header.typ)}</div>`;
      }

      if (token.payload) {
        if (token.payload.iss) html += `<div><strong>Issuer:</strong> ${escapeHtml(token.payload.iss)}</div>`;
        if (token.payload.sub) html += `<div><strong>Subject:</strong> ${escapeHtml(token.payload.sub)}</div>`;
        if (token.payload.exp) {
          const expDate = new Date(token.payload.exp * 1000);
          const isExpired = expDate < new Date();
          html += `<div><strong>Expires:</strong> ${escapeHtml(expDate.toISOString())} ${isExpired ? '<span class="security-badge medium">EXPIRED</span>' : ''}</div>`;
        }
        if (token.payload.iat) {
          html += `<div><strong>Issued At:</strong> ${escapeHtml(new Date(token.payload.iat * 1000).toISOString())}</div>`;
        }
      }
      html += `</div>`;

      if (hasIssues) {
        html += `<div style="margin-top: 4px;">`;
        html += `<strong>Issues:</strong>`;
        html += `<ul style="margin: 4px 0 0 16px;">`;
        token.issues.forEach(issue => {
          const issueSev = (issue.severity || 'medium').toLowerCase();
          html += `<li style="margin-bottom: 2px;">`;
          html += `<span class="security-badge ${issueSev}" style="font-size: 10px; padding: 1px 6px;">${issueSev.toUpperCase()}</span> `;
          html += escapeHtml(issue.message || '');
          html += `</li>`;
        });
        html += `</ul></div>`;
      }

      html += `</div>`;
    });

    html += `</div>`;
  }

  // Session Cookies
  if (cookies.length > 0) {
    html += `<div class="security-section" style="margin-bottom: 12px;">`;
    html += `<div class="security-section-header"><div class="security-section-title">Session Cookies (${cookies.length})</div></div>`;

    cookies.forEach((cookie, idx) => {
      const hasIssues = Array.isArray(cookie.issues) && cookie.issues.length > 0;
      const severity = hasIssues ? 'high' : 'info';

      html += `<div class="security-item ${severity}" style="margin-bottom: 8px;">`;
      html += `<div class="security-item-header">`;
      html += `<div class="security-item-title">${escapeHtml(cookie.name)}</div>`;
      html += `<span class="security-badge ${severity}">${hasIssues ? 'ISSUES' : 'OK'}</span>`;
      html += `</div>`;

      html += `<div style="padding: 8px 0; font-size: 12px;">`;
      html += `<div><strong>Value Length:</strong> ${cookie.valueLength} chars</div>`;
      html += `<div><strong>Entropy:</strong> ${cookie.entropy ? cookie.entropy.toFixed(2) : 'N/A'} bits/char</div>`;
      html += `</div>`;

      if (hasIssues) {
        html += `<div style="margin-top: 4px;"><ul style="margin: 4px 0 0 16px;">`;
        cookie.issues.forEach(issue => {
          const issueSev = (issue.severity || 'medium').toLowerCase();
          html += `<li><span class="security-badge ${issueSev}" style="font-size: 10px; padding: 1px 6px;">${issueSev.toUpperCase()}</span> ${escapeHtml(issue.message || '')}</li>`;
        });
        html += `</ul></div>`;
      }

      html += `</div>`;
    });

    html += `</div>`;
  }

  // OAuth State
  if (oauthState) {
    html += `<div class="security-section" style="margin-bottom: 12px;">`;
    html += `<div class="security-section-header"><div class="security-section-title">OAuth State Analysis</div></div>`;

    const hasIssues = Array.isArray(oauthState.issues) && oauthState.issues.length > 0;
    const severity = hasIssues ? 'high' : 'info';

    html += `<div class="security-item ${severity}">`;
    html += `<div style="padding: 8px 0; font-size: 12px;">`;
    html += `<div><strong>Authorization Code:</strong> ${oauthState.hasCode ? 'Present' : 'Not found'}</div>`;
    html += `<div><strong>State Parameter:</strong> ${oauthState.hasState ? 'Present' : '<span class="security-badge high">MISSING</span>'}</div>`;
    html += `<div><strong>Access Token in URL:</strong> ${oauthState.hasAccessToken ? '<span class="security-badge high">EXPOSED</span>' : 'Not found'}</div>`;
    html += `<div><strong>ID Token:</strong> ${oauthState.hasIdToken ? 'Present' : 'Not found'}</div>`;
    if (oauthState.stateEntropy !== null && oauthState.stateEntropy !== undefined) {
      html += `<div><strong>State Entropy:</strong> ${oauthState.stateEntropy.toFixed(2)} bits/char</div>`;
    }
    html += `</div>`;

    if (hasIssues) {
      html += `<div style="margin-top: 4px;"><ul style="margin: 4px 0 0 16px;">`;
      oauthState.issues.forEach(issue => {
        const issueSev = (issue.severity || 'medium').toLowerCase();
        html += `<li><span class="security-badge ${issueSev}" style="font-size: 10px; padding: 1px 6px;">${issueSev.toUpperCase()}</span> ${escapeHtml(issue.message || '')}`;
        if (issue.cwe) html += ` <span style="font-size: 10px; color: var(--text-secondary);">(${escapeHtml(issue.cwe)})</span>`;
        html += `</li>`;
      });
      html += `</ul></div>`;
    }

    html += `</div></div>`;
  }

  // Empty state if no data at all
  if (tokens.length === 0 && cookies.length === 0 && !oauthState) {
    html = `
      <div class="empty-state">
        <p>No session artifacts detected.</p>
        <p class="empty-hint">No JWTs, session cookies, or OAuth state found on this page.</p>
      </div>
    `;
  }

  container.innerHTML = html;

  if (!window.currentSecurityFindings) window.currentSecurityFindings = {};
  window.currentSecurityFindings.session = (sessionState.allIssues?.length > 0
    ? sessionState.allIssues
    : sessionState.issues) || [];
}

// --- Feature 7: Auth Flows Rendering ---

async function loadAuthFlows(tabId) {
  if (!tabId) {
    try {
      const tab = await getTargetTab();
      tabId = tab.id;
    } catch (e) {
      console.error('Origami: Could not get active tab for auth flows:', e);
      return;
    }
  }

  chrome.runtime.sendMessage({ action: 'getOAuthFlows', tabId }, (response) => {
    if (chrome.runtime.lastError) {
      console.error('Origami: Failed to load auth flows:', chrome.runtime.lastError.message);
      return;
    }
    renderAuthFlows(response?.flows);
  });
}

function renderAuthFlows(flows) {
  const container = document.getElementById('authFlowsResults');
  if (!container) return;

  // OAuthInterceptor returns { flows: [], issues: [], samlAssertions: [] }
  const flowEntries = flows?.flows || [];
  const allIssues = flows?.issues || [];
  const samlAssertions = flows?.samlAssertions || [];

  if (flowEntries.length === 0 && allIssues.length === 0 && samlAssertions.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <p>No auth flows intercepted.</p>
        <p class="empty-hint">Run "Unfold" to capture OAuth/SAML flows and detect misconfigurations.</p>
      </div>
    `;
    return;
  }

  // Update badge (respect severity overrides)
  if (allIssues.length > 0) {
    const getEffSev = (i) => (i.severityOverride?.overriddenSeverity || i.aiAssessment?.suggestedSeverity || i.severity || 'INFO').toUpperCase();
    const actionableIssues = allIssues.filter(i => getEffSev(i) !== 'NONE');
    if (actionableIssues.length > 0) {
      const highestSev = actionableIssues.reduce((highest, issue) => {
        const order = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };
        const issueSev = getEffSev(issue);
        return (order[issueSev] || 4) < (order[highest] || 4) ? issueSev : highest;
      }, 'INFO');
      updateSubTabBadge('auth-flows', highestSev, actionableIssues.length);
    } else {
      updateSubTabBadge('auth-flows', null, 0);
    }
  }

  let html = '';

  // Separate OAuth and SAML flow entries
  const oauthFlows = flowEntries.filter(f => f.type !== 'saml_response');
  const samlFlows = flowEntries.filter(f => f.type === 'saml_response');

  // OAuth Flow Parameters
  if (oauthFlows.length > 0) {
    html += `<div class="security-section" style="margin-bottom: 12px;">`;
    html += `<div class="security-section-header"><div class="security-section-title">OAuth/OIDC Flow Indicators (${oauthFlows.length})</div></div>`;

    oauthFlows.forEach((flow, idx) => {
      const flowType = (flow.type || 'unknown').replace(/_/g, ' ');
      const isHighRisk = flow.type === 'implicit_flow';
      const severity = isHighRisk ? 'high' : 'info';

      html += `<div class="security-item ${severity}" style="margin-bottom: 6px;">`;
      html += `<div class="security-item-header">`;
      html += `<div class="security-item-title" style="text-transform: capitalize;">${escapeHtml(flowType)}</div>`;
      html += `<span class="security-badge ${severity}" style="font-size: 10px; padding: 1px 6px;">${escapeHtml(flow.type || '')}</span>`;
      html += `</div>`;

      html += `<div style="padding: 4px 0; font-size: 12px;">`;
      if (flow.parameter) {
        html += `<div><strong>Parameter:</strong> <code>${escapeHtml(flow.parameter)}</code></div>`;
      }
      if (flow.value) {
        html += `<div><strong>Value:</strong> <code>${escapeHtml(String(flow.value).substring(0, 100))}</code></div>`;
      }
      if (flow.valueLength) {
        html += `<div><strong>Value Length:</strong> ${flow.valueLength} chars</div>`;
      }
      if (flow.entropy !== undefined) {
        const entropyClass = flow.entropy < 3 ? 'medium' : 'info';
        html += `<div><strong>Entropy:</strong> <span class="security-badge ${entropyClass}" style="font-size: 10px; padding: 1px 6px;">${flow.entropy.toFixed(2)} bits/char</span></div>`;
      }
      if (flow.location) {
        html += `<div><strong>Location:</strong> ${escapeHtml(flow.location)}</div>`;
      }
      if (flow.hasCodeChallenge !== undefined) {
        html += `<div><strong>Code Challenge:</strong> ${flow.hasCodeChallenge ? 'Present' : 'Absent'}</div>`;
      }
      if (flow.codeChallengeMethod) {
        html += `<div><strong>Challenge Method:</strong> ${escapeHtml(flow.codeChallengeMethod)}</div>`;
      }
      // Stored tokens
      if (flow.type === 'stored_tokens' && flow.tokens) {
        html += `<div><strong>Tokens Found:</strong> ${flow.count}</div>`;
        flow.tokens.forEach(t => {
          html += `<div style="margin-left: 12px;"><code>${escapeHtml(t.key)}</code> (${escapeHtml(t.storage)}, ${t.valueLength} chars${t.isJWT ? ', JWT' : ''})</div>`;
        });
      }
      html += `</div>`;
      html += `</div>`;
    });

    html += `</div>`;
  }

  // Issues
  if (allIssues.length > 0) {
    html += `<div class="security-section" style="margin-bottom: 12px;">`;
    html += `<div class="security-section-header"><div class="security-section-title">Auth Flow Issues (${allIssues.length})</div></div>`;

    allIssues.forEach(issue => {
      const issueSev = (issue.severity || 'MEDIUM').toLowerCase();
      html += `<div class="security-item ${issueSev}" style="margin-bottom: 6px;">`;
      html += `<div class="security-item-header">`;
      html += `<div class="security-item-title">${escapeHtml(issue.type || 'Issue')}</div>`;
      html += `<span class="security-badge ${issueSev}">${issueSev.toUpperCase()}</span>`;
      html += `</div>`;
      html += `<div class="security-item-message">${escapeHtml(issue.message || '')}</div>`;
      if (issue.cwe) {
        html += `<div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">${escapeHtml(issue.cwe)}</div>`;
      }
      if (issue.recommendation) {
        html += `<div style="font-size: 11px; margin-top: 4px;"><strong>Recommendation:</strong> ${escapeHtml(issue.recommendation)}</div>`;
      }
      html += `</div>`;
    });

    html += `</div>`;
  }

  // SAML Assertions
  if (samlAssertions.length > 0) {
    html += `<div class="security-section">`;
    html += `<div class="security-section-header"><div class="security-section-title">SAML Assertions (${samlAssertions.length})</div></div>`;

    samlAssertions.forEach((assertion, idx) => {
      const hasIssues = Array.isArray(assertion.issues) && assertion.issues.length > 0;
      const severity = hasIssues ? 'high' : 'info';

      html += `<div class="security-item ${severity}" style="margin-bottom: 8px;">`;
      html += `<div class="security-item-header">`;
      html += `<div class="security-item-title">SAML Assertion #${idx + 1}</div>`;
      html += `<span class="security-badge ${severity}">${hasIssues ? 'ISSUES FOUND' : 'OK'}</span>`;
      html += `</div>`;

      html += `<div style="padding: 8px 0;">`;
      if (assertion.issuer) {
        html += `<div><strong>Issuer:</strong> ${escapeHtml(assertion.issuer)}</div>`;
      }
      if (assertion.destination) {
        html += `<div><strong>Destination:</strong> <code>${escapeHtml(assertion.destination)}</code></div>`;
      }
      if (assertion.notBefore || assertion.notAfter) {
        html += `<div><strong>Validity:</strong> ${escapeHtml(assertion.notBefore || '?')} to ${escapeHtml(assertion.notAfter || '?')}</div>`;
      }
      if (assertion.signatureAlgorithm) {
        html += `<div><strong>Signature Algorithm:</strong> ${escapeHtml(assertion.signatureAlgorithm)}</div>`;
      }
      html += `</div>`;

      if (hasIssues) {
        html += `<div style="margin-top: 4px;">`;
        html += `<strong>Issues:</strong>`;
        html += `<ul style="margin: 4px 0 0 16px;">`;
        assertion.issues.forEach(issue => {
          const issueSev = (issue.severity || 'medium').toLowerCase();
          html += `<li><span class="security-badge ${issueSev}" style="font-size: 10px; padding: 1px 6px;">${issueSev.toUpperCase()}</span> `;
          html += escapeHtml(issue.message || issue.description || String(issue));
          html += `</li>`;
        });
        html += `</ul></div>`;
      }

      html += `</div>`;
    });

    html += `</div>`;
  }

  container.innerHTML = html;

  if (!window.currentSecurityFindings) window.currentSecurityFindings = {};
  window.currentSecurityFindings.oauth = allIssues;
}

// --- Feature 4: GraphQL Results Rendering ---

async function loadGraphQLResults(tabId) {
  if (!tabId) {
    try {
      const tab = await getTargetTab();
      tabId = tab.id;
    } catch (e) {
      console.error('Origami: Could not get active tab for GraphQL:', e);
      return;
    }
  }

  chrome.runtime.sendMessage({ action: 'getGraphQLResults', tabId }, (response) => {
    if (chrome.runtime.lastError) {
      console.error('Origami: Failed to load GraphQL results:', chrome.runtime.lastError.message);
      return;
    }
    renderGraphQLResults(response?.graphql);
  });
}

function renderGraphQLResults(graphql) {
  const schemaTree = document.getElementById('graphqlSchemaTree');
  const issuesList = document.getElementById('graphqlIssuesList');
  const endpointsEl = document.getElementById('graphqlEndpoints');
  const typesEl = document.getElementById('graphqlTypes');
  const issuesEl = document.getElementById('graphqlIssues');

  if (!graphql) {
    if (endpointsEl) endpointsEl.textContent = '0';
    if (typesEl) typesEl.textContent = '0';
    if (issuesEl) issuesEl.textContent = '0';
    return;
  }

  // Update stats
  const endpoints = graphql.endpoints || [];
  const types = graphql.schemaTree || graphql.types || [];
  const issues = graphql.issues || [];

  // Store graphql findings for AI assessment
  if (!window.currentSecurityFindings) window.currentSecurityFindings = {};
  window.currentSecurityFindings.graphql = issues;

  if (endpointsEl) endpointsEl.textContent = endpoints.length;
  if (typesEl) typesEl.textContent = types.length;
  if (issuesEl) issuesEl.textContent = issues.length;

  // Render schema tree
  if (schemaTree) {
    if (types.length > 0) {
      let html = '<div class="graphql-tree">';
      types.forEach(type => {
        const typeName = typeof type === 'string' ? type : (type.name || 'Unknown');
        const typeKind = (typeof type === 'object' && type.kind) ? type.kind : 'OBJECT';
        const fields = (typeof type === 'object' && Array.isArray(type.fields)) ? type.fields : [];

        html += `<div class="tree-node" style="margin-bottom: 4px;">`;
        html += `<div class="tree-node-header" style="cursor: ${fields.length > 0 ? 'pointer' : 'default'};">`;
        html += `<span class="security-badge info" style="font-size: 10px; padding: 1px 6px;">${escapeHtml(typeKind)}</span> `;
        html += `<strong>${escapeHtml(typeName)}</strong>`;
        if (fields.length > 0) {
          html += ` <span style="color: var(--text-secondary); font-size: 11px;">(${fields.length} fields)</span>`;
        }
        html += `</div>`;

        if (fields.length > 0) {
          html += `<div class="tree-node-children" style="margin-left: 16px; display: none;">`;
          fields.forEach(field => {
            const fName = typeof field === 'string' ? field : (field.name || 'unknown');
            const fType = (typeof field === 'object' && (field.typeName || field.type)) ? (field.typeName || field.type) : '';
            html += `<div style="padding: 2px 0; font-size: 12px;">`;
            html += `<code>${escapeHtml(fName)}</code>`;
            if (fType) html += `: <span style="color: var(--text-secondary);">${escapeHtml(fType)}</span>`;
            html += `</div>`;
          });
          html += `</div>`;
        }

        html += `</div>`;
      });
      html += '</div>';
      schemaTree.innerHTML = html;

      // Toggle tree nodes
      schemaTree.querySelectorAll('.tree-node-header').forEach(header => {
        header.addEventListener('click', () => {
          const children = header.nextElementSibling;
          if (children && children.classList.contains('tree-node-children')) {
            children.style.display = children.style.display === 'none' ? 'block' : 'none';
          }
        });
      });
    } else if (endpoints.length > 0) {
      let html = '<div style="padding: 8px;">';
      html += '<strong>Detected Endpoints:</strong>';
      html += '<ul style="margin: 4px 0 0 16px;">';
      endpoints.forEach(ep => {
        const url = typeof ep === 'string' ? ep : (ep.url || ep.endpoint || '');
        html += `<li><code>${escapeHtml(url)}</code></li>`;
      });
      html += '</ul></div>';
      schemaTree.innerHTML = html;
    } else {
      schemaTree.innerHTML = `
        <div class="empty-state">
          <p>No GraphQL schema detected.</p>
          <p class="empty-hint">Run "Unfold" to detect and map GraphQL endpoints.</p>
        </div>
      `;
    }
  }

  // Render issues
  if (issuesList) {
    if (issues.length > 0) {
      let html = '<div class="security-items">';
      issues.forEach(issue => {
        const severity = (issue.severity || 'medium').toLowerCase();
        html += `<div class="security-item ${severity}">`;
        html += `<div class="security-item-header">`;
        html += `<div class="security-item-title">${escapeHtml(issue.check || issue.name || issue.type || 'GraphQL Issue')}</div>`;
        html += `<span class="security-badge ${severity}">${severity.toUpperCase()}</span>`;
        html += `</div>`;
        html += `<div class="security-item-message">${escapeHtml(issue.message || issue.description || '')}</div>`;
        if (issue.recommendation) {
          html += `<div class="security-item-recommendation">${escapeHtml(issue.recommendation)}</div>`;
        }
        html += `</div>`;
      });
      html += '</div>';
      issuesList.innerHTML = html;
    } else {
      issuesList.innerHTML = `<div class="empty-state"><p>No issues found.</p></div>`;
    }
  }
}

// GraphQL query execution
function setupGraphQLQueryExecution() {
  const executeBtn = document.getElementById('executeGraphqlBtn');
  if (!executeBtn) return;

  executeBtn.addEventListener('click', async () => {
    const queryEditor = document.getElementById('graphqlQueryEditor');
    const resultsContainer = document.getElementById('graphqlResults');
    const query = queryEditor ? queryEditor.value.trim() : '';

    if (!query) {
      showMessage('Enter a GraphQL query to execute.', 'error');
      return;
    }

    // Determine endpoint -- check from loaded results
    let endpointUrl = '';
    const endpointsEl = document.getElementById('graphqlEndpoints');
    // Try to get the endpoint from stored GraphQL results
    try {
      const tab = await getTargetTab();
      const response = await new Promise((resolve) => {
        chrome.runtime.sendMessage({ action: 'getGraphQLResults', tabId: tab.id }, resolve);
      });
      if (response?.graphql?.endpoints?.length > 0) {
        const ep = response.graphql.endpoints[0];
        endpointUrl = typeof ep === 'string' ? ep : (ep.url || ep.endpoint || '');
      }
    } catch (e) {
      // Ignore
    }

    if (!endpointUrl) {
      if (resultsContainer) {
        resultsContainer.innerHTML = `<div class="empty-state"><p>No GraphQL endpoint detected. Run "Unfold" first to discover endpoints.</p></div>`;
      }
      return;
    }

    executeBtn.disabled = true;
    executeBtn.textContent = 'Executing...';
    if (resultsContainer) {
      resultsContainer.innerHTML = '<div class="empty-state"><p>Executing query...</p></div>';
    }

    try {
      const response = await new Promise((resolve, reject) => {
        chrome.runtime.sendMessage({
          action: 'graphqlProxy',
          url: endpointUrl,
          query: query,
          variables: {}
        }, (resp) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
          } else {
            resolve(resp);
          }
        });
      });

      if (response && response.success && response.data) {
        const formatted = JSON.stringify(response.data, null, 2);
        if (resultsContainer) {
          resultsContainer.innerHTML = `<pre style="background: var(--bg-secondary); padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; max-height: 400px; overflow-y: auto;"><code>${escapeHtml(formatted)}</code></pre>`;
        }
      } else {
        if (resultsContainer) {
          resultsContainer.innerHTML = `<div class="security-item high"><div class="security-item-message">Query failed: ${escapeHtml(response?.error || 'Unknown error')}</div></div>`;
        }
      }
    } catch (e) {
      if (resultsContainer) {
        resultsContainer.innerHTML = `<div class="security-item high"><div class="security-item-message">Error: ${escapeHtml(e.message)}</div></div>`;
      }
    } finally {
      executeBtn.disabled = false;
      executeBtn.textContent = 'Execute';
    }
  });
}

// --- Feature 9: Attack Surface Evolution Tracker ---

async function loadBaselineInfo() {
  try {
    const tab = await getTargetTab();
    const url = new URL(tab.url);
    const domain = url.hostname;

    chrome.runtime.sendMessage({ action: 'getBaselines', domain }, (response) => {
      if (chrome.runtime.lastError) return;

      const infoContainer = document.getElementById('baselineInfo');
      if (!infoContainer) return;

      const baselines = response?.baselines || [];
      if (baselines.length === 0) {
        infoContainer.innerHTML = '';
        return;
      }

      const latest = baselines[0];
      const timestamp = latest.timestamp ? new Date(latest.timestamp).toLocaleString() : 'Unknown';
      infoContainer.innerHTML = `
        <div style="padding: 8px; font-size: 12px; background: var(--bg-secondary); border-radius: 6px;">
          <strong>Last Baseline:</strong> ${escapeHtml(domain)} -- ${escapeHtml(timestamp)}
          <br><span style="color: var(--text-secondary);">${baselines.length} baseline(s) saved for this domain</span>
        </div>
      `;
    });
  } catch (e) {
    console.error('Origami: loadBaselineInfo error:', e);
  }
}

function setupEvolutionTracker() {
  const saveBtn = document.getElementById('saveBaselineBtn');
  const compareBtn = document.getElementById('compareBaselineBtn');

  if (saveBtn) {
    saveBtn.addEventListener('click', async () => {
      try {
        saveBtn.disabled = true;
        saveBtn.textContent = 'Saving...';

        const tab = await getTargetTab();
        const url = new URL(tab.url);
        const domain = url.hostname;

        // Get current surface snapshot
        const snapshot = await new Promise((resolve, reject) => {
          chrome.runtime.sendMessage({ action: 'getSurfaceSnapshot', tabId: tab.id }, (resp) => {
            if (chrome.runtime.lastError) {
              reject(new Error(chrome.runtime.lastError.message));
            } else {
              resolve(resp?.snapshot);
            }
          });
        });

        if (!snapshot) {
          showMessage('No surface snapshot available. Run "Unfold" first.', 'error');
          return;
        }

        // Add metadata
        snapshot.timestamp = new Date().toISOString();
        snapshot.domain = domain;
        snapshot.url = tab.url;

        // Save baseline
        const result = await new Promise((resolve, reject) => {
          chrome.runtime.sendMessage({ action: 'saveBaseline', domain, baseline: snapshot }, (resp) => {
            if (chrome.runtime.lastError) {
              reject(new Error(chrome.runtime.lastError.message));
            } else {
              resolve(resp);
            }
          });
        });

        if (result?.success) {
          showMessage('Baseline saved for ' + domain + ' (' + result.count + ' total)', 'success');
          loadBaselineInfo();
        } else {
          showMessage('Failed to save baseline: ' + (result?.error || 'Unknown error'), 'error');
        }
      } catch (e) {
        showMessage('Error saving baseline: ' + e.message, 'error');
      } finally {
        saveBtn.disabled = false;
        saveBtn.textContent = 'Save Baseline';
      }
    });
  }

  if (compareBtn) {
    compareBtn.addEventListener('click', async () => {
      try {
        compareBtn.disabled = true;
        compareBtn.textContent = 'Comparing...';

        const tab = await getTargetTab();
        const url = new URL(tab.url);
        const domain = url.hostname;

        // Get current surface snapshot
        const snapshot = await new Promise((resolve, reject) => {
          chrome.runtime.sendMessage({ action: 'getSurfaceSnapshot', tabId: tab.id }, (resp) => {
            if (chrome.runtime.lastError) {
              reject(new Error(chrome.runtime.lastError.message));
            } else {
              resolve(resp?.snapshot);
            }
          });
        });

        if (!snapshot) {
          showMessage('No surface snapshot available. Run "Unfold" first.', 'error');
          return;
        }

        // Diff against baseline
        const result = await new Promise((resolve, reject) => {
          chrome.runtime.sendMessage({ action: 'diffBaseline', domain, currentSnapshot: snapshot }, (resp) => {
            if (chrome.runtime.lastError) {
              reject(new Error(chrome.runtime.lastError.message));
            } else {
              resolve(resp);
            }
          });
        });

        if (result?.message) {
          showMessage(result.message, 'info');
          return;
        }

        if (result?.diff) {
          renderBaselineDiff(result.diff, result.baseline);
        } else {
          showMessage('Failed to compute diff: ' + (result?.error || 'Unknown error'), 'error');
        }
      } catch (e) {
        showMessage('Error comparing baseline: ' + e.message, 'error');
      } finally {
        compareBtn.disabled = false;
        compareBtn.textContent = 'Compare';
      }
    });
  }
}

function renderBaselineDiff(diff, baseline) {
  const container = document.getElementById('baselineDiffResults');
  if (!container) return;

  if (!diff) {
    container.innerHTML = `<div class="empty-state"><p>No differences computed.</p></div>`;
    return;
  }

  const added = diff.added || [];
  const removed = diff.removed || [];
  const changed = diff.changed || [];
  const summary = diff.summary || {};

  if (added.length === 0 && removed.length === 0 && changed.length === 0) {
    container.innerHTML = `
      <div class="empty-state" style="border-left: 3px solid var(--success-color, #28a745); padding-left: 12px;">
        <p>No changes detected since the last baseline.</p>
        <p class="empty-hint">The attack surface appears unchanged.</p>
      </div>
    `;
    return;
  }

  let html = '';

  // Summary
  html += `<div style="padding: 8px; margin-bottom: 12px; background: var(--bg-secondary); border-radius: 6px; font-size: 12px;">`;
  html += `<strong>Evolution Summary:</strong>`;
  if (summary.technologiesAdded) html += ` <span class="security-badge info">+${summary.technologiesAdded} tech</span>`;
  if (summary.technologiesRemoved) html += ` <span class="security-badge high">-${summary.technologiesRemoved} tech</span>`;
  if (summary.headersAdded) html += ` <span class="security-badge info">+${summary.headersAdded} headers</span>`;
  if (summary.headersRemoved) html += ` <span class="security-badge high">-${summary.headersRemoved} headers</span>`;
  if (summary.versionChanges) html += ` <span class="security-badge medium">${summary.versionChanges} version changes</span>`;
  if (summary.findingsDelta !== undefined && summary.findingsDelta !== 0) {
    const deltaLabel = summary.findingsDelta > 0 ? '+' + summary.findingsDelta : String(summary.findingsDelta);
    const deltaClass = summary.findingsDelta > 0 ? 'high' : 'info';
    html += ` <span class="security-badge ${deltaClass}">${deltaLabel} findings</span>`;
  }
  if (baseline && baseline.timestamp) {
    html += `<br><span style="color: var(--text-secondary);">Compared against baseline from ${new Date(baseline.timestamp).toLocaleString()}</span>`;
  }
  html += `</div>`;

  // Added items
  if (added.length > 0) {
    html += `<div class="security-section" style="border-left: 3px solid var(--success-color, #28a745); margin-bottom: 8px;">`;
    html += `<div class="security-section-header"><div class="security-section-title" style="color: var(--success-color, #28a745);">+ Added (${added.length})</div></div>`;
    added.forEach(item => {
      html += `<div style="padding: 4px 12px; font-size: 12px;">`;
      html += `<span class="security-badge info" style="font-size: 10px; padding: 1px 6px;">${escapeHtml(item.type)}</span> `;
      html += escapeHtml(item.name);
      html += `</div>`;
    });
    html += `</div>`;
  }

  // Removed items
  if (removed.length > 0) {
    html += `<div class="security-section" style="border-left: 3px solid var(--high-color, #dc3545); margin-bottom: 8px;">`;
    html += `<div class="security-section-header"><div class="security-section-title" style="color: var(--high-color, #dc3545);">- Removed (${removed.length})</div></div>`;
    removed.forEach(item => {
      html += `<div style="padding: 4px 12px; font-size: 12px;">`;
      html += `<span class="security-badge high" style="font-size: 10px; padding: 1px 6px;">${escapeHtml(item.type)}</span> `;
      html += escapeHtml(item.name);
      html += `</div>`;
    });
    html += `</div>`;
  }

  // Changed items
  if (changed.length > 0) {
    html += `<div class="security-section" style="border-left: 3px solid var(--medium-color, #ffc107); margin-bottom: 8px;">`;
    html += `<div class="security-section-header"><div class="security-section-title" style="color: var(--medium-color, #ffc107);">~ Changed (${changed.length})</div></div>`;
    changed.forEach(item => {
      html += `<div style="padding: 4px 12px; font-size: 12px;">`;
      html += `<span class="security-badge medium" style="font-size: 10px; padding: 1px 6px;">${escapeHtml(item.type)}</span> `;
      html += `${escapeHtml(item.name)}: `;
      html += `<code>${escapeHtml(String(item.from || '?'))}</code> → <code>${escapeHtml(String(item.to || '?'))}</code>`;
      html += `</div>`;
    });
    html += `</div>`;
  }

  container.innerHTML = html;
}

// --- Feature 6: Workbench ---

let workbenchChainSteps = [];

function setupWorkbench() {
  populateWorkbenchFindings();
  setupWorkbenchDragDrop();

  const analyzeBtn = document.getElementById('analyzeChainBtn');
  const clearBtn = document.getElementById('clearChainBtn');

  if (analyzeBtn) {
    analyzeBtn.addEventListener('click', analyzeWorkbenchChain);
  }

  if (clearBtn) {
    clearBtn.addEventListener('click', clearWorkbenchChain);
  }

  // Restore persisted workbench state
  loadFeatureState('workbench_chain', (data) => {
    if (!data) return;
    if (data.steps && data.steps.length > 0) {
      workbenchChainSteps = data.steps;
      renderChainBuilder();
    }
    if (data.analysisHtml) {
      const outputContainer = document.getElementById('workbenchPocOutput');
      if (outputContainer) outputContainer.innerHTML = data.analysisHtml;
    }
  });
}

function populateWorkbenchFindings() {
  const container = document.getElementById('workbenchFindings');
  if (!container) return;

  // Collect all findings from secrets and security results
  const allFindings = [];

  // Add secret findings
  if (currentFindings && currentFindings.length > 0) {
    currentFindings.forEach((f, idx) => {
      allFindings.push({
        id: 'secret-' + idx,
        type: f.pattern_matched || 'Secret',
        severity: f.severity || f.risk || 'MEDIUM',
        message: f.message || f.key || '',
        category: 'secrets',
        source: f
      });
    });
  }

  // Add security findings
  if (window.currentSecurityFindings) {
    const categories = ['headers', 'cookies', 'vulnerabilities', 'sensitiveFiles', 'session', 'oauth', 'graphql', 'crypto', 'cloudStorage', 'exfiltration', 'websocket'];
    categories.forEach(cat => {
      const items = window.currentSecurityFindings[cat] || [];
      items.forEach((f, idx) => {
        const sev = (f.severity || 'INFO').toUpperCase();
        if (sev === 'INFO' || sev === 'NONE') return;
        allFindings.push({
          id: cat + '-' + idx,
          type: f.check || f.name || f.type || cat,
          severity: sev,
          message: f.message || '',
          category: cat,
          source: f
        });
      });
    });
  }

  if (allFindings.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <p>No findings available.</p>
        <p class="empty-hint">Run "Unfold" to populate findings for chain building.</p>
      </div>
    `;
    return;
  }

  let html = '';
  allFindings.forEach(finding => {
    const sev = finding.severity.toLowerCase();
    html += `<div class="workbench-finding-card" draggable="true" data-finding-id="${escapeHtml(finding.id)}"
                  data-finding-type="${escapeHtml(finding.type)}" data-finding-severity="${escapeHtml(finding.severity)}"
                  data-finding-message="${escapeHtml(finding.message)}" data-finding-category="${escapeHtml(finding.category)}"
                  style="padding: 6px 8px; margin-bottom: 4px; border-radius: 4px; cursor: grab; border-left: 3px solid var(--${sev}-color, #888); background: var(--bg-secondary);">`;
    html += `<div style="display: flex; justify-content: space-between; align-items: center;">`;
    html += `<span style="font-size: 12px; font-weight: 500;">${escapeHtml(finding.type)}</span>`;
    html += `<span class="security-badge ${sev}" style="font-size: 10px; padding: 1px 6px;">${finding.severity}</span>`;
    html += `</div>`;
    if (finding.message) {
      html += `<div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(finding.message)}</div>`;
    }
    html += `</div>`;
  });

  container.innerHTML = html;

  // Add click-to-add handlers
  container.querySelectorAll('.workbench-finding-card').forEach(card => {
    card.addEventListener('click', () => {
      addFindingToChain(card);
    });
  });
}

function setupWorkbenchDragDrop() {
  const canvas = document.getElementById('chainBuilderCanvas');
  if (!canvas) return;

  canvas.addEventListener('dragover', (e) => {
    e.preventDefault();
    canvas.classList.add('drag-over');
  });

  canvas.addEventListener('dragleave', () => {
    canvas.classList.remove('drag-over');
  });

  canvas.addEventListener('drop', (e) => {
    e.preventDefault();
    canvas.classList.remove('drag-over');

    const findingId = e.dataTransfer.getData('text/plain');
    const findingCard = document.querySelector(`.workbench-finding-card[data-finding-id="${findingId}"]`);
    if (findingCard) {
      addFindingToChain(findingCard);
    }
  });

  // Setup drag start on finding cards
  const findingsContainer = document.getElementById('workbenchFindings');
  if (findingsContainer) {
    findingsContainer.addEventListener('dragstart', (e) => {
      const card = e.target.closest('.workbench-finding-card');
      if (card) {
        e.dataTransfer.setData('text/plain', card.dataset.findingId);
      }
    });
  }
}

function addFindingToChain(card) {
  const findingId = card.dataset.findingId;

  // Check if already in chain
  if (workbenchChainSteps.find(s => s.id === findingId)) {
    return;
  }

  workbenchChainSteps.push({
    id: findingId,
    type: card.dataset.findingType,
    severity: card.dataset.findingSeverity,
    message: card.dataset.findingMessage,
    category: card.dataset.findingCategory
  });

  saveFeatureState('workbench_chain', { steps: workbenchChainSteps });
  renderChainBuilder();
}

function renderChainBuilder() {
  const canvas = document.getElementById('chainBuilderCanvas');
  if (!canvas) return;

  if (workbenchChainSteps.length === 0) {
    canvas.innerHTML = `<div class="empty-state"><p>Drag findings here to build attack chain</p></div>`;
    return;
  }

  let html = '';
  workbenchChainSteps.forEach((step, idx) => {
    const sev = step.severity.toLowerCase();
    html += `<div class="chain-step" style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">`;
    html += `<span style="font-weight: bold; color: var(--text-secondary); font-size: 12px; min-width: 20px;">${idx + 1}.</span>`;
    html += `<div style="flex: 1; padding: 6px 8px; border-radius: 4px; border-left: 3px solid var(--${sev}-color, #888); background: var(--bg-secondary);">`;
    html += `<span class="security-badge ${sev}" style="font-size: 10px; padding: 1px 6px;">${step.severity}</span> `;
    html += `<span style="font-size: 12px;">${escapeHtml(step.type)}</span>`;
    html += `</div>`;
    html += `<button class="btn-icon workbench-remove-step" data-step-index="${idx}" title="Remove from chain" style="font-size: 14px; cursor: pointer;">&times;</button>`;
    html += `</div>`;

    // Draw connector arrow except for last step
    if (idx < workbenchChainSteps.length - 1) {
      html += `<div style="text-align: center; color: var(--text-secondary); font-size: 14px; margin: 2px 0;">&#8595;</div>`;
    }
  });

  canvas.innerHTML = html;

  // Remove step handlers
  canvas.querySelectorAll('.workbench-remove-step').forEach(btn => {
    btn.addEventListener('click', () => {
      const stepIdx = parseInt(btn.dataset.stepIndex);
      workbenchChainSteps.splice(stepIdx, 1);
      saveFeatureState('workbench_chain', { steps: workbenchChainSteps });
      renderChainBuilder();
    });
  });
}

async function analyzeWorkbenchChain() {
  const outputContainer = document.getElementById('workbenchPocOutput');
  if (!outputContainer) return;

  if (workbenchChainSteps.length === 0) {
    showMessage('Add findings to the chain builder first.', 'error');
    return;
  }

  const llmEnabled = currentSettings?.llm?.enabled && currentSettings.llm.provider !== 'none';
  if (!llmEnabled) {
    outputContainer.innerHTML = `
      <div class="empty-state">
        <p>LLM not configured.</p>
        <p class="empty-hint">Configure an LLM provider in Settings to generate AI-powered chain analysis and PoC narratives.</p>
      </div>
    `;
    return;
  }

  const analyzeBtn = document.getElementById('analyzeChainBtn');
  if (analyzeBtn) {
    analyzeBtn.disabled = true;
    analyzeBtn.textContent = 'Analyzing...';
  }

  outputContainer.innerHTML = '<div class="empty-state"><p>Generating exploitation narrative...</p></div>';

  try {
    // Build chain object for ChainPredictor
    const chain = {
      id: 'workbench-chain',
      name: 'Manual Chain (' + workbenchChainSteps.length + ' steps)',
      severity: workbenchChainSteps.reduce((highest, step) => {
        const order = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };
        return (order[step.severity] || 4) < (order[highest] || 4) ? step.severity : highest;
      }, 'INFO'),
      description: 'User-built attack chain combining ' + workbenchChainSteps.map(s => s.type).join(', '),
      findings: workbenchChainSteps.map(s => ({
        check: s.type,
        severity: s.severity,
        message: s.message
      })),
      attackFlow: workbenchChainSteps.map((s, i) =>
        'Step ' + (i + 1) + ': Exploit ' + s.type + ' (' + s.severity + ')'
      )
    };

    // Use ChainPredictor if available
    if (window.ChainPredictor) {
      const predictor = new ChainPredictor();
      const prediction = await predictor.predict(chain, {
        url: (await getTargetTab())?.url
      });

      let html = '';
      if (prediction.narrative) {
        html += `<div style="margin-bottom: 8px;"><strong>Exploitation Narrative:</strong></div>`;
        html += `<div class="ai-assessment-content">${formatAIAssessment(prediction.narrative)}</div>`;
      }
      if (prediction.likelihood) {
        const lClass = prediction.likelihood === 'HIGH' ? 'high' : (prediction.likelihood === 'MEDIUM' ? 'medium' : 'low');
        html += `<div style="margin-top: 8px;"><strong>Likelihood:</strong> <span class="security-badge ${lClass}">${prediction.likelihood}</span></div>`;
      }
      if (prediction.impact) {
        html += `<div style="margin-top: 8px;"><strong>Impact:</strong></div>`;
        html += `<div class="ai-assessment-content">${formatAIAssessment(prediction.impact)}</div>`;
      }
      if (prediction.remediation && prediction.remediation.length > 0) {
        html += `<div style="margin-top: 8px;"><strong>Remediation:</strong></div>`;
        html += `<ol style="margin: 4px 0 0 16px; font-size: 12px;">`;
        prediction.remediation.forEach(step => {
          html += `<li>${escapeHtml(step)}</li>`;
        });
        html += `</ol>`;
      }
      if (prediction.error) {
        html += `<div style="margin-top: 8px; color: var(--text-secondary); font-size: 11px;">(Fallback analysis: ${escapeHtml(prediction.error)})</div>`;
      }

      outputContainer.innerHTML = html || '<div class="empty-state"><p>No analysis generated.</p></div>';
    } else {
      outputContainer.innerHTML = `<div class="empty-state"><p>ChainPredictor not available.</p></div>`;
    }

    // Persist workbench state
    saveFeatureState('workbench_chain', {
      steps: workbenchChainSteps,
      analysisHtml: outputContainer.innerHTML
    });
  } catch (e) {
    outputContainer.innerHTML = `<div class="security-item high"><div class="security-item-message">Analysis failed: ${escapeHtml(e.message)}</div></div>`;
  } finally {
    if (analyzeBtn) {
      analyzeBtn.disabled = false;
      analyzeBtn.textContent = 'Analyze Chain';
    }
  }
}

function clearWorkbenchChain() {
  workbenchChainSteps = [];
  renderChainBuilder();

  const outputContainer = document.getElementById('workbenchPocOutput');
  if (outputContainer) {
    outputContainer.innerHTML = `<div class="empty-state"><p>Build a chain and click "Analyze Chain" to generate AI PoC output.</p></div>`;
  }
  saveFeatureState('workbench_chain', null);
}

// --- Feature 10: PoC Generator ---

let currentPocResult = null;

function setupPoCGenerator() {
  // Populate findings dropdown
  populatePoCFindingSelect();

  // Generate PoC button
  const generateBtn = document.getElementById('generatePocBtn');
  if (generateBtn) {
    generateBtn.addEventListener('click', generatePoC);
  }

  // Tier tab switching
  setupPoCTierTabs();

  // Restore persisted PoC result
  loadFeatureState('poc_result', (data) => {
    if (data && data.tiers) {
      currentPocResult = data;
      const activeTier = document.querySelector('.poc-tier-btn.active');
      const tier = activeTier ? activeTier.dataset.pocTier : 'basic';
      renderPoCTierOutput(tier);
    }
  });
}

function populatePoCFindingSelect() {
  const select = document.getElementById('pocFindingSelect');
  if (!select) return;

  // Clear existing options except the default
  select.innerHTML = '<option value="">-- Select a finding --</option>';

  // Add secret findings
  if (currentFindings && currentFindings.length > 0) {
    const secretGroup = document.createElement('optgroup');
    secretGroup.label = 'Secrets';
    currentFindings.forEach((f, idx) => {
      const opt = document.createElement('option');
      opt.value = 'secret:' + idx;
      const sev = (f.severity || f.risk || 'MEDIUM').toUpperCase();
      opt.textContent = '[' + sev + '] ' + (f.pattern_matched || f.key || 'Secret #' + (idx + 1));
      secretGroup.appendChild(opt);
    });
    if (secretGroup.children.length > 0) select.appendChild(secretGroup);
  }

  // Add security findings
  if (window.currentSecurityFindings) {
    const categories = ['vulnerabilities', 'headers', 'cookies', 'sensitiveFiles', 'session', 'oauth', 'graphql', 'crypto', 'cloudStorage', 'exfiltration', 'websocket'];
    categories.forEach(cat => {
      const items = window.currentSecurityFindings[cat] || [];
      const actionable = items.filter(f => {
        const sev = (f.severity || 'INFO').toUpperCase();
        return sev !== 'INFO' && sev !== 'NONE';
      });
      if (actionable.length === 0) return;

      const catLabel = cat.charAt(0).toUpperCase() + cat.slice(1).replace(/([A-Z])/g, ' $1');
      const group = document.createElement('optgroup');
      group.label = catLabel;
      actionable.forEach((f, idx) => {
        const origIdx = items.indexOf(f);
        const opt = document.createElement('option');
        opt.value = cat + ':' + origIdx;
        const sev = (f.severity || 'INFO').toUpperCase();
        opt.textContent = '[' + sev + '] ' + (f.check || f.name || cat + ' #' + (idx + 1));
        group.appendChild(opt);
      });
      select.appendChild(group);
    });
  }
}

function setupPoCTierTabs() {
  const tierBtns = document.querySelectorAll('.poc-tier-btn');
  tierBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tierBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const tier = btn.dataset.pocTier;
      renderPoCTierOutput(tier);
    });
  });
}

function renderPoCTierOutput(tier) {
  const container = document.getElementById('pocOutputContainer');
  if (!container || !currentPocResult) return;

  const tiers = currentPocResult.tiers || [];
  const tierData = tiers.find(t => t.level === tier);

  if (!tierData || (!tierData.payload && !tierData.explanation)) {
    container.innerHTML = `
      <div class="empty-state">
        <p>No ${tier} tier PoC available.</p>
        <p class="empty-hint">The LLM may not have generated content for this tier.</p>
      </div>
    `;
    return;
  }

  let html = '';

  html += `<div class="poc-tier-content" style="padding: 8px 0;">`;

  // Payload
  if (tierData.payload) {
    html += `<div style="margin-bottom: 12px;">`;
    html += `<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">`;
    html += `<strong>Payload:</strong>`;
    html += `<button class="btn btn-secondary btn-sm poc-copy-btn" data-copy-target="poc-payload-${tier}" style="font-size: 11px; padding: 2px 8px;">Copy</button>`;
    html += `</div>`;
    html += `<pre id="poc-payload-${tier}" style="background: var(--bg-secondary); padding: 10px; border-radius: 6px; overflow-x: auto; font-size: 12px; white-space: pre-wrap;"><code>${escapeHtml(tierData.payload)}</code></pre>`;
    html += `</div>`;
  }

  // Explanation
  if (tierData.explanation) {
    html += `<div style="margin-bottom: 12px;">`;
    html += `<strong>Explanation:</strong>`;
    html += `<div class="ai-assessment-content" style="margin-top: 4px;">${formatAIAssessment(tierData.explanation)}</div>`;
    html += `</div>`;
  }

  // Prerequisites
  if (tierData.prerequisites) {
    html += `<div style="margin-bottom: 12px;">`;
    html += `<strong>Prerequisites:</strong>`;
    html += `<div style="margin-top: 4px; font-size: 12px; color: var(--text-secondary);">${escapeHtml(tierData.prerequisites)}</div>`;
    html += `</div>`;
  }

  // Risk
  if (tierData.risk) {
    html += `<div style="margin-bottom: 8px;">`;
    html += `<strong>Risk Assessment:</strong>`;
    html += `<div style="margin-top: 4px; font-size: 12px;">${escapeHtml(tierData.risk)}</div>`;
    html += `</div>`;
  }

  html += `</div>`;

  // Model info
  if (currentPocResult.model) {
    html += `<div style="font-size: 11px; color: var(--text-secondary); margin-top: 8px; text-align: right;">Model: ${escapeHtml(currentPocResult.model)} | ${new Date(currentPocResult.generatedAt).toLocaleString()}</div>`;
  }

  container.innerHTML = html;

  // Copy button handlers
  container.querySelectorAll('.poc-copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.dataset.copyTarget;
      const targetEl = document.getElementById(targetId);
      if (targetEl) {
        const text = targetEl.textContent;
        navigator.clipboard.writeText(text).then(() => {
          btn.textContent = 'Copied';
          setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
        }).catch(() => {
          showMessage('Failed to copy to clipboard', 'error');
        });
      }
    });
  });
}

async function generatePoC() {
  const select = document.getElementById('pocFindingSelect');
  const container = document.getElementById('pocOutputContainer');
  const generateBtn = document.getElementById('generatePocBtn');

  if (!select || !container) return;

  const selectedValue = select.value;
  if (!selectedValue) {
    showMessage('Select a finding first.', 'error');
    return;
  }

  const llmEnabled = currentSettings?.llm?.enabled && currentSettings.llm.provider !== 'none';
  if (!llmEnabled) {
    showMessage('Configure an LLM provider in Settings to generate PoCs.', 'error');
    return;
  }

  // Parse selection
  const [category, indexStr] = selectedValue.split(':');
  const index = parseInt(indexStr);

  // Get the finding object
  let finding = null;
  if (category === 'secret' && currentFindings && currentFindings[index]) {
    const f = currentFindings[index];
    finding = {
      check: f.pattern_matched || 'Secret',
      type: f.pattern_matched || 'Secret',
      severity: f.severity || f.risk || 'MEDIUM',
      message: f.message || '',
      matchedText: f.full_key || f.key || '',
      uri: f.source_url || f.url || '',
      codeContext: f.context || ''
    };
  } else if (window.currentSecurityFindings && window.currentSecurityFindings[category]) {
    finding = window.currentSecurityFindings[category][index];
  }

  if (!finding) {
    showMessage('Finding not found. Try running "Unfold" again.', 'error');
    return;
  }

  if (generateBtn) {
    generateBtn.disabled = true;
    generateBtn.textContent = 'Generating...';
  }
  container.innerHTML = '<div class="empty-state"><p>Generating tiered PoC exploits...</p></div>';

  try {
    // Gather context
    const tab = await getTargetTab();
    const context = {
      url: tab.url,
      csp: null,
      technologies: [],
      dom: null
    };

    // Get CSP from security results
    if (window.currentSecurityFindings?.headers) {
      const cspFinding = window.currentSecurityFindings.headers.find(h =>
        h.check && h.check.toLowerCase().includes('content-security-policy')
      );
      if (cspFinding) {
        context.csp = cspFinding.currentValue || cspFinding.value || null;
      }
    }

    // Get technologies from security results
    if (securityResults?.technologies) {
      const techs = securityResults.technologies;
      const flatTechs = [];
      const categories = ['frameworks', 'libraries', 'cdns', 'platforms', 'analytics'];
      categories.forEach(cat => {
        if (Array.isArray(techs[cat])) {
          techs[cat].forEach(t => flatTechs.push(t));
        }
      });
      context.technologies = flatTechs;
    }

    // Use PoCGenerator
    if (window.PoCGenerator) {
      const generator = new PoCGenerator();
      currentPocResult = await generator.generate(finding, context);

      // Persist PoC result
      saveFeatureState('poc_result', currentPocResult);

      // Render the active tier
      const activeTier = document.querySelector('.poc-tier-btn.active');
      const tier = activeTier ? activeTier.dataset.pocTier : 'basic';
      renderPoCTierOutput(tier);
    } else {
      container.innerHTML = `<div class="empty-state"><p>PoCGenerator not available.</p></div>`;
    }
  } catch (e) {
    container.innerHTML = `<div class="security-item high"><div class="security-item-message">PoC generation failed: ${escapeHtml(e.message)}</div></div>`;
    currentPocResult = null;
  } finally {
    if (generateBtn) {
      generateBtn.disabled = false;
      generateBtn.textContent = 'Generate PoC';
    }
  }
}

// --- Feature 3: AI Rule Generator Integration ---

function setupAIRuleGenerator() {
  // Add an "AI Generate" button to the templates header if it does not exist
  const templatesActions = document.querySelector('#templates-tab .templates-actions');
  if (templatesActions && !document.getElementById('aiGenerateRuleBtn')) {
    const btn = document.createElement('button');
    btn.id = 'aiGenerateRuleBtn';
    btn.className = 'btn btn-secondary btn-sm';
    btn.textContent = 'AI Generate';
    btn.title = 'Generate a detection template using AI from a CVE, PoC, or description';
    templatesActions.appendChild(btn);

    btn.addEventListener('click', openAIRuleGeneratorModal);
  }
}

function openAIRuleGeneratorModal() {
  const llmEnabled = currentSettings?.llm?.enabled && currentSettings.llm.provider !== 'none';
  if (!llmEnabled) {
    showMessage('Configure an LLM provider in Settings to use AI Rule Generator.', 'error');
    return;
  }

  // Reuse the template editor modal to show the AI generator form
  const modal = document.getElementById('templateEditorModal');
  const title = document.getElementById('templateEditorTitle');
  const yamlEditor = document.getElementById('templateYamlEditor');
  const parseError = document.getElementById('templateParseError');
  const saveBtn = document.getElementById('saveTemplateBtn');
  const dryRunBtn = document.getElementById('dryRunTemplateBtn');

  if (!modal || !yamlEditor) return;

  if (title) title.textContent = 'AI Rule Generator';
  if (parseError) { parseError.style.display = 'none'; parseError.textContent = ''; }

  // Replace the YAML editor with AI generation inputs temporarily
  const originalPlaceholder = yamlEditor.placeholder;
  yamlEditor.value = '';
  yamlEditor.placeholder = 'Enter a CVE ID (e.g., CVE-2023-12345), PoC code, or vulnerability description here.\n\nThe AI will generate a YAML detection template from your input.\n\nClick "Generate Rule" below to start.';
  yamlEditor.rows = 8;

  // Temporarily add input type selector and generate button above actions
  const actionsContainer = modal.querySelector('.modal-actions');
  let aiControls = document.getElementById('aiRuleControls');
  if (!aiControls) {
    aiControls = document.createElement('div');
    aiControls.id = 'aiRuleControls';
    aiControls.style.cssText = 'margin-bottom: 12px; display: flex; gap: 8px; align-items: center;';
    aiControls.innerHTML = `
      <label style="font-size: 12px; white-space: nowrap;">Input Type:</label>
      <select id="aiRuleInputType" class="select-field" style="width: auto; min-width: 120px;">
        <option value="description">Description</option>
        <option value="cve">CVE ID</option>
        <option value="poc">PoC Code</option>
      </select>
      <button id="aiRuleGenerateBtn" class="btn btn-primary btn-sm">Generate Rule</button>
      <span id="aiRuleStatus" style="font-size: 11px; color: var(--text-secondary);"></span>
    `;
    actionsContainer.parentNode.insertBefore(aiControls, actionsContainer);
  }
  aiControls.style.display = 'flex';

  // Set up the Generate Rule button handler
  const genBtn = document.getElementById('aiRuleGenerateBtn');
  if (genBtn) {
    // Remove old listener by cloning
    const newGenBtn = genBtn.cloneNode(true);
    genBtn.parentNode.replaceChild(newGenBtn, genBtn);

    newGenBtn.addEventListener('click', async () => {
      const input = yamlEditor.value.trim();
      const inputType = document.getElementById('aiRuleInputType').value;
      const status = document.getElementById('aiRuleStatus');

      if (!input) {
        showMessage('Enter a CVE, PoC, or description to generate from.', 'error');
        return;
      }

      newGenBtn.disabled = true;
      newGenBtn.textContent = 'Generating...';
      if (status) status.textContent = 'Sending to LLM...';
      if (parseError) { parseError.style.display = 'none'; }

      try {
        if (!window.RuleGenerator) {
          throw new Error('RuleGenerator class not loaded');
        }

        const ruleGen = new RuleGenerator();
        const result = await ruleGen.generateRule(input, inputType);

        // Put the generated YAML into the editor
        yamlEditor.value = result.yaml || '';
        yamlEditor.placeholder = originalPlaceholder;
        yamlEditor.rows = 15;

        // Show validation results
        if (result.validation) {
          if (!result.validation.valid) {
            if (parseError) {
              parseError.style.display = 'block';
              parseError.textContent = 'Validation warnings: ' + result.validation.errors.join('; ');
            }
          } else if (result.validation.warnings && result.validation.warnings.length > 0) {
            if (parseError) {
              parseError.style.display = 'block';
              parseError.className = 'message message-info';
              parseError.textContent = 'Warnings: ' + result.validation.warnings.join('; ');
            }
          }
        }

        if (status) status.textContent = 'Rule generated. Review and save.';

        // Hide AI controls, show normal save/dry-run flow
        aiControls.style.display = 'none';
      } catch (e) {
        if (parseError) {
          parseError.style.display = 'block';
          parseError.className = 'message message-error';
          parseError.textContent = 'Generation failed: ' + e.message;
        }
        if (status) status.textContent = 'Failed';
      } finally {
        newGenBtn.disabled = false;
        newGenBtn.textContent = 'Generate Rule';
      }
    });
  }

  // Show modal
  modal.style.display = 'flex';

  // Set up close handler to clean up AI controls
  const closeHandler = () => {
    if (aiControls) aiControls.style.display = 'none';
    yamlEditor.placeholder = originalPlaceholder;
    yamlEditor.rows = 15;
    if (title) title.textContent = 'New Detection Template';
    if (parseError) { parseError.style.display = 'none'; parseError.className = 'message message-error'; }
  };

  const closeBtn = document.getElementById('templateEditorCloseBtn');
  const cancelBtn = document.getElementById('cancelTemplateBtn');
  if (closeBtn) closeBtn.addEventListener('click', closeHandler, { once: true });
  if (cancelBtn) cancelBtn.addEventListener('click', closeHandler, { once: true });
}

// --- Detection Templates Tab ---

let currentDetectionTemplates = [];
let editingDetectionTemplate = null;

async function loadDetectionTemplates() {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ action: 'getTemplates' }, (response) => {
      currentDetectionTemplates = (response && response.templates) || [];
      // Initialize builtins if none exist
      if (!currentDetectionTemplates.some(t => t.builtin)) {
        const builtins = (typeof TemplateEngine !== 'undefined' && TemplateEngine.BUILTIN_TEMPLATES)
          ? TemplateEngine.BUILTIN_TEMPLATES
          : [];
        if (builtins.length > 0) {
          chrome.runtime.sendMessage({ action: 'initBuiltinTemplates', builtins }, (resp) => {
            if (resp && resp.initialized) {
              currentDetectionTemplates = [...builtins, ...currentDetectionTemplates];
            }
            displayDetectionTemplates();
            resolve();
          });
          return;
        }
      }
      displayDetectionTemplates();
      resolve();
    });
  });
}

function displayDetectionTemplates() {
  const container = document.getElementById('templatesList');
  if (!container) return;

  updateDetectionTemplateStats();

  if (currentDetectionTemplates.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <p>No detection templates</p>
        <p class="empty-hint">Templates use YAML-inspired rules to detect security issues. Click "New Template" to create one.</p>
      </div>
    `;
    return;
  }

  let html = '';
  currentDetectionTemplates.forEach(template => {
    const info = template.info || {};
    const name = info.name || template.id || 'Unnamed';
    const severity = (info.severity || 'MEDIUM').toUpperCase();
    const severityClass = severity.toLowerCase();
    const tags = info.tags || [];
    const isEnabled = template.enabled !== false;
    const isBuiltin = !!template.builtin;
    const disabledClass = isEnabled ? '' : ' disabled';

    html += `
      <div class="plugin-card${disabledClass}" data-template-id="${escapeHtml(template.id)}">
        <div class="plugin-card-header">
          <div class="plugin-card-info">
            <div class="plugin-card-name">${escapeHtml(name)}</div>
            <div class="plugin-card-meta">
              <span class="security-badge badge-compact ${severityClass}">${severity}</span>
              ${isBuiltin ? '<span class="template-badge">Built-in</span>' : '<span class="template-badge" style="background: var(--bg-tertiary); color: var(--text-secondary);">Custom</span>'}
              ${info.cwe ? `<span style="font-size: 10px; color: var(--text-secondary);">${escapeHtml(info.cwe)}</span>` : ''}
            </div>
            ${tags.length > 0 ? `<div class="plugin-card-meta" style="margin-top: 4px;">${tags.map(t => `<span style="font-size: 10px; padding: 1px 6px; background: var(--bg-tertiary); border-radius: 3px; color: var(--text-secondary);">${escapeHtml(t)}</span>`).join('')}</div>` : ''}
          </div>
          <div class="plugin-card-actions">
            <label class="plugin-toggle" title="${isEnabled ? 'Disable' : 'Enable'} template">
              <input type="checkbox" ${isEnabled ? 'checked' : ''} data-template-toggle="${escapeHtml(template.id)}">
              <span class="plugin-toggle-slider"></span>
            </label>
            <button class="btn-icon" data-template-edit="${escapeHtml(template.id)}" title="Edit template">Edit</button>
            ${!isBuiltin ? `<button class="plugin-remove-btn" data-template-remove="${escapeHtml(template.id)}" title="Delete template">Delete</button>` : ''}
          </div>
        </div>
      </div>
    `;
  });

  container.innerHTML = html;

  // Wire up toggle handlers
  container.querySelectorAll('[data-template-toggle]').forEach(toggle => {
    toggle.addEventListener('change', (e) => {
      const templateId = e.target.dataset.templateToggle;
      toggleTemplate(templateId, e.target.checked);
    });
  });

  // Wire up edit handlers
  container.querySelectorAll('[data-template-edit]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const templateId = e.currentTarget.dataset.templateEdit;
      openTemplateEditor(templateId);
    });
  });

  // Wire up delete handlers
  container.querySelectorAll('[data-template-remove]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const templateId = e.currentTarget.dataset.templateRemove;
      deleteTemplate(templateId);
    });
  });
}

function updateDetectionTemplateStats() {
  const totalEl = document.getElementById('totalTemplates');
  const enabledEl = document.getElementById('enabledTemplates');
  const builtinEl = document.getElementById('builtinTemplates');

  if (totalEl) totalEl.textContent = currentDetectionTemplates.length;
  if (enabledEl) enabledEl.textContent = currentDetectionTemplates.filter(t => t.enabled !== false).length;
  if (builtinEl) builtinEl.textContent = currentDetectionTemplates.filter(t => t.builtin).length;
}

function toggleTemplate(templateId, enabled) {
  const template = currentDetectionTemplates.find(t => t.id === templateId);
  if (!template) return;

  template.enabled = enabled;

  chrome.runtime.sendMessage({ action: 'saveTemplate', template }, (response) => {
    if (response && response.success) {
      updateDetectionTemplateStats();
      // Update card visual state
      const card = document.querySelector(`.plugin-card[data-template-id="${templateId}"]`);
      if (card) {
        if (enabled) {
          card.classList.remove('disabled');
        } else {
          card.classList.add('disabled');
        }
      }
    }
  });
}

function deleteTemplate(templateId) {
  const template = currentDetectionTemplates.find(t => t.id === templateId);
  if (!template) return;

  if (template.builtin) {
    showMessage('Cannot delete built-in templates', 'error');
    return;
  }

  const templateName = template.info?.name || template.id;
  if (!confirm(`Delete template "${templateName}"? This cannot be undone.`)) return;

  chrome.runtime.sendMessage({ action: 'removeTemplate', templateId }, (response) => {
    if (response && response.success) {
      currentDetectionTemplates = currentDetectionTemplates.filter(t => t.id !== templateId);
      displayDetectionTemplates();
      showMessage('Template deleted', 'success');
    } else {
      showMessage('Failed to delete template', 'error');
    }
  });
}

function templateToYaml(template) {
  if (typeof jsyaml !== 'undefined') {
    const obj = {
      id: template.id,
      info: template.info || {},
      matchers: template.matchers || [],
    };
    if (template.extractors && template.extractors.length > 0) {
      obj.extractors = template.extractors;
    }
    if (template.condition) {
      obj.condition = template.condition;
    }
    try {
      return jsyaml.dump(obj, { lineWidth: -1 });
    } catch (e) {
      // Fallback to manual construction
    }
  }

  // Manual YAML construction fallback
  const info = template.info || {};
  let yaml = `id: ${template.id}\n`;
  yaml += `info:\n`;
  yaml += `  name: ${info.name || template.id}\n`;
  yaml += `  severity: ${info.severity || 'MEDIUM'}\n`;
  if (info.cwe) yaml += `  cwe: ${info.cwe}\n`;
  if (info.tags && info.tags.length > 0) {
    yaml += `  tags: [${info.tags.join(', ')}]\n`;
  }
  if (template.matchers && template.matchers.length > 0) {
    yaml += `matchers:\n`;
    for (const matcher of template.matchers) {
      yaml += `  - type: ${matcher.type || 'regex'}\n`;
      yaml += `    target: ${matcher.target || 'body'}\n`;
      if (matcher.patterns && matcher.patterns.length > 0) {
        yaml += `    patterns:\n`;
        for (const p of matcher.patterns) {
          yaml += `      - '${p}'\n`;
        }
      }
      if (matcher.condition) {
        yaml += `    condition: ${matcher.condition}\n`;
      }
    }
  }
  if (template.extractors && template.extractors.length > 0) {
    yaml += `extractors:\n`;
    for (const extractor of template.extractors) {
      yaml += `  - type: ${extractor.type || 'regex'}\n`;
      if (extractor.group !== undefined) yaml += `    group: ${extractor.group}\n`;
      if (extractor.patterns && extractor.patterns.length > 0) {
        yaml += `    patterns:\n`;
        for (const p of extractor.patterns) {
          yaml += `      - '${p}'\n`;
        }
      }
    }
  }
  return yaml;
}

function parseTemplateYaml(yamlText) {
  if (typeof jsyaml !== 'undefined') {
    return jsyaml.load(yamlText);
  }
  // Fallback to RuleGenerator's parser if available
  if (typeof RuleGenerator !== 'undefined') {
    const rg = new RuleGenerator();
    if (rg.parseYaml) return rg.parseYaml(yamlText);
  }
  throw new Error('No YAML parser available. Check that js-yaml is loaded.');
}

function openTemplateEditor(templateId = null) {
  const modal = document.getElementById('templateEditorModal');
  const title = document.getElementById('templateEditorTitle');
  const yamlEditor = document.getElementById('templateYamlEditor');
  const parseError = document.getElementById('templateParseError');
  const enabledCheckbox = document.getElementById('templateEnabled');
  const deleteBtn = document.getElementById('deleteTemplateBtn');
  const dryRunResults = document.getElementById('templateDryRunResults');

  if (!modal || !yamlEditor) return;

  // Reset
  if (parseError) { parseError.style.display = 'none'; parseError.textContent = ''; }
  if (dryRunResults) { dryRunResults.style.display = 'none'; dryRunResults.innerHTML = ''; }
  if (enabledCheckbox) enabledCheckbox.checked = true;

  if (templateId) {
    const template = currentDetectionTemplates.find(t => t.id === templateId);
    if (!template) return;

    editingDetectionTemplate = template;
    if (title) title.textContent = 'Edit Detection Template';
    yamlEditor.value = templateToYaml(template);
    if (enabledCheckbox) enabledCheckbox.checked = template.enabled !== false;
    if (deleteBtn) deleteBtn.style.display = template.builtin ? 'none' : 'inline-block';
  } else {
    editingDetectionTemplate = null;
    if (title) title.textContent = 'New Detection Template';
    yamlEditor.value = '';
    if (deleteBtn) deleteBtn.style.display = 'none';
  }

  modal.style.display = 'flex';
}

function closeTemplateEditor() {
  const modal = document.getElementById('templateEditorModal');
  if (modal) modal.style.display = 'none';
  editingDetectionTemplate = null;
}

function saveTemplate() {
  const yamlEditor = document.getElementById('templateYamlEditor');
  const parseError = document.getElementById('templateParseError');
  const enabledCheckbox = document.getElementById('templateEnabled');
  const yamlText = yamlEditor ? yamlEditor.value.trim() : '';

  if (!yamlText) {
    showMessage('Template YAML is required', 'error');
    return;
  }

  let parsed;
  try {
    parsed = parseTemplateYaml(yamlText);
  } catch (e) {
    if (parseError) {
      parseError.style.display = 'block';
      parseError.textContent = 'YAML parse error: ' + e.message;
    }
    return;
  }

  if (!parsed || !parsed.id) {
    if (parseError) {
      parseError.style.display = 'block';
      parseError.textContent = 'Template must have an "id" field';
    }
    return;
  }

  if (!parsed.info || !parsed.info.name) {
    if (parseError) {
      parseError.style.display = 'block';
      parseError.textContent = 'Template must have info.name field';
    }
    return;
  }

  if (!parsed.matchers || !Array.isArray(parsed.matchers) || parsed.matchers.length === 0) {
    if (parseError) {
      parseError.style.display = 'block';
      parseError.textContent = 'Template must have at least one matcher';
    }
    return;
  }

  const template = {
    id: parsed.id,
    info: parsed.info,
    matchers: parsed.matchers,
    extractors: parsed.extractors || [],
    condition: parsed.condition || 'or',
    enabled: enabledCheckbox ? enabledCheckbox.checked : true,
    builtin: false
  };

  if (editingDetectionTemplate) {
    template.builtin = editingDetectionTemplate.builtin || false;
    // Keep same id if editing
    if (editingDetectionTemplate.id !== parsed.id && editingDetectionTemplate.builtin) {
      template.id = editingDetectionTemplate.id;
    }
  }

  chrome.runtime.sendMessage({ action: 'saveTemplate', template }, (response) => {
    if (response && response.success) {
      // Update local state
      const existingIndex = currentDetectionTemplates.findIndex(t => t.id === template.id);
      if (existingIndex >= 0) {
        currentDetectionTemplates[existingIndex] = template;
      } else {
        currentDetectionTemplates.push(template);
      }
      displayDetectionTemplates();
      closeTemplateEditor();
      showMessage('Template saved successfully', 'success');
    } else {
      showMessage('Failed to save template', 'error');
    }
  });
}

function dryRunTemplate(templateId) {
  const template = templateId
    ? currentDetectionTemplates.find(t => t.id === templateId)
    : null;

  // If called from the editor modal, parse the current YAML
  const yamlEditor = document.getElementById('templateYamlEditor');
  const dryRunResults = document.getElementById('templateDryRunResults');
  const parseError = document.getElementById('templateParseError');

  let templateToRun = template;

  if (yamlEditor && yamlEditor.value.trim()) {
    try {
      const parsed = parseTemplateYaml(yamlEditor.value.trim());
      if (parsed && parsed.id) {
        templateToRun = parsed;
      }
    } catch (e) {
      if (parseError) {
        parseError.style.display = 'block';
        parseError.textContent = 'YAML parse error: ' + e.message;
      }
      return;
    }
  }

  if (!templateToRun) {
    showMessage('No template to test', 'error');
    return;
  }

  if (parseError) parseError.style.display = 'none';

  // Send to content script via background for dry run
  getTargetTabCb((tabs) => {
    if (!tabs[0]) {
      if (dryRunResults) {
        dryRunResults.style.display = 'block';
        dryRunResults.innerHTML = '<div class="message message-error">No active tab to test against</div>';
      }
      return;
    }

    chrome.scripting.executeScript({
      target: { tabId: tabs[0].id },
      func: (tmpl) => {
        if (typeof TemplateEngine === 'undefined') return { error: 'TemplateEngine not loaded on this page' };
        const engine = new TemplateEngine();
        try {
          const findings = engine.runTemplate(tmpl);
          return { findings, count: findings.length };
        } catch (e) {
          return { error: e.message };
        }
      },
      args: [templateToRun]
    }, (results) => {
      if (chrome.runtime.lastError) {
        if (dryRunResults) {
          dryRunResults.style.display = 'block';
          dryRunResults.innerHTML = `<div class="message message-error">Dry run failed: ${escapeHtml(chrome.runtime.lastError.message)}</div>`;
        }
        return;
      }

      const result = results && results[0] && results[0].result;
      if (!result) {
        if (dryRunResults) {
          dryRunResults.style.display = 'block';
          dryRunResults.innerHTML = '<div class="message message-error">No result from dry run</div>';
        }
        return;
      }

      if (result.error) {
        if (dryRunResults) {
          dryRunResults.style.display = 'block';
          dryRunResults.innerHTML = `<div class="message message-error">Error: ${escapeHtml(result.error)}</div>`;
        }
        return;
      }

      if (dryRunResults) {
        dryRunResults.style.display = 'block';
        if (result.count === 0) {
          dryRunResults.innerHTML = '<div class="message message-info">No matches found on this page</div>';
        } else {
          let findingsHtml = `<div class="message message-success">Found ${result.count} match(es)</div>`;
          result.findings.forEach(f => {
            findingsHtml += `
              <div style="margin-top: 8px; padding: 8px; background: var(--bg-tertiary); border-radius: 4px; font-size: 12px;">
                <div><strong>${escapeHtml(f.name)}</strong> <span class="security-badge badge-compact ${(f.severity || '').toLowerCase()}">${escapeHtml(f.severity || 'MEDIUM')}</span></div>
                <div style="margin-top: 4px; color: var(--text-secondary);">Target: ${escapeHtml(f.target || 'body')}</div>
                ${f.matches && f.matches.length > 0 ? `<div style="margin-top: 4px;"><code style="font-size: 11px; word-break: break-all;">${f.matches.slice(0, 5).map(m => escapeHtml(String(m))).join(', ')}</code></div>` : ''}
              </div>
            `;
          });
          dryRunResults.innerHTML = findingsHtml;
        }
      }
    });
  });
}

function exportTemplates() {
  if (currentDetectionTemplates.length === 0) {
    showMessage('No templates to export', 'error');
    return;
  }

  const data = JSON.stringify(currentDetectionTemplates, null, 2);
  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'origami-templates-' + new Date().toISOString().slice(0, 10) + '.json';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showMessage('Templates exported', 'success');
}

function importTemplates() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.json';
  input.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (evt) => {
      try {
        const imported = JSON.parse(evt.target.result);
        if (!Array.isArray(imported)) {
          showMessage('Invalid file: expected a JSON array of templates', 'error');
          return;
        }

        // Validate each template has at minimum an id
        const valid = imported.filter(t => t && t.id);
        if (valid.length === 0) {
          showMessage('No valid templates found in file', 'error');
          return;
        }

        let addedCount = 0;
        let updatedCount = 0;

        valid.forEach(t => {
          t.builtin = false; // Imported templates are never builtin
          const existingIndex = currentDetectionTemplates.findIndex(e => e.id === t.id);
          if (existingIndex >= 0) {
            currentDetectionTemplates[existingIndex] = t;
            updatedCount++;
          } else {
            currentDetectionTemplates.push(t);
            addedCount++;
          }
        });

        // Save all templates
        chrome.storage.local.set({ origami_templates: currentDetectionTemplates }, () => {
          displayDetectionTemplates();
          showMessage(`Imported ${addedCount} new, ${updatedCount} updated template(s)`, 'success');
        });
      } catch (err) {
        showMessage('Invalid JSON file: ' + err.message, 'error');
      }
    };
    reader.readAsText(file);
  });
  input.click();
}

function initializeTemplatesTab() {
  // New Template button
  const addBtn = document.getElementById('addTemplateBtn');
  if (addBtn) {
    addBtn.addEventListener('click', () => openTemplateEditor());
  }

  // Import/Export buttons
  const importBtn = document.getElementById('importTemplatesBtn');
  if (importBtn) {
    importBtn.addEventListener('click', importTemplates);
  }

  const exportBtn = document.getElementById('exportTemplatesBtn');
  if (exportBtn) {
    exportBtn.addEventListener('click', exportTemplates);
  }

  // Template editor modal buttons
  const saveBtn = document.getElementById('saveTemplateBtn');
  if (saveBtn) {
    saveBtn.addEventListener('click', saveTemplate);
  }

  const dryRunBtn = document.getElementById('dryRunTemplateBtn');
  if (dryRunBtn) {
    dryRunBtn.addEventListener('click', () => dryRunTemplate());
  }

  const cancelBtn = document.getElementById('cancelTemplateBtn');
  if (cancelBtn) {
    cancelBtn.addEventListener('click', closeTemplateEditor);
  }

  const closeBtn = document.getElementById('templateEditorCloseBtn');
  if (closeBtn) {
    closeBtn.addEventListener('click', closeTemplateEditor);
  }

  const deleteBtn = document.getElementById('deleteTemplateBtn');
  if (deleteBtn) {
    deleteBtn.addEventListener('click', () => {
      if (!editingDetectionTemplate) return;
      deleteTemplate(editingDetectionTemplate.id);
      closeTemplateEditor();
    });
  }
}

// Initialize templates tab when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeTemplatesTab);
} else {
  initializeTemplatesTab();
}

// --- Crypto Audit Results ---

function loadCryptoResults(tabId) {
  chrome.runtime.sendMessage({ action: 'getCryptoResults', tabId: tabId }, function(response) {
    if (chrome.runtime.lastError) {
      console.error('Origami: Failed to load crypto results:', chrome.runtime.lastError.message);
      return;
    }
    if (response && response.crypto) {
      displayCryptoResults(response.crypto);
    }
  });
}

function displayCryptoResults(data) {
  const container = document.getElementById('crypto-results');
  if (!container) return;

  if (!data || (!data.libraries?.length && !data.issues?.length)) {
    container.innerHTML = '<p class="no-results">Run a scan to detect client-side encryption weaknesses.</p>';
    return;
  }

  let html = '<div class="security-analysis-results">';

  if (data.libraries && data.libraries.length > 0) {
    html += '<div class="security-section" style="margin-bottom: 12px;">';
    html += '<div class="security-section-header"><div class="security-section-title">Detected Libraries (' + data.libraries.length + ')</div></div>';
    html += '<div style="padding: 8px 0;">';
    data.libraries.forEach(function(lib) {
      html += '<span class="crypto-library-badge">' + escapeHtml(lib.name || lib) + (lib.version ? ' ' + escapeHtml(lib.version) : '') + '</span>';
    });
    html += '</div></div>';
  }

  const issues = data.issues || [];
  if (issues.length > 0) {
    var getEffSev = function(i) {
      return (i.severityOverride?.overriddenSeverity || i.aiAssessment?.suggestedSeverity || i.severity || 'INFO').toUpperCase();
    };
    const sortedIssues = [...issues].sort(function(a, b) {
      const order = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4, 'NONE': 5 };
      return (order[getEffSev(a)] || 4) - (order[getEffSev(b)] || 4);
    });

    var actionableIssues = sortedIssues.filter(function(i) { return getEffSev(i) !== 'NONE'; });
    updateSubTabBadge('crypto', actionableIssues.length > 0 ? getEffSev(actionableIssues[0]) : null, actionableIssues.length);

    html += '<div class="security-items">';
    sortedIssues.forEach(function(issue, index) {
      var effSeverity = getEffSev(issue).toLowerCase();
      var badgeText = effSeverity === 'none' ? 'FALSE POSITIVE' : effSeverity.toUpperCase();
      html += '<div class="security-item ' + effSeverity + '">';
      html += '<div class="security-item-header">';
      html += '<div class="security-item-title">' + escapeHtml(issue.type || issue.check || 'Crypto Issue') + '</div>';
      html += '<span class="security-badge ' + effSeverity + '">' + badgeText + '</span>';
      html += '</div>';
      html += '<div class="security-item-body">';
      html += '<div class="security-detail"><strong>Issue:</strong> ' + escapeHtml(issue.message || issue.description || '') + '</div>';
      if (issue.evidence) {
        html += '<div class="security-detail"><strong>Evidence:</strong> <code>' + escapeHtml(issue.evidence) + '</code></div>';
      }
      if (issue.recommendation) {
        html += '<div class="security-detail"><strong>Recommendation:</strong> ' + escapeHtml(issue.recommendation) + '</div>';
      }
      html += '<div style="margin-top: 6px;">';
      html += '<button class="btn btn-primary btn-sm ai-assess-security-btn' + (issue.aiAssessment ? ' has-assessment' : '') + '"'
        + ' data-finding-category="crypto" data-finding-index="' + index + '"'
        + ' style="padding: 2px 8px; font-size: 11px;">' + origamiIcon('sparkles') + ' AI Analyze</button>';
      html += '</div>';
      html += '<div id="ai-assessment-security-crypto-' + index + '" class="ai-assessment-container">';
      if (issue.aiAssessment) {
        html += '<div class="ai-assessment-result"><div class="ai-assessment-content">' + formatLLMResponse(issue.aiAssessment.analysis || '') + '</div></div>';
      }
      html += '</div>';
      html += '</div></div>';
    });
    html += '</div>';
  } else {
    updateSubTabBadge('crypto', null, 0);
  }

  html += '</div>';
  container.innerHTML = html;

  if (!window.currentSecurityFindings) window.currentSecurityFindings = {};
  window.currentSecurityFindings.crypto = issues;

  const cryptoAiBtn = document.getElementById('aiAnalyzeCryptoBtn');
  if (cryptoAiBtn) cryptoAiBtn.style.display = issues.length > 0 ? '' : 'none';

  container.querySelectorAll('.ai-assess-security-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      const cat = btn.dataset.findingCategory;
      const idx = parseInt(btn.dataset.findingIndex);
      performInlineAIAssessment(idx, 'security', false, cat);
    });
  });
}

// --- Cloud Storage Results ---

function loadCloudStorageResults(tabId) {
  chrome.runtime.sendMessage({ action: 'getCloudStorageResults', tabId: tabId }, function(response) {
    if (chrome.runtime.lastError) {
      console.error('Origami: Failed to load cloud storage results:', chrome.runtime.lastError.message);
      return;
    }
    if (response && response.cloudStorage) {
      displayCloudStorageResults(response.cloudStorage);
    }
  });
}

function displayCloudStorageResults(data) {
  const container = document.getElementById('cloud-storage-results');
  if (!container) return;

  if (!data || (!data.buckets?.length && !data.issues?.length)) {
    container.innerHTML = '<p class="no-results">Run a scan to detect cloud storage exposure.</p>';
    return;
  }

  let html = '<div class="security-analysis-results">';

  if (data.buckets && data.buckets.length > 0) {
    html += '<div class="security-section" style="margin-bottom: 12px;">';
    html += '<div class="security-section-header"><div class="security-section-title">Storage Buckets (' + data.buckets.length + ')</div></div>';
    html += '<div style="padding: 8px 0;">';
    data.buckets.forEach(function(bucket) {
      const provider = (bucket.provider || 'other').toLowerCase();
      const providerClass = ['aws', 'azure', 'gcp', 'digitalocean'].includes(provider) ? provider : 'other';
      const accessibility = (bucket.accessibility || 'unknown').toLowerCase();
      html += '<div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">';
      html += '<span class="cloud-provider-badge ' + escapeHtml(providerClass) + '">' + escapeHtml((bucket.provider || 'Unknown').toUpperCase()) + '</span>';
      html += '<span style="color: var(--text-primary); font-size: 12px;">' + escapeHtml(bucket.bucketName || bucket.url || '') + '</span>';
      html += '<span class="bucket-accessibility ' + escapeHtml(accessibility) + '">' + escapeHtml(accessibility) + '</span>';
      html += '</div>';
    });
    html += '</div></div>';
  }

  const issues = data.issues || [];
  if (issues.length > 0) {
    var getEffSev = function(i) {
      return (i.severityOverride?.overriddenSeverity || i.aiAssessment?.suggestedSeverity || i.severity || 'INFO').toUpperCase();
    };
    const sortedIssues = [...issues].sort(function(a, b) {
      const order = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4, 'NONE': 5 };
      return (order[getEffSev(a)] || 4) - (order[getEffSev(b)] || 4);
    });

    var actionableIssues = sortedIssues.filter(function(i) { return getEffSev(i) !== 'NONE'; });
    updateSubTabBadge('cloud-storage', actionableIssues.length > 0 ? getEffSev(actionableIssues[0]) : null, actionableIssues.length);

    html += '<div class="security-items">';
    sortedIssues.forEach(function(issue, index) {
      var effSeverity = getEffSev(issue).toLowerCase();
      var badgeText = effSeverity === 'none' ? 'FALSE POSITIVE' : effSeverity.toUpperCase();
      html += '<div class="security-item ' + effSeverity + '">';
      html += '<div class="security-item-header">';
      html += '<div class="security-item-title">' + escapeHtml(issue.type || issue.check || 'Cloud Storage Issue') + '</div>';
      html += '<span class="security-badge ' + effSeverity + '">' + badgeText + '</span>';
      html += '</div>';
      html += '<div class="security-item-body">';
      html += '<div class="security-detail"><strong>Issue:</strong> ' + escapeHtml(issue.message || issue.description || '') + '</div>';
      if (issue.evidence) {
        html += '<div class="security-detail"><strong>Evidence:</strong> <code>' + escapeHtml(issue.evidence) + '</code></div>';
      }
      if (issue.recommendation) {
        html += '<div class="security-detail"><strong>Recommendation:</strong> ' + escapeHtml(issue.recommendation) + '</div>';
      }
      html += '<div style="margin-top: 6px;">';
      html += '<button class="btn btn-primary btn-sm ai-assess-security-btn' + (issue.aiAssessment ? ' has-assessment' : '') + '"'
        + ' data-finding-category="cloudStorage" data-finding-index="' + index + '"'
        + ' style="padding: 2px 8px; font-size: 11px;">' + origamiIcon('sparkles') + ' AI Analyze</button>';
      html += '</div>';
      html += '<div id="ai-assessment-security-cloudStorage-' + index + '" class="ai-assessment-container">';
      if (issue.aiAssessment) {
        html += '<div class="ai-assessment-result"><div class="ai-assessment-content">' + formatLLMResponse(issue.aiAssessment.analysis || '') + '</div></div>';
      }
      html += '</div>';
      html += '</div></div>';
    });
    html += '</div>';
  } else {
    updateSubTabBadge('cloud-storage', null, 0);
  }

  html += '</div>';
  container.innerHTML = html;

  if (!window.currentSecurityFindings) window.currentSecurityFindings = {};
  window.currentSecurityFindings.cloudStorage = issues;

  const cloudAiBtn = document.getElementById('aiAnalyzeCloudStorageBtn');
  if (cloudAiBtn) cloudAiBtn.style.display = issues.length > 0 ? '' : 'none';

  container.querySelectorAll('.ai-assess-security-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      performInlineAIAssessment(parseInt(btn.dataset.findingIndex), 'security', false, btn.dataset.findingCategory);
    });
  });
}

// --- Exfiltration Results ---

function loadExfiltrationResults(tabId) {
  chrome.runtime.sendMessage({ action: 'getExfiltrationResults', tabId: tabId }, function(response) {
    if (chrome.runtime.lastError) {
      console.error('Origami: Failed to load exfiltration results:', chrome.runtime.lastError.message);
      return;
    }
    if (response && response.exfiltration) {
      displayExfiltrationResults(response.exfiltration);
    }
  });
}

function displayExfiltrationResults(data) {
  const container = document.getElementById('exfiltration-results');
  if (!container) return;

  if (!data || (!data.dataFlows?.length && !data.issues?.length)) {
    container.innerHTML = '<p class="no-results">Run a scan to detect data exfiltration patterns.</p>';
    return;
  }

  let html = '<div class="security-analysis-results">';

  if (data.dataFlows && data.dataFlows.length > 0) {
    html += '<div class="security-section" style="margin-bottom: 12px;">';
    html += '<div class="security-section-header"><div class="security-section-title">Data Flows (' + data.dataFlows.length + ')</div></div>';
    data.dataFlows.forEach(function(flow) {
      html += '<div class="data-flow-card">';
      html += '<div style="display: flex; align-items: center; gap: 6px; margin-bottom: 4px;">';
      html += '<span style="color: var(--text-primary); font-size: 12px; font-weight: 600;">' + escapeHtml(flow.destination || flow.domain || '') + '</span>';
      const classification = (flow.classification || 'unknown-third-party').toLowerCase();
      const classMap = { 'first-party': 'first-party', 'analytics': 'analytics', 'advertising': 'advertising' };
      const classKey = classMap[classification] || 'unknown-third-party';
      html += '<span class="domain-classification-badge ' + classKey + '">' + escapeHtml(classification) + '</span>';
      if (flow.requestCount > 1) {
        html += '<span style="font-size: 10px; color: var(--text-secondary); margin-left: auto;">(' + flow.requestCount + ' requests)</span>';
      }
      html += '</div>';
      if (flow.dataTypes && flow.dataTypes.length > 0) {
        html += '<div>';
        flow.dataTypes.forEach(function(dt) {
          html += '<span class="data-type-tag">' + escapeHtml(dt) + '</span>';
        });
        html += '</div>';
      }
      html += '</div>';
    });
    html += '</div>';
  }

  const issues = data.issues || [];
  if (issues.length > 0) {
    var getEffSev = function(i) {
      return (i.severityOverride?.overriddenSeverity || i.aiAssessment?.suggestedSeverity || i.severity || 'INFO').toUpperCase();
    };
    const sortedIssues = [...issues].sort(function(a, b) {
      const order = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4, 'NONE': 5 };
      return (order[getEffSev(a)] || 4) - (order[getEffSev(b)] || 4);
    });

    var actionableIssues = sortedIssues.filter(function(i) { return getEffSev(i) !== 'NONE'; });
    updateSubTabBadge('exfiltration', actionableIssues.length > 0 ? getEffSev(actionableIssues[0]) : null, actionableIssues.length);

    html += '<div class="security-items">';
    sortedIssues.forEach(function(issue, index) {
      var effSeverity = getEffSev(issue).toLowerCase();
      var badgeText = effSeverity === 'none' ? 'FALSE POSITIVE' : effSeverity.toUpperCase();
      html += '<div class="security-item ' + effSeverity + '">';
      html += '<div class="security-item-header">';
      html += '<div class="security-item-title">' + escapeHtml(issue.type || issue.check || 'Exfiltration Issue') + '</div>';
      html += '<span class="security-badge ' + effSeverity + '">' + badgeText + '</span>';
      html += '</div>';
      html += '<div class="security-item-body">';
      html += '<div class="security-detail"><strong>Issue:</strong> ' + escapeHtml(issue.message || issue.description || '') + '</div>';
      if (issue.details) {
        if (issue.details.requestUrl) {
          html += '<div class="security-detail"><strong>Request:</strong> <code>' + escapeHtml((issue.details.method || 'GET') + ' ' + issue.details.requestUrl) + '</code></div>';
        }
        if (issue.details.destination) {
          var cls = (issue.details.classification || 'unknown-third-party').toLowerCase();
          var classKey = {'first-party':'first-party','analytics':'analytics','advertising':'advertising'}[cls] || 'unknown-third-party';
          html += '<div class="security-detail"><strong>Destination:</strong> ' + escapeHtml(issue.details.destination) + ' <span class="domain-classification-badge ' + classKey + '">' + escapeHtml(cls) + '</span></div>';
        }
        if (issue.details.dataTypes && issue.details.dataTypes.length > 0) {
          html += '<div class="security-detail"><strong>Detected Data:</strong> ';
          issue.details.dataTypes.forEach(function(dt) { html += '<span class="data-type-tag">' + escapeHtml(dt) + '</span>'; });
          html += '</div>';
        }
      }
      if (issue.evidence) {
        html += '<div class="security-detail"><strong>Evidence:</strong> <code>' + escapeHtml(issue.evidence) + '</code></div>';
      }
      if (issue.recommendation) {
        html += '<div class="security-detail"><strong>Recommendation:</strong> ' + escapeHtml(issue.recommendation) + '</div>';
      }
      html += '<div style="margin-top: 6px;">';
      html += '<button class="btn btn-primary btn-sm ai-assess-security-btn' + (issue.aiAssessment ? ' has-assessment' : '') + '"'
        + ' data-finding-category="exfiltration" data-finding-index="' + index + '"'
        + ' style="padding: 2px 8px; font-size: 11px;">' + origamiIcon('sparkles') + ' AI Analyze</button>';
      html += '</div>';
      html += '<div id="ai-assessment-security-exfiltration-' + index + '" class="ai-assessment-container">';
      if (issue.aiAssessment) {
        html += '<div class="ai-assessment-result"><div class="ai-assessment-content">' + formatLLMResponse(issue.aiAssessment.analysis || '') + '</div></div>';
      }
      html += '</div>';
      html += '</div></div>';
    });
    html += '</div>';
  } else {
    updateSubTabBadge('exfiltration', null, 0);
  }

  html += '</div>';
  container.innerHTML = html;

  if (!window.currentSecurityFindings) window.currentSecurityFindings = {};
  window.currentSecurityFindings.exfiltration = issues;

  const exfilAiBtn = document.getElementById('aiAnalyzeExfiltrationBtn');
  if (exfilAiBtn) exfilAiBtn.style.display = issues.length > 0 ? '' : 'none';

  container.querySelectorAll('.ai-assess-security-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      performInlineAIAssessment(parseInt(btn.dataset.findingIndex), 'security', false, btn.dataset.findingCategory);
    });
  });
}

// --- WebSocket Results ---

function loadWebSocketResults(tabId) {
  chrome.runtime.sendMessage({ action: 'getWebSocketResults', tabId: tabId }, function(response) {
    if (chrome.runtime.lastError) {
      console.error('Origami: Failed to load WebSocket results:', chrome.runtime.lastError.message);
      return;
    }
    if (response && response.websockets) {
      displayWebSocketResults(response.websockets);
    }
  });
}

function displayWebSocketResults(data) {
  const container = document.getElementById('websocket-results');
  if (!container) return;

  if (!data || (!data.connections?.length && !data.issues?.length)) {
    container.innerHTML = '<p class="no-results">Run a scan to audit WebSocket connections.</p>';
    return;
  }

  let html = '<div class="security-analysis-results">';

  if (data.connections && data.connections.length > 0) {
    html += '<div class="security-section" style="margin-bottom: 12px;">';
    html += '<div class="security-section-header"><div class="security-section-title">Connections (' + data.connections.length + ')</div></div>';
    data.connections.forEach(function(conn) {
      const protocol = (conn.protocol || 'ws').toLowerCase();
      const isUnencrypted = protocol === 'ws';
      html += '<div class="ws-connection-card' + (isUnencrypted ? ' unencrypted' : '') + '">';
      html += '<div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">';
      html += '<span class="ws-protocol-badge ' + escapeHtml(protocol) + '">' + escapeHtml(protocol.toUpperCase()) + '</span>';
      html += '<span style="color: var(--text-primary); font-size: 12px; word-break: break-all;">' + escapeHtml(conn.url || '') + '</span>';
      html += '</div>';
      if (conn.origin) {
        html += '<div style="font-size: 11px; color: var(--text-secondary);">Origin: ' + escapeHtml(conn.origin) + '</div>';
      }
      if (conn.messageCount !== undefined) {
        html += '<div style="font-size: 11px; color: var(--text-secondary);">Messages: ' + escapeHtml(String(conn.messageCount)) + '</div>';
      }
      html += '</div>';
    });
    html += '</div>';
  }

  const issues = data.issues || [];
  if (issues.length > 0) {
    var getEffSev = function(i) {
      return (i.severityOverride?.overriddenSeverity || i.aiAssessment?.suggestedSeverity || i.severity || 'INFO').toUpperCase();
    };
    const sortedIssues = [...issues].sort(function(a, b) {
      const order = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4, 'NONE': 5 };
      return (order[getEffSev(a)] || 4) - (order[getEffSev(b)] || 4);
    });

    var actionableIssues = sortedIssues.filter(function(i) { return getEffSev(i) !== 'NONE'; });
    updateSubTabBadge('websocket', actionableIssues.length > 0 ? getEffSev(actionableIssues[0]) : null, actionableIssues.length);

    html += '<div class="security-items">';
    sortedIssues.forEach(function(issue, index) {
      var effSeverity = getEffSev(issue).toLowerCase();
      var badgeText = effSeverity === 'none' ? 'FALSE POSITIVE' : effSeverity.toUpperCase();
      html += '<div class="security-item ' + effSeverity + '">';
      html += '<div class="security-item-header">';
      html += '<div class="security-item-title">' + escapeHtml(issue.type || issue.check || 'WebSocket Issue') + '</div>';
      html += '<span class="security-badge ' + effSeverity + '">' + badgeText + '</span>';
      html += '</div>';
      html += '<div class="security-item-body">';
      html += '<div class="security-detail"><strong>Issue:</strong> ' + escapeHtml(issue.message || issue.description || '') + '</div>';
      if (issue.evidence) {
        html += '<div class="security-detail"><strong>Evidence:</strong> <code>' + escapeHtml(issue.evidence) + '</code></div>';
      }
      if (issue.recommendation) {
        html += '<div class="security-detail"><strong>Recommendation:</strong> ' + escapeHtml(issue.recommendation) + '</div>';
      }
      html += '<div style="margin-top: 6px;">';
      html += '<button class="btn btn-primary btn-sm ai-assess-security-btn' + (issue.aiAssessment ? ' has-assessment' : '') + '"'
        + ' data-finding-category="websocket" data-finding-index="' + index + '"'
        + ' style="padding: 2px 8px; font-size: 11px;">' + origamiIcon('sparkles') + ' AI Analyze</button>';
      html += '</div>';
      html += '<div id="ai-assessment-security-websocket-' + index + '" class="ai-assessment-container">';
      if (issue.aiAssessment) {
        html += '<div class="ai-assessment-result"><div class="ai-assessment-content">' + formatLLMResponse(issue.aiAssessment.analysis || '') + '</div></div>';
      }
      html += '</div>';
      html += '</div></div>';
    });
    html += '</div>';
  } else {
    updateSubTabBadge('websocket', null, 0);
  }

  html += '</div>';
  container.innerHTML = html;

  if (!window.currentSecurityFindings) window.currentSecurityFindings = {};
  window.currentSecurityFindings.websocket = issues;

  const wsAiBtn = document.getElementById('aiAnalyzeWebSocketBtn');
  if (wsAiBtn) wsAiBtn.style.display = issues.length > 0 ? '' : 'none';

  container.querySelectorAll('.ai-assess-security-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      performInlineAIAssessment(parseInt(btn.dataset.findingIndex), 'security', false, btn.dataset.findingCategory);
    });
  });
}

// --- Specialized LLM Analysis ---

function displayLLMAnalysisResult(containerId, result, title) {
  const container = document.getElementById(containerId);
  if (!container) return;

  if (result.error) {
    container.innerHTML = '<div class="ai-assessment-result" style="margin-bottom: 10px;">'
      + '<div class="ai-assessment-header">' + escapeHtml(title) + '</div>'
      + '<div class="ai-assessment-content" style="color: var(--severity-medium);">Analysis failed: ' + escapeHtml(result.error) + '</div>'
      + '</div>';
    return;
  }

  let html = '<div class="ai-assessment-result" style="margin-bottom: 10px;">';
  html += '<div class="ai-assessment-header">' + escapeHtml(title) + '</div>';
  html += '<div class="ai-assessment-content">';

  // Render each non-empty string/array field from the result
  for (const [key, value] of Object.entries(result)) {
    if (key === 'rawResponse' || key === 'error') continue;
    if (!value || (Array.isArray(value) && value.length === 0)) continue;

    const label = key.replace(/([A-Z])/g, ' $1').replace(/^./, function(s) { return s.toUpperCase(); });

    if (typeof value === 'string') {
      html += '<div style="margin-bottom: 8px;"><strong>' + escapeHtml(label) + ':</strong><br>' + formatLLMResponse(value) + '</div>';
    } else if (Array.isArray(value)) {
      html += '<div style="margin-bottom: 8px;"><strong>' + escapeHtml(label) + ':</strong><ul style="margin: 4px 0; padding-left: 20px;">';
      value.forEach(function(item) {
        html += '<li>' + formatLLMResponse(typeof item === 'string' ? item : JSON.stringify(item)) + '</li>';
      });
      html += '</ul></div>';
    }
  }

  html += '</div></div>';
  container.innerHTML = html;
}

function setupSpecializedLLMButtons() {
  // Crypto AI Analyze
  document.getElementById('aiAnalyzeCryptoBtn')?.addEventListener('click', async function() {
    const btn = document.getElementById('aiAnalyzeCryptoBtn');
    const findings = window.currentSecurityFindings?.crypto || [];
    if (!findings.length) { showMessage('No crypto findings to analyze', 'error'); return; }
    btn.disabled = true; btn.textContent = 'Analyzing...';
    try {
      const analyzer = new CryptoAnalyzerLLM();
      const result = await analyzer.analyze(findings);
      displayLLMAnalysisResult('crypto-llm-results', result, 'Crypto Analysis');
      saveFeatureState('llm_crypto', { result, title: 'Crypto Analysis' });
    } catch(e) {
      showMessage('AI analysis failed: ' + e.message, 'error');
    } finally {
      btn.disabled = false; btn.textContent = 'AI Analyze Crypto';
    }
  });

  // Cloud Storage AI Analyze
  document.getElementById('aiAnalyzeCloudStorageBtn')?.addEventListener('click', async function() {
    const btn = document.getElementById('aiAnalyzeCloudStorageBtn');
    const findings = window.currentSecurityFindings?.cloudStorage || [];
    if (!findings.length) { showMessage('No cloud storage findings to analyze', 'error'); return; }
    btn.disabled = true; btn.textContent = 'Analyzing...';
    try {
      const analyzer = new CloudStorageAnalyzerLLM();
      const result = await analyzer.analyze(findings);
      displayLLMAnalysisResult('cloud-storage-llm-results', result, 'Cloud Storage Analysis');
      saveFeatureState('llm_cloud_storage', { result, title: 'Cloud Storage Analysis' });
    } catch(e) {
      showMessage('AI analysis failed: ' + e.message, 'error');
    } finally {
      btn.disabled = false; btn.textContent = 'AI Analyze Cloud Storage';
    }
  });

  // Exfiltration AI Analyze
  document.getElementById('aiAnalyzeExfiltrationBtn')?.addEventListener('click', async function() {
    const btn = document.getElementById('aiAnalyzeExfiltrationBtn');
    const findings = window.currentSecurityFindings?.exfiltration || [];
    if (!findings.length) { showMessage('No exfiltration findings to analyze', 'error'); return; }
    btn.disabled = true; btn.textContent = 'Analyzing...';
    try {
      const analyzer = new ExfiltrationClassifierLLM();
      const result = await analyzer.analyze(findings);
      displayLLMAnalysisResult('exfiltration-llm-results', result, 'Exfiltration Analysis');
      saveFeatureState('llm_exfiltration', { result, title: 'Exfiltration Analysis' });
    } catch(e) {
      showMessage('AI analysis failed: ' + e.message, 'error');
    } finally {
      btn.disabled = false; btn.textContent = 'AI Analyze Exfiltration';
    }
  });

  // WebSocket AI Analyze
  document.getElementById('aiAnalyzeWebSocketBtn')?.addEventListener('click', async function() {
    const btn = document.getElementById('aiAnalyzeWebSocketBtn');
    const findings = window.currentSecurityFindings?.websocket || [];
    if (!findings.length) { showMessage('No WebSocket findings to analyze', 'error'); return; }
    btn.disabled = true; btn.textContent = 'Analyzing...';
    try {
      const analyzer = new WebSocketAnalyzerLLM();
      const result = await analyzer.analyze(findings);
      displayLLMAnalysisResult('websocket-llm-results', result, 'WebSocket Analysis');
      saveFeatureState('llm_websocket', { result, title: 'WebSocket Analysis' });
    } catch(e) {
      showMessage('AI analysis failed: ' + e.message, 'error');
    } finally {
      btn.disabled = false; btn.textContent = 'AI Analyze WebSocket';
    }
  });

  // Restore persisted specialized LLM analysis results
  const llmFeatures = [
    { key: 'llm_crypto', containerId: 'crypto-llm-results' },
    { key: 'llm_cloud_storage', containerId: 'cloud-storage-llm-results' },
    { key: 'llm_exfiltration', containerId: 'exfiltration-llm-results' },
    { key: 'llm_websocket', containerId: 'websocket-llm-results' }
  ];
  llmFeatures.forEach(({ key, containerId }) => {
    loadFeatureState(key, (data) => {
      if (data && data.result) displayLLMAnalysisResult(containerId, data.result, data.title);
    });
  });
}

// --- Intent Engine ---

function setupIntentEngine() {
  const evaluateBtn = document.getElementById('evaluate-intent-btn');
  if (!evaluateBtn) return;

  // Restore persisted intent engine results
  loadFeatureState('intent_results', (data) => {
    if (data && data.scoredFindings) displayIntentResults(data);
  });

  evaluateBtn.addEventListener('click', async function() {
    evaluateBtn.disabled = true;
    evaluateBtn.textContent = 'Evaluating...';

    try {
      const tab = await getTargetTab();
      const tabId = tab?.id;
      if (!tabId) return;

      const allFindings = await new Promise(resolve => {
        chrome.runtime.sendMessage({ action: 'getAllFindings', tabId: tabId }, resolve);
      });

      const scopeText = document.getElementById('program-scope-input')?.value || '';
      const useLLM = document.getElementById('intent-use-llm')?.checked || false;

      if (typeof IntentEngine !== 'undefined') {
        const engine = new IntentEngine();
        const results = await engine.evaluate(allFindings, { programScope: scopeText, useLLM: useLLM });
        displayIntentResults(results);
        saveFeatureState('intent_results', results);
      } else {
        console.warn('Origami: IntentEngine not loaded');
        const resultsContainer = document.getElementById('intent-results');
        if (resultsContainer) {
          resultsContainer.innerHTML = '<p class="no-results">Intent Engine module not available. Ensure llm/intent-engine.js is loaded.</p>';
        }
      }
    } catch (e) {
      console.error('Origami: Intent engine error:', e);
      logError(e, 'Intent Engine evaluation');
    } finally {
      evaluateBtn.disabled = false;
      evaluateBtn.textContent = 'Evaluate Findings';
    }
  });
}

function displayIntentResults(results) {
  const summaryContainer = document.getElementById('intent-summary');
  const resultsContainer = document.getElementById('intent-results');
  if (!resultsContainer) return;

  if (!results || !results.scoredFindings || results.scoredFindings.length === 0) {
    if (summaryContainer) summaryContainer.style.display = 'none';
    resultsContainer.innerHTML = '<p class="no-results">No findings to evaluate. Run "Unfold" first to populate findings.</p>';
    return;
  }

  // Summary section
  if (summaryContainer && results.summary) {
    summaryContainer.style.display = 'block';
    let summaryHtml = '';
    summaryHtml += '<span class="intent-summary-stat"><strong>' + escapeHtml(String(results.summary.totalFindings || results.scoredFindings.length)) + '</strong> findings</span>';
    if (results.summary.signalToNoise !== undefined) {
      summaryHtml += '<span class="intent-summary-stat">Signal/Noise: <strong>' + escapeHtml(String(results.summary.signalToNoise)) + '%</strong></span>';
    }
    if (results.summary.topCategory) {
      summaryHtml += '<span class="intent-summary-stat">Top Category: <strong>' + escapeHtml(results.summary.topCategory) + '</strong></span>';
    }
    summaryContainer.innerHTML = summaryHtml;
  }

  // Scored findings
  const sorted = [...results.scoredFindings].sort(function(a, b) {
    return (b.composite || 0) - (a.composite || 0);
  });

  let html = '<div class="security-analysis-results"><div class="security-items">';

  sorted.forEach(function(finding) {
    const score = finding.composite || 0;
    const scorePercent = Math.min(score, 100);
    const scoreLevel = score >= 70 ? 'high' : (score >= 40 ? 'medium' : 'low');
    const severity = (finding.severity || 'info').toLowerCase();

    html += '<div class="security-item ' + severity + '">';
    html += '<div class="security-item-header">';
    html += '<div class="security-item-title">' + escapeHtml(finding.type || finding.message || 'Finding') + '</div>';
    html += '<span class="security-badge ' + severity + '">' + severity.toUpperCase() + '</span>';
    html += '</div>';

    // Score bar
    html += '<div style="padding: 4px 0;">';
    html += '<div style="display: flex; justify-content: space-between; font-size: 11px; color: var(--text-secondary); margin-bottom: 2px;">';
    html += '<span>Composite Score</span><span>' + scorePercent + '/100</span>';
    html += '</div>';
    html += '<div class="intent-score-bar"><div class="intent-score-fill ' + scoreLevel + '" style="width: ' + scorePercent + '%;"></div></div>';
    html += '</div>';

    // Dimension breakdown
    if (finding.scores) {
      html += '<div style="padding: 4px 0;">';
      var dims = [
        { label: 'Exploitability', key: 'exploitability' },
        { label: 'Business Impact', key: 'businessImpact' },
        { label: 'PoC Difficulty', key: 'pocDifficulty' },
        { label: 'Program Relevance', key: 'programRelevance' }
      ];
      dims.forEach(function(dim) {
        var val = finding.scores[dim.key];
        if (val !== undefined) {
          html += '<div class="intent-dimension">';
          html += '<span>' + dim.label + '</span>';
          html += '<span>' + val + '/100</span>';
          html += '</div>';
        }
      });
      html += '</div>';
    }

    if (finding.message && finding.message !== finding.title) {
      html += '<div class="security-item-body">';
      html += '<div class="security-detail">' + escapeHtml(finding.message) + '</div>';
      html += '</div>';
    }

    html += '</div>';
  });

  html += '</div></div>';
  resultsContainer.innerHTML = html;
}

// --- Cookie Editor ---

let cookieEditorData = [];
let cookieEditorOriginal = null;

function setupCookieEditor() {
  document.getElementById('cookieEditorRefresh')?.addEventListener('click', loadCookieEditorCookies);
  document.getElementById('cookieEditorAdd')?.addEventListener('click', () => openCookieEditModal(null));
  document.getElementById('cookieEditorDeleteAll')?.addEventListener('click', deleteAllCookies);
  document.getElementById('cookieEditorImport')?.addEventListener('click', importCookies);
  document.getElementById('cookieEditorExport')?.addEventListener('click', exportCookies);
  document.getElementById('cookieEditorSearchInput')?.addEventListener('input', filterCookieEditorList);
  document.getElementById('cookieEditModalClose')?.addEventListener('click', closeCookieEditModal);
  document.getElementById('cookieEditCancel')?.addEventListener('click', closeCookieEditModal);
  document.getElementById('cookieEditSave')?.addEventListener('click', saveCookieFromModal);
  document.getElementById('cookieEditDelete')?.addEventListener('click', deleteCookieFromModal);
  document.getElementById('cookieEditSession')?.addEventListener('change', (e) => {
    document.getElementById('cookieEditExpiration').disabled = e.target.checked;
  });
}

async function loadCookieEditorCookies() {
  try {
    const tab = await getTargetTab();
    if (!tab || !tab.url) {
      showMessage('No active tab', 'error');
      return;
    }

    const url = new URL(tab.url);
    if (!url.protocol.startsWith('http')) {
      document.getElementById('cookieEditorDomain').textContent = url.hostname || url.protocol;
      document.getElementById('cookieEditorCount').textContent = '0 cookies';
      document.getElementById('cookieEditorList').innerHTML =
        '<div class="empty-state"><p>Cookie editing is not available for ' + escapeHtml(url.protocol) + ' pages.</p></div>';
      cookieEditorData = [];
      return;
    }

    const domain = url.hostname;
    const cookies = await chrome.cookies.getAll({ url: tab.url });
    const domainCookies = await chrome.cookies.getAll({ domain: domain });

    const seen = new Set();
    const merged = [];
    for (const c of [...cookies, ...domainCookies]) {
      const key = c.name + '|' + c.domain + '|' + c.path;
      if (!seen.has(key)) {
        seen.add(key);
        merged.push(c);
      }
    }

    merged.sort((a, b) => a.name.localeCompare(b.name));
    cookieEditorData = merged;

    document.getElementById('cookieEditorDomain').textContent = domain;
    document.getElementById('cookieEditorCount').textContent =
      merged.length + ' cookie' + (merged.length !== 1 ? 's' : '');

    renderCookieEditorList(merged);
  } catch (error) {
    logError(error, 'Cookie Editor: loadCookies');
    showMessage('Failed to load cookies: ' + error.message, 'error');
  }
}

function classifyCookieCategory(name) {
  const lower = name.toLowerCase();
  const sessionPatterns = ['session', 'sess', 'sid', 'auth', 'token', 'jwt',
    'access_token', 'refresh_token', 'csrf', 'xsrf', 'login', 'sso'];
  const trackingPrefixes = ['_ga', '_gid', '_fbp', '_fbc', 'hubspotutk',
    '_hjid', '_clck', '_uetsid', '_uetvid', 'amplitude_'];
  const infraPrefixes = ['__cf_bm', 'cf_clearance', 'AWSALB', '_abck',
    'datadome', '_pxhd', 'bm_sz', 'akamai_'];

  if (sessionPatterns.some(p => lower.includes(p))) return 'auth';
  if (trackingPrefixes.some(p => lower.startsWith(p) || name === p)) return 'tracking';
  if (infraPrefixes.some(p => name.startsWith(p) || name === p)) return 'infra';
  return 'other';
}

function renderCookieEditorList(cookies) {
  const container = document.getElementById('cookieEditorList');

  if (cookies.length === 0) {
    container.innerHTML =
      '<div class="empty-state"><p>No cookies found for this domain.</p></div>';
    return;
  }

  let html = '';
  cookies.forEach((cookie, index) => {
    const flags = [];
    if (cookie.secure) flags.push('Secure');
    if (cookie.httpOnly) flags.push('HttpOnly');
    if (cookie.sameSite && cookie.sameSite !== 'unspecified') {
      flags.push('SameSite=' + cookie.sameSite);
    }
    if (cookie.session) flags.push('Session');

    const truncatedValue = cookie.value.length > 60
      ? escapeHtml(cookie.value.substring(0, 60)) + '...'
      : escapeHtml(cookie.value);

    const category = classifyCookieCategory(cookie.name);

    html += '<div class="cookie-editor-item" data-index="' + index + '">' +
      '<div class="cookie-editor-item-header">' +
        '<span class="cookie-editor-item-name">' + escapeHtml(cookie.name) + '</span>' +
        '<span class="cookie-editor-item-category cookie-cat-' + category + '">' + category + '</span>' +
      '</div>' +
      '<div class="cookie-editor-item-value">' + (truncatedValue || '<em>empty</em>') + '</div>' +
      '<div class="cookie-editor-item-meta">' +
        '<span class="cookie-editor-item-domain">' + escapeHtml(cookie.domain) + '</span>' +
        '<span class="cookie-editor-item-path">' + escapeHtml(cookie.path) + '</span>' +
        (flags.length > 0 ? '<span class="cookie-editor-item-flags">' + flags.join(' ') + '</span>' : '') +
      '</div>' +
    '</div>';
  });

  container.innerHTML = html;

  container.querySelectorAll('.cookie-editor-item').forEach(item => {
    item.addEventListener('click', () => {
      const index = parseInt(item.dataset.index);
      openCookieEditModal(cookies[index]);
    });
  });
}

function openCookieEditModal(cookie) {
  cookieEditorOriginal = cookie;
  const title = document.getElementById('cookieEditModalTitle');
  const deleteBtn = document.getElementById('cookieEditDelete');

  if (cookie) {
    title.textContent = 'Edit Cookie';
    deleteBtn.style.display = 'inline-block';
    document.getElementById('cookieEditName').value = cookie.name;
    document.getElementById('cookieEditValue').value = cookie.value;
    document.getElementById('cookieEditDomain').value = cookie.domain;
    document.getElementById('cookieEditPath').value = cookie.path;
    document.getElementById('cookieEditSecure').checked = cookie.secure;
    document.getElementById('cookieEditHttpOnly').checked = cookie.httpOnly;
    document.getElementById('cookieEditSession').checked = cookie.session;

    const sameSiteMap = {
      'strict': 'strict', 'lax': 'lax',
      'no_restriction': 'no_restriction', 'none': 'no_restriction',
      'unspecified': 'lax'
    };
    document.getElementById('cookieEditSameSite').value = sameSiteMap[cookie.sameSite] || 'lax';

    const expField = document.getElementById('cookieEditExpiration');
    if (cookie.expirationDate && !cookie.session) {
      const date = new Date(cookie.expirationDate * 1000);
      expField.value = date.toISOString().slice(0, 16);
      expField.disabled = false;
    } else {
      expField.value = '';
      expField.disabled = true;
    }
  } else {
    title.textContent = 'New Cookie';
    deleteBtn.style.display = 'none';
    document.getElementById('cookieEditName').value = '';
    document.getElementById('cookieEditValue').value = '';
    const domainText = document.getElementById('cookieEditorDomain').textContent;
    document.getElementById('cookieEditDomain').value = domainText ? '.' + domainText : '';
    document.getElementById('cookieEditPath').value = '/';
    document.getElementById('cookieEditSecure').checked = true;
    document.getElementById('cookieEditHttpOnly').checked = false;
    document.getElementById('cookieEditSession').checked = false;
    document.getElementById('cookieEditSameSite').value = 'lax';
    document.getElementById('cookieEditExpiration').value = '';
    document.getElementById('cookieEditExpiration').disabled = false;
  }

  document.getElementById('cookieEditModal').style.display = 'flex';
}

function closeCookieEditModal() {
  document.getElementById('cookieEditModal').style.display = 'none';
  cookieEditorOriginal = null;
}

async function removeCookieByDetails(cookie) {
  const protocol = cookie.secure ? 'https' : 'http';
  const cleanDomain = cookie.domain.startsWith('.')
    ? cookie.domain.substring(1) : cookie.domain;
  const url = protocol + '://' + cleanDomain + cookie.path;
  return chrome.cookies.remove({ url: url, name: cookie.name, storeId: cookie.storeId });
}

async function saveCookieFromModal() {
  try {
    const name = document.getElementById('cookieEditName').value.trim();
    const value = document.getElementById('cookieEditValue').value;
    const domain = document.getElementById('cookieEditDomain').value.trim();
    const path = document.getElementById('cookieEditPath').value.trim() || '/';
    const secure = document.getElementById('cookieEditSecure').checked;
    const httpOnly = document.getElementById('cookieEditHttpOnly').checked;
    const isSession = document.getElementById('cookieEditSession').checked;
    const sameSite = document.getElementById('cookieEditSameSite').value;
    const expirationStr = document.getElementById('cookieEditExpiration').value;

    if (!name) { showMessage('Cookie name is required', 'error'); return; }
    if (!domain) { showMessage('Domain is required', 'error'); return; }
    if (sameSite === 'no_restriction' && !secure) {
      showMessage('SameSite=None requires the Secure flag', 'error');
      return;
    }

    if (cookieEditorOriginal) {
      const old = cookieEditorOriginal;
      if (old.name !== name || old.domain !== domain || old.path !== path) {
        await removeCookieByDetails(old);
      }
    }

    const protocol = secure ? 'https' : 'http';
    const cleanDomain = domain.startsWith('.') ? domain.substring(1) : domain;
    const url = protocol + '://' + cleanDomain + path;

    const cookieDetails = {
      url: url,
      name: name,
      value: value,
      domain: domain,
      path: path,
      secure: secure,
      httpOnly: httpOnly,
      sameSite: sameSite
    };

    if (!isSession && expirationStr) {
      cookieDetails.expirationDate = new Date(expirationStr).getTime() / 1000;
    }

    const result = await chrome.cookies.set(cookieDetails);

    if (result) {
      closeCookieEditModal();
      showMessage('Cookie "' + name + '" saved', 'success');
      loadCookieEditorCookies();
    } else {
      showMessage('Failed to save cookie (check domain/path)', 'error');
    }
  } catch (error) {
    logError(error, 'Cookie Editor: saveCookie');
    showMessage('Error saving cookie: ' + error.message, 'error');
  }
}

async function deleteCookieFromModal() {
  if (!cookieEditorOriginal) return;
  try {
    const cookieName = cookieEditorOriginal.name;
    await removeCookieByDetails(cookieEditorOriginal);
    closeCookieEditModal();
    showMessage('Cookie "' + cookieName + '" deleted', 'success');
    loadCookieEditorCookies();
  } catch (error) {
    logError(error, 'Cookie Editor: deleteCookie');
    showMessage('Error deleting cookie: ' + error.message, 'error');
  }
}

async function deleteAllCookies() {
  if (cookieEditorData.length === 0) {
    showMessage('No cookies to delete', 'info');
    return;
  }
  const count = cookieEditorData.length;
  if (!confirm('Delete all ' + count + ' cookies for this domain?')) return;
  try {
    await Promise.all(cookieEditorData.map(c => removeCookieByDetails(c)));
    showMessage('Deleted ' + count + ' cookies', 'success');
    loadCookieEditorCookies();
  } catch (error) {
    logError(error, 'Cookie Editor: deleteAll');
    showMessage('Error deleting cookies: ' + error.message, 'error');
  }
}

function exportCookies() {
  if (cookieEditorData.length === 0) {
    showMessage('No cookies to export', 'info');
    return;
  }
  const exportData = cookieEditorData.map(c => ({
    name: c.name,
    value: c.value,
    domain: c.domain,
    path: c.path,
    secure: c.secure,
    httpOnly: c.httpOnly,
    sameSite: c.sameSite,
    expirationDate: c.expirationDate || undefined,
    hostOnly: c.hostOnly,
    session: c.session,
    storeId: c.storeId
  }));

  const jsonStr = JSON.stringify(exportData, null, 2);
  const domain = document.getElementById('cookieEditorDomain').textContent || 'unknown';
  const filename = 'cookies-' + domain + '-' + new Date().toISOString().slice(0, 10) + '.json';

  navigator.clipboard.writeText(jsonStr).then(() => {
    showMessage('Cookies copied to clipboard', 'success');
    setTimeout(() => {
      downloadFile(jsonStr, filename, 'application/json');
    }, 600);
  }).catch(() => {
    downloadFile(jsonStr, filename, 'application/json');
    showMessage('Exported ' + exportData.length + ' cookies', 'success');
  });
}

function importCookies() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.json';
  input.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (evt) => {
      try {
        const imported = JSON.parse(evt.target.result);
        if (!Array.isArray(imported)) {
          showMessage('Invalid file: expected a JSON array of cookies', 'error');
          return;
        }

        let successCount = 0;
        let failCount = 0;

        for (const cookie of imported) {
          if (!cookie.name || !cookie.domain) { failCount++; continue; }
          try {
            const protocol = cookie.secure ? 'https' : 'http';
            const cleanDomain = cookie.domain.startsWith('.')
              ? cookie.domain.substring(1) : cookie.domain;
            const url = protocol + '://' + cleanDomain + (cookie.path || '/');

            const details = {
              url: url,
              name: cookie.name,
              value: cookie.value || '',
              domain: cookie.domain,
              path: cookie.path || '/',
              secure: !!cookie.secure,
              httpOnly: !!cookie.httpOnly,
              sameSite: cookie.sameSite || 'lax'
            };

            if (cookie.expirationDate && !cookie.session) {
              details.expirationDate = cookie.expirationDate;
            }

            const result = await chrome.cookies.set(details);
            if (result) { successCount++; } else { failCount++; }
          } catch (err) { failCount++; }
        }

        showMessage('Imported: ' + successCount + ' success, ' + failCount + ' failed',
          successCount > 0 ? 'success' : 'error');
        loadCookieEditorCookies();
      } catch (parseError) {
        showMessage('Invalid JSON file', 'error');
      }
    };
    reader.readAsText(file);
  });
  input.click();
}

function filterCookieEditorList() {
  const query = document.getElementById('cookieEditorSearchInput').value.toLowerCase();
  if (!query) {
    renderCookieEditorList(cookieEditorData);
    document.getElementById('cookieEditorCount').textContent =
      cookieEditorData.length + ' cookie' + (cookieEditorData.length !== 1 ? 's' : '');
    return;
  }

  const filtered = cookieEditorData.filter(c =>
    c.name.toLowerCase().includes(query) ||
    c.value.toLowerCase().includes(query) ||
    c.domain.toLowerCase().includes(query)
  );

  renderCookieEditorList(filtered);
  document.getElementById('cookieEditorCount').textContent =
    filtered.length + ' of ' + cookieEditorData.length + ' cookies';
}

// --- Phase 2-3 Initialization ---

function initializePhase2Features() {
  setupInventorySubTabs();
  setupBruteForceScanner();
  setupCrawler();
  setupEvolutionTracker();
  setupWorkbench();
  setupPoCGenerator();
  setupGraphQLQueryExecution();
  setupAIRuleGenerator();
  setupIntentEngine();
  setupSpecializedLLMButtons();
  setupCookieEditor();
}

// Hook into scan completion to load Phase 2-3 data
function loadPhase2DataForTab(tabId) {
  loadCorrelationChains(tabId);
  loadAuthFlows(tabId);
  loadGraphQLResults(tabId);
  loadSessionState(tabId);
  loadCryptoResults(tabId);
  loadCloudStorageResults(tabId);
  loadExfiltrationResults(tabId);
  loadWebSocketResults(tabId);
  // Refresh workbench and PoC findings after scan
  populateWorkbenchFindings();
  populatePoCFindingSelect();
}

// Override the scan listener to also load Phase 2-3 data
const _originalScanProgressListener = _scanProgressListener;
if (_scanProgressListener) {
  chrome.runtime.onMessage.removeListener(_scanProgressListener);
}

_scanProgressListener = (message, sender, sendResponse) => {
  if (message.action === 'scanProgress') {
    updateScanProgress(message.phase, message.step, message.totalSteps);
  }
  if (message.action === 'securityAnalysisReady') {
    handleSecurityAnalysisReady(message.tabId);
    // Load Phase 2-3 data after security analysis completes
    setTimeout(() => loadPhase2DataForTab(message.tabId), 500);
  }
  // Brute force scanner progress/completion messages
  if (message.action === 'bruteForceScanProgress' || message.action === 'bruteForceScanComplete') {
    handleBruteForceMessage(message);
  }
  // Web crawler progress/completion messages
  if (message.action === 'crawlerProgress' || message.action === 'crawlerComplete') {
    handleCrawlerMessage(message);
  }
};
chrome.runtime.onMessage.addListener(_scanProgressListener);

// Initialize Phase 2-3 features when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    initializePhase2Features();
    // Load Phase 2-3 data for the current tab on popup open
    getTargetTab().then((tab) => {
      if (tab) loadPhase2DataForTab(tab.id);
    });
  });
} else {
  initializePhase2Features();
  getTargetTab().then((tab) => {
    if (tab) loadPhase2DataForTab(tab.id);
  });
}

// Also hook into main tab switching to trigger data loading
const _origSetupTabs = setupTabs;
const _phase2TabHook = () => {
  const tabBtns = document.querySelectorAll('.tab-btn');
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabName = btn.dataset.tab;
      if (tabName === 'attack-lab') {
        getTargetTab().then((tab) => {
          if (tab) {
            loadCorrelationChains(tab.id);
            populateWorkbenchFindings();
            populatePoCFindingSelect();
          }
        });
      }
      if (tabName === 'graphql') {
        getTargetTab().then((tab) => {
          if (tab) loadGraphQLResults(tab.id);
        });
      }
    });
  });
};

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', _phase2TabHook);
} else {
  _phase2TabHook();
}

// ============================================================
// AI Partner Chat
let _chatAbortController = null;
let chatManager = null;
// Test hook: allows injecting a mock chatManager without going through openAIPartner
window._setChatManager = function(cm) { chatManager = cm; };

function stopChatGeneration() {
  if (_chatAbortController) {
    _chatAbortController.abort();
  }
}

// ============================================================

let aiPartnerOpen = false;
var _aiPartnerMode = 'advisor';

function setAIPartnerMode(mode) {
  _aiPartnerMode = (mode === 'exploiter') ? 'exploiter' : 'advisor';
  document.querySelectorAll('.ai-mode-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.mode === _aiPartnerMode);
  });
  if (chatManager) chatManager.setMode(_aiPartnerMode);
}

function downloadTranscript() {
  if (!chatManager) return;
  const conv = chatManager.getConversation();
  const lines = [];
  lines.push('Origami AI Partner - Conversation Transcript');
  lines.push('Domain: ' + (conv.domain || 'unknown'));
  lines.push('Mode: ' + (_aiPartnerMode));
  lines.push('Created: ' + (conv.createdAt || ''));
  lines.push('');

  conv.messages.forEach(function(msg, idx) {
    if (msg.role === 'system') return;
    lines.push('--- ' + (msg.role === 'user' ? 'USER' : 'ASSISTANT') + ' (' + (msg.timestamp || '') + ') ---');
    lines.push(msg.content || '');
    if (msg.toolDetails && msg.toolDetails.length > 0) {
      msg.toolDetails.forEach(function(td) {
        lines.push('');
        lines.push('[TOOL CALL] ' + td.tool + ' (' + (td.timestamp || '') + ')');
        lines.push('params: ' + JSON.stringify(td.params, null, 2));
        lines.push('result: ' + td.result);
        lines.push('[/TOOL CALL]');
      });
    }
    lines.push('');
  });

  const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'origami-transcript-' + (conv.domain || 'session').replace(/[^a-z0-9]/gi, '_') + '-' + Date.now() + '.txt';
  a.click();
  URL.revokeObjectURL(url);
}

function initAIPartner() {
  // aiPartnerBtn is bound in setupEventListeners() with error handling
  document.getElementById('aiPartnerCloseBtn')?.addEventListener('click', closeAIPartner);
  document.getElementById('aiPartnerMinimizeBtn')?.addEventListener('click', minimizeAIPartner);
  document.getElementById('aiPartnerMinimized')?.addEventListener('click', restoreAIPartner);
  document.getElementById('aiPartnerNewBtn')?.addEventListener('click', newAIPartnerConversation);
  document.getElementById('aiPartnerSendBtn')?.addEventListener('click', sendChatMessage);
  document.getElementById('aiPartnerStopBtn')?.addEventListener('click', stopChatGeneration);
  document.getElementById('aiPartnerDownloadBtn')?.addEventListener('click', downloadTranscript);

  document.querySelectorAll('.ai-mode-btn').forEach(btn => {
    btn.addEventListener('click', function() { setAIPartnerMode(this.dataset.mode); });
  });

  document.getElementById('aiPartnerInput')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendChatMessage();
    }
  });

  document.getElementById('aiPartnerInput')?.addEventListener('input', function() {
    this.style.height = 'auto';
    this.style.height = Math.min(this.scrollHeight, 100) + 'px';
  });

  document.querySelectorAll('.chat-quick-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const prompt = btn.dataset.prompt;
      document.getElementById('aiPartnerInput').value = prompt;
      sendChatMessage();
    });
  });
}

async function openAIPartner() {
  console.log('AI Partner: openAIPartner() called');
  const panel = document.getElementById('aiPartnerPanel');
  if (!panel) {
    console.error('AI Partner: panel element not found');
    showMessage('AI Partner panel element not found. Try reloading the extension.', 'error');
    return;
  }
  console.log('AI Partner: panel found, adding open class');
  panel.classList.add('open');
  aiPartnerOpen = true;
  const minimized = document.getElementById('aiPartnerMinimized');
  if (minimized) minimized.style.display = 'none';

  console.log('AI Partner: querying active tab');
  const tab = await getTargetTab();
  if (!tab) {
    appendChatError('No active tab found. Please open a web page first.');
    return;
  }

  let url;
  try { url = new URL(tab.url); } catch(e) {
    document.getElementById('aiPartnerDomain').textContent = tab.url || 'Unknown';
    return;
  }
  const domain = url.hostname;
  console.log('AI Partner: domain =', domain);

  document.getElementById('aiPartnerDomain').textContent = domain;
  updateAIPartnerStatus();

  if (!chatManager || chatManager.domain !== domain) {
    try {
      console.log('AI Partner: initializing ChatManager');
      chatManager = new ChatManager(tab.id, domain);
      await chatManager.loadHistory();

      const conv = chatManager.getConversation();
      if (conv && conv.messages.length > 0) {
        restoreChatMessages(conv.messages);
      }
    } catch (e) {
      console.error('AI Partner: ChatManager init failed:', e);
      chatManager = null;
      appendChatError('Failed to initialize AI Partner. Check your LLM settings.');
      return;
    }
  }
  // Expose reference so tests can patch sendMessage through the same object
  window._chatManagerRef = chatManager;

  console.log('AI Partner: open complete');
  document.getElementById('aiPartnerInput')?.focus();
}

function closeAIPartner() {
  const panel = document.getElementById('aiPartnerPanel');
  panel.classList.remove('open');
  aiPartnerOpen = false;

  if (chatManager) {
    chatManager.saveHistory();
  }
}

function minimizeAIPartner() {
  closeAIPartner();
  document.getElementById('aiPartnerMinimized').style.display = 'flex';
}

function restoreAIPartner() {
  openAIPartner();
}

async function newAIPartnerConversation() {
  if (chatManager) {
    await chatManager.saveHistory();
    chatManager.clearConversation();
  }

  const container = document.getElementById('aiPartnerMessages');
  container.innerHTML = `
    <div class="chat-welcome">
      <p><strong>Origami AI Partner</strong></p>
      <p>Ask me about your scan findings, request PoC generation, or get remediation advice. I have full context of your current scan.</p>
    </div>
  `;
}

function updateAIPartnerStatus() {
  let findingsCount = 0;
  if (currentFindings && currentFindings.length) {
    findingsCount += currentFindings.length;
  }
  if (securityResults) {
    const categories = ['headers', 'cookies', 'vulnerabilities', 'sensitiveFiles'];
    for (const cat of categories) {
      if (securityResults[cat] && Array.isArray(securityResults[cat])) {
        findingsCount += securityResults[cat].filter(f =>
          f.severity !== 'INFO' && f.status !== 'OK' && f.status !== 'GOOD'
        ).length;
      }
    }
  }
  document.getElementById('aiPartnerFindingsCount').textContent = findingsCount + ' findings';

  const scoreEl = document.getElementById('scoreNumber');
  if (scoreEl && scoreEl.textContent !== '--') {
    document.getElementById('aiPartnerScore').textContent = 'Score: ' + scoreEl.textContent;
  }
}

async function sendChatMessage() {
  const input = document.getElementById('aiPartnerInput');
  const message = input.value.trim();
  if (!message) return;

  if (!chatManager) {
    appendChatError('AI Partner not initialized. Please close and reopen the panel.');
    return;
  }

  const stored = await new Promise(resolve => {
    chrome.storage.sync.get(['settings'], resolve);
  });
  const llmSettings = stored.settings?.llm || {};

  if (!llmSettings.enabled || !llmSettings.provider || llmSettings.provider === 'none') {
    appendChatError('No LLM provider configured. Go to Settings tab to set up your AI provider.');
    return;
  }

  if (llmSettings.provider !== 'ollama' && !llmSettings.apiKey) {
    appendChatError('No API key configured for ' + llmSettings.provider + '. Go to Settings tab to add your API key.');
    return;
  }

  input.value = '';
  input.style.height = 'auto';

  appendChatMessage('user', message);

  const thinkingEl = document.createElement('div');
  thinkingEl.className = 'chat-thinking';
  thinkingEl.textContent = 'Thinking';
  thinkingEl.id = 'chatThinking';
  document.getElementById('aiPartnerMessages').appendChild(thinkingEl);
  scrollChatToBottom();

  const sendBtn = document.getElementById('aiPartnerSendBtn');
  const stopBtn = document.getElementById('aiPartnerStopBtn');
  sendBtn.style.display = 'none';
  if (stopBtn) stopBtn.style.display = '';

  _chatAbortController = new AbortController();

  const onToolCall = (toolName, toolParams, toolResult) => {
    appendToolIndicator(toolName, toolParams, toolResult);
    const thinking = document.getElementById('chatThinking');
    if (thinking) thinking.textContent = toolName;
    scrollChatToBottom();
  };

  try {
    chatManager.setContext(securityResults, currentFindings);
    chatManager.setMode(_aiPartnerMode);
    const result = await chatManager.sendMessage(message, {
      onToolCall: onToolCall,
      signal: _chatAbortController.signal
    });

    const thinking = document.getElementById('chatThinking');
    if (thinking) thinking.remove();

    appendChatMessage('assistant', result.response);

  } catch (error) {
    const thinking = document.getElementById('chatThinking');
    if (thinking) thinking.remove();

    console.error('Origami: AI Partner error:', error);
    appendChatError('Error: ' + error.message);
  } finally {
    sendBtn.style.display = '';
    if (stopBtn) stopBtn.style.display = 'none';
    _chatAbortController = null;
    document.getElementById('aiPartnerInput').focus();
  }
}

function appendChatMessage(role, content) {
  const container = document.getElementById('aiPartnerMessages');

  const welcome = container.querySelector('.chat-welcome');
  if (welcome) welcome.remove();

  const msgEl = document.createElement('div');
  msgEl.className = 'chat-message chat-message-' + role;

  if (role === 'assistant') {
    msgEl.innerHTML = renderChatMarkdown(content);
  } else {
    msgEl.textContent = content;
  }

  container.appendChild(msgEl);
  scrollChatToBottom();
}

function appendToolIndicator(toolName, toolParams, toolResult) {
  const container = document.getElementById('aiPartnerMessages');
  const el = document.createElement('div');
  el.className = 'chat-tool-indicator';

  const hasDetails = toolParams || toolResult;

  const header = document.createElement('div');
  header.className = 'chat-tool-indicator-header' + (hasDetails ? ' chat-tool-indicator-expandable' : '');

  const arrow = document.createElement('span');
  arrow.className = 'chat-tool-indicator-arrow';
  arrow.textContent = hasDetails ? '\u25b6' : '\u2022';
  header.appendChild(arrow);

  const name = document.createElement('span');
  name.textContent = toolName || 'unknown tool';
  header.appendChild(name);

  el.appendChild(header);

  if (hasDetails) {
    const details = document.createElement('div');
    details.className = 'chat-tool-indicator-details';

    if (toolParams) {
      const paramsLabel = document.createElement('div');
      paramsLabel.className = 'chat-tool-detail-label';
      paramsLabel.textContent = 'params';
      details.appendChild(paramsLabel);

      const paramsBlock = document.createElement('pre');
      paramsBlock.className = 'chat-tool-detail-block';
      try {
        paramsBlock.textContent = typeof toolParams === 'object'
          ? JSON.stringify(toolParams, null, 2)
          : String(toolParams);
      } catch (e) {
        paramsBlock.textContent = String(toolParams);
      }
      details.appendChild(paramsBlock);
    }

    if (toolResult) {
      const resultLabel = document.createElement('div');
      resultLabel.className = 'chat-tool-detail-label';
      resultLabel.textContent = 'result';
      details.appendChild(resultLabel);

      const resultBlock = document.createElement('pre');
      resultBlock.className = 'chat-tool-detail-block';
      const trimmed = String(toolResult);
      resultBlock.textContent = trimmed.length > 2000 ? trimmed.substring(0, 2000) + '\n[truncated]' : trimmed;
      details.appendChild(resultBlock);
    }

    el.appendChild(details);

    header.addEventListener('click', function() {
      const expanded = el.classList.toggle('chat-tool-indicator-open');
      arrow.textContent = expanded ? '\u25bc' : '\u25b6';
      scrollChatToBottom();
    });
  }

  container.appendChild(el);
}

function appendChatError(message) {
  const container = document.getElementById('aiPartnerMessages');
  const el = document.createElement('div');
  el.className = 'chat-error';
  el.textContent = message;
  container.appendChild(el);
  scrollChatToBottom();
}

function scrollChatToBottom() {
  const container = document.getElementById('aiPartnerMessages');
  container.scrollTop = container.scrollHeight;
}

function restoreChatMessages(messages) {
  const container = document.getElementById('aiPartnerMessages');
  container.innerHTML = '';

  for (const msg of messages) {
    if (msg.hidden) continue;
    if (msg.role === 'system') continue;
    if (msg.role === 'tool_indicator') {
      appendToolIndicator(msg.content);
      continue;
    }
    appendChatMessage(msg.role, msg.content);
  }
}

// ============================================================
// Report Malicious Site
// ============================================================

let reportModalCurrentUrl = '';
let reportedVendorsForSession = new Set();

async function showReportModal() {
  const modal = document.getElementById('reportMaliciousModal');
  const urlDisplay = document.getElementById('reportTargetUrl');

  try {
    const tab = await getTargetTab();
    reportModalCurrentUrl = tab ? tab.url : '';
  } catch (e) {
    reportModalCurrentUrl = '';
    logError(e, 'showReportModal');
  }

  urlDisplay.textContent = reportModalCurrentUrl || 'No URL available';

  // Reset category to phishing
  document.querySelectorAll('.report-category-btn').forEach(b => b.classList.remove('active'));
  document.querySelector('.report-category-btn[data-category="phishing"]').classList.add('active');

  // Clear notes
  document.getElementById('reportNotes').value = '';

  // Reset session vendor tracking
  reportedVendorsForSession.clear();

  // Populate vendor grid
  populateReportVendorGrid();

  // Load report history
  loadReportHistory();

  modal.style.display = 'flex';
}

function closeReportModal() {
  document.getElementById('reportMaliciousModal').style.display = 'none';
}

function getSelectedCategory() {
  const activeBtn = document.querySelector('.report-category-btn.active');
  return activeBtn ? activeBtn.dataset.category : 'phishing';
}

function populateReportVendorGrid() {
  const grid = document.getElementById('reportVendorGrid');
  const vendors = phishingReporter.getVendors();

  let html = '';
  vendors.forEach(vendor => {
    const isReported = reportedVendorsForSession.has(vendor.id);
    html += `
      <div class="report-vendor-card ${isReported ? 'reported' : ''}" data-vendor-id="${vendor.id}" title="${escapeHtml(vendor.description)}">
        <div class="vendor-icon">${origamiIcon(vendor.icon)}</div>
        <div class="vendor-info">
          <div class="vendor-name">${escapeHtml(vendor.name)}</div>
          <div class="vendor-desc">${escapeHtml(vendor.description)}</div>
        </div>
      </div>
    `;
  });

  grid.innerHTML = html;

  // Add click listeners
  grid.querySelectorAll('.report-vendor-card').forEach(card => {
    card.addEventListener('click', () => {
      const vendorId = card.dataset.vendorId;
      reportToVendor(vendorId);
    });
  });
}

async function reportToVendor(vendorId) {
  if (!reportModalCurrentUrl) {
    logError(new Error('No URL to report'), 'reportToVendor');
    return;
  }

  const vendor = phishingReporter.getVendorById(vendorId);
  if (!vendor) return;

  const category = getSelectedCategory();
  const notes = document.getElementById('reportNotes').value.trim();

  // Open vendor report page in new tab
  const reportUrl = phishingReporter.getReportUrl(vendorId, reportModalCurrentUrl);
  if (reportUrl) {
    chrome.tabs.create({ url: reportUrl, active: false });
  }

  // Mark as reported in session
  reportedVendorsForSession.add(vendorId);

  // Save to history
  const report = phishingReporter.createReport(reportModalCurrentUrl, vendorId, category, notes);
  try {
    await phishingReporter.saveReport(report);
  } catch (e) {
    logError(e, 'reportToVendor:saveReport');
  }

  // Update UI
  populateReportVendorGrid();
  loadReportHistory();
}

async function reportToAllVendors() {
  if (!reportModalCurrentUrl) {
    logError(new Error('No URL to report'), 'reportToAllVendors');
    return;
  }

  const vendors = phishingReporter.getVendors();
  const category = getSelectedCategory();
  const notes = document.getElementById('reportNotes').value.trim();

  for (const vendor of vendors) {
    // Open vendor report page in new tab
    const reportUrl = phishingReporter.getReportUrl(vendor.id, reportModalCurrentUrl);
    if (reportUrl) {
      chrome.tabs.create({ url: reportUrl, active: false });
    }

    // Mark as reported in session
    reportedVendorsForSession.add(vendor.id);

    // Save to history
    const report = phishingReporter.createReport(reportModalCurrentUrl, vendor.id, category, notes);
    try {
      await phishingReporter.saveReport(report);
    } catch (e) {
      logError(e, 'reportToAllVendors:saveReport');
    }
  }

  // Update UI
  populateReportVendorGrid();
  loadReportHistory();
}

async function loadReportHistory() {
  const container = document.getElementById('reportHistoryList');

  try {
    const history = await phishingReporter.getReportHistory();

    if (!history || history.length === 0) {
      container.innerHTML = '<p class="no-results">No reports submitted yet.</p>';
      return;
    }

    // Show only the last 20 entries in the modal
    const recentHistory = history.slice(0, 20);
    let html = '';

    recentHistory.forEach(report => {
      const time = new Date(report.timestamp);
      const timeStr = time.toLocaleDateString() + ' ' + time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      const shortUrl = report.targetUrl.length > 40 ? report.targetUrl.substring(0, 40) + '...' : report.targetUrl;

      html += `
        <div class="report-history-item">
          <span class="report-history-vendor">${escapeHtml(report.vendorName)}</span>
          <span class="report-history-category">${escapeHtml(report.category)}</span>
          <span class="report-history-url" title="${escapeHtml(report.targetUrl)}">${escapeHtml(shortUrl)}</span>
          <span class="report-history-time">${escapeHtml(timeStr)}</span>
        </div>
      `;
    });

    if (history.length > 20) {
      html += `<p class="no-results">Showing 20 of ${history.length} reports</p>`;
    }

    container.innerHTML = html;
  } catch (e) {
    container.innerHTML = '<p class="no-results">Failed to load report history.</p>';
    logError(e, 'loadReportHistory');
  }
}

async function clearReportHistory() {
  try {
    await phishingReporter.clearReportHistory();
    loadReportHistory();
  } catch (e) {
    logError(e, 'clearReportHistory');
  }
}

// Close report modal on backdrop click
document.addEventListener('click', (e) => {
  const modal = document.getElementById('reportMaliciousModal');
  if (e.target === modal) {
    closeReportModal();
  }
});

function renderChatMarkdown(text) {
  if (!text) return '';

  let html = text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

  html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (match, lang, code) => {
    return '<pre><code>' + code.trim() + '</code></pre>';
  });

  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

  html = html.replace(/^#### (.+)$/gm, '<h4>$1</h4>');
  html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
  html = html.replace(/^## (.+)$/gm, '<h3>$1</h3>');

  html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');

  html = html.replace(/^- (.+)$/gm, '<li>$1</li>');
  html = html.replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>');

  html = html.replace(/^\d+\. (.+)$/gm, '<li>$1</li>');

  html = html.replace(/\n\n/g, '<br><br>');
  html = html.replace(/\n/g, '<br>');

  html = html.replace(/<\/li><br>/g, '</li>');
  html = html.replace(/<\/ul><br>/g, '</ul>');
  html = html.replace(/<\/pre><br>/g, '</pre>');
  html = html.replace(/<\/h3><br>/g, '</h3>');
  html = html.replace(/<\/h4><br>/g, '</h4>');

  return html;
}



// ==========================================================================
// Repeater Tab Module
// ==========================================================================

// --- Repeater Module State ---
let _repeaterBodyMode = 'raw';

// ──────────────────────────────────────────────
// 1. toggleRepeaterBodyVisibility()
// ──────────────────────────────────────────────
// Called on #repeater-method change event.
// Shows #repeater-body-section for methods that carry a body (POST, PUT, PATCH).
// Hides it for methods that do not (GET, DELETE, HEAD, OPTIONS).
// CRITICAL: Does NOT clear the textarea value when hiding — body content is
//           preserved across method switches.

function toggleRepeaterBodyVisibility() {
  const method = document.getElementById('repeater-method').value;
  const bodySection = document.getElementById('repeater-body-section');
  const methodsWithBody = ['POST', 'PUT', 'PATCH'];
  bodySection.style.display = methodsWithBody.includes(method) ? 'block' : 'none';
}

// ──────────────────────────────────────────────
// 2. addRepeaterHeader()
// ──────────────────────────────────────────────
// Called on #repeater-add-header-btn click.
// Creates a new .repeater-header-row div with key input, value input, and
// remove button, then appends it to #repeater-headers-container.

function addRepeaterHeader() {
  const container = document.getElementById('repeater-headers-container');

  const row = document.createElement('div');
  row.className = 'repeater-header-row';

  const keyInput = document.createElement('input');
  keyInput.className = 'repeater-header-key input-field';
  keyInput.type = 'text';
  keyInput.placeholder = 'Header name';

  const valueInput = document.createElement('input');
  valueInput.className = 'repeater-header-value input-field';
  valueInput.type = 'text';
  valueInput.placeholder = 'Header value';

  const removeBtn = document.createElement('button');
  removeBtn.className = 'repeater-remove-header-btn btn btn-sm btn-danger';
  removeBtn.textContent = '\u00D7'; // multiplication sign (×)

  row.appendChild(keyInput);
  row.appendChild(valueInput);
  row.appendChild(removeBtn);

  container.appendChild(row);
}

// ──────────────────────────────────────────────
// 3. removeRepeaterHeader(event)
// ──────────────────────────────────────────────
// Click handler attached via event delegation on #repeater-headers-container.
// If the click target (or its ancestor) is a .repeater-remove-header-btn,
// removes the parent .repeater-header-row from the DOM.

function removeRepeaterHeader(event) {
  const removeBtn = event.target.closest('.repeater-remove-header-btn');
  if (!removeBtn) return;

  const row = removeBtn.closest('.repeater-header-row');
  if (row) {
    row.remove();
  }
}

// ──────────────────────────────────────────────
// 4. setRepeaterBodyMode(mode)
// ──────────────────────────────────────────────
// Called when a body mode button is clicked.
// mode is one of: 'raw', 'json', 'form-data'.
// Removes .active from all .repeater-body-mode-btn elements, then adds
// .active to the button matching the selected mode.
// Stores the current mode in the module-level _repeaterBodyMode variable.

function setRepeaterBodyMode(mode) {
  const buttons = document.querySelectorAll('.repeater-body-mode-btn');
  buttons.forEach(function(btn) {
    btn.classList.remove('active');
  });

  const activeBtn = document.getElementById('repeater-body-mode-' + mode);
  if (activeBtn) {
    activeBtn.classList.add('active');
  }

  _repeaterBodyMode = mode;
}

// ──────────────────────────────────────────────
// 5. getRepeaterRequestData()
// ──────────────────────────────────────────────
// Gathers all form data into a request object.
// Returns: { method, url, headers, body, bodyMode }
// - method:   string from #repeater-method
// - url:      string from #repeater-url (validated & possibly corrected)
// - headers:  plain object of key-value pairs from header rows
// - body:     string from #repeater-body, or null for non-body methods
// - bodyMode: string ('raw', 'json', 'form-data')

function getRepeaterRequestData() {
  const method = document.getElementById('repeater-method').value;
  const rawUrl = document.getElementById('repeater-url').value.trim();
  const headers = getRepeaterHeaders();
  const methodsWithBody = ['POST', 'PUT', 'PATCH'];
  const bodyTextarea = document.getElementById('repeater-body');
  const body = methodsWithBody.includes(method) ? bodyTextarea.value : null;

  // Validate and possibly correct the URL
  const validation = validateRepeaterUrl(rawUrl);

  return {
    method: method,
    url: validation.valid ? validation.url : rawUrl,
    headers: headers,
    body: body,
    bodyMode: _repeaterBodyMode
  };
}

// ──────────────────────────────────────────────
// 6. validateRepeaterUrl(url)
// ──────────────────────────────────────────────
// Validates and normalises a URL string.
// Returns: { valid: boolean, url: string, error: string|null }
//
// Rules:
//  - Empty URL         -> invalid, error message
//  - No protocol       -> auto-prepend http:// then re-validate
//  - Protocol ALLOWLIST: only http: and https: are accepted
//  - Parse error       -> invalid, error message
//
// On validation failure the function also:
//  - Shows the inline #repeater-url-error element
//  - Adds .invalid class to #repeater-url input
//  - Calls showMessage() for a toast notification

function validateRepeaterUrl(url) {
  const urlInput = document.getElementById('repeater-url');
  const urlError = document.getElementById('repeater-url-error');

  // Helper: show an inline validation error
  function showUrlError(message) {
    if (urlError) {
      urlError.textContent = message;
      urlError.style.display = 'block';
    }
    if (urlInput) {
      urlInput.classList.add('invalid');
      urlInput.setAttribute('aria-invalid', 'true');
    }
    if (typeof showMessage === 'function') {
      showMessage(message, 'error');
    }
  }

  // Helper: clear any previous validation error
  function clearUrlError() {
    if (urlError) {
      urlError.textContent = '';
      urlError.style.display = 'none';
    }
    if (urlInput) {
      urlInput.classList.remove('invalid');
      urlInput.removeAttribute('aria-invalid');
    }
  }

  // Empty URL
  if (!url || url.trim() === '') {
    showUrlError('Please enter a URL');
    return { valid: false, url: url || '', error: 'Please enter a URL' };
  }

  // Auto-prepend http:// if no protocol is present
  let correctedUrl = url.trim();
  if (!/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//.test(correctedUrl)) {
    correctedUrl = 'http://' + correctedUrl;

    // Also update the input field so the user sees the corrected URL
    if (urlInput) {
      urlInput.value = correctedUrl;
    }
  }

  // Parse and validate
  let parsed;
  try {
    parsed = new URL(correctedUrl);
  } catch (e) {
    showUrlError('Invalid URL format');
    return { valid: false, url: correctedUrl, error: 'Invalid URL format' };
  }

  // Protocol allowlist: ONLY http: and https:
  const allowedProtocols = ['http:', 'https:'];
  if (!allowedProtocols.includes(parsed.protocol)) {
    var protocolError = 'Only http:// and https:// URLs are allowed';
    showUrlError(protocolError);
    return { valid: false, url: correctedUrl, error: protocolError };
  }

  // Valid
  clearUrlError();
  return { valid: true, url: correctedUrl, error: null };
}

// ──────────────────────────────────────────────
// 7. getRepeaterHeaders()
// ──────────────────────────────────────────────
// Reads all .repeater-header-row elements and returns a plain object of
// key-value pairs. Rows where the key input is empty are skipped.

function getRepeaterHeaders() {
  const headers = {};
  const rows = document.querySelectorAll('.repeater-header-row');

  rows.forEach(function(row) {
    const keyInput = row.querySelector('.repeater-header-key');
    const valueInput = row.querySelector('.repeater-header-value');

    if (keyInput && valueInput) {
      const key = keyInput.value.trim();
      if (key !== '') {
        headers[key] = valueInput.value;
      }
    }
  });

  return headers;
}

// ──────────────────────────────────────────────
// 8. clearRepeaterForm()
// ──────────────────────────────────────────────
// Resets every field in the request builder to its default state:
//  - Method select -> GET
//  - URL input     -> empty
//  - Headers       -> all rows removed
//  - Body textarea -> empty
//  - Body mode     -> raw
//  - Body section  -> hidden (since default method is GET)
//  - URL error     -> cleared

function clearRepeaterForm() {
  // Reset method to GET
  var methodSelect = document.getElementById('repeater-method');
  if (methodSelect) {
    methodSelect.value = 'GET';
  }

  // Clear URL
  var urlInput = document.getElementById('repeater-url');
  if (urlInput) {
    urlInput.value = '';
    urlInput.classList.remove('invalid');
    urlInput.removeAttribute('aria-invalid');
  }

  // Clear inline URL error
  var urlError = document.getElementById('repeater-url-error');
  if (urlError) {
    urlError.textContent = '';
    urlError.style.display = 'none';
  }

  // Remove all header rows
  var container = document.getElementById('repeater-headers-container');
  if (container) {
    while (container.firstChild) {
      container.removeChild(container.firstChild);
    }
  }

  // Clear body textarea (but do NOT rely on visibility toggle for this)
  var bodyTextarea = document.getElementById('repeater-body');
  if (bodyTextarea) {
    bodyTextarea.value = '';
  }

  // Reset body mode to raw
  setRepeaterBodyMode('raw');

  // Hide body section (GET does not carry a body)
  var bodySection = document.getElementById('repeater-body-section');
  if (bodySection) {
    bodySection.style.display = 'none';
  }
}


// ============================================================================
// Repeater — Send Request Handler (Agent 4)
//
// Functions:
//   sendRepeaterRequest()   — Main send handler for #repeater-send-btn click
//   sendRepeaterMessage()   — Wraps chrome.runtime.sendMessage with 35s timeout
//   showRepeaterLoading()   — Shows loading state, disables send button
//   hideRepeaterLoading()   — Hides loading state, re-enables send button
//   showRepeaterError()     — Displays error in the response section
//
// Dependencies (from other agents):
//   getRepeaterRequestData()      — Agent 3 (form data collection)
//   validateRepeaterUrl()         — Agent 3 (URL validation)
//   displayRepeaterResponse()     — Agent 5 (response rendering)
//   addToRepeaterHistory()        — Agent 7 (history management)
//   saveRepeaterFormState()       — Agent 8 (session persistence)
// ============================================================================

/**
 * Main send handler, invoked when the user clicks #repeater-send-btn.
 *
 * Flow:
 *   1. Collect form data via getRepeaterRequestData()
 *   2. Validate the URL — show inline error and return early if invalid
 *   3. Enter loading state synchronously (disable button before any async work)
 *   4. Send the request via sendRepeaterMessage() with a 35s popup-side timeout
 *   5. On success: render response, record history, persist form state
 *   6. On error/timeout: display error in the response area
 *   7. Always: hide loading indicator and re-enable the send button
 */
async function sendRepeaterRequest() {
  // 1. Gather form data (method, url, headers, body)
  const requestData = getRepeaterRequestData();

  // 2. Validate URL — validateRepeaterUrl handles inline error display + toast
  const validation = validateRepeaterUrl(requestData.url);
  if (!validation.valid) {
    return;
  }
  // Use the possibly-corrected URL (e.g., auto-prepended http://)
  requestData.url = validation.url;

  // 3. Show loading state synchronously before any async work
  showRepeaterLoading();

  // 4. Record start time using Date.now() (not performance.now() — avoids
  //    precision issues when timing spans popup + service worker boundary)
  const startTime = Date.now();

  try {
    // 5. Send via chrome.runtime.sendMessage wrapped in a Promise with 35s timeout
    const response = await sendRepeaterMessage(requestData);

    // Attach client-side timing if the background did not provide its own
    if (response && !response.error) {
      const elapsed = Date.now() - startTime;
      // Prefer the background-measured timing (more accurate for network),
      // but fall back to popup-measured round-trip if absent
      if (response.timing === undefined || response.timing === null) {
        response.timing = elapsed;
      }
    }

    // 6a. Check for application-level errors returned by the background handler
    if (response && response.error) {
      showRepeaterError(response.error);
      return;
    }

    // 6b. Success path — render response, record history, persist form state
    displayRepeaterResponse(response);
    addToRepeaterHistory(requestData, response);

    // Persist form state to session storage so it survives popup close/reopen
    if (typeof saveRepeaterFormState === 'function') {
      saveRepeaterFormState();
    }
  } catch (error) {
    // 7. Error/timeout path — display in response area so user sees it
    showRepeaterError(error.message || 'An unexpected error occurred');
  } finally {
    // 8. Always re-enable the send button and hide loading
    hideRepeaterLoading();
  }
}

// ────────────────────────────────────────────────────────────────────────────
// sendRepeaterMessage(requestData)
// ────────────────────────────────────────────────────────────────────────────

/**
 * Wraps chrome.runtime.sendMessage in a Promise with a 35-second popup-side
 * timeout. This protects the popup from hanging forever if the service worker
 * is terminated mid-request (the callback would never fire).
 *
 * Pattern mirrors the existing checkCVEsWithTimeout approach at popup.js ~L1240.
 *
 * @param {Object} requestData - { method, url, headers, body }
 * @returns {Promise<Object>} The response object from the background handler
 */
function sendRepeaterMessage(requestData) {
  return new Promise((resolve, reject) => {
    const TIMEOUT_MS = 35000;

    const timeout = setTimeout(() => {
      reject(new Error(
        'Request timed out (35s) — the extension service worker may have been terminated'
      ));
    }, TIMEOUT_MS);

    try {
      chrome.runtime.sendMessage(
        {
          action: 'repeaterRequest',
          url: requestData.url,
          method: requestData.method,
          headers: requestData.headers,
          body: requestData.body
        },
        (response) => {
          clearTimeout(timeout);

          // Always check chrome.runtime.lastError first — if the service worker
          // was unloaded or the message port closed, this will be set.
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }

          resolve(response);
        }
      );
    } catch (error) {
      // Synchronous throw from sendMessage (e.g., extension context invalidated)
      clearTimeout(timeout);
      reject(error);
    }
  });
}

// ────────────────────────────────────────────────────────────────────────────
// showRepeaterLoading()
// ────────────────────────────────────────────────────────────────────────────

/**
 * Enters the "sending" loading state:
 *   - Disables #repeater-send-btn and changes its text to "Sending..."
 *   - Shows #repeater-loading indicator
 *   - Clears any previous response content and errors so stale data is not
 *     visible while the new request is in flight
 */
function showRepeaterLoading() {
  // Disable the send button immediately (synchronous, before async work)
  const sendBtn = document.getElementById('repeater-send-btn');
  if (sendBtn) {
    sendBtn.disabled = true;
    sendBtn.textContent = 'Sending...';
  }

  // Show the loading spinner
  const loading = document.getElementById('repeater-loading');
  if (loading) {
    loading.style.display = '';
  }

  // Clear previous response data so stale results are not confusing
  const statusEl = document.getElementById('repeater-response-status');
  if (statusEl) {
    statusEl.textContent = '';
    statusEl.className = '';
  }

  const timeEl = document.getElementById('repeater-response-time');
  if (timeEl) {
    timeEl.textContent = '';
  }

  const bodyEl = document.getElementById('repeater-response-body');
  if (bodyEl) {
    bodyEl.textContent = '';
  }

  const headersContent = document.getElementById('repeater-response-headers-content');
  if (headersContent) {
    headersContent.textContent = '';
  }
}

// ────────────────────────────────────────────────────────────────────────────
// hideRepeaterLoading()
// ────────────────────────────────────────────────────────────────────────────

/**
 * Exits the loading state:
 *   - Hides #repeater-loading indicator
 *   - Re-enables #repeater-send-btn and restores its label to "Send"
 */
function hideRepeaterLoading() {
  const loading = document.getElementById('repeater-loading');
  if (loading) {
    loading.style.display = 'none';
  }

  const sendBtn = document.getElementById('repeater-send-btn');
  if (sendBtn) {
    sendBtn.disabled = false;
    sendBtn.textContent = 'Send';
  }
}

// ────────────────────────────────────────────────────────────────────────────
// showRepeaterError(message)
// ────────────────────────────────────────────────────────────────────────────

/**
 * Displays a network / timeout error in the response section so the user can
 * see what went wrong without opening DevTools.
 *
 * - Sets #repeater-response-status text to "Error" with the status-error class
 *   (red badge styling from repeater-styles.css)
 * - Sets #repeater-response-body textContent to the error message
 * - Clears the timing display since no valid timing exists
 *
 * Uses .textContent exclusively — never .innerHTML with untrusted content.
 *
 * @param {string} message - Human-readable error description
 */
function showRepeaterError(message) {
  const statusEl = document.getElementById('repeater-response-status');
  if (statusEl) {
    statusEl.textContent = 'Error';
    // Clear all status classes and apply the error class
    statusEl.className = 'repeater-status-badge status-error';
  }

  const timeEl = document.getElementById('repeater-response-time');
  if (timeEl) {
    timeEl.textContent = '';
  }

  const bodyEl = document.getElementById('repeater-response-body');
  if (bodyEl) {
    // Use textContent only — safe against XSS
    bodyEl.textContent = message;
  }

  // Clear response headers since there are none on error
  const headersContent = document.getElementById('repeater-response-headers-content');
  if (headersContent) {
    headersContent.textContent = '';
  }
}


// ============================================================
// Repeater Tab — Response Display Functions
// ============================================================
//
// These functions render HTTP responses received from the
// background script into the Repeater response viewer.
//
// SECURITY: All server-provided content is rendered via
// textContent or safe DOM APIs (createTextNode, createElement).
// innerHTML / insertAdjacentHTML are NEVER used with response data.
// ============================================================

/**
 * Main entry point: render a response object into the response viewer.
 *
 * @param {Object} response
 * @param {number}       response.status     - HTTP status code (0 for network error)
 * @param {string}       response.statusText - HTTP status text
 * @param {Object}       response.headers    - Response headers as key-value pairs
 * @param {string}       response.body       - Response body text
 * @param {number}       response.timing     - Request duration in ms
 * @param {string|null}  response.error      - Error message if failed
 * @param {boolean}      response.truncated  - Whether body was truncated
 * @param {number}       response.size       - Total response size in bytes
 */
function displayRepeaterResponse(response) {
  const statusEl = document.getElementById('repeater-response-status');
  const headersEl = document.getElementById('repeater-response-headers');
  const bodyEl = document.getElementById('repeater-response-body');
  const timeEl = document.getElementById('repeater-response-time');

  if (!statusEl || !bodyEl) return;

  // --- 1. Clear previous response ---
  statusEl.textContent = '';
  statusEl.className = 'repeater-status-badge';
  if (bodyEl) bodyEl.textContent = '';
  if (timeEl) timeEl.textContent = '';

  // --- 2. Display status with color coding ---
  if (response.error) {
    statusEl.textContent = 'Error';
    statusEl.className = 'repeater-status-badge status-error';
  } else {
    const statusText = response.statusText ? ` ${response.statusText}` : '';
    statusEl.textContent = `${response.status}${statusText}`;
    statusEl.className = `repeater-status-badge ${getRepeaterStatusClass(response.status)}`;
  }

  // --- 3. Display timing ---
  if (timeEl) {
    timeEl.textContent = response.timing ? `${response.timing}ms` : '';
  }

  // --- 4. Display response headers (collapsible) ---
  if (headersEl) {
    displayRepeaterResponseHeaders(headersEl, response.headers);
  }

  // --- 5. Display response body ---
  if (bodyEl) {
    displayRepeaterResponseBody(bodyEl, response);
  }
}

/**
 * Return a CSS class name based on the HTTP status code range.
 *
 * @param {number} statusCode
 * @returns {string} CSS class name
 */
function getRepeaterStatusClass(statusCode) {
  if (statusCode >= 200 && statusCode <= 299) return 'status-2xx';
  if (statusCode >= 300 && statusCode <= 399) return 'status-3xx';
  if (statusCode >= 400 && statusCode <= 499) return 'status-4xx';
  if (statusCode >= 500 && statusCode <= 599) return 'status-5xx';
  return 'status-error';
}

/**
 * Render response headers into a collapsible section.
 *
 * The container (#repeater-response-headers) already contains a
 * toggle button and a content div in the HTML skeleton:
 *   <button id="repeater-response-headers-toggle" ...>
 *   <div id="repeater-response-headers-content" ...>
 *
 * @param {HTMLElement} container - The #repeater-response-headers element
 * @param {Object}      headers  - Key-value header pairs
 */
function displayRepeaterResponseHeaders(container, headers) {
  const contentEl = document.getElementById('repeater-response-headers-content');
  const toggleBtn = document.getElementById('repeater-response-headers-toggle');

  if (!contentEl) return;

  // Clear previous header content (safe — no server data involved)
  contentEl.textContent = '';

  if (!headers || Object.keys(headers).length === 0) {
    contentEl.textContent = '(no headers)';
    // Make sure the content is visible and the toggle is wired up
    contentEl.style.display = '';
    return;
  }

  // Build header text as "key: value\n" pairs using textContent (safe)
  const headerLines = Object.entries(headers)
    .map(([key, value]) => `${key}: ${value}`)
    .join('\n');

  const preEl = document.createElement('pre');
  preEl.style.margin = '0';
  preEl.style.fontSize = '12px';
  preEl.style.whiteSpace = 'pre-wrap';
  preEl.style.wordBreak = 'break-all';
  preEl.textContent = headerLines;

  contentEl.appendChild(preEl);

  // Ensure the headers content is visible by default after a response arrives
  contentEl.style.display = '';

  // Wire up the toggle button (idempotent — uses onclick assignment)
  if (toggleBtn) {
    toggleBtn.onclick = toggleRepeaterResponseHeaders;
  }
}

/**
 * Toggle visibility of the response headers content section.
 */
function toggleRepeaterResponseHeaders() {
  const contentEl = document.getElementById('repeater-response-headers-content');
  const toggleBtn = document.getElementById('repeater-response-headers-toggle');

  if (!contentEl) return;

  const isHidden = contentEl.style.display === 'none';
  contentEl.style.display = isHidden ? '' : 'none';

  // Update the toggle arrow indicator
  if (toggleBtn) {
    // Replace the last character (arrow) with the appropriate direction
    const label = 'Response Headers';
    toggleBtn.textContent = isHidden ? `${label} \u25BC` : `${label} \u25B6`;
  }
}

/**
 * Render the response body safely into the container.
 *
 * Rules:
 * - Error responses: show error message via textContent
 * - 204 / empty body: show "(empty)" or "No Content"
 * - JSON: pretty-print and apply syntax highlighting via safe DOM fragment
 * - HTML / other: display raw text via textContent (never render HTML)
 * - Truncated: append a truncation notice
 *
 * @param {HTMLElement} container - The #repeater-response-body <pre> element
 * @param {Object}      response - The full response object
 */
function displayRepeaterResponseBody(container, response) {
  // Clear previous content safely
  container.textContent = '';

  // --- Error state ---
  if (response.error) {
    container.textContent = response.error;
    return;
  }

  // --- 204 No Content or empty body ---
  if (response.status === 204 || (!response.body && response.body !== '0')) {
    container.textContent = '(empty)';
    return;
  }

  // --- Detect JSON content ---
  const contentType = getContentTypeFromHeaders(response.headers);
  let isJson = false;
  let parsedJson = null;

  if (contentType && contentType.includes('application/json')) {
    isJson = true;
  }

  // Try to parse as JSON regardless of content-type (servers sometimes lie)
  if (response.body) {
    try {
      parsedJson = JSON.parse(response.body);
      isJson = true;
    } catch (_e) {
      // Not valid JSON — fall through to plain text
    }
  }

  if (isJson && parsedJson !== null) {
    // Pretty-print the JSON
    const prettyJson = JSON.stringify(parsedJson, null, 2);

    // Try to use syntaxHighlightJSON from Agent 6 if available
    if (typeof syntaxHighlightJSON === 'function') {
      container.textContent = ''; // Clear safely before appending fragment
      const fragment = syntaxHighlightJSON(prettyJson);
      container.appendChild(fragment);
    } else {
      // Fallback: build a highlighted fragment ourselves
      container.textContent = ''; // Clear safely
      const fragment = buildJsonHighlightFragment(prettyJson);
      container.appendChild(fragment);
    }
  } else {
    // --- Plain text / HTML / binary / everything else ---
    // Always use textContent to prevent XSS — HTML tags are shown as raw text
    container.textContent = response.body;
  }

  // --- Truncation notice ---
  if (response.truncated) {
    const notice = document.createElement('div');
    notice.style.color = 'var(--text-secondary, #999)';
    notice.style.fontStyle = 'italic';
    notice.style.marginTop = '8px';
    notice.style.borderTop = '1px solid var(--border-color, #333)';
    notice.style.paddingTop = '4px';
    const sizeLabel = response.size ? formatBytes(response.size) : 'unknown';
    notice.textContent = `[Response truncated at ${sizeLabel}]`;
    container.appendChild(notice);
  }
}

/**
 * Extract the Content-Type value from a headers object (case-insensitive).
 *
 * @param {Object} headers
 * @returns {string|null}
 */
function getContentTypeFromHeaders(headers) {
  if (!headers) return null;
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === 'content-type') {
      return value.toLowerCase();
    }
  }
  return null;
}

/**
 * Build a DocumentFragment with syntax-highlighted JSON.
 *
 * This is the built-in fallback used when the external
 * syntaxHighlightJSON function (from Agent 6) is not yet loaded.
 * It uses ONLY safe DOM APIs: createTextNode, createElement.
 * No innerHTML is ever used.
 *
 * @param {string} jsonString - Pretty-printed JSON string
 * @returns {DocumentFragment}
 */
function buildJsonHighlightFragment(jsonString) {
  const fragment = document.createDocumentFragment();

  // Regex to match JSON tokens on each line
  // Matches: strings (keys and values), numbers, booleans, null
  const tokenRegex = /("(?:[^"\\]|\\.)*")\s*:/g;
  const valueRegex = /:\s*("(?:[^"\\]|\\.)*"|true|false|null|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;

  // Process line by line to keep things manageable
  const lines = jsonString.split('\n');

  for (let i = 0; i < lines.length; i++) {
    if (i > 0) {
      fragment.appendChild(document.createTextNode('\n'));
    }

    const line = lines[i];
    let lastIndex = 0;
    const tokens = [];

    // Find all tokens in this line and their positions
    // We'll use a comprehensive regex that matches all JSON tokens
    const allTokenRegex = /("(?:[^"\\]|\\.)*")(\s*:)?|(\btrue\b|\bfalse\b|\bnull\b)|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;
    let match;

    while ((match = allTokenRegex.exec(line)) !== null) {
      // Add any text before this token as plain text
      if (match.index > lastIndex) {
        tokens.push({
          type: 'plain',
          text: line.substring(lastIndex, match.index),
        });
      }

      if (match[1]) {
        // It's a string
        if (match[2]) {
          // String followed by colon — it's a key
          tokens.push({ type: 'key', text: match[1] });
          tokens.push({ type: 'plain', text: match[2] }); // the ": " part
        } else {
          // String value
          tokens.push({ type: 'string', text: match[1] });
        }
      } else if (match[3]) {
        // Boolean or null
        if (match[3] === 'null') {
          tokens.push({ type: 'null', text: match[3] });
        } else {
          tokens.push({ type: 'bool', text: match[3] });
        }
      } else if (match[4]) {
        // Number
        tokens.push({ type: 'number', text: match[4] });
      }

      lastIndex = match.index + match[0].length;
    }

    // Add remaining text on this line
    if (lastIndex < line.length) {
      tokens.push({ type: 'plain', text: line.substring(lastIndex) });
    }

    // Build DOM nodes from tokens
    for (const token of tokens) {
      if (token.type === 'plain') {
        fragment.appendChild(document.createTextNode(token.text));
      } else {
        const span = document.createElement('span');
        // Use both prefixed (for CSS styling) and unprefixed (for test matching) class names
        const classMap = {
          key: 'json-key repeater-json-key',
          string: 'json-string repeater-json-string',
          number: 'json-number repeater-json-number',
          bool: 'json-bool repeater-json-bool',
          null: 'json-null repeater-json-null',
        };
        span.className = classMap[token.type] || '';
        span.appendChild(document.createTextNode(token.text));
        fragment.appendChild(span);
      }
    }
  }

  return fragment;
}

/**
 * Format a byte count into a human-readable string.
 *
 * @param {number} bytes
 * @returns {string}
 */
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const k = 1024;
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const value = bytes / Math.pow(k, i);
  return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}


/**
 * syntaxHighlightJSON(jsonString)
 *
 * Takes a pre-formatted JSON string (already passed through
 * JSON.stringify(parsed, null, 2)) and returns a DocumentFragment
 * with colored <span> elements for syntax tokens.
 *
 * SECURITY: This function NEVER uses innerHTML, insertAdjacentHTML,
 * or any other HTML parsing method. All DOM construction uses only
 * safe APIs: createDocumentFragment, createElement, createTextNode,
 * className assignment, and appendChild.
 *
 * CSS classes applied (defined in repeater-styles.css):
 *   .repeater-json-key    — object keys (blue)
 *   .repeater-json-string  — string values (orange)
 *   .repeater-json-number  — numeric values (green)
 *   .repeater-json-bool    — true/false (purple)
 *   .repeater-json-null    — null (muted)
 *
 * @param {string} jsonString - A pre-formatted JSON string
 * @returns {DocumentFragment} Fragment with colored spans for each token
 */
function syntaxHighlightJSON(jsonString) {
  const fragment = document.createDocumentFragment();

  // Performance guard: skip highlighting for very large JSON (>50KB)
  // to avoid UI jank from thousands of DOM nodes.
  if (jsonString.length > 50000) {
    fragment.appendChild(document.createTextNode(jsonString));
    return fragment;
  }

  // Regex matches JSON tokens in order of priority:
  //   Group 1 — Keys: a quoted string immediately followed by optional whitespace and a colon
  //   Group 2 — String values: any other quoted string
  //   Group 3 — Numbers: integer, decimal, and scientific notation (negative allowed)
  //   Group 4 — Booleans: true or false
  //   Group 5 — Null: null
  //   Group 6 — Structural characters: braces, brackets, colons, commas, and whitespace
  //
  // The quoted-string pattern "(?:\\.|[^"\\])*" correctly handles:
  //   - Escaped quotes: \"
  //   - Escaped backslashes: \\
  //   - Unicode escapes: \u0041
  //   - Strings containing JSON-like content: "{\"nested\": true}"
  const tokenRegex = /("(?:\\.|[^"\\])*")\s*(?=:)|("(?:\\.|[^"\\])*")|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)\b|(true|false)\b|(null)\b|([{}[\]:,\s]+)/g;

  let lastIndex = 0;
  let match;

  while ((match = tokenRegex.exec(jsonString)) !== null) {
    // If the regex skipped over any characters (shouldn't happen with
    // well-formed JSON, but handle defensively), emit them as plain text.
    if (match.index > lastIndex) {
      fragment.appendChild(
        document.createTextNode(jsonString.slice(lastIndex, match.index))
      );
    }

    if (match[6] !== undefined) {
      // Structural characters and whitespace — no coloring, just text nodes
      fragment.appendChild(document.createTextNode(match[6]));
      lastIndex = tokenRegex.lastIndex;
      continue;
    }

    const span = document.createElement('span');

    if (match[1] !== undefined) {
      // JSON object key
      span.className = 'repeater-json-key';
      span.appendChild(document.createTextNode(match[1]));
    } else if (match[2] !== undefined) {
      // String value
      span.className = 'repeater-json-string';
      span.appendChild(document.createTextNode(match[2]));
    } else if (match[3] !== undefined) {
      // Number value
      span.className = 'repeater-json-number';
      span.appendChild(document.createTextNode(match[3]));
    } else if (match[4] !== undefined) {
      // Boolean value (true / false)
      span.className = 'repeater-json-bool';
      span.appendChild(document.createTextNode(match[4]));
    } else if (match[5] !== undefined) {
      // Null value
      span.className = 'repeater-json-null';
      span.appendChild(document.createTextNode(match[5]));
    }

    fragment.appendChild(span);
    lastIndex = tokenRegex.lastIndex;
  }

  // Emit any remaining unmatched text at the end of the string
  if (lastIndex < jsonString.length) {
    fragment.appendChild(
      document.createTextNode(jsonString.slice(lastIndex))
    );
  }

  return fragment;
}


// ──────────────────────────────────────────────
// Repeater History Module
// ──────────────────────────────────────────────
// Manages the request history list for the Repeater tab.
// Entries are stored in chrome.storage.local under 'repeater_history',
// capped at 50 entries, newest first. Body content is truncated to 10KB
// per entry to avoid storage quota issues.
//
// Dependencies (defined in other repeater modules):
//   - addRepeaterHeader()          from repeater-request-builder.js
//   - setRepeaterBodyMode(mode)    from repeater-request-builder.js
//   - toggleRepeaterBodyVisibility() from repeater-request-builder.js
//
// DOM contract (element IDs / classes):
//   - #repeater-history-list        — container for history items
//   - #repeater-history-empty       — empty-state message element
//   - .repeater-history-item        — individual history entry div
//   - .repeater-history-method      — method badge span
//   - .repeater-history-url         — truncated URL span
//   - .repeater-history-status      — status code span
//   - #repeater-method              — method <select>
//   - #repeater-url                 — URL <input>
//   - #repeater-headers-container   — header rows container
//   - #repeater-body                — body <textarea>
//   - #repeater-clear-history-btn   — clear history button

// ──────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────

const REPEATER_HISTORY_KEY = 'repeater_history';
const REPEATER_MAX_HISTORY = 50;
const REPEATER_MAX_BODY_STORAGE = 10240; // 10KB per entry

// ──────────────────────────────────────────────
// Module State
// ──────────────────────────────────────────────

let _repeaterHistory = [];
let _repeaterHistoryWriteChain = Promise.resolve();

// ──────────────────────────────────────────────
// 1. addToRepeaterHistory(requestData, response)
// ──────────────────────────────────────────────
// Called after a request completes (from sendRepeaterRequest).
// Creates a history entry from the request data and response, adds it to the
// in-memory array (newest first), renders it immediately, and persists to
// chrome.storage.local. Writes are serialized via _repeaterHistoryWriteChain
// to prevent read-modify-write race conditions.

function addToRepeaterHistory(requestData, response) {
  var entry = {
    id: Date.now() + '-' + Math.random().toString(36).substr(2, 9),
    timestamp: Date.now(),
    method: requestData.method,
    url: requestData.url,
    headers: requestData.headers || {},
    body: requestData.body ? requestData.body.substring(0, REPEATER_MAX_BODY_STORAGE) : null,
    bodyMode: requestData.bodyMode || 'raw',
    status: response.status || 0,
    statusText: response.statusText || '',
    responseBody: (response.body || '').substring(0, REPEATER_MAX_BODY_STORAGE),
    responseHeaders: response.headers || {},
    timing: response.timing || 0,
    error: response.error || null,
  };

  // Add to in-memory array (newest first)
  _repeaterHistory.unshift(entry);
  if (_repeaterHistory.length > REPEATER_MAX_HISTORY) {
    _repeaterHistory = _repeaterHistory.slice(0, REPEATER_MAX_HISTORY);
  }

  // Render immediately (prepend to top of list)
  renderRepeaterHistoryItem(entry, true);

  // Serialize writes to chrome.storage.local to avoid race conditions
  _repeaterHistoryWriteChain = _repeaterHistoryWriteChain.then(function () {
    return new Promise(function (resolve) {
      chrome.storage.local.set({ [REPEATER_HISTORY_KEY]: _repeaterHistory }, function () {
        if (chrome.runtime.lastError) {
          console.warn('Repeater: Failed to save history:', chrome.runtime.lastError.message);
        }
        resolve();
      });
    });
  });

  // Update empty state visibility
  updateRepeaterHistoryEmptyState();
}

// ──────────────────────────────────────────────
// 2. loadRepeaterHistory()
// ──────────────────────────────────────────────
// Loads history from chrome.storage.local and renders the full list.
// Called during repeater tab initialization and when switching back
// to the repeater tab.

function loadRepeaterHistory() {
  chrome.storage.local.get([REPEATER_HISTORY_KEY], function (data) {
    _repeaterHistory = data[REPEATER_HISTORY_KEY] || [];
    renderRepeaterHistoryList();
  });
}

// ──────────────────────────────────────────────
// 3. renderRepeaterHistoryList()
// ──────────────────────────────────────────────
// Clears #repeater-history-list and re-renders all history items.
// Called by loadRepeaterHistory() after loading from storage.

function renderRepeaterHistoryList() {
  var list = document.getElementById('repeater-history-list');
  if (!list) return;

  // Clear existing items
  list.textContent = '';

  // Render each entry (array is already newest-first)
  for (var i = 0; i < _repeaterHistory.length; i++) {
    renderRepeaterHistoryItem(_repeaterHistory[i], false);
  }

  updateRepeaterHistoryEmptyState();
}

// ──────────────────────────────────────────────
// 4. renderRepeaterHistoryItem(entry, prepend)
// ──────────────────────────────────────────────
// Creates a .repeater-history-item div for a single history entry and
// appends (or prepends) it to #repeater-history-list.
//
// Structure:
//   <div class="repeater-history-item" data-history-id="...">
//     <span class="repeater-history-method method-{method}">{METHOD}</span>
//     <span class="repeater-history-url">{truncated URL path}</span>
//     <span class="repeater-history-status">{status}</span>
//   </div>
//
// All dynamic values are set via textContent (XSS safe).
// Adds a click listener to load the entry into the request builder.

function renderRepeaterHistoryItem(entry, prepend) {
  var list = document.getElementById('repeater-history-list');
  if (!list) return;

  var item = document.createElement('div');
  item.className = 'repeater-history-item';
  item.setAttribute('data-history-id', entry.id);

  // Method badge
  var methodSpan = document.createElement('span');
  methodSpan.className = 'repeater-history-method method-' + entry.method.toLowerCase();
  methodSpan.textContent = entry.method;

  // URL (show pathname, truncated for display)
  var urlSpan = document.createElement('span');
  urlSpan.className = 'repeater-history-url';
  urlSpan.textContent = truncateHistoryUrl(entry.url);

  // Status code
  var statusSpan = document.createElement('span');
  statusSpan.className = 'repeater-history-status';
  statusSpan.textContent = entry.status ? String(entry.status) : '';

  item.appendChild(methodSpan);
  item.appendChild(urlSpan);
  item.appendChild(statusSpan);

  // Click handler loads entry into the request builder
  item.addEventListener('click', function () {
    loadRepeaterHistoryItem(entry);
  });

  if (prepend) {
    list.insertBefore(item, list.firstChild);
  } else {
    list.appendChild(item);
  }
}

// ──────────────────────────────────────────────
// 5. loadRepeaterHistoryItem(entry)
// ──────────────────────────────────────────────
// Populates the request builder form from a history entry.
// Sets method, URL, headers, body mode, and body content.
// Does NOT automatically re-send the request.

function loadRepeaterHistoryItem(entry) {
  // Set method
  var methodSelect = document.getElementById('repeater-method');
  if (methodSelect) {
    methodSelect.value = entry.method;
  }

  // Set URL
  var urlInput = document.getElementById('repeater-url');
  if (urlInput) {
    urlInput.value = entry.url;
  }

  // Clear existing headers
  var headersContainer = document.getElementById('repeater-headers-container');
  if (headersContainer) {
    headersContainer.textContent = '';
  }

  // Add headers from the history entry
  var headers = entry.headers || {};
  var headerKeys = Object.keys(headers);
  for (var i = 0; i < headerKeys.length; i++) {
    var key = headerKeys[i];
    var value = headers[key];

    // Use the shared addRepeaterHeader() to create the row,
    // then populate its inputs
    if (typeof addRepeaterHeader === 'function') {
      addRepeaterHeader();
    }

    var rows = headersContainer.querySelectorAll('.repeater-header-row');
    var lastRow = rows[rows.length - 1];
    if (lastRow) {
      var keyInput = lastRow.querySelector('.repeater-header-key');
      var valueInput = lastRow.querySelector('.repeater-header-value');
      if (keyInput) keyInput.value = key;
      if (valueInput) valueInput.value = value;
    }
  }

  // Set body mode
  var bodyMode = entry.bodyMode || 'raw';
  if (typeof setRepeaterBodyMode === 'function') {
    setRepeaterBodyMode(bodyMode);
  }

  // Set body content
  var bodyTextarea = document.getElementById('repeater-body');
  if (bodyTextarea) {
    bodyTextarea.value = entry.body || '';
  }

  // Toggle body section visibility based on method
  if (typeof toggleRepeaterBodyVisibility === 'function') {
    toggleRepeaterBodyVisibility();
  }
}

// ──────────────────────────────────────────────
// 6. clearRepeaterHistory()
// ──────────────────────────────────────────────
// Clears all history entries from memory, storage, and the DOM.

function clearRepeaterHistory() {
  _repeaterHistory = [];
  chrome.storage.local.remove(REPEATER_HISTORY_KEY);

  var list = document.getElementById('repeater-history-list');
  if (list) {
    list.textContent = '';
  }

  updateRepeaterHistoryEmptyState();
}

// ──────────────────────────────────────────────
// 7. updateRepeaterHistoryEmptyState()
// ──────────────────────────────────────────────
// Shows #repeater-history-empty when there are no history entries,
// hides it when there are entries.

function updateRepeaterHistoryEmptyState() {
  var emptyState = document.getElementById('repeater-history-empty');
  if (!emptyState) return;

  if (_repeaterHistory.length === 0) {
    emptyState.style.display = 'block';
  } else {
    emptyState.style.display = 'none';
  }
}

// ──────────────────────────────────────────────
// Helper: truncateHistoryUrl(url)
// ──────────────────────────────────────────────
// Extracts the pathname (+ query) from a URL for compact display.
// Falls back to the raw URL string if parsing fails.
// Truncates to 60 characters max.

function truncateHistoryUrl(url) {
  var display = url;
  try {
    var parsed = new URL(url);
    display = parsed.pathname + parsed.search;
  } catch (e) {
    // If URL parsing fails, use the raw URL
    display = url;
  }

  var maxLength = 60;
  if (display.length > maxLength) {
    return display.substring(0, maxLength - 3) + '...';
  }
  return display;
}


// ============================================================================
// Repeater — Initialization, Event Wiring, and State Persistence (Agent 9)
//
// This file contains:
//   1. Event listener registrations      (to add into setupEventListeners())
//   2. Tab switch hook                   (to add into setupTabs())
//   3. saveRepeaterFormState()           — persist form to chrome.storage.session
//   4. restoreRepeaterFormState()        — restore form from chrome.storage.session
//   5. addRepeaterHeaderRow(key, value)  — create a pre-filled header row
//   6. debounceRepeaterStateSave         — debounced wrapper for save
//   7. DOMContentLoaded hook             — initial form state restore
//   8. openCurlImport()                  — show the curl import section
//   9. confirmCurlImport()               — parse and apply a pasted curl command
//  10. cancelCurlImport()                — close the curl import section
//  11. exportAsCurl()                    — build a curl string from current form
//  12. parseCurlCommand(curlString)      — parse a curl command into request data
//
// Architecture note:
//   The existing codebase registers ALL event listeners eagerly inside
//   setupEventListeners(), which runs at DOMContentLoaded. Only DATA LOADING
//   is deferred to tab switch. The Repeater follows this same pattern:
//     - Event listeners  -> setupEventListeners() (eager, at DOMContentLoaded)
//     - Data loading     -> setupTabs() tab click handler (lazy, on tab switch)
//
// Dependencies (from other repeater modules):
//   - sendRepeaterRequest()             from repeater-send-request.js
//   - addRepeaterHeader()               from repeater-request-builder.js
//   - removeRepeaterHeader(event)       from repeater-request-builder.js
//   - toggleRepeaterBodyVisibility()    from repeater-request-builder.js
//   - setRepeaterBodyMode(mode)         from repeater-request-builder.js
//   - getRepeaterHeaders()              from repeater-request-builder.js
//   - clearRepeaterForm()               from repeater-request-builder.js
//   - loadRepeaterHistory()             from repeater-history.js
//   - clearRepeaterHistory()            from repeater-history.js
//   - toggleRepeaterResponseHeaders()   from repeater-response-display.js
//   - showMessage(text, type)           from popup.js (line 3811)
//   - _repeaterBodyMode                 from repeater-request-builder.js
//
// DOM contract (element IDs referenced):
//   #repeater-send-btn                  — Send button
//   #repeater-add-header-btn            — Add header button
//   #repeater-method                    — HTTP method select
//   #repeater-url                       — URL input
//   #repeater-body                      — Body textarea
//   #repeater-body-section              — Body section container
//   #repeater-body-mode-raw             — Raw body mode button
//   #repeater-body-mode-json            — JSON body mode button
//   #repeater-body-mode-form-data       — Form-data body mode button
//   #repeater-headers-container         — Header rows container
//   #repeater-import-curl-btn           — Import curl button
//   #repeater-export-curl-btn           — Export curl button
//   #repeater-clear-history-btn         — Clear history button
//   #repeater-curl-input                — Curl input textarea
//   #repeater-curl-import-confirm-btn   — Curl import confirm button
//   #repeater-curl-import-cancel-btn    — Curl import cancel button
//   #repeater-curl-import-error         — Curl import inline error
//   #repeater-curl-section              — Curl import section (collapsible)
//   #repeater-curl-output               — Curl export output <pre>
//   #repeater-response-headers-toggle   — Response headers toggle button
// ============================================================================


// ──────────────────────────────────────────────
// Debounce State (module-level)
// ──────────────────────────────────────────────

let _repeaterStateSaveTimeout = null;


// ============================================================================
// 1. ADD TO setupEventListeners()
// ============================================================================
// Paste the body of this function into the existing setupEventListeners() in
// popup.js, just before the closing brace. All listeners are registered
// eagerly at DOMContentLoaded, regardless of which tab is currently visible.

function setupRepeaterEventListeners() {
  // --- Send button ---
  document.getElementById('repeater-send-btn').addEventListener('click', sendRepeaterRequest);

  // --- Add header button ---
  document.getElementById('repeater-add-header-btn').addEventListener('click', addRepeaterHeader);

  // --- Method change: toggle body visibility ---
  document.getElementById('repeater-method').addEventListener('change', toggleRepeaterBodyVisibility);

  // --- Curl import / export / clear history ---
  document.getElementById('repeater-import-curl-btn').addEventListener('click', openCurlImport);
  document.getElementById('repeater-export-curl-btn').addEventListener('click', exportAsCurl);
  document.getElementById('repeater-clear-history-btn').addEventListener('click', clearRepeaterHistory);

  // --- Curl import confirm / cancel ---
  document.getElementById('repeater-curl-import-confirm-btn').addEventListener('click', confirmCurlImport);
  document.getElementById('repeater-curl-import-cancel-btn').addEventListener('click', cancelCurlImport);

  // --- Body mode buttons ---
  document.getElementById('repeater-body-mode-raw').addEventListener('click', function () {
    setRepeaterBodyMode('raw');
  });
  document.getElementById('repeater-body-mode-json').addEventListener('click', function () {
    setRepeaterBodyMode('json');
  });
  document.getElementById('repeater-body-mode-form-data').addEventListener('click', function () {
    setRepeaterBodyMode('form-data');
  });

  // --- Header remove buttons via event delegation on the container ---
  // A single listener on the container handles all current and future remove
  // buttons, avoiding the need to attach listeners to each row individually.
  document.getElementById('repeater-headers-container').addEventListener('click', function (e) {
    if (e.target.classList.contains('repeater-remove-header-btn')) {
      removeRepeaterHeader(e);
    }
  });

  // --- Response headers toggle (collapsible) ---
  var repeaterHeadersToggle = document.getElementById('repeater-response-headers-toggle');
  if (repeaterHeadersToggle) {
    repeaterHeadersToggle.addEventListener('click', toggleRepeaterResponseHeaders);
  }

  // --- Save form state on meaningful changes (debounced) ---
  // Listen on both 'input' (keystrokes in text fields) and 'change' (select
  // dropdown changes) to capture all user edits without firing on every
  // keystroke (the debounce collapses rapid events into a single save).
  var stateSaveIds = ['repeater-method', 'repeater-url', 'repeater-body'];
  for (var i = 0; i < stateSaveIds.length; i++) {
    var el = document.getElementById(stateSaveIds[i]);
    if (el) {
      el.addEventListener('input', debounceRepeaterStateSave);
      el.addEventListener('change', debounceRepeaterStateSave);
    }
  }
}


// ============================================================================
// 2. ADD TO setupTabs()
// ============================================================================
// Paste this block into the tab click handler in setupTabs(), alongside the
// existing if (tabName === 'reports') / 'errors' / 'plugins' / etc. blocks.
// This defers data loading to tab switch, following the established pattern.

// --- Inside setupTabs(), within the btn click handler: ---
//
//   if (tabName === 'repeater') {
//     loadRepeaterHistory();
//     restoreRepeaterFormState();
//   }
//


// ============================================================================
// 3. saveRepeaterFormState()
// ============================================================================
// Persists the current Repeater form state to chrome.storage.session.
//
// chrome.storage.session is an MV3 API that survives popup close/reopen but
// is cleared when the browser closes. This is the correct scope for
// "in-progress" form data that the user hasn't explicitly saved.
//
// Saved fields: method, URL, body text, body mode, and all headers.

function saveRepeaterFormState() {
  var methodEl = document.getElementById('repeater-method');
  var urlEl = document.getElementById('repeater-url');
  var bodyEl = document.getElementById('repeater-body');

  var state = {
    method: methodEl ? methodEl.value : 'GET',
    url: urlEl ? urlEl.value : '',
    body: bodyEl ? bodyEl.value : '',
    bodyMode: (typeof _repeaterBodyMode !== 'undefined') ? _repeaterBodyMode : 'raw',
    headers: (typeof getRepeaterHeaders === 'function') ? getRepeaterHeaders() : {}
  };

  chrome.storage.session.set({ repeater_form_state: state }, function () {
    if (chrome.runtime.lastError) {
      console.warn('Repeater: Failed to save form state:', chrome.runtime.lastError.message);
    }
  });
}


// ============================================================================
// 4. restoreRepeaterFormState()
// ============================================================================
// Restores the Repeater form state from chrome.storage.session.
//
// Called in two places:
//   1. DOMContentLoaded (initial page load) — restores state if the popup was
//      closed and reopened during the same browser session.
//   2. Tab switch to 'repeater' — re-applies state in case the form was
//      modified by other actions (e.g., loading a history item then switching
//      tabs and back).
//
// The function is idempotent: calling it multiple times with the same stored
// state produces the same result.

function restoreRepeaterFormState() {
  chrome.storage.session.get(['repeater_form_state'], function (data) {
    var state = data.repeater_form_state;
    if (!state) return;

    // Restore method
    var methodEl = document.getElementById('repeater-method');
    if (methodEl) {
      methodEl.value = state.method || 'GET';
    }

    // Restore URL
    var urlEl = document.getElementById('repeater-url');
    if (urlEl) {
      urlEl.value = state.url || '';
    }

    // Restore body text
    var bodyEl = document.getElementById('repeater-body');
    if (bodyEl && state.body) {
      bodyEl.value = state.body;
    }

    // Restore body mode (updates the module-level _repeaterBodyMode variable
    // and toggles the active class on mode buttons)
    if (state.bodyMode && typeof setRepeaterBodyMode === 'function') {
      setRepeaterBodyMode(state.bodyMode);
    }

    // Restore headers
    if (state.headers) {
      var container = document.getElementById('repeater-headers-container');
      if (container) {
        // Clear any existing header rows before restoring
        container.textContent = '';

        var keys = Object.keys(state.headers);
        for (var i = 0; i < keys.length; i++) {
          var key = keys[i];
          if (key) {
            addRepeaterHeaderRow(key, state.headers[key]);
          }
        }
      }
    }

    // Update body section visibility based on restored method
    if (typeof toggleRepeaterBodyVisibility === 'function') {
      toggleRepeaterBodyVisibility();
    }
  });
}


// ============================================================================
// 5. addRepeaterHeaderRow(key, value)
// ============================================================================
// Helper that programmatically creates a header row with pre-filled key/value
// inputs. Unlike addRepeaterHeader() which creates an empty row for the user
// to fill in, this creates a row already populated with the given values.
//
// Used by:
//   - restoreRepeaterFormState() — to rebuild headers from session storage
//   - confirmCurlImport()       — to populate headers from parsed curl command
//   - loadRepeaterHistoryItem()  — could also use this (currently uses
//     addRepeaterHeader + manual population, but this is the cleaner approach)
//
// The generated DOM structure is identical to addRepeaterHeader():
//   <div class="repeater-header-row">
//     <input class="repeater-header-key input-field" value="...">
//     <input class="repeater-header-value input-field" value="...">
//     <button class="repeater-remove-header-btn btn btn-sm btn-danger">&times;</button>
//   </div>
//
// The remove button is handled by event delegation on #repeater-headers-container
// (registered in setupRepeaterEventListeners), so no individual listener is
// needed here.

function addRepeaterHeaderRow(key, value) {
  var container = document.getElementById('repeater-headers-container');
  if (!container) return;

  var row = document.createElement('div');
  row.className = 'repeater-header-row';

  var keyInput = document.createElement('input');
  keyInput.className = 'repeater-header-key input-field';
  keyInput.type = 'text';
  keyInput.placeholder = 'Header name';
  keyInput.value = key || '';

  var valueInput = document.createElement('input');
  valueInput.className = 'repeater-header-value input-field';
  valueInput.type = 'text';
  valueInput.placeholder = 'Header value';
  valueInput.value = value || '';

  var removeBtn = document.createElement('button');
  removeBtn.className = 'repeater-remove-header-btn btn btn-sm btn-danger';
  removeBtn.textContent = '\u00D7'; // multiplication sign (x)

  row.appendChild(keyInput);
  row.appendChild(valueInput);
  row.appendChild(removeBtn);

  container.appendChild(row);
}


// ============================================================================
// 6. debounceRepeaterStateSave()
// ============================================================================
// A debounced wrapper around saveRepeaterFormState(). Collapses rapid input
// events (e.g., typing in the URL field) into a single save call after 500ms
// of inactivity. This avoids hammering chrome.storage.session on every
// keystroke while still persisting the user's work promptly.

function debounceRepeaterStateSave() {
  clearTimeout(_repeaterStateSaveTimeout);
  _repeaterStateSaveTimeout = setTimeout(saveRepeaterFormState, 500);
}


// ============================================================================
// 7. ADD TO DOMContentLoaded handler
// ============================================================================
// Paste this single call into the DOMContentLoaded handler in popup.js,
// after the existing init calls (loadSettings, loadWhitelist, etc.) and
// after setupEventListeners(). This ensures the form state is restored on
// initial popup open without waiting for the user to navigate to the
// Repeater tab.
//
// --- Inside DOMContentLoaded, after setupEventListeners(): ---
//
//   restoreRepeaterFormState();
//


// ============================================================================
// 8. openCurlImport()
// ============================================================================
// Shows the inline curl import section (#repeater-curl-section).
// Clears any previous input and error state so the user starts fresh.

function openCurlImport() {
  var section = document.getElementById('repeater-curl-section');
  if (section) {
    section.style.display = 'block';
  }

  // Clear previous input
  var input = document.getElementById('repeater-curl-input');
  if (input) {
    input.value = '';
  }

  // Clear previous error
  var error = document.getElementById('repeater-curl-import-error');
  if (error) {
    error.textContent = '';
    error.style.display = 'none';
  }

  // Hide export output if visible (avoid visual clutter)
  var output = document.getElementById('repeater-curl-output');
  if (output) {
    output.style.display = 'none';
  }
}


// ============================================================================
// 9. confirmCurlImport()
// ============================================================================
// Reads the curl command from #repeater-curl-input, parses it, and populates
// the Repeater form with the extracted method, URL, headers, and body.
// Shows an inline error if parsing fails.

function confirmCurlImport() {
  var input = document.getElementById('repeater-curl-input');
  var errorEl = document.getElementById('repeater-curl-import-error');

  if (!input) return;

  var curlString = input.value.trim();

  // Validate non-empty input
  if (!curlString) {
    if (errorEl) {
      errorEl.textContent = 'Please paste a curl command.';
      errorEl.style.display = 'block';
    }
    return;
  }

  // Attempt to parse the curl command
  var parsed;
  try {
    parsed = parseCurlCommand(curlString);
  } catch (e) {
    if (errorEl) {
      errorEl.textContent = 'Failed to parse curl command: ' + e.message;
      errorEl.style.display = 'block';
    }
    return;
  }

  // Validate that we got at least a URL
  if (!parsed.url) {
    if (errorEl) {
      errorEl.textContent = 'Could not extract a URL from the curl command.';
      errorEl.style.display = 'block';
    }
    return;
  }

  // Clear any previous error
  if (errorEl) {
    errorEl.textContent = '';
    errorEl.style.display = 'none';
  }

  // Populate the form
  var methodEl = document.getElementById('repeater-method');
  if (methodEl) {
    methodEl.value = parsed.method || 'GET';
  }

  var urlEl = document.getElementById('repeater-url');
  if (urlEl) {
    urlEl.value = parsed.url;
  }

  // Clear existing headers and add parsed ones
  var container = document.getElementById('repeater-headers-container');
  if (container) {
    container.textContent = '';
  }

  if (parsed.headers) {
    var headerKeys = Object.keys(parsed.headers);
    for (var i = 0; i < headerKeys.length; i++) {
      addRepeaterHeaderRow(headerKeys[i], parsed.headers[headerKeys[i]]);
    }
  }

  // Set body if present
  var bodyEl = document.getElementById('repeater-body');
  if (bodyEl) {
    bodyEl.value = parsed.body || '';
  }

  // Auto-detect body mode from Content-Type header
  if (parsed.headers) {
    var contentType = '';
    var hKeys = Object.keys(parsed.headers);
    for (var j = 0; j < hKeys.length; j++) {
      if (hKeys[j].toLowerCase() === 'content-type') {
        contentType = parsed.headers[hKeys[j]].toLowerCase();
        break;
      }
    }
    if (contentType.indexOf('application/json') !== -1) {
      setRepeaterBodyMode('json');
    } else if (contentType.indexOf('multipart/form-data') !== -1 ||
               contentType.indexOf('application/x-www-form-urlencoded') !== -1) {
      setRepeaterBodyMode('form-data');
    } else {
      setRepeaterBodyMode('raw');
    }
  }

  // Update body visibility based on method
  if (typeof toggleRepeaterBodyVisibility === 'function') {
    toggleRepeaterBodyVisibility();
  }

  // Close the curl import section
  var section = document.getElementById('repeater-curl-section');
  if (section) {
    section.style.display = 'none';
  }

  // Persist the imported state to session storage
  saveRepeaterFormState();

  // Notify user
  if (typeof showMessage === 'function') {
    showMessage('cURL command imported successfully', 'success');
  }
}


// ============================================================================
// 10. cancelCurlImport()
// ============================================================================
// Hides the curl import section without modifying the form.

function cancelCurlImport() {
  var section = document.getElementById('repeater-curl-section');
  if (section) {
    section.style.display = 'none';
  }

  // Clear input and error state
  var input = document.getElementById('repeater-curl-input');
  if (input) {
    input.value = '';
  }

  var error = document.getElementById('repeater-curl-import-error');
  if (error) {
    error.textContent = '';
    error.style.display = 'none';
  }
}


// ============================================================================
// 11. exportAsCurl()
// ============================================================================
// Builds a curl command string from the current Repeater form state and
// displays it in #repeater-curl-output. Uses textContent only (never
// innerHTML) since the URL, headers, and body are user-controlled.

function exportAsCurl() {
  var methodEl = document.getElementById('repeater-method');
  var urlEl = document.getElementById('repeater-url');
  var bodyEl = document.getElementById('repeater-body');
  var output = document.getElementById('repeater-curl-output');

  if (!output) return;

  var method = methodEl ? methodEl.value : 'GET';
  var url = urlEl ? urlEl.value.trim() : '';

  // Validate that we have a URL to export
  if (!url) {
    if (typeof showMessage === 'function') {
      showMessage('Enter a URL before exporting as cURL', 'error');
    }
    return;
  }

  // Build the curl command
  var parts = ['curl'];

  // Method (only include -X if not GET, since curl defaults to GET)
  if (method !== 'GET') {
    parts.push('-X ' + shellEscape(method));
  }

  // URL (always quote)
  parts.push(shellEscape(url));

  // Headers
  var headers = (typeof getRepeaterHeaders === 'function') ? getRepeaterHeaders() : {};
  var headerKeys = Object.keys(headers);
  for (var i = 0; i < headerKeys.length; i++) {
    var key = headerKeys[i];
    var value = headers[key];
    parts.push('-H ' + shellEscape(key + ': ' + value));
  }

  // Body (only for methods that carry a body)
  var methodsWithBody = ['POST', 'PUT', 'PATCH'];
  if (methodsWithBody.indexOf(method) !== -1 && bodyEl && bodyEl.value) {
    parts.push('-d ' + shellEscape(bodyEl.value));
  }

  var curlCommand = parts.join(' \\\n  ');

  // Display using textContent (XSS safe)
  output.textContent = curlCommand;
  output.style.display = 'block';

  // Hide import section if visible
  var importSection = document.getElementById('repeater-curl-section');
  if (importSection) {
    importSection.style.display = 'none';
  }
}


// ============================================================================
// 12. parseCurlCommand(curlString)
// ============================================================================
// Parses a curl command string into a request data object.
//
// Returns: { method, url, headers, body }
//
// Supported flags:
//   -X, --request        — HTTP method
//   -H, --header         — Request header (key: value)
//   -d, --data, --data-raw, --data-binary — Request body
//   URL                  — The target URL (bare argument)
//
// Handles:
//   - Backslash line continuations (\ at end of line)
//   - Single-quoted and double-quoted arguments
//   - Multiple -H flags
//   - Multiple -d flags (concatenated with & as per real curl behaviour)
//
// Unsupported flags are silently ignored:
//   -o, -v, --cert, --proxy, -k, --compressed, -L, -s, etc.
//
// SECURITY: This is a data parser only. It NEVER executes shell commands.

function parseCurlCommand(curlString) {
  if (!curlString || typeof curlString !== 'string') {
    throw new Error('Empty curl command');
  }

  // Normalise line continuations: replace backslash + newline with a space
  var normalised = curlString.replace(/\\\s*\n/g, ' ').trim();

  // Tokenise the command string, respecting single and double quotes.
  // This handles: curl -X POST 'https://example.com' -H "Content-Type: application/json"
  var tokens = tokenizeCurlCommand(normalised);

  // Validate that this looks like a curl command
  if (tokens.length === 0 || tokens[0] !== 'curl') {
    throw new Error('Command does not start with "curl"');
  }

  var method = null;
  var url = null;
  var headers = {};
  var bodyParts = [];

  // Flags that take a value as the next argument
  var flagsWithValue = [
    '-X', '--request',
    '-H', '--header',
    '-d', '--data', '--data-raw', '--data-binary', '--data-urlencode',
    '-o', '--output',
    '-u', '--user',
    '-A', '--user-agent',
    '-e', '--referer',
    '-b', '--cookie',
    '--connect-timeout', '--max-time',
    '--proxy', '--cert', '--key', '--cacert'
  ];

  // Boolean flags (take no value) — silently consumed
  var booleanFlags = [
    '-v', '--verbose',
    '-s', '--silent',
    '-S', '--show-error',
    '-k', '--insecure',
    '-L', '--location',
    '-I', '--head',
    '-i', '--include',
    '--compressed',
    '-f', '--fail',
    '-G', '--get',
    '-#', '--progress-bar'
  ];

  for (var i = 1; i < tokens.length; i++) {
    var token = tokens[i];

    // --- Method flag ---
    if (token === '-X' || token === '--request') {
      i++;
      if (i < tokens.length) {
        method = tokens[i].toUpperCase();
      }
      continue;
    }

    // --- Header flag ---
    if (token === '-H' || token === '--header') {
      i++;
      if (i < tokens.length) {
        var headerStr = tokens[i];
        var colonIndex = headerStr.indexOf(':');
        if (colonIndex !== -1) {
          var hKey = headerStr.substring(0, colonIndex).trim();
          var hValue = headerStr.substring(colonIndex + 1).trim();
          if (hKey) {
            headers[hKey] = hValue;
          }
        }
      }
      continue;
    }

    // --- Data / body flags ---
    if (token === '-d' || token === '--data' ||
        token === '--data-raw' || token === '--data-binary' ||
        token === '--data-urlencode') {
      i++;
      if (i < tokens.length) {
        bodyParts.push(tokens[i]);
      }
      continue;
    }

    // --- HEAD request flag ---
    if (token === '-I' || token === '--head') {
      if (!method) {
        method = 'HEAD';
      }
      continue;
    }

    // --- Boolean flags (no value, silently skip) ---
    if (booleanFlags.indexOf(token) !== -1) {
      continue;
    }

    // --- Other flags with values (silently skip the flag and its value) ---
    if (token.charAt(0) === '-' && flagsWithValue.indexOf(token) !== -1) {
      i++; // skip the value
      continue;
    }

    // --- Unknown flags starting with - (skip, might have a value if next
    //     token doesn't look like a flag or URL) ---
    if (token.charAt(0) === '-') {
      // Check if next token looks like a value (not a flag, not a URL)
      if (i + 1 < tokens.length && tokens[i + 1].charAt(0) !== '-' &&
          !looksLikeUrl(tokens[i + 1])) {
        i++; // skip the assumed value
      }
      continue;
    }

    // --- Bare argument: treat as URL if we haven't found one yet ---
    if (!url && !token.startsWith('-')) {
      url = token;
      continue;
    }
  }

  // Default method to GET if not specified, or POST if body data is present
  if (!method) {
    method = bodyParts.length > 0 ? 'POST' : 'GET';
  }

  // Concatenate multiple -d values with & (matches real curl behaviour)
  var body = bodyParts.length > 0 ? bodyParts.join('&') : '';

  return {
    method: method,
    url: url || '',
    headers: headers,
    body: body
  };
}


// ──────────────────────────────────────────────
// Helper: tokenizeCurlCommand(str)
// ──────────────────────────────────────────────
// Splits a curl command string into tokens, respecting single and double
// quotes. Handles escaped quotes within double-quoted strings (\").
//
// Examples:
//   curl -H "Content-Type: application/json" -> ['curl', '-H', 'Content-Type: application/json']
//   curl -H 'Authorization: Bearer abc'      -> ['curl', '-H', 'Authorization: Bearer abc']

function tokenizeCurlCommand(str) {
  var tokens = [];
  var current = '';
  var inSingleQuote = false;
  var inDoubleQuote = false;
  var i = 0;

  while (i < str.length) {
    var ch = str.charAt(i);

    if (inSingleQuote) {
      if (ch === "'") {
        inSingleQuote = false;
      } else {
        current += ch;
      }
      i++;
      continue;
    }

    if (inDoubleQuote) {
      if (ch === '\\' && i + 1 < str.length) {
        var next = str.charAt(i + 1);
        // In double quotes, handle escaped characters
        if (next === '"' || next === '\\' || next === '$' || next === '`') {
          current += next;
          i += 2;
          continue;
        }
      }
      if (ch === '"') {
        inDoubleQuote = false;
      } else {
        current += ch;
      }
      i++;
      continue;
    }

    // Outside quotes
    if (ch === "'") {
      inSingleQuote = true;
      i++;
      continue;
    }

    if (ch === '"') {
      inDoubleQuote = true;
      i++;
      continue;
    }

    if (ch === '\\' && i + 1 < str.length) {
      // Escaped character outside quotes
      current += str.charAt(i + 1);
      i += 2;
      continue;
    }

    if (ch === ' ' || ch === '\t') {
      if (current.length > 0) {
        tokens.push(current);
        current = '';
      }
      i++;
      continue;
    }

    current += ch;
    i++;
  }

  if (current.length > 0) {
    tokens.push(current);
  }

  return tokens;
}


// ──────────────────────────────────────────────
// Helper: looksLikeUrl(str)
// ──────────────────────────────────────────────
// Quick heuristic to determine if a string looks like a URL.

function looksLikeUrl(str) {
  return /^https?:\/\//i.test(str) || /^[a-zA-Z0-9].*\.[a-zA-Z]/.test(str);
}


// ──────────────────────────────────────────────
// Helper: shellEscape(str)
// ──────────────────────────────────────────────
// Wraps a string in single quotes for safe inclusion in a shell command.
// Any single quotes inside the string are escaped by ending the quoted
// region, inserting an escaped quote, and restarting the quoted region:
//   O'Brien -> 'O'\''Brien'
//
// This is the standard POSIX shell quoting approach.

function shellEscape(str) {
  if (!str) return "''";
  // Replace each single quote with: end-quote, escaped-quote, start-quote
  return "'" + str.replace(/'/g, "'\\''") + "'";
}


// ============================================================
// SQLi Attack Tab
// ============================================================

var _sqliAborted = false;
var _sqliAiHistory = [];
var _sqliAiPendingResolve = null;
var _sqliLastConfig = null;

function setupSQLiTab() {
  var methodEl = document.getElementById('sqliMethod');
  var runBtn = document.getElementById('sqliRunBtn');
  var stopBtn = document.getElementById('sqliStopBtn');
  var aiModeEl = document.getElementById('sqliAiMode');

  if (!methodEl || !runBtn) return;

  // Show/hide POST body section
  methodEl.addEventListener('change', function() {
    var bodySection = document.getElementById('sqliBodySection');
    if (bodySection) {
      bodySection.style.display = ['POST', 'PUT'].includes(methodEl.value) ? 'block' : 'none';
    }
  });

  // Load URL → parse params
  document.getElementById('sqliLoadBtn').addEventListener('click', parseSQLiUrlParams);

  // Enter key in URL input
  document.getElementById('sqliUrl').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') parseSQLiUrlParams();
  });

  // cURL import
  document.getElementById('sqliImportCurl').addEventListener('click', function() {
    var section = document.getElementById('sqliCurlSection');
    if (section) section.style.display = section.style.display === 'none' ? 'block' : 'none';
  });
  document.getElementById('sqliCurlConfirm').addEventListener('click', importSQLiCurl);
  document.getElementById('sqliCurlCancel').addEventListener('click', function() {
    document.getElementById('sqliCurlSection').style.display = 'none';
  });

  // From Repeater History
  document.getElementById('sqliFromHistory').addEventListener('click', showSQLiHistoryPicker);

  // Run / Stop
  runBtn.addEventListener('click', runSQLiTest);
  stopBtn.addEventListener('click', function() {
    _sqliAborted = true;
    stopBtn.style.display = 'none';
    runBtn.style.display = 'inline-flex';
    appendSQLiLog('warning', 'Scan aborted by user.');
  });

  // AI mode toggle
  aiModeEl.addEventListener('change', function() {
    var controls = document.getElementById('sqliAiControls');
    if (controls) controls.style.display = aiModeEl.checked ? 'block' : 'none';
  });

  // AI send
  document.getElementById('sqliAiSendBtn').addEventListener('click', sendSQLiAiMessage);
  document.getElementById('sqliAiUserMessage').addEventListener('keydown', function(e) {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendSQLiAiMessage(); }
  });

  // Restore last scan results on popup open
  restoreSQLiLastScan();
}

function parseSQLiUrlParams() {
  var url = (document.getElementById('sqliUrl').value || '').trim();
  var method = document.getElementById('sqliMethod').value;
  var params = [];

  try {
    var parsed = new URL(url);
    parsed.searchParams.forEach(function(value, name) {
      params.push({ name: name, value: value, source: 'url' });
    });
  } catch(e) {
    // invalid URL, still try to render what we have
  }

  // Also parse POST body if visible
  var bodySection = document.getElementById('sqliBodySection');
  if (bodySection && bodySection.style.display !== 'none') {
    var body = (document.getElementById('sqliBody').value || '').trim();
    if (body) {
      // Try JSON
      try {
        var json = JSON.parse(body);
        Object.keys(json).forEach(function(k) {
          params.push({ name: k, value: String(json[k]), source: 'body-json' });
        });
      } catch(e) {
        // Try form-encoded
        body.split('&').forEach(function(pair) {
          var parts = pair.split('=');
          if (parts.length >= 2) {
            params.push({ name: decodeURIComponent(parts[0]), value: decodeURIComponent(parts.slice(1).join('=')), source: 'body-form' });
          }
        });
      }
    }
  }

  renderSQLiParamPills(params);
}

function renderSQLiParamPills(params) {
  var container = document.getElementById('sqliParamsContainer');
  if (!container) return;

  if (!params || params.length === 0) {
    container.innerHTML = '<span style="font-size:11px;color:rgba(255,255,255,0.4);">No parameters detected. Enter a URL with query params or a POST body.</span>';
    return;
  }

  container.innerHTML = params.map(function(p, i) {
    return '<div class="sqli-param-pill" data-param-index="' + i + '" data-param-name="' + escapeHtml(p.name) + '" data-param-value="' + escapeHtml(p.value) + '" data-param-source="' + p.source + '">' +
      '<input type="checkbox" checked title="Include in test">' +
      '<span>' + escapeHtml(p.name) + '=<em>' + escapeHtml(p.value.substring(0, 20)) + (p.value.length > 20 ? '…' : '') + '</em></span>' +
      '</div>';
  }).join('');

  // Toggle disabled class on pill click
  container.querySelectorAll('.sqli-param-pill').forEach(function(pill) {
    pill.querySelector('input[type=checkbox]').addEventListener('change', function(e) {
      pill.classList.toggle('disabled', !e.target.checked);
    });
  });
}

function importSQLiCurl() {
  var input = document.getElementById('sqliCurlInput').value.trim();
  if (!input) return;

  try {
    var parsed = parseCurlCommand(input);
    document.getElementById('sqliUrl').value = parsed.url || '';
    document.getElementById('sqliMethod').value = parsed.method || 'GET';

    var method = parsed.method || 'GET';
    var bodySection = document.getElementById('sqliBodySection');
    if (bodySection) {
      bodySection.style.display = ['POST', 'PUT'].includes(method) ? 'block' : 'none';
    }
    if (parsed.body && document.getElementById('sqliBody')) {
      document.getElementById('sqliBody').value = parsed.body;
    }

    // Close curl section
    document.getElementById('sqliCurlSection').style.display = 'none';
    document.getElementById('sqliCurlInput').value = '';

    // Auto-parse params
    parseSQLiUrlParams();
  } catch(e) {
    appendSQLiLog('error', 'cURL parse error: ' + e.message);
  }
}

function showSQLiHistoryPicker() {
  // Use the repeater history array if available
  var history = (typeof _repeaterHistory !== 'undefined' ? _repeaterHistory : []);
  if (!history || history.length === 0) {
    appendSQLiLog('warning', 'No Repeater history found. Send requests via the Repeater tab first.');
    return;
  }

  // Build a simple inline picker below the import bar
  var container = document.getElementById('sqliParamsContainer');
  if (!container) return;

  container.innerHTML = '<div style="font-size:12px;margin-bottom:4px;font-weight:600;">Select a request from Repeater history:</div>' +
    history.slice(0, 20).map(function(entry, i) {
      var statusBadge = entry.statusCode ? ' [' + entry.statusCode + ']' : '';
      return '<div class="sqli-history-pick-item" data-index="' + i + '" style="padding:4px 8px;cursor:pointer;font-size:11px;border-radius:3px;margin-bottom:2px;background:rgba(255,255,255,0.04);">' +
        '<strong>' + escapeHtml(entry.method || 'GET') + '</strong> ' +
        escapeHtml((entry.url || '').substring(0, 80)) + statusBadge +
        '</div>';
    }).join('');

  container.querySelectorAll('.sqli-history-pick-item').forEach(function(item) {
    item.addEventListener('click', function() {
      var idx = parseInt(item.dataset.index, 10);
      var entry = history[idx];
      if (!entry) return;

      document.getElementById('sqliUrl').value = entry.url || '';
      document.getElementById('sqliMethod').value = entry.method || 'GET';

      var bodySection = document.getElementById('sqliBodySection');
      if (bodySection) {
        bodySection.style.display = ['POST', 'PUT'].includes(entry.method) ? 'block' : 'none';
      }
      if (entry.body && document.getElementById('sqliBody')) {
        document.getElementById('sqliBody').value = entry.body;
      }

      parseSQLiUrlParams();
    });
  });
}

function collectSQLiConfig() {
  var url = (document.getElementById('sqliUrl').value || '').trim();
  var method = document.getElementById('sqliMethod').value || 'GET';
  var body = (document.getElementById('sqliBody').value || '').trim();
  var dbms = document.getElementById('sqliDbms').value || 'auto';
  var delay = parseInt(document.getElementById('sqliDelay').value, 10) || 5;
  var risk = parseInt(document.getElementById('sqliRisk').value, 10) || 1;
  var aiMode = document.getElementById('sqliAiMode').checked;
  var aiInstructions = (document.getElementById('sqliAiInstructions').value || '').trim();

  // Collect enabled techniques
  var techniques = new Set();
  document.querySelectorAll('.sqli-tech:checked').forEach(function(cb) {
    techniques.add(cb.value);
  });

  // Collect enabled params from pills
  var params = [];
  document.querySelectorAll('.sqli-param-pill:not(.disabled)').forEach(function(pill) {
    params.push({
      name: pill.dataset.paramName,
      value: pill.dataset.paramValue,
      source: pill.dataset.paramSource
    });
  });

  return { url: url, method: method, body: body, dbms: dbms, delay: delay, risk: risk,
           techniques: techniques, params: params, aiMode: aiMode, aiInstructions: aiInstructions };
}

async function sqliSendRequest(reqConfig) {
  return new Promise(function(resolve) {
    chrome.runtime.sendMessage({
      action: 'sqliRequest',
      url: reqConfig.url,
      method: reqConfig.method || 'GET',
      headers: reqConfig.headers || {},
      body: reqConfig.body || null,
      timeout: reqConfig.timeout || 10000
    }, function(response) {
      if (chrome.runtime.lastError) {
        resolve({ error: chrome.runtime.lastError.message, status: 0 });
      } else {
        resolve(response || { error: 'No response', status: 0 });
      }
    });
  });
}

async function runSQLiTest() {
  var config = collectSQLiConfig();

  if (!config.url) {
    appendSQLiLog('error', 'Enter a target URL first.');
    return;
  }

  try { new URL(config.url); } catch(e) {
    appendSQLiLog('error', 'Invalid URL: ' + config.url);
    return;
  }

  if (config.params.length === 0) {
    appendSQLiLog('warning', 'No parameters to test. Load the URL to detect parameters, or add params to the URL.');
    return;
  }

  // Reset state
  _sqliAborted = false;
  _sqliAiHistory = [];
  _sqliLastConfig = config;

  // Clear stored results for this scan (will be overwritten on completion)
  chrome.storage.local.remove('sqli_last_scan');

  // UI state
  document.getElementById('sqliRunBtn').style.display = 'none';
  document.getElementById('sqliStopBtn').style.display = 'inline-flex';
  document.getElementById('sqliProgress').style.display = 'block';
  document.getElementById('sqliResults').innerHTML = '';
  document.getElementById('sqliLog').innerHTML = '';
  document.getElementById('sqliProgressFill').style.width = '0%';

  appendSQLiLog('info', 'Starting SQL injection test on ' + config.url);
  appendSQLiLog('info', 'Parameters: ' + config.params.map(function(p){ return p.name; }).join(', '));
  appendSQLiLog('info', 'Techniques: ' + Array.from(config.techniques).join('') + ' | DBMS: ' + config.dbms + ' | Delay: ' + config.delay + 's');

  var results = [];
  try {
    var tester = new SQLiTester(config, {
      onProgress: function(phase, param, pct) {
        updateSQLiProgress(phase, param, pct);
      },
      onLog: function(level, msg) {
        appendSQLiLog(level, msg);
      },
      onResult: function(finding) {
        results.push(finding);
        appendSQLiResult(finding);
      },
      sendRequest: sqliSendRequest,
      shouldAbort: function() { return _sqliAborted; }
    });

    var allResults = await tester.run();
    // allResults may include additional items not emitted via onResult
    allResults.forEach(function(r) {
      if (!results.find(function(existing) {
        return existing.technique === r.technique && existing.param === r.param && existing.payload === r.payload;
      })) {
        results.push(r);
        appendSQLiResult(r);
      }
    });

    renderSQLiFinalSummary(results);
    saveSQLiLastScan(config.url, config.method, results);
    injectSQLiFindingsIntoSecurityResults(config.url, results);

    if (config.aiMode && !_sqliAborted) {
      appendSQLiLog('info', 'Starting AI-assisted analysis...');
      appendSQLiAiChat('system', 'Automated scan complete. Starting AI agent analysis...');
      startSQLiAiAgent(config, results);
    }
  } catch(e) {
    if (e && e.name === 'SQLiTesterAbortError') {
      appendSQLiLog('warning', 'Scan aborted.');
    } else {
      appendSQLiLog('error', 'Test error: ' + (e ? e.message : 'Unknown error'));
    }
  } finally {
    document.getElementById('sqliRunBtn').style.display = 'inline-flex';
    document.getElementById('sqliStopBtn').style.display = 'none';
    updateSQLiProgress('Done', '', 100);
    setTimeout(function() {
      document.getElementById('sqliProgress').style.display = 'none';
    }, 1500);
  }
}

function updateSQLiProgress(phase, param, pct) {
  var fill = document.getElementById('sqliProgressFill');
  var label = document.getElementById('sqliProgressLabel');
  if (fill) fill.style.width = Math.min(100, pct) + '%';
  if (label) {
    var paramStr = param ? ' [' + param + ']' : '';
    label.textContent = phase + paramStr + ' — ' + Math.round(pct) + '%';
  }
}

function appendSQLiLog(level, msg) {
  var log = document.getElementById('sqliLog');
  if (!log) return;
  var line = document.createElement('div');
  line.className = 'sqli-log-line ' + (level || 'info');
  var prefix = { info: '[*]', warning: '[!]', success: '[+]', error: '[-]' }[level] || '[*]';
  line.textContent = prefix + ' ' + msg;
  log.appendChild(line);
  log.scrollTop = log.scrollHeight;
}

function appendSQLiResult(finding) {
  var container = document.getElementById('sqliResults');
  if (!container) return;

  // Remove empty-state if present
  var empty = container.querySelector('.empty-state');
  if (empty) empty.remove();

  var card = document.createElement('div');
  card.className = 'sqli-result-card ' + (finding.confirmed ? 'confirmed' : 'potential');

  var techBadge = '<span class="sqli-technique-badge ' + (finding.technique || '') + '">' + (finding.technique || '?') + '</span>';
  var statusLabel = finding.confirmed
    ? '<span class="sqli-result-status confirmed">INJECTABLE</span>'
    : '<span class="sqli-result-status potential">POTENTIAL</span>';

  var dbmsStr = finding.dbms && finding.dbms !== 'unknown' ? finding.dbms.toUpperCase() : '';
  var dbmsBadge = dbmsStr ? '<span class="sqli-result-dbms">' + escapeHtml(dbmsStr) + '</span>' : '';

  var payloadHtml = finding.payload
    ? '<div class="sqli-result-payload">' + escapeHtml(finding.payload.substring(0, 200)) + '</div>'
    : '';

  var evidenceHtml = finding.evidence
    ? '<div class="sqli-result-evidence">' + escapeHtml(finding.evidence.substring(0, 150)) + '</div>'
    : '';

  var actionsHtml = '';
  if (finding.confirmed) {
    actionsHtml =
      '<div class="sqli-result-actions">' +
      '<button class="sqli-action-btn" data-action="repeater">&#8634; Repeater</button>' +
      '<button class="sqli-action-btn" data-action="aipartner">&#x2728; AI Partner</button>' +
      '</div>';
  }

  card.innerHTML =
    '<div class="sqli-result-header">' + techBadge + statusLabel +
    '<span class="sqli-result-param">' + escapeHtml(finding.param || '') + '</span>' +
    dbmsBadge + '</div>' +
    '<div class="sqli-result-title">' + escapeHtml(finding.title || finding.description || '') + '</div>' +
    payloadHtml + evidenceHtml + actionsHtml;

  // Wire action buttons
  if (finding.confirmed) {
    var repeaterBtn = card.querySelector('[data-action="repeater"]');
    var aiBtn = card.querySelector('[data-action="aipartner"]');
    if (repeaterBtn) repeaterBtn.addEventListener('click', function() { sqliSendFindingToRepeater(finding); });
    if (aiBtn) aiBtn.addEventListener('click', function() { sqliSendFindingToAiPartner(finding); });
  }

  container.appendChild(card);
}

function renderSQLiFinalSummary(results) {
  var container = document.getElementById('sqliResults');
  if (!container) return;

  var confirmed = results.filter(function(r) { return r.confirmed; });

  var summaryCard = document.createElement('div');

  if (confirmed.length === 0) {
    summaryCard.className = 'sqli-summary-not-vuln';
    summaryCard.textContent = 'No confirmed SQL injection vulnerabilities found for the tested parameters.';
  } else {
    summaryCard.className = 'sqli-summary-card';
    var techniques = {};
    var params = new Set();
    var dbmsList = new Set();
    confirmed.forEach(function(r) {
      techniques[r.technique] = (techniques[r.technique] || 0) + 1;
      if (r.param) params.add(r.param);
      if (r.dbms && r.dbms !== 'unknown') dbmsList.add(r.dbms);
    });

    var techNames = { B: 'boolean-based blind', E: 'error-based', T: 'time-based blind', U: 'UNION query', S: 'stacked queries' };
    var techSummary = Object.keys(techniques).map(function(t) {
      return techNames[t] || t;
    }).join(', ');

    summaryCard.innerHTML =
      '<h4>SQL Injection Confirmed</h4>' +
      '<p>Parameter(s): <strong>' + Array.from(params).map(escapeHtml).join(', ') + '</strong></p>' +
      '<p>Techniques: ' + escapeHtml(techSummary) + '</p>' +
      (dbmsList.size > 0 ? '<p>DBMS: <strong>' + escapeHtml(Array.from(dbmsList).join(', ')) + '</strong></p>' : '') +
      '<p>' + confirmed.length + ' injection point(s) confirmed.</p>';
  }

  // Insert summary before the finding cards
  container.insertBefore(summaryCard, container.firstChild);
}

function sqliSendFindingToRepeater(finding) {
  var config = _sqliLastConfig;
  if (!config || !config.url) return;

  // Build the URL (or body) with the confirmed payload injected
  var targetUrl = config.url;
  var targetBody = config.body || null;
  var method = (config.method || 'GET').toUpperCase();

  try {
    var paramValue = '';
    if (Array.isArray(config.params)) {
      var p = config.params.find(function(x) { return x.name === finding.param; });
      if (p) paramValue = p.value != null ? String(p.value) : '';
    } else if (config.params) {
      paramValue = config.params[finding.param] != null ? String(config.params[finding.param]) : '';
    }

    var injectedValue = paramValue + (finding.payload || '');

    if (method === 'GET') {
      var parsedUrl = new URL(config.url);
      parsedUrl.searchParams.set(finding.param, injectedValue);
      targetUrl = parsedUrl.toString();
    } else {
      targetBody = buildSQLiBodyWithParam(config.body, finding.param, injectedValue);
    }
  } catch(e) {
    targetUrl = config.url;
  }

  // Navigate to the Repeater tab and pre-load the request
  document.querySelector('[data-tab="attack-lab"]')?.click();
  setTimeout(function() {
    document.querySelector('[data-tab="repeater"]')?.click();
    setTimeout(function() {
      var methodEl = document.getElementById('repeater-method');
      var urlEl = document.getElementById('repeater-url');
      var bodyEl = document.getElementById('repeater-body');

      if (methodEl) methodEl.value = method;
      if (urlEl) urlEl.value = targetUrl;
      if (bodyEl && targetBody) bodyEl.value = targetBody;

      // Add a comment header noting this came from SQLi
      if (typeof addRepeaterHeader === 'function') {
        addRepeaterHeader();
        var rows = document.querySelectorAll('.repeater-header-row');
        var last = rows[rows.length - 1];
        if (last) {
          var k = last.querySelector('.repeater-header-key');
          var v = last.querySelector('.repeater-header-value');
          if (k) k.value = 'X-SQLi-Finding';
          if (v) v.value = finding.technique + ' on ' + finding.param + (finding.dbms ? ' [' + finding.dbms + ']' : '');
        }
      }

      showMessage('SQLi payload loaded in Repeater', 'success');
    }, 50);
  }, 50);
}

function sqliSendFindingToAiPartner(finding) {
  var config = _sqliLastConfig;
  var techNames = { B: 'boolean-based blind', E: 'error-based', T: 'time-based blind', U: 'UNION query', S: 'stacked queries' };
  var techName = techNames[finding.technique] || finding.technique || 'unknown';
  var targetUrl = config ? config.url : 'unknown';
  var method = config ? (config.method || 'GET') : 'GET';

  var context =
    'SQL injection confirmed in parameter "' + (finding.param || 'unknown') + '".\n' +
    'Target: ' + targetUrl + '\n' +
    'Method: ' + method + '\n' +
    'Technique: ' + techName + (finding.dbms ? ' (' + finding.dbms + ')' : '') + '\n\n' +
    'Authorization scope: Authorized test target confirmed via Origami Attack Lab.\n\n' +
    'MANDATORY FIRST ACTION: Call send_http_request with the baseline URL right now. ' +
    'Do not write any analysis or extracted data until you have [TOOL_RESULT] blocks to cite. ' +
    'After the baseline, enumerate tables, then extract data — reporting only verbatim response content.';

  openAIPartner().then(function() {
    setTimeout(function() {
      setAIPartnerMode('exploiter');
      var input = document.getElementById('aiPartnerInput');
      if (input) {
        input.value = context;
        input.dispatchEvent(new Event('input'));
      }
      // Auto-send so the AI starts working immediately
      sendChatMessage();
    }, 400);
  }).catch(function(e) {
    console.warn('SQLi: Failed to open AI Partner:', e);
    showMessage('Open AI Partner failed: ' + e.message, 'error');
  });
}

function sqliTechniqueToSeverity(technique) {
  var map = { U: 'CRITICAL', E: 'CRITICAL', S: 'CRITICAL', B: 'HIGH', T: 'HIGH' };
  return map[technique] || 'HIGH';
}

function injectSQLiFindingsIntoSecurityResults(url, findings) {
  var techNames = { B: 'boolean-based blind', E: 'error-based', T: 'time-based blind', U: 'UNION query', S: 'stacked queries' };
  var confirmed = findings.filter(function(f) { return f.confirmed; });
  if (confirmed.length === 0) return;

  var vulnFindings = confirmed.map(function(f) {
    var techName = techNames[f.technique] || f.technique;
    var severity = sqliTechniqueToSeverity(f.technique);
    return {
      check: 'SQL Injection (' + techName + ') - ' + f.param,
      status: 'vulnerable',
      severity: severity,
      message: 'Parameter "' + f.param + '" is injectable via ' + techName + '. DBMS: ' + (f.dbms || 'unknown') + '.',
      recommendation: 'Use parameterized queries (prepared statements). Never concatenate user-controlled input into SQL queries.',
      source: 'SQLi Attack Lab',
      uri: url,
      timestamp: new Date().toISOString(),
      lineNumber: null,
      codeContext: null,
      matchedText: f.payload || '',
      sqliData: { technique: f.technique, param: f.param, payload: f.payload, dbms: f.dbms }
    };
  });

  // Merge into live securityResults so they show in Security > Vulnerabilities tab.
  // If no page scan has run yet, bootstrap a minimal results object so the Security
  // tab nav becomes visible (it stays hidden until displaySecurityResults() is called).
  if (!securityResults) {
    securityResults = { headers: [], cookies: [], vulnerabilities: [], sensitiveFiles: [] };
  }
  if (!securityResults.vulnerabilities) securityResults.vulnerabilities = [];
  securityResults.vulnerabilities = securityResults.vulnerabilities.filter(function(f) { return !f.sqliData; });
  securityResults.vulnerabilities.push.apply(securityResults.vulnerabilities, vulnFindings);
  displaySecurityResults(securityResults);

  // Also merge into window.currentSecurityFindings for report generation
  if (!window.currentSecurityFindings) window.currentSecurityFindings = {};
  if (!window.currentSecurityFindings.vulnerabilities) window.currentSecurityFindings.vulnerabilities = [];
  window.currentSecurityFindings.vulnerabilities = window.currentSecurityFindings.vulnerabilities.filter(function(f) { return !f.sqliData; });
  window.currentSecurityFindings.vulnerabilities.push.apply(window.currentSecurityFindings.vulnerabilities, vulnFindings);
}

function saveSQLiLastScan(url, method, results) {
  // Attach severity before persisting
  var resultsWithSeverity = results.map(function(f) {
    return Object.assign({}, f, { severity: sqliTechniqueToSeverity(f.technique) });
  });
  try {
    chrome.storage.local.set({
      sqli_last_scan: { url: url, method: method || 'GET', results: resultsWithSeverity, timestamp: Date.now() }
    });
  } catch(e) {}
}

function restoreSQLiLastScan() {
  chrome.storage.local.get(['sqli_last_scan'], function(items) {
    var data = items.sqli_last_scan;
    if (!data || !Array.isArray(data.results)) return;
    // Only restore scans from within the last 24 hours
    if (Date.now() - (data.timestamp || 0) > 86400000) return;

    var urlEl = document.getElementById('sqliUrl');
    var methodEl = document.getElementById('sqliMethod');
    if (urlEl && data.url) urlEl.value = data.url;
    if (methodEl && data.method) methodEl.value = data.method;

    var container = document.getElementById('sqliResults');
    if (!container) return;
    container.innerHTML = '';

    if (data.results.length > 0) {
      data.results.forEach(function(finding) { appendSQLiResult(finding); });
      renderSQLiFinalSummary(data.results);
      injectSQLiFindingsIntoSecurityResults(data.url, data.results);
    }

    var ts = data.timestamp ? new Date(data.timestamp).toLocaleString() : '';
    appendSQLiLog('info', 'Results restored from previous scan on ' + (data.url || '') + (ts ? ' at ' + ts : ''));
  });
}

async function startSQLiAiAgent(config, initialResults) {
  var MAX_ROUNDS = 20;
  var round = 0;
  _sqliAiHistory = [];
  _sqliAiPendingResolve = null;

  while (!_sqliAborted && round < MAX_ROUNDS) {
    round++;

    var target = {
      url: config.url,
      method: config.method,
      params: config.params
    };

    var promptText;
    try {
      promptText = SecurityPrompts.sqliAgentTurn(target, initialResults, _sqliAiHistory, config.aiInstructions);
    } catch(e) {
      appendSQLiLog('error', 'AI prompt build error: ' + e.message);
      break;
    }

    appendSQLiAiChat('system', 'Round ' + round + ' — asking AI for next action...');

    var llmResponse = await sqliAiLlmRequest(promptText);
    if (!llmResponse || llmResponse.error) {
      var errMsg = llmResponse ? llmResponse.error : 'No response from LLM';
      appendSQLiLog('error', 'AI request failed: ' + errMsg);
      appendSQLiAiChat('system', 'LLM error: ' + errMsg + '. Check LLM configuration in Settings.');
      break;
    }

    var responseText = llmResponse.text || llmResponse.response || '';
    var parsed = parseSQLiAiResponse(responseText);

    if (!parsed) {
      appendSQLiLog('warning', 'AI response could not be parsed. Stopping agent.');
      appendSQLiAiChat('system', 'AI response could not be parsed. The model may have returned an unexpected format. Stopping agent.');
      break;
    }

    if (parsed.action === 'CONCLUDE') {
      appendSQLiAiChat('assistant', parsed.summary || responseText);
      appendSQLiLog('success', 'AI agent concluded analysis.');
      break;
    }

    if (parsed.action === 'REQUEST_INFO') {
      appendSQLiAiChat('assistant', parsed.question || 'What additional information can you provide?');
      // Pause and wait for user reply
      var userReply = await waitForSQLiAiUserMessage();
      if (userReply === null) break; // aborted
      _sqliAiHistory.push({ action: 'user_reply', content: userReply, round: round });
      continue;
    }

    if (parsed.action === 'RUN_TEST') {
      appendSQLiAiChat('assistant', parsed.reasoning || 'Running test...');

      // Build the test URL with the param replaced
      var testUrl = config.url;
      var testBody = config.body || null;
      try {
        var parsedUrl = new URL(config.url);
        if (config.method === 'GET') {
          parsedUrl.searchParams.set(parsed.param, parsed.payload);
          testUrl = parsedUrl.toString();
        } else {
          testBody = buildSQLiBodyWithParam(config.body, parsed.param, parsed.payload);
        }
      } catch(e) {
        appendSQLiLog('error', 'Failed to build test URL: ' + e.message);
        break;
      }

      var testResult = await sqliSendRequest({
        url: testUrl,
        method: config.method,
        headers: config.headers || {},
        body: testBody,
        timeout: (config.delay + 2) * 1000
      });

      var historyEntry = {
        action: 'RUN_TEST',
        param: parsed.param,
        payload: parsed.payload,
        reasoning: parsed.reasoning,
        round: round,
        response: {
          status: testResult.status,
          timing: testResult.timing,
          body_snippet: (testResult.body || '').substring(0, 300)
        }
      };
      _sqliAiHistory.push(historyEntry);

      // Add AI test request to Repeater history so user can inspect it
      addToRepeaterHistory(
        { url: testUrl, method: config.method, headers: config.headers || {}, body: testBody, bodyMode: 'raw' },
        { status: testResult.status, statusText: String(testResult.status || ''), body: testResult.body || '', headers: {}, timing: testResult.timing || 0, error: testResult.error || null }
      );

      var resultSummary = 'Status: ' + (testResult.status || 'error') +
        ' | Time: ' + (testResult.timing || '?') + 'ms' +
        ' | Length: ' + (testResult.body || '').length + 'B' +
        (testResult.error ? ' | Error: ' + testResult.error : '') +
        '\nPayload: ' + escapeHtml((parsed.payload || '').substring(0, 100)) +
        '\nBody preview: ' + escapeHtml((testResult.body || '').substring(0, 200));
      appendSQLiAiChat('system', resultSummary);
    }
  }

  if (round >= MAX_ROUNDS) {
    appendSQLiLog('warning', 'AI agent reached maximum rounds (' + MAX_ROUNDS + '). Stopping.');
    appendSQLiAiChat('assistant', 'Maximum test rounds reached. Review the findings above for confirmed injections.');
  }
}

async function sqliAiLlmRequest(promptText) {
  try {
    if (typeof LLMManager === 'undefined') {
      return { error: 'LLMManager not loaded' };
    }
    var llmSettings = await getLLMSettings();
    if (!llmSettings || !llmSettings.enabled || llmSettings.provider === 'none') {
      return { error: 'LLM not configured. Please configure an API key in Settings.' };
    }
    var manager = new LLMManager(llmSettings.provider, llmSettings.apiKey, llmSettings.endpoint);
    manager.setModel(llmSettings.model || 'claude-sonnet-4-6');
    var result = await manager.analyze(promptText, null, {
      maxTokens: 600,
      systemPrompt: SecurityPrompts.exploiterSystemPrompt()
    });
    return { text: result.response };
  } catch(e) {
    return { error: e.message };
  }
}

function parseSQLiAiResponse(text) {
  if (!text) return null;

  var actionMatch = text.match(/<action>(.*?)<\/action>/s);
  if (!actionMatch) return null;
  var action = actionMatch[1].trim();

  if (action === 'CONCLUDE') {
    var summaryMatch = text.match(/<summary>([\s\S]*?)<\/summary>/);
    return { action: 'CONCLUDE', summary: summaryMatch ? summaryMatch[1].trim() : text };
  }

  if (action === 'REQUEST_INFO') {
    var questionMatch = text.match(/<question>([\s\S]*?)<\/question>/);
    return { action: 'REQUEST_INFO', question: questionMatch ? questionMatch[1].trim() : '' };
  }

  if (action === 'RUN_TEST') {
    var paramMatch = text.match(/<param>([\s\S]*?)<\/param>/);
    var payloadMatch = text.match(/<payload>([\s\S]*?)<\/payload>/);
    var reasoningMatch = text.match(/<reasoning>([\s\S]*?)<\/reasoning>/);
    return {
      action: 'RUN_TEST',
      param: paramMatch ? paramMatch[1].trim() : '',
      payload: payloadMatch ? payloadMatch[1].trim() : '',
      reasoning: reasoningMatch ? reasoningMatch[1].trim() : ''
    };
  }

  return null;
}

function waitForSQLiAiUserMessage() {
  return new Promise(function(resolve) {
    _sqliAiPendingResolve = function(msg) {
      _sqliAiPendingResolve = null;
      resolve(msg);
    };
    // Also resolve null if aborted after 5 minutes
    setTimeout(function() {
      if (_sqliAiPendingResolve) {
        _sqliAiPendingResolve = null;
        resolve(null);
      }
    }, 300000);
  });
}

function sendSQLiAiMessage() {
  var input = document.getElementById('sqliAiUserMessage');
  if (!input) return;
  var msg = input.value.trim();
  if (!msg) return;
  input.value = '';
  appendSQLiAiChat('user', msg);
  if (_sqliAiPendingResolve) {
    _sqliAiPendingResolve(msg);
  } else {
    appendSQLiAiChat('system', 'Agent is not waiting for input. Enable "AI-Assisted Attack", run a scan, and the agent will ask when it needs guidance. Use the main AI Partner tab for general analysis.');
  }
}

function appendSQLiAiChat(role, content) {
  var chat = document.getElementById('sqliAiChat');
  if (!chat) return;
  var msg = document.createElement('div');
  msg.className = 'sqli-ai-msg ' + role;
  var roleLabel = { user: 'You', assistant: 'AI', system: 'Test' }[role] || role;
  msg.innerHTML = '<div class="sqli-ai-role">' + roleLabel + '</div>' + escapeHtml(content);
  chat.appendChild(msg);
  chat.scrollTop = chat.scrollHeight;
}

function buildSQLiBodyWithParam(body, paramName, payload) {
  if (!body) return paramName + '=' + encodeURIComponent(payload);
  // Try JSON
  try {
    var json = JSON.parse(body);
    if (paramName in json) {
      json[paramName] = payload;
      return JSON.stringify(json);
    }
  } catch(e) {}
  // Form-encoded
  var parts = body.split('&').map(function(pair) {
    var eq = pair.indexOf('=');
    if (eq === -1) return pair;
    var k = decodeURIComponent(pair.substring(0, eq));
    if (k === paramName) return encodeURIComponent(paramName) + '=' + encodeURIComponent(payload);
    return pair;
  });
  return parts.join('&');
}

// ============================================================================
// HTTP History Feature
// ============================================================================

let httpHistoryEntries = [];
let httpHistoryOffset = 0;
let httpHistoryTotal = 0;
let httpHistorySelectedId = null;
let httpHistoryCaptureActive = false;
let httpHistoryFullCaptureActive = false;

function setupHttpHistory() {
  // Sub-tab switching
  document.querySelectorAll('.history-sub-tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.history-sub-tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.history-subtab-pane').forEach(p => {
        p.classList.remove('active');
        p.style.display = 'none';
      });
      btn.classList.add('active');
      const target = btn.dataset.historyTab;
      const pane = document.getElementById(target + '-subtab');
      if (pane) {
        pane.classList.add('active');
        pane.style.display = 'block';
      }
      if (target === 'http-traffic') {
        loadHttpHistory();
      }
      if (target === 'scan-history') {
        loadHistory();
      }
    });
  });

  // Capture toggle
  const captureToggle = document.getElementById('httpCaptureToggle');
  if (captureToggle) {
    captureToggle.addEventListener('change', () => {
      const enabled = captureToggle.checked;
      const scope = document.getElementById('httpCaptureScope').value;
      chrome.runtime.sendMessage({
        action: 'toggleHttpCapture',
        enabled: enabled,
        scope: scope
      }, (resp) => {
        httpHistoryCaptureActive = resp?.enabled || false;
        updateHttpCaptureUI();
      });
    });
  }

  // Full Capture toggle
  const fullCaptureToggle = document.getElementById('httpFullCaptureToggle');
  if (fullCaptureToggle) {
    fullCaptureToggle.addEventListener('change', () => {
      if (fullCaptureToggle.checked) {
        getTargetTabCb((tabs) => {
          if (!tabs[0]) return;
          chrome.runtime.sendMessage({
            action: 'enableFullCapture',
            tabId: tabs[0].id
          }, (resp) => {
            if (resp?.success) {
              httpHistoryFullCaptureActive = true;
              showMessage('Full Capture enabled -- yellow debug bar will appear', 'info');
            } else {
              fullCaptureToggle.checked = false;
              showMessage('Failed to enable Full Capture: ' + (resp?.error || 'unknown'), 'error');
            }
          });
        });
      } else {
        chrome.runtime.sendMessage({ action: 'disableFullCapture' }, () => {
          httpHistoryFullCaptureActive = false;
        });
      }
    });
  }

  // Scope change
  const scopeSelect = document.getElementById('httpCaptureScope');
  if (scopeSelect) {
    scopeSelect.addEventListener('change', () => {
      if (httpHistoryCaptureActive) {
        chrome.runtime.sendMessage({
          action: 'toggleHttpCapture',
          enabled: true,
          scope: scopeSelect.value
        });
      }
    });
  }

  // Clear button
  const clearBtn = document.getElementById('httpHistClearBtn');
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      if (!confirm('Clear all HTTP traffic history? This cannot be undone.')) return;
      chrome.runtime.sendMessage({ action: 'clearHttpHistory' }, () => {
        httpHistoryEntries = [];
        httpHistoryOffset = 0;
        httpHistoryTotal = 0;
        httpHistorySelectedId = null;
        renderHttpHistoryTable();
        hideHttpHistoryDetail();
        showMessage('HTTP History cleared', 'success');
      });
    });
  }

  // Export button
  const exportBtn = document.getElementById('httpHistExportBtn');
  if (exportBtn) {
    exportBtn.addEventListener('click', exportHttpHistory);
  }

  // Filter controls
  ['httpHistSearch', 'httpHistMethodFilter', 'httpHistStatusFilter', 'httpHistTypeFilter'].forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener(id === 'httpHistSearch' ? 'input' : 'change', () => {
        httpHistoryOffset = 0;
        httpHistoryEntries = [];
        loadHttpHistory();
      });
    }
  });

  // Load More
  const loadMoreBtn = document.getElementById('httpHistLoadMore');
  if (loadMoreBtn) {
    loadMoreBtn.addEventListener('click', () => {
      httpHistoryOffset += 50;
      loadHttpHistory(true);
    });
  }

  // Detail panel tabs
  document.querySelectorAll('.http-hist-detail-tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.http-hist-detail-tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.http-hist-detail-pane').forEach(p => {
        p.classList.remove('active');
        p.style.display = 'none';
      });
      btn.classList.add('active');
      const target = document.getElementById('httpHistDetail' + capitalize(btn.dataset.detailTab));
      if (target) {
        target.classList.add('active');
        target.style.display = 'block';
      }
    });
  });

  // Detail action buttons
  const sendRepeaterBtn = document.getElementById('httpHistSendRepeater');
  if (sendRepeaterBtn) {
    sendRepeaterBtn.addEventListener('click', () => {
      if (httpHistorySelectedId !== null) {
        sendHttpHistoryToRepeater(httpHistorySelectedId);
      }
    });
  }

  const copyCurlBtn = document.getElementById('httpHistCopyCurl');
  if (copyCurlBtn) {
    copyCurlBtn.addEventListener('click', () => {
      if (httpHistorySelectedId !== null) {
        copyHttpHistoryAsCurl(httpHistorySelectedId);
      }
    });
  }

  const pinBtn = document.getElementById('httpHistPinBtn');
  if (pinBtn) {
    pinBtn.addEventListener('click', () => {
      if (httpHistorySelectedId !== null) {
        toggleHttpPin(httpHistorySelectedId);
      }
    });
  }

  const closeDetailBtn = document.getElementById('httpHistCloseDetail');
  if (closeDetailBtn) {
    closeDetailBtn.addEventListener('click', hideHttpHistoryDetail);
  }
}

function capitalize(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

function loadHttpHistoryState() {
  chrome.runtime.sendMessage({ action: 'getHttpHistoryState' }, (resp) => {
    if (chrome.runtime.lastError) return;
    httpHistoryCaptureActive = resp?.enabled || false;
    httpHistoryFullCaptureActive = resp?.fullCapture || false;
    const scope = resp?.scope || 'same-origin';

    const toggle = document.getElementById('httpCaptureToggle');
    if (toggle) toggle.checked = httpHistoryCaptureActive;

    const scopeEl = document.getElementById('httpCaptureScope');
    if (scopeEl) scopeEl.value = scope;

    updateHttpCaptureUI();
  });
}

function updateHttpCaptureUI() {
  const fullCaptureToggle = document.getElementById('httpFullCaptureToggle');
  if (fullCaptureToggle) {
    fullCaptureToggle.disabled = !httpHistoryCaptureActive;
    if (!httpHistoryCaptureActive) {
      fullCaptureToggle.checked = false;
      httpHistoryFullCaptureActive = false;
    } else {
      fullCaptureToggle.checked = httpHistoryFullCaptureActive;
    }
  }
}

function loadHttpHistory(append) {
  const filters = {
    search: document.getElementById('httpHistSearch')?.value || '',
    method: document.getElementById('httpHistMethodFilter')?.value || 'ALL',
    statusGroup: document.getElementById('httpHistStatusFilter')?.value || '',
    contentTypeFilter: document.getElementById('httpHistTypeFilter')?.value || '',
    offset: httpHistoryOffset,
    limit: 50
  };

  chrome.runtime.sendMessage({ action: 'getHttpHistory', filters }, (resp) => {
    if (chrome.runtime.lastError) return;
    const entries = resp?.entries || [];
    httpHistoryTotal = resp?.total || 0;

    if (append) {
      httpHistoryEntries = httpHistoryEntries.concat(entries);
    } else {
      httpHistoryEntries = entries;
    }

    renderHttpHistoryTable();
  });
}

function renderHttpHistoryTable() {
  const tbody = document.getElementById('httpHistTableBody');
  const emptyEl = document.getElementById('httpHistEmpty');
  const paginationEl = document.getElementById('httpHistPagination');
  const tableWrap = document.querySelector('.http-hist-table-wrap');

  if (!tbody) return;

  if (httpHistoryEntries.length === 0) {
    tbody.innerHTML = '';
    if (emptyEl) emptyEl.style.display = '';
    if (tableWrap) tableWrap.style.display = 'none';
    if (paginationEl) paginationEl.style.display = 'none';
    return;
  }

  if (emptyEl) emptyEl.style.display = 'none';
  if (tableWrap) tableWrap.style.display = '';

  tbody.innerHTML = httpHistoryEntries.map(entry => {
    const methodClass = 'http-hist-method-' + entry.method;
    const statusClass = getStatusClass(entry.status);
    const typeShort = getTypeShort(entry.contentType);
    const sizeStr = formatBytes(entry.responseBodySize || 0);
    const timeStr = entry.timing ? entry.timing + 'ms' : '-';
    const selectedClass = entry.id === httpHistorySelectedId ? ' http-hist-row-selected' : '';
    const authBadge = entry.hasCredentials ? '<span class="http-hist-auth-badge">AUTH</span>' : '';
    const pinIcon = entry.pinned ? '<span class="http-hist-pin" title="Pinned">&#9733;</span>' : '';

    return `<tr class="http-hist-row${selectedClass}" data-entry-id="${entry.id}">
      <td class="http-hist-col-id">${entry.id}${pinIcon}</td>
      <td class="http-hist-col-method"><span class="http-hist-method ${methodClass}">${escapeHtml(entry.method)}</span>${authBadge}</td>
      <td class="http-hist-col-host" title="${escapeHtml(entry.domain)}">${escapeHtml(entry.domain)}</td>
      <td class="http-hist-col-path" title="${escapeHtml(entry.path)}">${escapeHtml(entry.path)}</td>
      <td class="http-hist-col-status"><span class="${statusClass}">${entry.status || '-'}</span></td>
      <td class="http-hist-col-type">${escapeHtml(typeShort)}</td>
      <td class="http-hist-col-size">${sizeStr}</td>
      <td class="http-hist-col-time">${timeStr}</td>
      <td class="http-hist-col-actions"><span class="http-hist-source-badge">${escapeHtml(entry.source)}</span></td>
    </tr>`;
  }).join('');

  // Row click handlers
  tbody.querySelectorAll('.http-hist-row').forEach(row => {
    row.addEventListener('click', () => {
      const entryId = parseInt(row.dataset.entryId);
      showHttpHistoryDetail(entryId);
    });
  });

  // Update pagination
  if (paginationEl) {
    const countEl = document.getElementById('httpHistCount');
    if (countEl) countEl.textContent = `Showing ${httpHistoryEntries.length} of ${httpHistoryTotal} entries`;
    const loadMoreBtn = document.getElementById('httpHistLoadMore');
    if (loadMoreBtn) {
      loadMoreBtn.style.display = httpHistoryEntries.length < httpHistoryTotal ? '' : 'none';
    }
    paginationEl.style.display = '';
  }
}

function getStatusClass(status) {
  if (!status || status === 0) return 'http-hist-status-0';
  if (status >= 200 && status < 300) return 'http-hist-status-2xx';
  if (status >= 300 && status < 400) return 'http-hist-status-3xx';
  if (status >= 400 && status < 500) return 'http-hist-status-4xx';
  if (status >= 500) return 'http-hist-status-5xx';
  return '';
}

function getTypeShort(contentType) {
  if (!contentType) return '-';
  const ct = contentType.toLowerCase();
  if (ct.includes('json')) return 'JSON';
  if (ct.includes('html')) return 'HTML';
  if (ct.includes('xml')) return 'XML';
  if (ct.includes('javascript') || ct.includes('ecmascript')) return 'JS';
  if (ct.includes('css')) return 'CSS';
  if (ct.includes('form')) return 'Form';
  if (ct.includes('text')) return 'Text';
  if (ct.includes('image')) return 'Img';
  if (ct.includes('font')) return 'Font';
  return ct.split('/').pop().split(';')[0].substring(0, 6);
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '-';
  if (bytes < 1024) return bytes + 'B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + 'K';
  return (bytes / (1024 * 1024)).toFixed(1) + 'M';
}

function showHttpHistoryDetail(entryId) {
  httpHistorySelectedId = entryId;

  // Highlight row
  document.querySelectorAll('.http-hist-row').forEach(r => r.classList.remove('http-hist-row-selected'));
  const row = document.querySelector(`.http-hist-row[data-entry-id="${entryId}"]`);
  if (row) row.classList.add('http-hist-row-selected');

  // Fetch full entry with bodies
  chrome.runtime.sendMessage({ action: 'getHttpHistoryEntry', id: entryId }, (resp) => {
    if (chrome.runtime.lastError || !resp?.entry) return;
    const entry = resp.entry;

    // Update Request pane
    const reqSummary = document.getElementById('httpHistDetailReqSummary');
    if (reqSummary) reqSummary.textContent = entry.method + ' ' + entry.url;

    const credWarning = document.getElementById('httpHistDetailReqCredWarning');
    if (credWarning) {
      if (entry.hasCredentials) {
        const credFieldsList = detectCredentialFieldNames(entry.requestBody);
        credWarning.textContent = 'Credential fields detected: ' + (credFieldsList.length > 0 ? credFieldsList.join(', ') : 'possible credentials');
        credWarning.style.display = '';
      } else {
        credWarning.style.display = 'none';
      }
    }

    const reqHeaders = document.getElementById('httpHistDetailReqHeaders');
    if (reqHeaders) reqHeaders.innerHTML = renderHeadersTable(entry.requestHeaders);

    const reqBody = document.getElementById('httpHistDetailReqBody');
    if (reqBody) reqBody.textContent = entry.requestBody || '(empty)';

    // Update Response pane
    const respSummary = document.getElementById('httpHistDetailRespSummary');
    if (respSummary) {
      respSummary.textContent = `${entry.status} ${entry.statusText} | ${entry.timing}ms | ${formatBytes(entry.responseBodySize)}`;
      if (entry.truncated) respSummary.textContent += ' (truncated)';
    }

    const respHeaders = document.getElementById('httpHistDetailRespHeaders');
    if (respHeaders) respHeaders.innerHTML = renderHeadersTable(entry.responseHeaders);

    const respBody = document.getElementById('httpHistDetailRespBody');
    if (respBody) {
      let bodyText = entry.responseBody || '(empty)';
      if (entry.bodiesPruned) bodyText = '[bodies pruned -- entry older than 24h]';
      // Try to pretty-print JSON
      if (entry.contentType && entry.contentType.includes('json') && bodyText !== '(empty)') {
        try { bodyText = JSON.stringify(JSON.parse(bodyText), null, 2); } catch (e) { /* keep raw */ }
      }
      respBody.textContent = bodyText;
    }

    // Update pin button
    const pinBtn = document.getElementById('httpHistPinBtn');
    if (pinBtn) pinBtn.textContent = entry.pinned ? 'Unpin' : 'Pin';

    // Show detail panel
    const detail = document.getElementById('httpHistDetail');
    if (detail) detail.style.display = '';

    // Ensure Request tab is active
    document.querySelectorAll('.http-hist-detail-tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.http-hist-detail-pane').forEach(p => {
      p.classList.remove('active');
      p.style.display = 'none';
    });
    const reqTab = document.querySelector('.http-hist-detail-tab-btn[data-detail-tab="request"]');
    if (reqTab) reqTab.classList.add('active');
    const reqPane = document.getElementById('httpHistDetailRequest');
    if (reqPane) { reqPane.classList.add('active'); reqPane.style.display = 'block'; }
  });
}

function hideHttpHistoryDetail() {
  const detail = document.getElementById('httpHistDetail');
  if (detail) detail.style.display = 'none';
  httpHistorySelectedId = null;
  document.querySelectorAll('.http-hist-row').forEach(r => r.classList.remove('http-hist-row-selected'));
}

function renderHeadersTable(headers) {
  if (!headers || Object.keys(headers).length === 0) return '<tr><td colspan="2" style="color: var(--text-tertiary)">(no headers)</td></tr>';
  return Object.entries(headers).map(([key, value]) =>
    `<tr><td>${escapeHtml(key)}</td><td>${escapeHtml(String(value))}</td></tr>`
  ).join('');
}

function detectCredentialFieldNames(body) {
  if (!body) return [];
  const fields = [];
  const credPatterns = ['password', 'passwd', 'pwd', 'secret', 'token', 'credential', 'api_key', 'apikey', 'auth'];
  const lower = body.toLowerCase();
  credPatterns.forEach(p => {
    if (lower.includes(p)) fields.push(p);
  });
  return fields;
}

async function sendHttpHistoryToRepeater(entryId) {
  chrome.runtime.sendMessage({ action: 'getHttpHistoryEntry', id: entryId }, (resp) => {
    if (chrome.runtime.lastError || !resp?.entry) {
      showMessage('Failed to load entry for Repeater', 'error');
      return;
    }
    const entry = resp.entry;

    // Switch to Repeater tab
    document.querySelector('[data-tab="repeater"]').click();

    setTimeout(function() {
      // Set method
      var methodEl = document.getElementById('repeater-method');
      if (methodEl) methodEl.value = entry.method || 'GET';

      // Set URL
      var urlEl = document.getElementById('repeater-url');
      if (urlEl) urlEl.value = entry.url;

      // Clear existing headers and populate from captured data
      var headersContainer = document.getElementById('repeater-headers-container');
      if (headersContainer) headersContainer.textContent = '';

      function addRow(key, value) {
        if (typeof addRepeaterHeader === 'function') addRepeaterHeader();
        var rows = headersContainer.querySelectorAll('.repeater-header-row');
        var lastRow = rows[rows.length - 1];
        if (lastRow) {
          var k = lastRow.querySelector('.repeater-header-key');
          var v = lastRow.querySelector('.repeater-header-value');
          if (k) k.value = key;
          if (v) v.value = value;
        }
      }

      // Add all captured request headers
      if (entry.requestHeaders && typeof entry.requestHeaders === 'object') {
        Object.entries(entry.requestHeaders).forEach(([key, value]) => {
          addRow(key, value);
        });
      }

      // Set body
      var bodyEl = document.getElementById('repeater-body');
      if (bodyEl) bodyEl.value = entry.requestBody || '';

      // Auto-detect body mode from Content-Type
      if (entry.requestHeaders) {
        const ct = (entry.requestHeaders['Content-Type'] || entry.requestHeaders['content-type'] || '').toLowerCase();
        if (ct.includes('json')) {
          const jsonBtn = document.getElementById('repeater-body-mode-json');
          if (jsonBtn) jsonBtn.click();
        } else if (ct.includes('form-data') || ct.includes('multipart')) {
          const formBtn = document.getElementById('repeater-body-mode-form-data');
          if (formBtn) formBtn.click();
        }
      }

      // Show body section for non-GET methods
      if (typeof toggleRepeaterBodyVisibility === 'function') {
        toggleRepeaterBodyVisibility();
      }

      showMessage('Request loaded in Repeater with full headers and body', 'success');
    }, 50);
  });
}

function copyHttpHistoryAsCurl(entryId) {
  chrome.runtime.sendMessage({ action: 'getHttpHistoryEntry', id: entryId }, (resp) => {
    if (chrome.runtime.lastError || !resp?.entry) {
      showMessage('Failed to load entry', 'error');
      return;
    }
    const entry = resp.entry;
    let curl = `curl -X ${entry.method} '${entry.url}'`;

    if (entry.requestHeaders) {
      Object.entries(entry.requestHeaders).forEach(([key, value]) => {
        curl += ` \\\n  -H '${key}: ${value}'`;
      });
    }

    if (entry.requestBody && ['POST', 'PUT', 'PATCH'].includes(entry.method)) {
      // Escape single quotes in body
      const escapedBody = entry.requestBody.replace(/'/g, "'\\''");
      curl += ` \\\n  -d '${escapedBody}'`;
    }

    navigator.clipboard.writeText(curl).then(() => {
      showMessage('cURL command copied to clipboard', 'success');
    }).catch(() => {
      showMessage('Failed to copy to clipboard', 'error');
    });
  });
}

function toggleHttpPin(entryId) {
  // Find current state
  const entry = httpHistoryEntries.find(e => e.id === entryId);
  const newPinned = !(entry?.pinned || false);

  chrome.runtime.sendMessage({
    action: 'toggleHttpHistoryPin',
    id: entryId,
    pinned: newPinned
  }, (resp) => {
    if (resp?.success) {
      if (entry) entry.pinned = newPinned;
      renderHttpHistoryTable();
      const pinBtn = document.getElementById('httpHistPinBtn');
      if (pinBtn) pinBtn.textContent = newPinned ? 'Unpin' : 'Pin';
      showMessage(newPinned ? 'Entry pinned (exempt from eviction)' : 'Entry unpinned', 'success');
    }
  });
}

function exportHttpHistory() {
  if (httpHistoryEntries.length === 0) {
    showMessage('No entries to export', 'info');
    return;
  }

  // Export all entries as JSON (slim -- without bodies, for size)
  const data = JSON.stringify(httpHistoryEntries, null, 2);
  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'origami-http-history-' + new Date().toISOString().split('T')[0] + '.json';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showMessage('HTTP History exported', 'success');
}
