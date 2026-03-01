// Origami Analyzer Coordinator
// Coordinates running all security analyzers and collecting results

// Report scan progress to popup via chrome.runtime messaging
function reportProgress(phase, step, totalSteps) {
  try {
    chrome.runtime.sendMessage({
      action: 'scanProgress',
      phase: phase,
      step: step,
      totalSteps: totalSteps
    });
  } catch (e) {
    // Popup may not be open - that's fine
  }
}

// Expose runAllAnalyzers globally so scanner.js can call it directly
window.runAllAnalyzers = async function(options = {}) {
    const results = {
      timestamp: new Date().toISOString(),
      url: window.location.href,
      headers: null,
      cookies: null,
      vulnerabilities: null,
      technologies: null,
      sensitiveFiles: null,
      sessionState: null,
      oauthFlows: null,
      graphql: null,
      surfaceSnapshot: null,
      correlationChains: null,
      templateFindings: null,
      plugins: null,
      crypto: null,
      cloudStorage: null,
      exfiltration: null,
      websockets: null,
      jsObfuscation: null
    };

    // Read analyzer toggle settings
    let analyzerSettings = {};
    try {
      const stored = await new Promise(resolve => chrome.storage.sync.get(['settings'], resolve));
      analyzerSettings = stored?.settings?.analyzers || {};
    } catch(e) { /* use defaults: all enabled */ }

    const totalSteps = 18;

    try {
      // 1. Analyze HTTP headers
      reportProgress('Analyzing headers...', 1, totalSteps);
      results.headers = await analyzeHeaders();

      // 2. Analyze cookies
      reportProgress('Analyzing cookies...', 2, totalSteps);
      results.cookies = await analyzeCookies();

      // 3. Scan for vulnerabilities in page content
      reportProgress('Scanning vulnerabilities...', 3, totalSteps);
      results.vulnerabilities = await scanVulnerabilities();

      // 4. Fingerprint technologies
      reportProgress('Fingerprinting technologies...', 4, totalSteps);
      results.technologies = await fingerprintTechnologies();

      // 5. Check for sensitive file exposure (.git, .env, backups, source maps)
      if (options.skipSensitiveFiles) {
        reportProgress('Skipping sensitive files (disabled)...', 5, totalSteps);
        results.sensitiveFiles = [];
      } else {
        reportProgress('Checking sensitive files...', 5, totalSteps);
        results.sensitiveFiles = await scanSensitiveFiles();
      }

      // 6. Collect page resources for Inventory
      reportProgress('Collecting resources...', 6, totalSteps);
      try {
        if (typeof ResourceCollector !== 'undefined') {
          const collector = new ResourceCollector();
          const inventory = await collector.collect();
          chrome.runtime.sendMessage({
            action: 'inventoryCollected',
            inventory: inventory
          });
        }
      } catch (e) {
        console.error('Origami: Resource collection error:', e);
        try {
          chrome.runtime.sendMessage({
            action: 'inventoryCollected',
            inventory: null,
            error: 'Resource collection failed: ' + e.message
          });
        } catch (_) { /* popup may not be open */ }
      }

      // 7. Analyze session state (JWTs, session cookies, OAuth)
      reportProgress('Analyzing session state...', 7, totalSteps);
      results.sessionState = { tokens: [], cookies: [], oauthState: null, issues: [], allIssues: [] };
      if (analyzerSettings.session !== false) {
        try {
          if (typeof SessionAnalyzer !== 'undefined') {
            const sessionAnalyzer = new SessionAnalyzer();
            results.sessionState = await sessionAnalyzer.analyze();
          }
        } catch (e) {
          console.error('Origami: Session analysis error:', e);
        }
      }

      // 8. Intercept OAuth/SAML flows
      reportProgress('Intercepting auth flows...', 8, totalSteps);
      results.oauthFlows = { flows: [], issues: [], samlAssertions: [] };
      if (analyzerSettings.oauth !== false) {
        try {
          if (typeof OAuthInterceptor !== 'undefined') {
            const interceptor = new OAuthInterceptor();
            results.oauthFlows = await interceptor.analyze();
            try {
              chrome.runtime.sendMessage({
                action: 'oauthFlowCaptured',
                flows: results.oauthFlows
              });
            } catch (_) { /* popup may not be open */ }
          }
        } catch (e) {
          console.error('Origami: OAuth interceptor error:', e);
        }
      }

      // 9. Map GraphQL attack surface
      reportProgress('Mapping GraphQL endpoints...', 9, totalSteps);
      results.graphql = { endpoints: [], schema: null, schemaTree: null, issues: [], technologies: [] };
      if (analyzerSettings.graphql !== false) {
        try {
          if (typeof GraphQLMapper !== 'undefined') {
            const mapper = new GraphQLMapper();
            results.graphql = await mapper.analyze();
            try {
              chrome.runtime.sendMessage({
                action: 'graphqlResultsCollected',
                graphql: results.graphql
              });
            } catch (_) { /* popup may not be open */ }
          }
        } catch (e) {
          console.error('Origami: GraphQL mapper error:', e);
        }
      }

      // 10. Audit client-side cryptography
      reportProgress('Auditing client-side crypto...', 10, totalSteps);
      results.crypto = { libraries: [], operations: [], issues: [] };
      if (analyzerSettings.crypto !== false) {
        try {
          if (typeof CryptoAuditor !== 'undefined') {
            const cryptoAuditor = new CryptoAuditor();
            results.crypto = await cryptoAuditor.analyze();
            try {
              chrome.runtime.sendMessage({
                action: 'cryptoResultsCollected',
                crypto: results.crypto
              });
            } catch (_) { /* popup may not be open */ }
          }
        } catch (e) {
          console.error('Origami: Crypto auditor error:', e);
        }
      }

      // 11. Map cloud storage exposure
      reportProgress('Mapping cloud storage...', 11, totalSteps);
      results.cloudStorage = { buckets: [], issues: [] };
      if (analyzerSettings.cloudStorage !== false) {
        try {
          if (typeof CloudStorageMapper !== 'undefined') {
            const cloudMapper = new CloudStorageMapper();
            results.cloudStorage = await cloudMapper.analyze();
            try {
              chrome.runtime.sendMessage({
                action: 'cloudStorageResultsCollected',
                cloudStorage: results.cloudStorage
              });
            } catch (_) { /* popup may not be open */ }
          }
        } catch (e) {
          console.error('Origami: Cloud storage mapper error:', e);
        }
      }

      // 12. Detect data exfiltration patterns
      reportProgress('Monitoring data exfiltration...', 12, totalSteps);
      results.exfiltration = { dataFlows: [], issues: [] };
      if (analyzerSettings.exfiltration !== false) {
        try {
          if (typeof ExfiltrationDetector !== 'undefined') {
            const exfilDetector = new ExfiltrationDetector();
            results.exfiltration = await exfilDetector.analyze();
            try {
              chrome.runtime.sendMessage({
                action: 'exfiltrationResultsCollected',
                exfiltration: results.exfiltration
              });
            } catch (_) { /* popup may not be open */ }
          }
        } catch (e) {
          console.error('Origami: Exfiltration detector error:', e);
        }
      }

      // 13. Audit WebSocket connections
      reportProgress('Auditing WebSocket connections...', 13, totalSteps);
      results.websockets = { connections: [], messages: [], issues: [] };
      if (analyzerSettings.websocket !== false) {
        try {
          if (typeof WebSocketAuditor !== 'undefined') {
            const wsAuditor = new WebSocketAuditor();
            results.websockets = await wsAuditor.analyze();
            try {
              chrome.runtime.sendMessage({
                action: 'websocketResultsCollected',
                websockets: results.websockets
              });
            } catch (_) { /* popup may not be open */ }
          }
        } catch (e) {
          console.error('Origami: WebSocket auditor error:', e);
        }
      }

      // 14. Detect JavaScript obfuscation
      reportProgress('Detecting JS obfuscation...', 14, totalSteps);
      results.jsObfuscation = { scripts: [], issues: [] };
      if (analyzerSettings.jsObfuscation !== false) {
        try {
          if (typeof JSObfuscationDetector !== 'undefined') {
            const obfuscationDetector = new JSObfuscationDetector();
            results.jsObfuscation = await obfuscationDetector.analyze();
            try {
              chrome.runtime.sendMessage({
                action: 'jsObfuscationResultsCollected',
                jsObfuscation: results.jsObfuscation
              });
            } catch (_) { /* popup may not be open */ }
          }
        } catch (e) {
          console.error('Origami: JS obfuscation detector error:', e);
        }
      }

      // 15. Run YAML detection templates
      reportProgress('Running detection templates...', 15, totalSteps);
      try {
        if (typeof TemplateEngine !== 'undefined') {
          const engine = new TemplateEngine();
          results.templateFindings = await engine.runAll();
        } else {
          results.templateFindings = [];
        }
      } catch (e) {
        console.error('Origami: Template engine error:', e);
        results.templateFindings = [];
      }

      // 16. Snapshot attack surface for evolution tracking
      reportProgress('Capturing attack surface...', 16, totalSteps);
      results.surfaceSnapshot = null;
      if (analyzerSettings.surfaceTracker !== false) {
        try {
          if (typeof SurfaceTracker !== 'undefined') {
            const tracker = new SurfaceTracker();
            results.surfaceSnapshot = tracker.captureSnapshot(results);
            try {
              chrome.runtime.sendMessage({
                action: 'surfaceSnapshotCaptured',
                snapshot: results.surfaceSnapshot
              });
            } catch (_) { /* popup may not be open */ }
          }
        } catch (e) {
          console.error('Origami: Surface tracker error:', e);
        }
      }

      // 17. Correlate findings into attack chains
      reportProgress('Correlating attack chains...', 17, totalSteps);
      results.correlationChains = [];
      if (analyzerSettings.correlationEngine !== false) {
        try {
          if (typeof CorrelationEngine !== 'undefined') {
            const correlator = new CorrelationEngine();
            results.correlationChains = correlator.correlate(results);
            try {
              chrome.runtime.sendMessage({
                action: 'correlationChainsDetected',
                chains: results.correlationChains
              });
            } catch (_) { /* popup may not be open */ }
          }
        } catch (e) {
          console.error('Origami: Correlation engine error:', e);
        }
      }

      // 18. Run registered plugins (always last)
      reportProgress('Running plugins...', 18, totalSteps);
      results.plugins = await runPluginAnalyzers();

      reportProgress('Scan complete', totalSteps, totalSteps);

    } catch (error) {
      console.error('Origami: Analyzer error:', error);
    }

    return results;
  };

  async function analyzeHeaders() {
    try {
      // Fetch the current page to get headers
      const response = await fetch(window.location.href, {
        method: 'HEAD',
        credentials: 'include'
      });

      const headers = {};
      response.headers.forEach((value, key) => {
        headers[key] = value;
      });

      // Share headers globally for other analyzers (avoids redundant fetch)
      window._origamiHeaders = headers;

      // Use SecurityHeaderAnalyzer
      if (typeof SecurityHeaderAnalyzer !== 'undefined') {
        const analyzer = new SecurityHeaderAnalyzer();
        return analyzer.analyze(headers, window.location.href);
      } else {
        return [{ error: 'SecurityHeaderAnalyzer not loaded' }];
      }
    } catch (error) {
      return [{ error: `Header analysis failed: ${error.message}` }];
    }
  }

  async function analyzeCookies() {
    try {
      if (typeof CookieSecurityAnalyzer !== 'undefined') {
        const analyzer = new CookieSecurityAnalyzer();
        return await analyzer.analyze(window.location.href);
      } else {
        return [{ error: 'CookieSecurityAnalyzer not loaded' }];
      }
    } catch (error) {
      return [{ error: `Cookie analysis failed: ${error.message}` }];
    }
  }

  async function scanVulnerabilities() {
    try {
      if (typeof VulnerabilityScanner !== 'undefined') {
        const scanner = new VulnerabilityScanner();
        return await scanner.scan(document, window.location.href);
      } else {
        return [{ error: 'VulnerabilityScanner not loaded' }];
      }
    } catch (error) {
      return [{ error: `Vulnerability scan failed: ${error.message}` }];
    }
  }

  async function fingerprintTechnologies() {
    try {
      if (typeof TechnologyFingerprinter !== 'undefined') {
        const fingerprinter = new TechnologyFingerprinter();
        return await fingerprinter.fingerprint(document, window);
      } else {
        return { error: 'TechnologyFingerprinter not loaded' };
      }
    } catch (error) {
      return { error: `Technology fingerprinting failed: ${error.message}` };
    }
  }

  async function scanSensitiveFiles() {
    try {
      if (typeof SensitiveFileScanner !== 'undefined') {
        const scanner = new SensitiveFileScanner();
        return await scanner.scan(window.location.href);
      } else {
        return [{ error: 'SensitiveFileScanner not loaded' }];
      }
    } catch (error) {
      return [{ error: `Sensitive file scan failed: ${error.message}` }];
    }
  }

  // Plugin integration: track registered plugin analyzers
  const _registeredPlugins = [];

  document.addEventListener('origami-plugin-register', (event) => {
    const detail = event.detail;
    if (detail && detail.id && detail.analyzerClass) {
      _registeredPlugins.push(detail);
      console.log('Origami: Plugin analyzer registered:', detail.id, detail.analyzerClass);
    }
  });

  async function runPluginAnalyzers() {
    const pluginResults = [];

    if (_registeredPlugins.length === 0) return pluginResults;

    for (const plugin of _registeredPlugins) {
      try {
        const AnalyzerClass = window[plugin.analyzerClass];
        if (typeof AnalyzerClass === 'undefined') {
          console.warn('Origami: Plugin class not found:', plugin.analyzerClass);
          continue;
        }

        const analyzer = typeof AnalyzerClass === 'function' ? new AnalyzerClass() : AnalyzerClass;
        const analyzeMethod = analyzer.analyze || analyzer.scan || analyzer.run;

        if (typeof analyzeMethod !== 'function') {
          console.warn('Origami: Plugin has no analyze/scan/run method:', plugin.id);
          continue;
        }

        const result = await analyzeMethod.call(analyzer, document, window.location.href);
        pluginResults.push({
          pluginId: plugin.id,
          pluginName: plugin.name,
          category: plugin.resultCategory,
          findings: Array.isArray(result) ? result : (result ? [result] : [])
        });
      } catch (e) {
        console.error('Origami: Plugin error (' + plugin.id + '):', e);
        pluginResults.push({
          pluginId: plugin.id,
          pluginName: plugin.name,
          category: plugin.resultCategory,
          findings: [],
          error: e.message
        });
      }
    }

    // Send plugin results to background for storage
    if (pluginResults.length > 0) {
      try {
        chrome.runtime.sendMessage({
          action: 'pluginResultsCollected',
          results: pluginResults
        });
      } catch (e) {
        // Popup may not be open
      }
    }

    return pluginResults;
  }

  console.log('Origami: Analyzer coordinator initialized');

  // Signal to scanner.js that analyzers are ready (replaces polling race condition)
  document.dispatchEvent(new CustomEvent('origami-analyzers-ready'));

// Also listen for messages from popup (for manual scan)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'ping') {
    sendResponse({ alive: true });
    return false;
  }
  if (request.action === 'runSecurityAnalysis') {
    window.runAllAnalyzers().then(results => {
      sendResponse({ results });
    }).catch(error => {
      sendResponse({ error: error.message });
    });
    return true; // Will respond asynchronously
  }
});

