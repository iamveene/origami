// Resource Collector - Discovers all page resources for the Inventory tab
// Uses Performance API and DOM queries to build a comprehensive resource inventory

class ResourceCollector {
  constructor() {
    this.resources = new Map();
    this.externalResources = new Map();
  }

  async collect() {
    const baseUrl = new URL(window.location.href);
    const domain = baseUrl.hostname;

    // Add the document itself
    this.addResource(baseUrl.pathname || '/', {
      type: 'document',
      status: 200,
      size: document.documentElement.outerHTML.length,
      mimeType: 'text/html',
      source: 'document'
    });

    // Collect from Performance API (all loaded resources)
    this.collectFromPerformanceAPI(baseUrl);

    // Collect from DOM elements (linked/referenced resources)
    this.collectFromDOM(baseUrl);

    // Probe DOM-discovered resources that lack status codes
    await this.probeDiscoveredURLs(baseUrl);

    return {
      domain: domain,
      timestamp: new Date().toISOString(),
      url: window.location.href,
      resources: Object.fromEntries(this.resources),
      externalResources: Object.fromEntries(
        Array.from(this.externalResources.entries()).map(
          ([d, resources]) => [d, [...resources.values()]]
        )
      )
    };
  }

  collectFromPerformanceAPI(baseUrl) {
    let entries;
    try {
      entries = performance.getEntriesByType('resource');
    } catch (e) {
      return;
    }

    for (const entry of entries) {
      try {
        const url = new URL(entry.name);
        const isSameOrigin = url.hostname === baseUrl.hostname;

        const resourceInfo = {
          type: this.normalizeInitiatorType(entry.initiatorType),
          size: entry.transferSize || entry.decodedBodySize || 0,
          duration: Math.round(entry.duration),
          source: 'performance'
        };

        if (entry.responseStatus !== undefined && entry.responseStatus !== 0) {
          resourceInfo.status = entry.responseStatus;
        }

        if (isSameOrigin) {
          this.addResource(url.pathname + (url.search || ''), resourceInfo);
        } else {
          this.addExternalResource(url.hostname, url.pathname + (url.search || ''), resourceInfo);
        }
      } catch (e) {
        // Invalid URL
      }
    }
  }

  collectFromDOM(baseUrl) {
    const selectors = {
      'script[src]': 'script',
      'link[rel="stylesheet"][href]': 'stylesheet',
      'link[rel="icon"][href]': 'image',
      'link[rel="preload"][href]': 'preload',
      'img[src]': 'image',
      'iframe[src]': 'iframe',
      'source[src]': 'media',
      'video[src]': 'media',
      'audio[src]': 'media',
      'a[href]': 'link',
      'form[action]': 'form'
    };

    for (const [selector, type] of Object.entries(selectors)) {
      document.querySelectorAll(selector).forEach(el => {
        const urlAttr = el.href || el.src || el.action;
        if (!urlAttr) return;

        // Skip javascript:, data:, blob:, mailto:, tel: URLs
        if (/^(javascript|data|blob|mailto|tel|#)/.test(urlAttr)) return;

        try {
          const url = new URL(urlAttr, baseUrl);
          if (url.protocol !== 'http:' && url.protocol !== 'https:') return;

          if (url.hostname === baseUrl.hostname) {
            this.addResource(url.pathname + (url.search || ''), {
              type: type,
              source: 'dom'
            });
          } else {
            this.addExternalResource(url.hostname, url.pathname + (url.search || ''), {
              type: type,
              source: 'dom'
            });
          }
        } catch (e) {
          // Invalid URL
        }
      });
    }
  }

  async probeDiscoveredURLs(baseUrl) {
    const toProbe = [];
    for (const [path, info] of this.resources) {
      if (info.status === undefined && info.type !== 'link' && info.type !== 'form') {
        toProbe.push(path);
      }
    }

    const PROBE_LIMIT = 20;
    const TIMEOUT_MS = 3000;
    const batch = toProbe.slice(0, PROBE_LIMIT);

    for (const path of batch) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);
        const response = await fetch(new URL(path, baseUrl).href, {
          method: 'HEAD',
          credentials: 'omit',
          signal: controller.signal
        });
        clearTimeout(timeoutId);

        const info = this.resources.get(path);
        if (info) {
          info.status = response.status;
          const ct = response.headers.get('content-type');
          if (ct) info.mimeType = ct.split(';')[0].trim();
        }
      } catch (e) {
        // Network error or timeout
      }

      await new Promise(r => setTimeout(r, 50));
    }
  }

  addResource(path, info) {
    path = path || '/';
    if (!path.startsWith('/')) path = '/' + path;

    const existing = this.resources.get(path);
    if (existing) {
      // Merge: keep most informative data
      if (info.status !== undefined) existing.status = info.status;
      if (info.size && (!existing.size || info.size > existing.size)) existing.size = info.size;
      if (info.mimeType) existing.mimeType = info.mimeType;
      if (info.duration !== undefined) existing.duration = info.duration;
      if (info.type && existing.type === 'link') existing.type = info.type;
    } else {
      this.resources.set(path, { ...info });
    }
  }

  addExternalResource(domain, path, info) {
    if (!this.externalResources.has(domain)) {
      this.externalResources.set(domain, new Map());
    }
    const domainMap = this.externalResources.get(domain);
    const key = path || '/';
    const existing = domainMap.get(key);
    if (existing) {
      if (info.status !== undefined) existing.status = info.status;
      if (info.size && (!existing.size || info.size > existing.size)) existing.size = info.size;
      if (info.type && existing.type === 'link') existing.type = info.type;
    } else {
      domainMap.set(key, { path: key, ...info });
    }
  }

  normalizeInitiatorType(initiatorType) {
    const typeMap = {
      'xmlhttprequest': 'fetch',
      'fetch': 'fetch',
      'script': 'script',
      'css': 'stylesheet',
      'link': 'stylesheet',
      'img': 'image',
      'video': 'media',
      'audio': 'media'
    };
    return typeMap[initiatorType] || initiatorType || 'other';
  }
}

class ResourceObserver {
  constructor() {
    this.pendingResources = [];
    this.observer = null;
    this.batchTimer = null;
    this.BATCH_INTERVAL_MS = 2000;
  }

  start() {
    if (this.observer) return;
    try {
      this.observer = new PerformanceObserver((list) => {
        const entries = list.getEntries();
        for (const entry of entries) {
          this.pendingResources.push(entry);
        }
        this.scheduleBatch();
      });
      this.observer.observe({ type: 'resource', buffered: false });
    } catch (e) {
      // PerformanceObserver not supported
    }
  }

  stop() {
    if (this.observer) {
      this.observer.disconnect();
      this.observer = null;
    }
    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
      this.batchTimer = null;
    }
  }

  scheduleBatch() {
    if (this.batchTimer) return;
    this.batchTimer = setTimeout(() => {
      this.batchTimer = null;
      this.flushBatch();
    }, this.BATCH_INTERVAL_MS);
  }

  flushBatch() {
    if (this.pendingResources.length === 0) return;

    const entries = this.pendingResources.splice(0);
    const baseUrl = new URL(window.location.href);
    const domain = baseUrl.hostname;
    const normalize = ResourceCollector.prototype.normalizeInitiatorType;
    const resources = {};
    const externalResources = {};

    for (const entry of entries) {
      try {
        const url = new URL(entry.name);
        const isSameOrigin = url.hostname === baseUrl.hostname;
        const info = {
          type: normalize(entry.initiatorType),
          size: entry.transferSize || entry.decodedBodySize || 0,
          duration: Math.round(entry.duration),
          source: 'observer'
        };
        if (entry.responseStatus !== undefined && entry.responseStatus !== 0) {
          info.status = entry.responseStatus;
        }
        if (isSameOrigin) {
          const key = url.pathname + (url.search || '');
          resources[key] = info;
        } else {
          if (!externalResources[url.hostname]) {
            externalResources[url.hostname] = [];
          }
          externalResources[url.hostname].push({
            path: url.pathname + (url.search || ''),
            ...info
          });
        }
      } catch (e) {
        // Invalid URL
      }
    }

    if (Object.keys(resources).length === 0 && Object.keys(externalResources).length === 0) return;

    try {
      chrome.runtime.sendMessage({
        action: 'inventoryIncremental',
        domain: domain,
        timestamp: new Date().toISOString(),
        url: window.location.href,
        resources: resources,
        externalResources: externalResources
      });
    } catch (e) {
      // Extension context may be invalidated
    }
  }

  drain() {
    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
      this.batchTimer = null;
    }
    this.flushBatch();
  }
}

// Auto-start observer on page load
const _resourceObserver = new ResourceObserver();
_resourceObserver.start();

// Listen for collection requests from popup or coordinator
if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'collectResources') {
      _resourceObserver.drain();
      const collector = new ResourceCollector();
      collector.collect().then(results => {
        sendResponse({ results });
      }).catch(error => {
        sendResponse({ error: error.message });
      });
      return true;
    } else if (request.action === 'stopResourceObserver') {
      _resourceObserver.stop();
      sendResponse({ success: true });
    }
  });
}
