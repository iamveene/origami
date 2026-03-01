// Origami Attack Surface Evolution Tracker
// Captures baseline snapshots and diffs to track attack surface changes over time

class SurfaceTracker {
  constructor() {
    this.storagePrefix = 'baseline_';
    this.maxBaselinesPerDomain = 5;
  }

  // Build a snapshot from already-collected scan results (called by analyzer-coordinator)
  captureSnapshot(allResults) {
    try {
      const snapshot = {
        domain: window.location.hostname,
        timestamp: new Date().toISOString(),
        url: window.location.href,
        technologies: [],
        resources: this.captureResources(),
        headers: this.captureHeaders(),
        cookies: this.captureCookieNames(),
        findingSummary: { secrets: 0, vulns: 0, headers: 0, cookies: 0, total: 0 }
      };

      // Extract technologies from allResults
      if (allResults && allResults.technologies) {
        const techs = allResults.technologies;
        const categories = ['frameworks', 'libraries', 'backend', 'cms', 'cdn', 'analytics', 'security', 'hosting'];
        for (const category of categories) {
          if (techs[category] && Array.isArray(techs[category])) {
            for (const tech of techs[category]) {
              snapshot.technologies.push({
                name: tech.name || tech,
                version: tech.version || null,
                category: category
              });
            }
          }
        }
      }

      // Build finding summary from allResults
      if (allResults) {
        if (Array.isArray(allResults.headers)) {
          snapshot.findingSummary.headers = allResults.headers.filter(h => h.severity && h.severity !== 'INFO').length;
        }
        if (Array.isArray(allResults.cookies)) {
          snapshot.findingSummary.cookies = allResults.cookies.filter(c => c.severity && c.severity !== 'INFO').length;
        }
        if (Array.isArray(allResults.vulnerabilities)) {
          snapshot.findingSummary.vulns = allResults.vulnerabilities.length;
        }
        snapshot.findingSummary.total = snapshot.findingSummary.headers + snapshot.findingSummary.cookies + snapshot.findingSummary.vulns;
        if (allResults.crypto && Array.isArray(allResults.crypto.issues)) {
          snapshot.findingSummary.crypto = allResults.crypto.issues.length;
          snapshot.findingSummary.total += snapshot.findingSummary.crypto;
        }
        if (allResults.cloudStorage && Array.isArray(allResults.cloudStorage.issues)) {
          snapshot.findingSummary.cloudStorage = allResults.cloudStorage.issues.length;
          snapshot.findingSummary.total += snapshot.findingSummary.cloudStorage;
        }
        if (allResults.exfiltration && Array.isArray(allResults.exfiltration.issues)) {
          snapshot.findingSummary.exfiltration = allResults.exfiltration.issues.length;
          snapshot.findingSummary.total += snapshot.findingSummary.exfiltration;
        }
        if (allResults.websockets && Array.isArray(allResults.websockets.issues)) {
          snapshot.findingSummary.websockets = allResults.websockets.issues.length;
          snapshot.findingSummary.total += snapshot.findingSummary.websockets;
        }
      }

      return snapshot;
    } catch (error) {
      console.error('Origami: Failed to capture snapshot:', error.message);
      return null;
    }
  }

  async captureBaseline() {
    try {
      const domain = window.location.hostname;
      const baseline = {
        domain: domain,
        timestamp: new Date().toISOString(),
        url: window.location.href,
        technologies: await this.captureTechnologies(),
        resources: this.captureResources(),
        headers: this.captureHeaders(),
        cookies: this.captureCookieNames(),
        findingSummary: await this.captureFindingSummary()
      };

      await this.saveBaseline(domain, baseline);
      console.log('Origami: Baseline captured for', domain);

      return baseline;
    } catch (error) {
      console.error('Origami: Failed to capture baseline:', error.message);
      throw new Error('Baseline capture failed: ' + error.message);
    }
  }

  captureTechnologies() {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage({ action: 'getTabSecurityResults' }, (response) => {
          if (chrome.runtime.lastError) {
            resolve([]);
            return;
          }

          const results = response?.results;
          if (!results || !results.technologies) {
            resolve([]);
            return;
          }

          const techs = results.technologies;
          const techList = [];

          const categories = ['frameworks', 'libraries', 'backend', 'cms', 'cdn', 'analytics', 'security', 'hosting'];
          for (const category of categories) {
            if (techs[category] && Array.isArray(techs[category])) {
              for (const tech of techs[category]) {
                techList.push({
                  name: tech.name || tech,
                  version: tech.version || null,
                  category: category
                });
              }
            }
          }

          resolve(techList);
        });
      } catch (e) {
        console.warn('Origami: Failed to capture technologies:', e.message);
        resolve([]);
      }
    });
  }

  captureResources() {
    const resources = [];

    try {
      // Collect script sources
      const scripts = document.querySelectorAll('script[src]');
      scripts.forEach(s => {
        resources.push({ type: 'script', url: s.src });
      });

      // Collect stylesheet links
      const links = document.querySelectorAll('link[rel="stylesheet"]');
      links.forEach(l => {
        resources.push({ type: 'stylesheet', url: l.href });
      });

      // Collect form actions
      const forms = document.querySelectorAll('form[action]');
      forms.forEach(f => {
        resources.push({ type: 'form', url: f.action, method: f.method || 'GET' });
      });

      // Collect anchor hrefs (same-origin only)
      const origin = window.location.origin;
      const anchors = document.querySelectorAll('a[href]');
      const seenHrefs = new Set();
      anchors.forEach(a => {
        try {
          const url = new URL(a.href, origin);
          if (url.origin === origin && !seenHrefs.has(url.pathname)) {
            seenHrefs.add(url.pathname);
            resources.push({ type: 'link', url: url.pathname });
          }
        } catch (e) { /* invalid URL */ }
      });

      // Collect iframes
      const iframes = document.querySelectorAll('iframe[src]');
      iframes.forEach(f => {
        resources.push({ type: 'iframe', url: f.src });
      });

      // Collect image sources (just count, not individual URLs)
      const images = document.querySelectorAll('img[src]');
      if (images.length > 0) {
        resources.push({ type: 'images', count: images.length });
      }
    } catch (e) {
      console.warn('Origami: Failed to capture resources:', e.message);
    }

    return resources;
  }

  captureHeaders() {
    // Use cached headers from analyzer coordinator if available
    if (window._origamiHeaders) {
      const headers = {};
      for (const [key, value] of Object.entries(window._origamiHeaders)) {
        headers[key.toLowerCase()] = value;
      }
      return headers;
    }
    return {};
  }

  captureCookieNames() {
    try {
      const cookies = document.cookie;
      if (!cookies) return [];

      return cookies.split(';')
        .map(c => c.trim().split('=')[0])
        .filter(name => name.length > 0);
    } catch (e) {
      return [];
    }
  }

  captureFindingSummary() {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage({ action: 'getTabFindings' }, (response) => {
          if (chrome.runtime.lastError) {
            resolve({ secrets: 0, vulns: 0, headers: 0, cookies: 0, total: 0 });
            return;
          }

          const findings = response?.findings || [];
          const summary = {
            secrets: 0,
            vulns: 0,
            headers: 0,
            cookies: 0,
            total: findings.length
          };

          for (const f of findings) {
            const category = (f.category || f.type || '').toLowerCase();
            if (category.includes('secret') || category.includes('key') || category.includes('token')) {
              summary.secrets++;
            } else if (category.includes('vuln') || category.includes('xss') || category.includes('sqli')) {
              summary.vulns++;
            } else if (category.includes('header')) {
              summary.headers++;
            } else if (category.includes('cookie')) {
              summary.cookies++;
            }
          }

          resolve(summary);
        });
      } catch (e) {
        console.warn('Origami: Failed to capture finding summary:', e.message);
        resolve({ secrets: 0, vulns: 0, headers: 0, cookies: 0, total: 0 });
      }
    });
  }

  diffWithBaseline(baseline) {
    if (!baseline || typeof baseline !== 'object') {
      throw new Error('Invalid baseline provided');
    }

    try {
      const current = {
        technologies: this.getCurrentTechNames(),
        resources: this.captureResources(),
        headers: this.captureHeaders(),
        cookies: this.captureCookieNames()
      };

      const diff = {
        added: {},
        removed: {},
        changed: {},
        summary: ''
      };

      // Diff technologies
      const baselineTechs = new Set((baseline.technologies || []).map(t => t.name || t));
      const currentTechs = new Set(current.technologies);
      const addedTechs = [...currentTechs].filter(t => !baselineTechs.has(t));
      const removedTechs = [...baselineTechs].filter(t => !currentTechs.has(t));

      if (addedTechs.length > 0) diff.added.technologies = addedTechs;
      if (removedTechs.length > 0) diff.removed.technologies = removedTechs;

      // Diff resources (by URL)
      const baselineResUrls = new Set((baseline.resources || []).map(r => r.url).filter(Boolean));
      const currentResUrls = new Set(current.resources.map(r => r.url).filter(Boolean));
      const addedResources = [...currentResUrls].filter(u => !baselineResUrls.has(u));
      const removedResources = [...baselineResUrls].filter(u => !currentResUrls.has(u));

      if (addedResources.length > 0) diff.added.resources = addedResources;
      if (removedResources.length > 0) diff.removed.resources = removedResources;

      // Diff headers
      const baselineHeaders = baseline.headers || {};
      const currentHeaders = current.headers;
      const addedHeaders = {};
      const removedHeaders = {};
      const changedHeaders = {};

      for (const key of Object.keys(currentHeaders)) {
        if (!(key in baselineHeaders)) {
          addedHeaders[key] = currentHeaders[key];
        } else if (currentHeaders[key] !== baselineHeaders[key]) {
          changedHeaders[key] = { from: baselineHeaders[key], to: currentHeaders[key] };
        }
      }
      for (const key of Object.keys(baselineHeaders)) {
        if (!(key in currentHeaders)) {
          removedHeaders[key] = baselineHeaders[key];
        }
      }

      if (Object.keys(addedHeaders).length > 0) diff.added.headers = addedHeaders;
      if (Object.keys(removedHeaders).length > 0) diff.removed.headers = removedHeaders;
      if (Object.keys(changedHeaders).length > 0) diff.changed.headers = changedHeaders;

      // Diff cookies
      const baselineCookies = new Set(baseline.cookies || []);
      const currentCookies = new Set(current.cookies);
      const addedCookies = [...currentCookies].filter(c => !baselineCookies.has(c));
      const removedCookies = [...baselineCookies].filter(c => !currentCookies.has(c));

      if (addedCookies.length > 0) diff.added.cookies = addedCookies;
      if (removedCookies.length > 0) diff.removed.cookies = removedCookies;

      // Build summary
      diff.summary = this.buildSummary(diff);

      return diff;
    } catch (error) {
      console.error('Origami: Diff failed:', error.message);
      throw new Error('Diff failed: ' + error.message);
    }
  }

  getCurrentTechNames() {
    // Quick sync capture of visible technology indicators
    const techs = [];
    const seen = new Set();

    try {
      // Check meta generators
      const generators = document.querySelectorAll('meta[name="generator"]');
      generators.forEach(g => {
        const content = g.getAttribute('content');
        if (content && !seen.has(content)) {
          seen.add(content);
          techs.push(content);
        }
      });

      // Check common global variables
      const globals = [
        { name: 'React', check: () => typeof window.React !== 'undefined' || document.querySelector('[data-reactroot]') },
        { name: 'Vue', check: () => typeof window.Vue !== 'undefined' || document.querySelector('[data-v-]') },
        { name: 'Angular', check: () => typeof window.ng !== 'undefined' || document.querySelector('[ng-version]') },
        { name: 'jQuery', check: () => typeof window.jQuery !== 'undefined' || typeof window.$ !== 'undefined' },
        { name: 'Next.js', check: () => typeof window.__NEXT_DATA__ !== 'undefined' },
        { name: 'Nuxt', check: () => typeof window.__NUXT__ !== 'undefined' }
      ];

      for (const g of globals) {
        try {
          if (g.check() && !seen.has(g.name)) {
            seen.add(g.name);
            techs.push(g.name);
          }
        } catch (e) { /* skip */ }
      }
    } catch (e) {
      console.warn('Origami: Tech detection error in diff:', e.message);
    }

    return techs;
  }

  buildSummary(diff) {
    const parts = [];

    const addedResourceCount = (diff.added.resources || []).length;
    const removedResourceCount = (diff.removed.resources || []).length;
    const addedTechCount = (diff.added.technologies || []).length;
    const removedTechCount = (diff.removed.technologies || []).length;
    const addedHeaderCount = Object.keys(diff.added.headers || {}).length;
    const removedHeaderCount = Object.keys(diff.removed.headers || {}).length;
    const changedHeaderCount = Object.keys(diff.changed.headers || {}).length;
    const addedCookieCount = (diff.added.cookies || []).length;
    const removedCookieCount = (diff.removed.cookies || []).length;

    if (addedResourceCount > 0) parts.push(addedResourceCount + ' new endpoint' + (addedResourceCount > 1 ? 's' : ''));
    if (removedResourceCount > 0) parts.push(removedResourceCount + ' removed endpoint' + (removedResourceCount > 1 ? 's' : ''));
    if (addedTechCount > 0) parts.push(addedTechCount + ' new tech' + (addedTechCount > 1 ? 'nologies' : 'nology'));
    if (removedTechCount > 0) parts.push(removedTechCount + ' removed tech' + (removedTechCount > 1 ? 'nologies' : 'nology'));
    if (addedHeaderCount > 0) parts.push(addedHeaderCount + ' new header' + (addedHeaderCount > 1 ? 's' : ''));
    if (removedHeaderCount > 0) parts.push(removedHeaderCount + ' removed header' + (removedHeaderCount > 1 ? 's' : ''));
    if (changedHeaderCount > 0) parts.push(changedHeaderCount + ' changed header' + (changedHeaderCount > 1 ? 's' : ''));
    if (addedCookieCount > 0) parts.push(addedCookieCount + ' new cookie' + (addedCookieCount > 1 ? 's' : ''));
    if (removedCookieCount > 0) parts.push(removedCookieCount + ' removed cookie' + (removedCookieCount > 1 ? 's' : ''));

    if (parts.length === 0) return 'No changes detected since baseline';
    return parts.join(', ');
  }

  formatDiff(diff) {
    if (!diff || typeof diff !== 'object') return 'Invalid diff data';

    const lines = [];
    lines.push('Attack Surface Diff');
    lines.push('='.repeat(40));
    lines.push('');

    // Summary
    lines.push('Summary: ' + (diff.summary || 'No changes'));
    lines.push('');

    // Added
    if (diff.added && Object.keys(diff.added).length > 0) {
      lines.push('[+] ADDED');
      lines.push('-'.repeat(20));

      if (diff.added.technologies) {
        lines.push('  Technologies:');
        diff.added.technologies.forEach(t => lines.push('    + ' + t));
      }
      if (diff.added.resources) {
        lines.push('  Resources:');
        diff.added.resources.forEach(r => lines.push('    + ' + r));
      }
      if (diff.added.headers) {
        lines.push('  Headers:');
        Object.entries(diff.added.headers).forEach(([k, v]) => {
          lines.push('    + ' + k + ': ' + (v.length > 80 ? v.substring(0, 80) + '...' : v));
        });
      }
      if (diff.added.cookies) {
        lines.push('  Cookies:');
        diff.added.cookies.forEach(c => lines.push('    + ' + c));
      }
      lines.push('');
    }

    // Removed
    if (diff.removed && Object.keys(diff.removed).length > 0) {
      lines.push('[-] REMOVED');
      lines.push('-'.repeat(20));

      if (diff.removed.technologies) {
        lines.push('  Technologies:');
        diff.removed.technologies.forEach(t => lines.push('    - ' + t));
      }
      if (diff.removed.resources) {
        lines.push('  Resources:');
        diff.removed.resources.forEach(r => lines.push('    - ' + r));
      }
      if (diff.removed.headers) {
        lines.push('  Headers:');
        Object.entries(diff.removed.headers).forEach(([k, v]) => {
          lines.push('    - ' + k + ': ' + (v.length > 80 ? v.substring(0, 80) + '...' : v));
        });
      }
      if (diff.removed.cookies) {
        lines.push('  Cookies:');
        diff.removed.cookies.forEach(c => lines.push('    - ' + c));
      }
      lines.push('');
    }

    // Changed
    if (diff.changed && Object.keys(diff.changed).length > 0) {
      lines.push('[~] CHANGED');
      lines.push('-'.repeat(20));

      if (diff.changed.headers) {
        lines.push('  Headers:');
        Object.entries(diff.changed.headers).forEach(([k, v]) => {
          const from = v.from ? (v.from.length > 40 ? v.from.substring(0, 40) + '...' : v.from) : '(empty)';
          const to = v.to ? (v.to.length > 40 ? v.to.substring(0, 40) + '...' : v.to) : '(empty)';
          lines.push('    ~ ' + k);
          lines.push('      was: ' + from);
          lines.push('      now: ' + to);
        });
      }
      lines.push('');
    }

    return lines.join('\n');
  }

  saveBaseline(domain, baseline) {
    return new Promise((resolve, reject) => {
      try {
        const storageKey = this.storagePrefix + domain;

        chrome.runtime.sendMessage({
          action: 'storageGet',
          key: storageKey
        }, (response) => {
          if (chrome.runtime.lastError) {
            // Fallback: try direct storage access
            this.saveBaselineDirect(storageKey, baseline).then(resolve).catch(reject);
            return;
          }

          let baselines = [];
          if (response && response.data) {
            baselines = Array.isArray(response.data) ? response.data : [];
          }

          // Add new baseline and trim to max
          baselines.unshift(baseline);
          if (baselines.length > this.maxBaselinesPerDomain) {
            baselines = baselines.slice(0, this.maxBaselinesPerDomain);
          }

          chrome.runtime.sendMessage({
            action: 'storageSet',
            key: storageKey,
            value: baselines
          }, (setResponse) => {
            if (chrome.runtime.lastError) {
              this.saveBaselineDirect(storageKey, baseline).then(resolve).catch(reject);
              return;
            }
            resolve();
          });
        });
      } catch (e) {
        reject(new Error('Failed to save baseline: ' + e.message));
      }
    });
  }

  saveBaselineDirect(storageKey, baseline) {
    return new Promise((resolve, reject) => {
      try {
        chrome.storage.local.get([storageKey], (data) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }

          let baselines = data[storageKey] || [];
          if (!Array.isArray(baselines)) baselines = [];

          baselines.unshift(baseline);
          if (baselines.length > this.maxBaselinesPerDomain) {
            baselines = baselines.slice(0, this.maxBaselinesPerDomain);
          }

          chrome.storage.local.set({ [storageKey]: baselines }, () => {
            if (chrome.runtime.lastError) {
              reject(new Error(chrome.runtime.lastError.message));
              return;
            }
            resolve();
          });
        });
      } catch (e) {
        reject(new Error('Direct storage save failed: ' + e.message));
      }
    });
  }

  getBaselines(domain) {
    return new Promise((resolve) => {
      try {
        const storageKey = this.storagePrefix + (domain || window.location.hostname);

        chrome.storage.local.get([storageKey], (data) => {
          if (chrome.runtime.lastError) {
            console.warn('Origami: Failed to load baselines:', chrome.runtime.lastError.message);
            resolve([]);
            return;
          }

          const baselines = data[storageKey];
          resolve(Array.isArray(baselines) ? baselines : []);
        });
      } catch (e) {
        console.warn('Origami: Failed to load baselines:', e.message);
        resolve([]);
      }
    });
  }

  async getLatestBaseline(domain) {
    const baselines = await this.getBaselines(domain);
    return baselines.length > 0 ? baselines[0] : null;
  }

  async diffWithLatest() {
    try {
      const latest = await this.getLatestBaseline();
      if (!latest) {
        return { error: 'No baseline found for ' + window.location.hostname + '. Capture a baseline first.' };
      }

      return this.diffWithBaseline(latest);
    } catch (error) {
      console.error('Origami: Diff with latest baseline failed:', error.message);
      throw error;
    }
  }

  async clearBaselines(domain) {
    return new Promise((resolve, reject) => {
      try {
        const storageKey = this.storagePrefix + (domain || window.location.hostname);
        chrome.storage.local.remove(storageKey, () => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          console.log('Origami: Baselines cleared for', domain || window.location.hostname);
          resolve();
        });
      } catch (e) {
        reject(new Error('Failed to clear baselines: ' + e.message));
      }
    });
  }
}

window.SurfaceTracker = SurfaceTracker;
