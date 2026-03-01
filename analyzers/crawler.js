// Origami Web Crawler
// Discovers pages by following links breadth-first from a starting URL.
// This is a DEFENSIVE security tool for authorized penetration testing only.

class WebCrawler {
  constructor() {
    this.isScanning = false;
    this.abortController = null;
    this.results = [];
    this.visitedUrls = new Set();
    this.frontier = [];       // BFS queue: [{url, depth, parentUrl}]
    this.frontierIndex = 0;   // shared pointer for worker pool
  }

  static normalizeUrl(url) {
    // Strip fragments, normalize trailing slashes, return canonical href
    try {
      const u = new URL(url);
      u.hash = '';
      // Remove trailing slash except for root
      if (u.pathname !== '/' && u.pathname.endsWith('/')) {
        u.pathname = u.pathname.replace(/\/+$/, '');
      }
      return u.href;
    } catch (e) {
      return null;
    }
  }

  static extractLinks(html, baseUrl) {
    // Regex-based href extraction (no DOM in service worker)
    // Skips #, javascript:, mailto:, data:, tel:
    // Resolves relative URLs against baseUrl
    // Returns Set of normalized URLs
    const links = new Set();
    const hrefRegex = /href\s*=\s*["']([^"']+)["']/gi;
    let match;
    while ((match = hrefRegex.exec(html)) !== null) {
      const raw = match[1].trim();
      if (!raw || raw.startsWith('#') || raw.startsWith('javascript:') ||
          raw.startsWith('mailto:') || raw.startsWith('data:') || raw.startsWith('tel:')) {
        continue;
      }
      try {
        const resolved = new URL(raw, baseUrl);
        const normalized = WebCrawler.normalizeUrl(resolved.href);
        if (normalized) links.add(normalized);
      } catch (e) {
        // skip invalid URLs
      }
    }
    return links;
  }

  static isExternalLink(url, originHostname) {
    try {
      const u = new URL(url);
      return u.hostname !== originHostname;
    } catch (e) {
      return true;
    }
  }

  async crawlUrl(url, depth, config, signal) {
    // Fetch with per-request AbortController + timeout (same pattern as BruteForceScanner.probeUrl())
    try {
      const timeoutController = new AbortController();
      const timeoutTimer = setTimeout(() => {
        timeoutController.abort();
      }, config.timeout || 5000);

      if (signal) {
        signal.addEventListener('abort', () => {
          timeoutController.abort();
        }, { once: true });
      }

      const response = await fetch(url, {
        method: 'GET',
        signal: timeoutController.signal,
        redirect: 'follow',
        cache: 'no-store',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
      });

      clearTimeout(timeoutTimer);

      if (signal && signal.aborted) return null;

      const status = response.status;
      const contentType = response.headers.get('content-type') || 'unknown';
      const contentLength = response.headers.get('content-length');
      const size = contentLength ? parseInt(contentLength, 10) : -1;
      const finalUrl = response.url;

      // Extract path (include query string to differentiate URLs with different params)
      let path;
      try {
        const u = new URL(finalUrl);
        path = u.pathname + u.search;
      } catch (e) { path = url; }

      // Determine if external
      let originHostname;
      try { originHostname = new URL(config.targetUrl).hostname; } catch (e) { originHostname = ''; }
      const isExternal = WebCrawler.isExternalLink(finalUrl, originHostname);

      // Extract links from HTML responses when depth < maxDepth
      let discoveredLinks = [];
      let html = null;
      const isHtml = contentType.includes('text/html');
      if (isHtml) {
        try {
          html = await response.text();
          if (depth < config.maxDepth) {
            const links = WebCrawler.extractLinks(html, finalUrl);
            discoveredLinks = Array.from(links);
          }
        } catch (e) {
          // Could not read body
        }
      }

      const isLoginPage = WebCrawler.detectLoginPage(path, html);

      return {
        url: url,
        finalUrl: finalUrl,
        path: path,
        status: status,
        size: size,
        contentType: contentType.split(';')[0].trim(),
        depth: depth,
        linksFound: discoveredLinks.length,
        discoveredLinks: discoveredLinks,
        isExternal: isExternal,
        isLoginPage: isLoginPage,
        timestamp: Date.now()
      };
    } catch (error) {
      if (error.name === 'AbortError') {
        if (signal && signal.aborted) return null; // scan cancelled
      }
      return null; // network error, timeout, etc
    }
  }

  addToFrontier(url, depth, parentUrl) {
    const normalized = WebCrawler.normalizeUrl(url);
    if (!normalized) return false;
    if (this.visitedUrls.has(normalized)) return false;
    if (this.frontier.length >= 5000) return false; // safety valve
    this.visitedUrls.add(normalized);
    this.frontier.push({ url: normalized, depth, parentUrl });
    return true;
  }

  async startScan(config) {
    if (this.isScanning) {
      throw new Error('Crawl already in progress');
    }

    this.isScanning = true;
    this.abortController = new AbortController();
    this.results = [];
    this.visitedUrls = new Set();
    this.frontier = [];
    this.frontierIndex = 0;

    const scanConfig = {
      targetUrl: config.targetUrl,
      maxDepth: Math.min(Math.max(config.maxDepth || 2, 1), 5),
      followExternal: config.followExternal || false,
      concurrency: Math.min(Math.max(config.concurrency || 10, 1), 50),
      timeout: config.timeout || 5000,
      onProgress: config.onProgress || (() => {}),
      onComplete: config.onComplete || (() => {})
    };

    // Determine origin hostname for external link filtering
    let originHostname;
    try { originHostname = new URL(scanConfig.targetUrl).hostname; } catch (e) { originHostname = ''; }

    // Seed frontier with start URL at depth 0
    const startUrl = WebCrawler.normalizeUrl(scanConfig.targetUrl);
    if (!startUrl) {
      this.isScanning = false;
      scanConfig.onComplete({ results: [], crawled: 0, discovered: 0, cancelled: false });
      return;
    }
    this.addToFrontier(startUrl, 0, null);

    const signal = this.abortController.signal;

    // Worker pool using shared frontier index (same pattern as BruteForceScanner)
    const processNext = async () => {
      while (!signal.aborted) {
        const currentIndex = this.frontierIndex;
        if (currentIndex >= this.frontier.length) {
          // Idle wait: frontier might grow from other workers
          await new Promise(r => setTimeout(r, 100));
          // Single retry after idle wait
          if (this.frontierIndex >= this.frontier.length) {
            break; // No more work
          }
          continue;
        }
        this.frontierIndex++;

        const item = this.frontier[currentIndex];
        const result = await this.crawlUrl(item.url, item.depth, scanConfig, signal);

        if (signal.aborted) return;

        if (result) {
          // Add discovered links to frontier regardless of dedup
          if (result.discoveredLinks && result.discoveredLinks.length > 0) {
            for (const link of result.discoveredLinks) {
              const isExt = WebCrawler.isExternalLink(link, originHostname);
              if (isExt && !scanConfig.followExternal) continue;
              const linkDepth = isExt ? scanConfig.maxDepth : item.depth + 1;
              this.addToFrontier(link, linkDepth, item.url);
            }
          }

          // Dedup results by URL (defensive against frontier race conditions)
          const resultUrl = result.finalUrl || result.url;
          const isDupe = this.results.some(r => (r.finalUrl || r.url) === resultUrl);
          if (!isDupe) {
            this.results.push(result);
          }

          scanConfig.onProgress(this.results.length, this.frontier.length, isDupe ? null : result);
        } else {
          // Failed fetch, still report progress
          scanConfig.onProgress(this.results.length, this.frontier.length, null);
        }
      }
    };

    // Launch concurrent workers
    const workers = [];
    for (let i = 0; i < scanConfig.concurrency; i++) {
      workers.push(processNext());
    }

    try {
      await Promise.all(workers);
    } catch (error) {
      if (error.name !== 'AbortError') {
        console.error('WebCrawler: Unexpected error during crawl:', error);
      }
    }

    const cancelled = signal.aborted;
    this.isScanning = false;

    scanConfig.onComplete({
      results: this.results,
      crawled: this.results.length,
      discovered: this.frontier.length,
      cancelled: cancelled
    });

    return {
      results: this.results,
      crawled: this.results.length,
      discovered: this.frontier.length,
      cancelled: cancelled
    };
  }

  stopScan() {
    if (this.abortController) {
      this.abortController.abort();
    }
    this.isScanning = false;
  }

  static toInventoryResource(result) {
    return {
      path: result.path,
      type: 'crawler',
      status: result.status,
      size: result.size >= 0 ? result.size : undefined,
      mimeType: result.contentType,
      source: 'crawler',
      url: result.url,
      depth: result.depth,
      isLoginPage: result.isLoginPage || false,
      discoveredAt: result.timestamp || Date.now()
    };
  }

  static LOGIN_PATH_REGEX = /(?:^|\/)(?:log[_-]?in|sign[_-]?in|auth(?:enticate)?|oauth2?|sso|cas|saml|openid|wp-login|admin[_-]?login|user[_-]?login|account[_-]?login|signin|sign[_-]?up|register|forgot[_-]?password|reset[_-]?password|mfa|2fa|verify)(?:\.php|\.asp|\.aspx|\.jsp|\.html?)?(?:\/|$)/i;

  static detectLoginPage(path, html) {
    if (WebCrawler.LOGIN_PATH_REGEX.test(path)) return true;
    if (html) {
      const hasPasswordField = /<input[^>]*type\s*=\s*["']password["'][^>]*>/i.test(html);
      const hasLoginText = /(?:log\s*in|sign\s*in|authenticate|enter.+password)/i.test(html);
      if (hasPasswordField && hasLoginText) return true;
    }
    return false;
  }
}

// Make available in service worker context
if (typeof self !== 'undefined') {
  self.WebCrawler = WebCrawler;
}
