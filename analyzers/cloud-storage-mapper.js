// Origami Cloud Storage Exposure Mapper
// Detects cloud storage URLs and tests for public access misconfigurations

class CloudStorageMapper {
  constructor() {
    this.findings = { buckets: [], issues: [] };
    this._seenUrls = new Set();
    this._seenBuckets = new Map();

    this._patterns = {
      aws: [
        // https://BUCKET.s3.amazonaws.com/KEY
        /https?:\/\/(?<bucket>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3\.amazonaws\.com(?:\/[^\s"'<>)}\]]*)?/gi,
        // https://BUCKET.s3-REGION.amazonaws.com/KEY
        /https?:\/\/(?<bucket>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3-[a-z0-9-]+\.amazonaws\.com(?:\/[^\s"'<>)}\]]*)?/gi,
        // https://BUCKET.s3.REGION.amazonaws.com/KEY (current AWS standard)
        /https?:\/\/(?<bucket>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3\.[a-z0-9-]+\.amazonaws\.com(?:\/[^\s"'<>)}\]]*)?/gi,
        // https://s3.REGION.amazonaws.com/BUCKET/KEY
        /https?:\/\/s3\.[a-z0-9-]+\.amazonaws\.com\/(?<bucket>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])(?:\/[^\s"'<>)}\]]*)?/gi,
        // s3://BUCKET/KEY
        /s3:\/\/(?<bucket>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])(?:\/[^\s"'<>)}\]]*)?/gi
      ],
      azure: [
        // https://ACCOUNT.blob.core.windows.net/CONTAINER/BLOB
        /https?:\/\/(?<bucket>[a-z0-9]{3,24})\.blob\.core\.windows\.net\/(?<container>[a-z0-9][a-z0-9-]{1,61}[a-z0-9])(?:\/[^\s"'<>)}\]]*)?/gi
      ],
      gcp: [
        // https://storage.googleapis.com/BUCKET/OBJECT
        /https?:\/\/storage\.googleapis\.com\/(?<bucket>[a-z0-9][a-z0-9._-]{1,220}[a-z0-9])(?:\/[^\s"'<>)}\]]*)?/gi,
        // https://storage.cloud.google.com/BUCKET/OBJECT
        /https?:\/\/storage\.cloud\.google\.com\/(?<bucket>[a-z0-9][a-z0-9._-]{1,220}[a-z0-9])(?:\/[^\s"'<>)}\]]*)?/gi,
        // gs://BUCKET/OBJECT
        /gs:\/\/(?<bucket>[a-z0-9][a-z0-9._-]{1,220}[a-z0-9])(?:\/[^\s"'<>)}\]]*)?/gi
      ],
      digitalocean: [
        // https://BUCKET.REGION.digitaloceanspaces.com/KEY
        /https?:\/\/(?<bucket>[a-z0-9][a-z0-9-]{1,61}[a-z0-9])\.[a-z]{2,4}[0-9]\.digitaloceanspaces\.com(?:\/[^\s"'<>)}\]]*)?/gi,
        // https://REGION.digitaloceanspaces.com/BUCKET/KEY
        /https?:\/\/[a-z]{2,4}[0-9]\.digitaloceanspaces\.com\/(?<bucket>[a-z0-9][a-z0-9-]{1,61}[a-z0-9])(?:\/[^\s"'<>)}\]]*)?/gi
      ],
      backblaze: [
        // https://f00X.backblazeb2.com/file/BUCKET/FILE
        /https?:\/\/f[0-9]{3}\.backblazeb2\.com\/file\/(?<bucket>[a-zA-Z0-9][a-zA-Z0-9-]{0,48}[a-zA-Z0-9])(?:\/[^\s"'<>)}\]]*)?/gi
      ],
      wasabi: [
        // https://s3.REGION.wasabisys.com/BUCKET/KEY
        /https?:\/\/s3\.[a-z0-9-]+\.wasabisys\.com\/(?<bucket>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])(?:\/[^\s"'<>)}\]]*)?/gi,
        // https://BUCKET.s3.REGION.wasabisys.com/KEY
        /https?:\/\/(?<bucket>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3\.[a-z0-9-]+\.wasabisys\.com(?:\/[^\s"'<>)}\]]*)?/gi
      ],
      minio: [
        // Common MinIO self-hosted patterns: host:port/bucket or /minio/bucket
        /https?:\/\/[a-z0-9._-]+(?::[0-9]{4,5})\/(?<bucket>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])(?:\/[^\s"'<>)}\]]*)?/gi
      ]
    };

    this._errorPatterns = [
      { pattern: /AccessDenied/g, provider: 'aws', type: 'access-denied' },
      { pattern: /NoSuchBucket/g, provider: 'aws', type: 'no-such-bucket' },
      { pattern: /NoSuchKey/g, provider: 'aws', type: 'no-such-key' },
      { pattern: /BlobNotFound/g, provider: 'azure', type: 'blob-not-found' },
      { pattern: /The specified container does not exist/gi, provider: 'azure', type: 'container-not-found' },
      { pattern: /The specified blob does not exist/gi, provider: 'azure', type: 'blob-not-found' },
      { pattern: /The specified resource does not exist/gi, provider: 'azure', type: 'resource-not-found' },
      { pattern: /NoSuchLifecycleConfiguration/g, provider: 'aws', type: 'lifecycle-error' },
      { pattern: /AllAccessDisabled/g, provider: 'aws', type: 'access-disabled' },
      { pattern: /InvalidBucketName/g, provider: 'aws', type: 'invalid-bucket' }
    ];

    this._sensitivityMap = {
      high: [
        'backup', 'backups', 'db-export', 'db-exports', 'credentials',
        'secret', 'secrets', 'private', 'internal', 'admin', 'config',
        'configs', 'database', 'databases', 'keys', 'passwords', 'certs',
        'certificates', 'sensitive', 'restricted', 'confidential'
      ],
      medium: [
        'logs', 'log', 'data', 'uploads', 'upload', 'media', 'export',
        'exports', 'import', 'imports', 'migration', 'migrations', 'temp',
        'tmp', 'staging', 'dev', 'development', 'test', 'testing',
        'archive', 'archives', 'reports', 'snapshots', 'dump', 'dumps'
      ],
      low: [
        'public', 'static', 'assets', 'images', 'image', 'img', 'css',
        'js', 'cdn', 'dist', 'build', 'fonts', 'icons', 'thumbnails',
        'thumbs', 'avatars', 'photos', 'videos', 'downloads'
      ]
    };
  }

  async analyze() {
    this.findings = { buckets: [], issues: [] };
    this._seenUrls = new Set();
    this._seenBuckets = new Map();

    try {
      this._scanPageContent();
      this._scanScriptContent();
      this._scanNetworkRequests();
      this._scanMetaTags();
      this._scanErrorMessages();
      await this._testAccessibility();
      this._inferSensitivity();
    } catch (e) {
      console.error('Origami: Cloud storage mapper error:', e.message);
    }

    return this.findings;
  }

  _scanPageContent() {
    try {
      const body = document.body;
      if (!body) return;
      const html = body.innerHTML;
      if (!html) return;
      this._extractBucketsFromText(html, 'page-content');
    } catch (e) {
      // DOM access may fail in restricted contexts
    }
  }

  _scanScriptContent() {
    try {
      const scripts = document.querySelectorAll('script:not([src])');
      const content = Array.from(scripts).map(s => s.textContent).join('\n');
      if (!content) return;
      this._extractBucketsFromText(content, 'inline-script');
    } catch (e) {
      // Script access may fail
    }
  }

  _scanNetworkRequests() {
    try {
      const entries = performance.getEntriesByType('resource');
      if (!entries || entries.length === 0) return;

      const urls = entries.map(e => e.name).join('\n');
      this._extractBucketsFromText(urls, 'network-request');
    } catch (e) {
      // Performance API may be unavailable
    }
  }

  _scanMetaTags() {
    try {
      // og:image and similar meta tags
      const metaSelectors = [
        'meta[property="og:image"]',
        'meta[property="og:audio"]',
        'meta[property="og:video"]',
        'meta[name="twitter:image"]',
        'meta[name="twitter:image:src"]',
        'meta[name="msapplication-TileImage"]'
      ];

      for (const selector of metaSelectors) {
        const el = document.querySelector(selector);
        if (el) {
          const content = el.getAttribute('content');
          if (content) this._extractBucketsFromText(content, 'meta-tag');
        }
      }

      // link[href] for stylesheets, preloads, etc.
      const links = document.querySelectorAll('link[href]');
      for (const link of links) {
        const href = link.getAttribute('href');
        if (href) this._extractBucketsFromText(href, 'link-href');
      }

      // img[src], video[src], audio[src], source[src]
      const mediaTags = document.querySelectorAll('img[src], video[src], audio[src], source[src]');
      for (const tag of mediaTags) {
        const src = tag.getAttribute('src');
        if (src) this._extractBucketsFromText(src, 'media-src');
      }
    } catch (e) {
      // Meta tag scanning may fail
    }
  }

  _scanErrorMessages() {
    try {
      const body = document.body;
      if (!body) return;
      const text = body.innerText || '';
      if (!text) return;

      for (const errPattern of this._errorPatterns) {
        errPattern.pattern.lastIndex = 0;
        const matches = text.match(errPattern.pattern);
        if (matches && matches.length > 0) {
          // Extract surrounding context for better reporting
          const idx = text.indexOf(matches[0]);
          const start = Math.max(0, idx - 80);
          const end = Math.min(text.length, idx + matches[0].length + 80);
          const context = text.substring(start, end).trim();

          this.findings.issues.push({
            severity: 'LOW',
            type: 'cloud-storage-error-leak',
            message: 'Cloud storage error message exposed in page: ' + errPattern.type,
            cwe: 'CWE-200',
            details: {
              provider: errPattern.provider,
              errorType: errPattern.type,
              context: context.substring(0, 200)
            },
            recommendation: 'Cloud storage error messages reveal infrastructure details. Configure custom error pages and suppress backend error leakage.'
          });
        }
      }
    } catch (e) {
      // Error message scanning may fail
    }
  }

  async _testAccessibility() {
    const MAX_BUCKETS = 20;
    const CONCURRENCY = 5;
    const toTest = this.findings.buckets.slice(0, MAX_BUCKETS);

    for (let i = MAX_BUCKETS; i < this.findings.buckets.length; i++) {
      this.findings.buckets[i].accessibility = 'skipped';
    }

    for (let i = 0; i < toTest.length; i += CONCURRENCY) {
      const batch = toTest.slice(i, i + CONCURRENCY);
      await Promise.all(batch.map(bucket => this._testBucket(bucket)));
    }
  }

  async _testBucket(bucket) {
    if (!bucket.url.match(/^https?:\/\//i)) {
      bucket.accessibility = 'untestable';
      return;
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);

      // Use cors mode first to get a real response; fall back to no-cors for opaque
      let response;
      try {
        response = await fetch(bucket.url, {
          method: 'HEAD',
          mode: 'cors',
          signal: controller.signal,
          redirect: 'follow'
        });
      } catch (corsErr) {
        // CORS blocked - try no-cors to at least detect reachability
        if (corsErr.name !== 'AbortError') {
          response = await fetch(bucket.url, {
            method: 'HEAD',
            mode: 'no-cors',
            signal: controller.signal,
            redirect: 'follow'
          });
        } else {
          throw corsErr;
        }
      }

      clearTimeout(timeoutId);

      if (response.type === 'opaque') {
        bucket.accessibility = 'indeterminate';
      } else if (response.ok) {
        bucket.accessibility = 'public';
      } else if (response.status === 403) {
        bucket.accessibility = 'forbidden';
      } else if (response.status === 404) {
        bucket.accessibility = 'not-found';
      } else {
        bucket.accessibility = 'restricted';
      }
    } catch (e) {
      if (e.name === 'AbortError') {
        bucket.accessibility = 'timeout';
      } else {
        bucket.accessibility = 'error';
      }
    }
  }

  _inferSensitivity() {
    for (const bucket of this.findings.buckets) {
      const name = (bucket.bucketName || '').toLowerCase();
      const parts = name.split(/[.\-_/]/);

      let sensitivity = null;
      for (const part of parts) {
        if (!part) continue;
        if (this._sensitivityMap.high.includes(part)) {
          sensitivity = 'HIGH';
          break;
        }
        if (!sensitivity && this._sensitivityMap.medium.includes(part)) {
          sensitivity = 'MEDIUM';
        }
        if (!sensitivity && this._sensitivityMap.low.includes(part)) {
          sensitivity = 'LOW';
        }
      }

      bucket.nameSensitivity = sensitivity;

      // Create issues based on accessibility and name sensitivity
      this._createBucketIssue(bucket);
    }
  }

  _createBucketIssue(bucket) {
    const isPublic = bucket.accessibility === 'public';
    const sensitivity = bucket.nameSensitivity;
    let severity;

    if (isPublic && sensitivity === 'HIGH') {
      severity = 'CRITICAL';
    } else if (isPublic) {
      severity = 'HIGH';
    } else if (sensitivity === 'HIGH') {
      severity = 'HIGH';
    } else if (!sensitivity) {
      // Non-public bucket with no sensitive naming -- just an infrastructure reference
      severity = 'INFO';
    } else {
      severity = 'MEDIUM';
    }

    let message;
    if (isPublic && sensitivity === 'HIGH') {
      message = 'Publicly accessible cloud storage with sensitive naming: ' + bucket.bucketName;
    } else if (isPublic) {
      message = 'Publicly accessible cloud storage bucket detected: ' + bucket.bucketName;
    } else if (sensitivity === 'HIGH') {
      message = 'Cloud storage reference with sensitive naming detected: ' + bucket.bucketName;
    } else {
      message = 'Cloud storage bucket reference detected: ' + bucket.bucketName;
    }

    this.findings.issues.push({
      severity: severity,
      type: 'cloud-storage-exposure',
      message: message,
      cwe: isPublic ? 'CWE-284' : 'CWE-200',
      details: {
        provider: bucket.provider,
        bucketName: bucket.bucketName,
        url: bucket.url,
        urls: bucket.urls || [bucket.url],
        foundIn: bucket.foundIn,
        accessibility: bucket.accessibility,
        nameSensitivity: sensitivity
      },
      recommendation: isPublic
        ? 'Review bucket access policy. Ensure public access is intentional and no sensitive data is exposed. Enable bucket logging and apply least-privilege IAM policies.'
        : 'Cloud storage URLs in client-side code reveal infrastructure details. Use CDN or proxy endpoints to abstract storage backend.'
    });
  }

  _extractBucketsFromText(text, source) {
    if (!text || text.length === 0) return;

    // Skip MinIO patterns to avoid excessive false positives from generic host:port URLs
    const providers = ['aws', 'azure', 'gcp', 'digitalocean', 'backblaze', 'wasabi'];

    for (const provider of providers) {
      const patterns = this._patterns[provider];
      if (!patterns) continue;

      for (const pattern of patterns) {
        // Reset lastIndex for global regex
        pattern.lastIndex = 0;
        let match;

        while ((match = pattern.exec(text)) !== null) {
          const url = this._cleanUrl(match[0]);
          const bucketName = this._extractBucketName(match, provider);

          if (!bucketName || bucketName.length < 3) continue;
          if (this._isFalsePositive(bucketName, url)) continue;

          this._addBucket(provider, bucketName, url, source);
        }
      }
    }

    // MinIO detection handled separately with stricter validation
    this._scanMinioUrls(text, source);
  }

  _scanMinioUrls(text, source) {
    // MinIO URLs require additional context to avoid false positives
    // Look for URLs with MinIO-specific headers or path patterns
    const hasMinioContext = /minio/i.test(text);
    if (!hasMinioContext) return;

    for (const pattern of this._patterns.minio) {
      pattern.lastIndex = 0;
      let match;

      while ((match = pattern.exec(text)) !== null) {
        const url = this._cleanUrl(match[0]);
        const bucketName = match.groups && match.groups.bucket;
        if (!bucketName || bucketName.length < 3) continue;
        if (this._isFalsePositive(bucketName, url)) continue;
        this._addBucket('minio', bucketName, url, source);
      }
    }
  }

  _cleanUrl(rawUrl) {
    // Remove trailing punctuation or common URL terminators
    let url = rawUrl.replace(/['"`;,\s]+$/, '');
    // Remove trailing HTML entities
    url = url.replace(/&(?:amp|lt|gt|quot|#\d+);?$/, '');
    return url;
  }

  _extractBucketName(match, provider) {
    // Prefer named capture group
    if (match.groups && match.groups.bucket) {
      return match.groups.bucket;
    }
    if (match.groups && match.groups.container) {
      return match.groups.container;
    }

    // Fallback extraction by provider
    const url = match[0];
    try {
      switch (provider) {
        case 'aws': {
          // BUCKET.s3.amazonaws.com or BUCKET.s3-REGION.amazonaws.com
          const virtualHost = url.match(/\/\/([^.]+)\.s3[.-]/);
          if (virtualHost) return virtualHost[1];
          // s3.REGION.amazonaws.com/BUCKET
          const pathStyle = url.match(/s3\.[^/]+\.amazonaws\.com\/([^/?#]+)/);
          if (pathStyle) return pathStyle[1];
          // s3://BUCKET
          const s3Proto = url.match(/s3:\/\/([^/]+)/);
          if (s3Proto) return s3Proto[1];
          break;
        }
        case 'azure': {
          const azureMatch = url.match(/\/\/([^.]+)\.blob\.core\.windows\.net\/([^/?#]+)/);
          if (azureMatch) return azureMatch[1] + '/' + azureMatch[2];
          break;
        }
        case 'gcp': {
          const gcpMatch = url.match(/storage\.(?:googleapis|cloud\.google)\.com\/([^/?#]+)/);
          if (gcpMatch) return gcpMatch[1];
          const gsMatch = url.match(/gs:\/\/([^/]+)/);
          if (gsMatch) return gsMatch[1];
          break;
        }
        case 'digitalocean': {
          const doVirtual = url.match(/\/\/([^.]+)\.[^.]+\.digitaloceanspaces\.com/);
          if (doVirtual) return doVirtual[1];
          const doPath = url.match(/digitaloceanspaces\.com\/([^/?#]+)/);
          if (doPath) return doPath[1];
          break;
        }
        case 'backblaze': {
          const b2Match = url.match(/backblazeb2\.com\/file\/([^/?#]+)/);
          if (b2Match) return b2Match[1];
          break;
        }
        case 'wasabi': {
          const wasabiVirtual = url.match(/\/\/([^.]+)\.s3\.[^.]+\.wasabisys\.com/);
          if (wasabiVirtual) return wasabiVirtual[1];
          const wasabiPath = url.match(/wasabisys\.com\/([^/?#]+)/);
          if (wasabiPath) return wasabiPath[1];
          break;
        }
      }
    } catch (e) {
      // Extraction failed
    }

    return null;
  }

  _isFalsePositive(bucketName, url) {
    // Reject common non-bucket patterns
    const fpPatterns = [
      /^(www|api|cdn|docs|mail|smtp|ftp|ssh|vpn|dns)$/i,
      /^localhost$/i,
      /^127\./,
      /^10\./,
      /^192\.168\./,
      /^0\.0\./,
      /^\d+$/
    ];

    for (const fp of fpPatterns) {
      if (fp.test(bucketName)) return true;
    }

    // Reject if bucket name is just a TLD or common extension
    if (/^\.(com|org|net|io|dev|app|js|css|html|json|xml|png|jpg|gif|svg|woff|ttf|eot)$/i.test(bucketName)) {
      return true;
    }

    return false;
  }

  _addBucket(provider, bucketName, url, foundIn) {
    // Skip exact-URL duplicates (perf optimization)
    const normalizedUrl = url.replace(/^https?:\/\//i, '').replace(/\/+$/, '').toLowerCase();
    if (this._seenUrls.has(normalizedUrl)) {
      // Still merge foundIn source into existing bucket entry
      const bucketKey = `${provider}:${bucketName.toLowerCase()}`;
      const existing = this._seenBuckets.get(bucketKey);
      if (existing && !existing.foundIn.includes(foundIn)) {
        existing.foundIn.push(foundIn);
      }
      return;
    }
    this._seenUrls.add(normalizedUrl);

    // Deduplicate by bucket identity (provider + bucket name)
    const bucketKey = `${provider}:${bucketName.toLowerCase()}`;
    const existing = this._seenBuckets.get(bucketKey);

    if (existing) {
      if (!existing.urls.includes(url)) {
        existing.urls.push(url);
      }
      if (!existing.foundIn.includes(foundIn)) {
        existing.foundIn.push(foundIn);
      }
      return;
    }

    const entry = {
      provider: provider,
      bucketName: bucketName,
      url: url,
      urls: [url],
      foundIn: [foundIn],
      accessibility: 'untested'
    };

    this._seenBuckets.set(bucketKey, entry);
    this.findings.buckets.push(entry);
  }
}

window.CloudStorageMapper = CloudStorageMapper;
