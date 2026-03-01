// Origami Brute Force Directory/File Scanner
// Performs directory and file brute forcing from the background service worker.
// This is a DEFENSIVE security tool for authorized penetration testing only.

class BruteForceScanner {
  constructor() {
    this.isScanning = false;
    this.abortController = null;
    this.progressCallback = null;
    this.resultsCallback = null;
    this.completionCallback = null;
    this.scannedCount = 0;
    this.totalPaths = 0;
    this.results = [];
  }

  // Top ~500 common paths from dirsearch dict.txt and SecLists directory-list-2.3-medium.txt
  static DEFAULT_WORDLIST = [
    // Common directories
    'admin', 'administrator', 'api', 'app', 'application', 'assets', 'auth',
    'backup', 'backups', 'beta', 'bin', 'blog', 'build', 'cache', 'cdn',
    'cgi', 'cgi-bin', 'cms', 'common', 'components', 'config', 'configuration',
    'console', 'content', 'control', 'controller', 'core', 'cp', 'cpanel',
    'css', 'dashboard', 'data', 'database', 'db', 'debug', 'default', 'demo',
    'dev', 'develop', 'development', 'dist', 'doc', 'docs', 'documentation',
    'download', 'downloads', 'editor', 'email', 'engine', 'error', 'errors',
    'example', 'examples', 'export', 'external', 'extras', 'feed', 'file',
    'files', 'fonts', 'forum', 'framework', 'frontend', 'ftp', 'gateway',
    'global', 'graphql', 'group', 'groups', 'health', 'help', 'home', 'host',
    'html', 'http', 'https', 'images', 'img', 'import', 'inc', 'include',
    'includes', 'index', 'info', 'init', 'install', 'installer', 'internal',
    'intranet', 'io', 'java', 'js', 'json', 'key', 'keys', 'lang', 'language',
    'layout', 'lib', 'library', 'license', 'live', 'local', 'locale', 'log',
    'login', 'logout', 'logs', 'mail', 'main', 'manage', 'management',
    'manager', 'manual', 'map', 'master', 'media', 'member', 'members',
    'message', 'messages', 'meta', 'metrics', 'middleware', 'misc', 'mobile',
    'model', 'models', 'module', 'modules', 'monitor', 'monitoring', 'net',
    'new', 'news', 'node', 'node_modules', 'notifications', 'old', 'ops',
    'oracle', 'order', 'orders', 'out', 'output', 'package', 'packages',
    'page', 'pages', 'panel', 'password', 'path', 'payment', 'payments',
    'php', 'phpmyadmin', 'ping', 'plugin', 'plugins', 'portal', 'post',
    'preview', 'private', 'proc', 'process', 'production', 'profile',
    'profiles', 'project', 'projects', 'proxy', 'public', 'query', 'queue',
    'raw', 'redirect', 'register', 'release', 'remote', 'report', 'reports',
    'repository', 'reset', 'resource', 'resources', 'rest', 'root', 'route',
    'routes', 'rss', 'run', 'runtime', 'sample', 'samples', 'save', 'schema',
    'script', 'scripts', 'search', 'secret', 'secrets', 'secure', 'security',
    'server', 'service', 'services', 'session', 'sessions', 'setting',
    'settings', 'setup', 'share', 'shared', 'shell', 'shop', 'signin',
    'signup', 'site', 'sitemap', 'sites', 'socket', 'source', 'sql', 'src',
    'sso', 'staff', 'stage', 'staging', 'start', 'stat', 'static', 'stats',
    'status', 'storage', 'store', 'stream', 'style', 'styles', 'stylesheet',
    'stylesheets', 'submit', 'support', 'swagger', 'sync', 'sys', 'system',
    'tag', 'tags', 'task', 'tasks', 'temp', 'template', 'templates', 'test',
    'testing', 'tests', 'theme', 'themes', 'tmp', 'token', 'tokens', 'tool',
    'tools', 'trace', 'track', 'ui', 'update', 'updates', 'upgrade', 'upload',
    'uploads', 'url', 'user', 'users', 'util', 'utilities', 'utils', 'v1',
    'v2', 'v3', 'var', 'vendor', 'version', 'video', 'videos', 'view',
    'views', 'web', 'webapp', 'webmail', 'webpack', 'website', 'widget',
    'widgets', 'wiki', 'wordpress', 'work', 'wp', 'wp-admin', 'wp-content',
    'wp-includes', 'wp-json', 'xml', 'xsl',

    // API-specific paths
    'api/v1', 'api/v2', 'api/v3', 'api/users', 'api/user', 'api/admin',
    'api/auth', 'api/login', 'api/config', 'api/status', 'api/health',
    'api/info', 'api/docs', 'api/swagger', 'api/graphql', 'api/search',
    'api/token', 'api/tokens', 'api/session', 'api/data', 'api/export',
    'api/upload', 'api/download', 'api/file', 'api/files', 'api/settings',
    'api/test', 'api/debug', 'api/internal', 'api/private', 'api/public',

    // Common hidden / sensitive paths
    '.git', '.git/config', '.git/HEAD', '.gitignore', '.svn', '.svn/entries',
    '.hg', '.env', '.env.local', '.env.production', '.env.development',
    '.env.staging', '.env.backup', '.env.old', '.env.bak', '.htaccess',
    '.htpasswd', '.DS_Store', '.well-known', '.well-known/security.txt',
    '.well-known/openid-configuration', '.dockerignore', '.editorconfig',
    '.npmrc', '.babelrc', '.eslintrc', '.prettierrc',

    // Common files
    'robots.txt', 'sitemap.xml', 'sitemap_index.xml', 'crossdomain.xml',
    'favicon.ico', 'manifest.json', 'package.json', 'composer.json',
    'Gruntfile.js', 'Gulpfile.js', 'webpack.config.js', 'tsconfig.json',
    'bower.json', 'yarn.lock', 'package-lock.json', 'Gemfile', 'Gemfile.lock',
    'requirements.txt', 'Pipfile', 'Pipfile.lock', 'Makefile', 'Dockerfile',
    'docker-compose.yml', 'docker-compose.yaml', 'Vagrantfile',
    'README.md', 'README.txt', 'README', 'CHANGELOG.md', 'LICENSE',
    'LICENSE.txt', 'CONTRIBUTING.md', 'humans.txt', 'security.txt',
    'ads.txt', 'app-ads.txt',

    // Config files
    'config.php', 'config.js', 'config.json', 'config.yml', 'config.yaml',
    'config.xml', 'config.ini', 'config.inc.php', 'configuration.php',
    'settings.php', 'settings.py', 'settings.json', 'settings.yml',
    'database.yml', 'database.php', 'db.php', 'db.sql', 'wp-config.php',
    'wp-config.php.bak', 'wp-config.php.old', 'local.xml', 'web.config',
    'web.xml', 'server.xml', 'httpd.conf', 'nginx.conf', 'php.ini',
    'my.cnf', '.user.ini', 'application.properties', 'application.yml',
    'appsettings.json', 'appsettings.Development.json',

    // Backup / dump files
    'backup.sql', 'backup.zip', 'backup.tar.gz', 'backup.tar', 'dump.sql',
    'database.sql', 'db.sql.gz', 'site.zip', 'www.zip', 'archive.zip',
    'old.zip', 'data.sql', 'export.sql',

    // PHP / CMS specific
    'wp-login.php', 'wp-cron.php', 'xmlrpc.php', 'wp-signup.php',
    'wp-links-opml.php', 'wp-trackback.php', 'wp-blog-header.php',
    'wp-load.php', 'wp-settings.php', 'wp-mail.php', 'wp-activate.php',
    'wp-comments-post.php', 'wp-config-sample.php', 'readme.html',
    'license.txt', 'info.php', 'phpinfo.php', 'test.php', 'i.php',
    'adminer.php', 'phpmyadmin', 'pma', 'myadmin', 'mysql', 'mysqladmin',

    // Server status / info
    'server-status', 'server-info', 'nginx_status', 'stub_status',
    'health', 'healthz', 'healthcheck', 'ready', 'readyz', 'livez',
    'ping', 'pong', 'version', 'build-info', 'actuator', 'actuator/health',
    'actuator/env', 'actuator/info', 'actuator/beans', 'actuator/metrics',
    'actuator/mappings', 'actuator/configprops', 'actuator/trace',

    // Authentication / user management
    'signin', 'signup', 'register', 'auth/login', 'auth/register',
    'auth/forgot', 'auth/reset', 'auth/callback', 'oauth', 'oauth/authorize',
    'oauth/token', 'oauth2', 'oauth2/authorize', '.well-known/jwks.json',
    'token', 'jwt', 'saml', 'sso/login', 'cas/login', 'openid',

    // Admin panels
    'admin/login', 'admin/dashboard', 'admin/config', 'admin/users',
    'admin/settings', 'admin/logs', 'admin/console', 'admin/api',
    'administrator/login', 'manager/html', 'manager/status', 'manager/text',
    'webadmin', 'sysadmin', 'controlpanel', 'adminpanel',

    // Debug / dev endpoints
    'debug', 'debug/default/view', 'trace', 'console', 'terminal',
    'shell', 'cmd', 'exec', 'eval', 'phpunit', 'telescope', 'horizon',
    'elmah.axd', 'glimpse.axd', 'profiler', '_profiler', '_debugbar',
    'silk', 'django-debug', '__debug__',

    // Swagger / API docs
    'swagger', 'swagger-ui', 'swagger-ui.html', 'swagger.json',
    'swagger.yaml', 'api-docs', 'api/api-docs', 'openapi', 'openapi.json',
    'openapi.yaml', 'redoc', 'graphiql', 'graphql/console', 'playground',
    'api/explorer', 'api/documentation',

    // Error pages
    'error', '404', '403', '500', '401',

    // CI/CD related
    '.gitlab-ci.yml', '.travis.yml', 'Jenkinsfile', '.circleci/config.yml',
    '.github', '.github/workflows', 'bitbucket-pipelines.yml',

    // Cloud / DevOps
    'aws', 'azure', 'gcp', 'cloud', 'terraform', '.terraform',
    'cloudformation', 'kubernetes', 'k8s', 'helm', 'ansible',
    'metrics', 'prometheus', 'grafana', 'kibana', 'elasticsearch',

    // Misc interesting
    'ckeditor', 'elfinder', 'filemanager', 'tinymce', 'kcfinder',
    'fckeditor', 'webdav', 'caldav', 'dav',
    'crossdomain.xml', 'clientaccesspolicy.xml',
    'browserconfig.xml', 'apple-touch-icon.png',
    'service-worker.js', 'sw.js', 'worker.js', 'precache-manifest',
    'asset-manifest.json', 'build-manifest.json',
    'firebase-messaging-sw.js', 'OneSignalSDKWorker.js',

    // Common frameworks / tools
    'laravel', 'symfony', 'codeigniter', 'cakephp', 'zend',
    'spring', 'struts', 'express', 'flask', 'django', 'rails',
    'artisan', 'craft', 'drupal', 'joomla', 'magento', 'shopify',
    'ghost', 'keystone', 'strapi', 'directus', 'payload',

    // Common numeric / date-based
    '2020', '2021', '2022', '2023', '2024', '2025',
    'old', 'new', 'latest', 'current', 'previous', 'archive',
    'bak', 'orig', 'copy', 'temp', 'tmp', 'test', 'dev', 'staging'
  ];

  // Common file extensions for brute force probing
  static COMMON_EXTENSIONS = [
    '.php', '.asp', '.aspx', '.jsp', '.jspx', '.html', '.htm', '.shtml',
    '.js', '.json', '.xml', '.txt', '.cfg', '.conf', '.ini', '.yml',
    '.yaml', '.toml', '.env', '.bak', '.old', '.orig', '.save', '.swp',
    '.sql', '.db', '.sqlite', '.log', '.csv', '.tar', '.gz', '.zip',
    '.rar', '.7z', '.pdf', '.doc', '.xls'
  ];

  /**
   * Generate the full list of URLs to probe based on scan configuration.
   * @param {Object} config - Scan configuration
   * @param {string} config.targetUrl - Base URL origin (e.g. https://example.com)
   * @param {string} config.scanMode - 'directories', 'files', 'both'
   * @param {string[]} config.wordlist - Array of path entries
   * @param {string[]} config.extensions - File extensions to append (e.g. ['.php', '.html'])
   * @returns {string[]} Array of full URLs to probe
   */
  generatePaths(config) {
    const { targetUrl, scanMode, wordlist, extensions } = config;
    const base = targetUrl.replace(/\/+$/, '');
    const paths = new Set();

    for (const word of wordlist) {
      const cleanWord = word.replace(/^\/+/, '').trim();
      if (!cleanWord) continue;

      // If word already has an extension (e.g. robots.txt), add it directly
      const hasExtension = /\.\w{1,10}$/.test(cleanWord);

      if (scanMode === 'directories' || scanMode === 'both') {
        // Add as directory path (trailing slash)
        paths.add(`${base}/${cleanWord}/`);
        // Also add without trailing slash
        paths.add(`${base}/${cleanWord}`);
      }

      if (scanMode === 'files' || scanMode === 'both') {
        if (hasExtension) {
          // Word already has an extension - add as-is
          paths.add(`${base}/${cleanWord}`);
        }

        // Append each configured extension
        if (extensions && extensions.length > 0) {
          for (const ext of extensions) {
            const cleanExt = ext.startsWith('.') ? ext : `.${ext}`;
            // Don't double-add if word already has this extension
            if (!cleanWord.endsWith(cleanExt)) {
              paths.add(`${base}/${cleanWord}${cleanExt}`);
            }
          }
        }
      }
    }

    return Array.from(paths);
  }

  /**
   * Probe a single URL and return result info.
   * @param {string} url - The URL to probe
   * @param {Object} config - Scan configuration
   * @param {number} config.timeout - Request timeout in ms
   * @param {boolean} config.followRedirects - Whether to follow redirects
   * @param {number[]} config.statusCodes - Status codes to consider "found"
   * @param {AbortSignal} signal - AbortController signal for cancellation
   * @returns {Object|null} Result object or null if not interesting
   */
  async probeUrl(url, config, signal) {
    try {
      const fetchOptions = {
        method: 'HEAD',
        signal: signal,
        redirect: config.followRedirects ? 'follow' : 'manual',
        cache: 'no-store',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
      };

      // Use a timeout wrapper
      const timeoutId = setTimeout(() => {
        // We cannot abort the signal directly, but we track it
      }, config.timeout || 5000);

      let response;
      try {
        // Create a per-request timeout using AbortController
        const timeoutController = new AbortController();
        const combinedSignal = signal;

        const timeoutTimer = setTimeout(() => {
          timeoutController.abort();
        }, config.timeout || 5000);

        // If the main signal aborts, we should also abort
        if (signal) {
          signal.addEventListener('abort', () => {
            timeoutController.abort();
          }, { once: true });
        }

        fetchOptions.signal = timeoutController.signal;
        response = await fetch(url, fetchOptions);
        clearTimeout(timeoutTimer);
      } catch (fetchError) {
        clearTimeout(timeoutId);
        if (fetchError.name === 'AbortError') {
          // Check if it was the main scan abort or just a timeout
          if (signal && signal.aborted) {
            return null; // Scan was cancelled
          }
          // Timeout - not interesting
          return null;
        }
        // Network error - skip
        return null;
      }

      clearTimeout(timeoutId);

      const status = response.status;
      const isInteresting = config.statusCodes.includes(status);

      if (!isInteresting) return null;

      // Try to get content length and type from HEAD response
      const contentType = response.headers.get('content-type') || 'unknown';
      const contentLength = response.headers.get('content-length');
      const size = contentLength ? parseInt(contentLength, 10) : -1;
      const location = response.headers.get('location') || '';

      // Extract path from URL
      const urlObj = new URL(url);
      const path = urlObj.pathname;

      const isLoginPage = BruteForceScanner.detectLoginPage(path);

      return {
        url: url,
        path: path,
        status: status,
        size: size,
        contentType: contentType,
        location: location,
        isLoginPage: isLoginPage,
        timestamp: Date.now()
      };
    } catch (error) {
      // Unexpected error - skip silently
      return null;
    }
  }

  /**
   * Start a brute force scan with the given configuration.
   * @param {Object} config
   * @param {string} config.targetUrl - Base URL origin
   * @param {string} config.scanMode - 'directories', 'files', 'both'
   * @param {string[]} [config.wordlist] - Custom wordlist (uses DEFAULT_WORDLIST if not provided)
   * @param {string[]} [config.extensions] - Extensions to append
   * @param {number} [config.concurrency=10] - Max concurrent requests
   * @param {number} [config.timeout=5000] - Request timeout in ms
   * @param {boolean} [config.followRedirects=false] - Follow HTTP redirects
   * @param {number[]} [config.statusCodes=[200,301,302,403]] - Status codes to match
   * @param {Function} [config.onProgress] - Progress callback: (scanned, total, result)
   * @param {Function} [config.onResult] - Called for each found result
   * @param {Function} [config.onComplete] - Called when scan finishes
   */
  async startScan(config) {
    if (this.isScanning) {
      throw new Error('Scan already in progress');
    }

    this.isScanning = true;
    this.abortController = new AbortController();
    this.results = [];
    this.scannedCount = 0;

    // Apply defaults
    const scanConfig = {
      targetUrl: config.targetUrl,
      scanMode: config.scanMode || 'both',
      wordlist: config.wordlist || BruteForceScanner.DEFAULT_WORDLIST,
      extensions: config.extensions || [],
      concurrency: Math.min(Math.max(config.concurrency || 10, 1), 50),
      timeout: config.timeout || 5000,
      followRedirects: config.followRedirects !== undefined ? config.followRedirects : false,
      statusCodes: config.statusCodes || [200, 301, 302, 403],
      onProgress: config.onProgress || (() => {}),
      onResult: config.onResult || (() => {}),
      onComplete: config.onComplete || (() => {})
    };

    // Generate all paths to probe
    const paths = this.generatePaths(scanConfig);
    this.totalPaths = paths.length;

    if (this.totalPaths === 0) {
      this.isScanning = false;
      scanConfig.onComplete({ results: [], scanned: 0, total: 0, cancelled: false });
      return;
    }

    // Report initial progress
    scanConfig.onProgress(0, this.totalPaths, null);

    const signal = this.abortController.signal;

    // Process paths with concurrency control
    let pathIndex = 0;

    const processNext = async () => {
      while (pathIndex < paths.length && !signal.aborted) {
        const currentIndex = pathIndex++;
        const url = paths[currentIndex];

        const result = await this.probeUrl(url, scanConfig, signal);

        if (signal.aborted) return;

        this.scannedCount++;

        if (result) {
          this.results.push(result);
          scanConfig.onResult(result);
        }

        scanConfig.onProgress(this.scannedCount, this.totalPaths, result);
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
        console.error('BruteForceScanner: Unexpected error during scan:', error);
      }
    }

    const cancelled = signal.aborted;
    this.isScanning = false;

    scanConfig.onComplete({
      results: this.results,
      scanned: this.scannedCount,
      total: this.totalPaths,
      cancelled: cancelled
    });

    return {
      results: this.results,
      scanned: this.scannedCount,
      total: this.totalPaths,
      cancelled: cancelled
    };
  }

  /**
   * Stop the current scan.
   */
  stopScan() {
    if (this.abortController) {
      this.abortController.abort();
    }
    this.isScanning = false;
  }

  /**
   * Convert a found result into the inventory resource format.
   * @param {Object} result - A probe result
   * @returns {Object} Inventory-compatible resource entry
   */
  static toInventoryResource(result) {
    return {
      path: result.path,
      type: 'bruteforce',
      status: result.status,
      size: result.size >= 0 ? result.size : undefined,
      mimeType: result.contentType,
      source: 'bruteforce',
      url: result.url,
      isLoginPage: result.isLoginPage || false,
      discoveredAt: result.timestamp || Date.now()
    };
  }

  static LOGIN_PATH_REGEX = /(?:^|\/)(?:log[_-]?in|sign[_-]?in|auth(?:enticate)?|oauth2?|sso|cas|saml|openid|wp-login|admin[_-]?login|user[_-]?login|account[_-]?login|signin|sign[_-]?up|register|forgot[_-]?password|reset[_-]?password|mfa|2fa|verify)(?:\.php|\.asp|\.aspx|\.jsp|\.html?)?(?:\/|$)/i;

  static detectLoginPage(path) {
    return BruteForceScanner.LOGIN_PATH_REGEX.test(path);
  }
}

// Make available in service worker context
if (typeof self !== 'undefined') {
  self.BruteForceScanner = BruteForceScanner;
}
