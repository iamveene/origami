// Origami Shared Constants
// Loaded first in content scripts to provide shared values across all analyzers

const ORIGAMI_SEVERITY_ORDER = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };

// Entropy threshold for filtering low-randomness values (e.g., MEDIUM-risk secrets)
const ORIGAMI_ENTROPY_THRESHOLD = 4.0;

// Inline script batch size to avoid blocking the main thread on large pages
const ORIGAMI_INLINE_SCRIPT_BATCH_SIZE = 50;

// Maximum number of tab entries to retain in background.js before cleanup
const ORIGAMI_MAX_TAB_ENTRIES = 50;

// Cache duration for CVE/EOL results (7 days in milliseconds)
const ORIGAMI_CVE_CACHE_DURATION_MS = 7 * 24 * 60 * 60 * 1000;

// CVE cache max size in bytes (5MB)
const ORIGAMI_CVE_CACHE_MAX_SIZE = 5 * 1024 * 1024;

// Minified script detection threshold (avg chars per line)
const ORIGAMI_MINIFIED_LINE_THRESHOLD = 600;

// Helper: compare two severity levels, returns negative if a is more severe
function origamiCompareSeverity(a, b) {
  const scoreA = ORIGAMI_SEVERITY_ORDER[a] !== undefined ? ORIGAMI_SEVERITY_ORDER[a] : 5;
  const scoreB = ORIGAMI_SEVERITY_ORDER[b] !== undefined ? ORIGAMI_SEVERITY_ORDER[b] : 5;
  return scoreA - scoreB;
}

// Helper: get numeric score for a severity (lower = more severe)
function origamiSeverityScore(severity) {
  return ORIGAMI_SEVERITY_ORDER[severity] !== undefined ? ORIGAMI_SEVERITY_ORDER[severity] : 5;
}

// Canonical secret key normalization (shared by scanner.js and background.js)
function origamiNormalizeSecretKey(secretValue) {
  if (!secretValue) return '';

  // Extract known API key patterns (most reliable method)
  const keyPatterns = [
    /AIza[A-Za-z0-9_-]{35}/,
    /sk_(?:live|test)_[A-Za-z0-9]{24,}/,
    /pk_(?:live|test)_[A-Za-z0-9]{24,}/,
    /AKIA[A-Z0-9]{16}/,
    /ghp_[A-Za-z0-9]{36}/,
    /gho_[A-Za-z0-9]{36}/,
    /xox[baprs]-[A-Za-z0-9-]+/,
    /ya29\.[A-Za-z0-9_-]{20,}/,
    /1\/\/[0-9A-Za-z_-]{43,}/,
    /GOCSPX-[0-9A-Za-z_-]{28}/,
    /[0-9]{8,21}-[a-z0-9]{32}\.apps\.googleusercontent\.com/,
    /sq0atp-[A-Za-z0-9_-]{22}/,
    /sk-[A-Za-z0-9]{48}/,
    /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/
  ];

  for (const pattern of keyPatterns) {
    const match = secretValue.match(pattern);
    if (match) return match[0];
  }

  // Fallback: string manipulation strategies
  let normalized = secretValue;

  if (normalized.includes('=') || normalized.includes(':')) {
    normalized = normalized
      .replace(/^.*?[=:]\s*["'`]?/, '')
      .replace(/["'`].*$/, '')
      .trim();
  }

  if (normalized.includes('"') || normalized.includes("'") || normalized.includes('`')) {
    normalized = normalized.replace(/["'`]/g, '').trim();
  }

  const prefixes = ['key:', 'token:', 'secret:', 'apikey:', 'api_key:'];
  for (const prefix of prefixes) {
    if (normalized.toLowerCase().startsWith(prefix)) {
      normalized = normalized.substring(prefix.length).trim();
    }
  }

  if (normalized.includes(' ')) {
    const segments = normalized.split(/\s+/).filter(s => s.length > 10);
    if (segments.length > 0) {
      normalized = segments.reduce((longest, current) =>
        current.length > longest.length ? current : longest
      );
    }
  }

  return normalized;
}

// HTTP History constants
const ORIGAMI_HTTP_HISTORY_DB_NAME = 'origami_http_history';
const ORIGAMI_HTTP_HISTORY_DB_VERSION = 1;
const ORIGAMI_HTTP_HISTORY_STORE = 'requests';
const ORIGAMI_HTTP_HISTORY_MAX_BODY_SIZE = 512 * 1024; // 500KB per body
const ORIGAMI_HTTP_HISTORY_RETENTION_DAYS = 7; // metadata retention
const ORIGAMI_HTTP_HISTORY_BODY_RETENTION_HOURS = 24; // body retention
const ORIGAMI_HTTP_HISTORY_MAX_TOTAL_SIZE_MB = 200;
const ORIGAMI_HTTP_HISTORY_PAGE_SIZE = 50;
const ORIGAMI_HTTP_HISTORY_EXCLUDE_MIME = ['image/', 'font/', 'video/', 'audio/'];
const ORIGAMI_HTTP_HISTORY_CREDENTIAL_FIELDS = ['password', 'passwd', 'pwd', 'secret', 'token', 'credential', 'api_key', 'apikey', 'auth'];

// Stable fingerprint for a finding, used to match AI assessments across scans
function origamiFindingFingerprint(finding, category) {
  if (category === 'secrets' || finding.full_key || finding.key) {
    return 'secret:' + origamiNormalizeSecretKey(finding.full_key || finding.key);
  }
  const type = finding.type || finding.header || finding.name || finding.issue || '';
  const desc = (finding.description || finding.message || '').substring(0, 80);
  return `${category}:${type}:${desc}`;
}
