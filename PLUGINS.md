# Origami Plugin Development Guide

This document covers everything you need to write, test, and distribute custom analyzer plugins for Origami.


## Plugin System Overview

Plugins extend Origami with custom security analyzers that run alongside the built-in analysis pipeline. Each plugin is a self-contained unit consisting of a JSON manifest and a JavaScript analyzer class.

**What plugins can do:**

- Scan page content, scripts, and DOM for custom patterns
- Run compliance or policy checks against the current page
- Detect organization-specific secrets or data exposure
- Add new vulnerability detection logic
- Perform technology-specific security audits

**How the system works:**

1. Plugins are stored in `chrome.storage.local` as JSON objects containing a manifest and analyzer code.
2. On page load, the plugin loader reads all enabled plugins from storage.
3. Each plugin's manifest is validated by the plugin validator.
4. Valid plugin code is injected into the content script context.
5. The injected code dispatches an `origami-plugin-register` CustomEvent, registering the analyzer class with the coordinator.
6. During the 13-step analysis pipeline, the coordinator calls `runPluginAnalyzers()` as step 13, instantiating each registered class and calling its `analyze()` method.
7. Plugin results merge into the unified findings pipeline alongside built-in analyzer output.

**Plugin lifecycle:**

```
Load -> Validate -> Inject -> Register -> Execute -> Results
```


## Plugin Format

A plugin consists of two parts: a **manifest** (`plugin.json`) describing the plugin metadata, and **analyzer code** (`analyzer.js`) containing the detection logic.

### Manifest Schema (plugin.json)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier. Lowercase alphanumeric with hyphens, 3-64 characters. Must start and end with an alphanumeric character. Example: `my-custom-scanner` |
| `name` | string | Yes | Human-readable name, 1-128 characters. Displayed in the Plugins tab. |
| `version` | string | Yes | Semver version string (e.g., `1.0.0`). |
| `analyzerClass` | string | Yes | The global class name defined in your analyzer code. Must start with an uppercase letter and contain only alphanumeric characters. Example: `MyCustomScanner` |
| `resultCategory` | string | Yes | Category for grouping results. Must be one of: `custom`, `secrets`, `headers`, `cookies`, `vulnerabilities`, `technologies`, `network`, `privacy`, `compliance`, `recon` |
| `description` | string | No | Short description of what the plugin detects. |
| `author` | string | No | Author name or handle. |
| `enabled` | boolean | No | Whether the plugin is active. Defaults to `true`. |
| `tags` | array | No | Freeform tags for organization. Not validated. |

**Example manifest:**

```json
{
  "id": "sensitive-data-detector",
  "name": "Sensitive Data Detector",
  "version": "1.0.0",
  "description": "Detects sensitive personal data patterns exposed in page content and scripts",
  "author": "Origami Community",
  "analyzerClass": "SensitiveDataAnalyzer",
  "resultCategory": "privacy",
  "enabled": true,
  "tags": ["pii", "data-exposure", "compliance"]
}
```

### ID Format Rules

The `id` field must match the pattern `^[a-z0-9][a-z0-9-]*[a-z0-9]$`:

- Starts and ends with a lowercase letter or digit
- Contains only lowercase letters, digits, and hyphens
- Minimum 3 characters, maximum 64

Valid: `my-plugin`, `xss-checker`, `corp-policy-v2`
Invalid: `-my-plugin`, `My_Plugin`, `a`, `plugin--name`


## Writing a Plugin

### Step 1: Create the Manifest

Create a `plugin.json` file with the required fields. Choose a `resultCategory` that best fits your analyzer's purpose.

### Step 2: Write the Analyzer Class

Create an `analyzer.js` file that defines a class matching the `analyzerClass` name in your manifest. The class must be declared in the global scope (no module wrapping).

```javascript
class MyCustomScanner {
  analyze(document, url) {
    const findings = [];

    // Your detection logic here

    return findings;
  }
}
```

### Step 3: Implement the analyze() Method

The `analyze()` method is the entry point called by the coordinator during each scan. It receives two arguments:

| Argument | Type | Description |
|----------|------|-------------|
| `document` | Document | The current page's DOM document object |
| `url` | string | The current page URL (`window.location.href`) |

The method must return an array of finding objects (or a Promise that resolves to one). Return an empty array `[]` when no findings are detected. Never return `undefined` or `null`.

### Step 4: Return Findings in the Correct Format

Each finding is a plain object with these fields:

```javascript
{
  check: 'my-check-name',
  severity: 'HIGH',
  message: 'Human-readable description of the finding',
  details: {
    pattern: 'the matched content or value',
    location: 'where in the page it was found',
    recommendation: 'how to remediate the issue'
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `check` | string | Yes | Unique identifier for this check type within your plugin. Used for deduplication and filtering. |
| `severity` | string | Yes | One of: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `message` | string | Yes | Concise description of what was found. Should be meaningful on its own when displayed in the UI. |
| `details` | object | No | Additional context. The `pattern`, `location`, and `recommendation` subfields are conventional but not enforced. You can include any keys relevant to your check. |

### Step 5: Test Your Plugin

1. Create an importable JSON file combining your manifest and code (see "Installing a Plugin" below).
2. Import it via the Plugins tab in Origami.
3. Navigate to a test page containing patterns your plugin should detect.
4. Click "Unfold" to trigger a scan and verify your findings appear in the results.


## The Analyzer Contract

The coordinator supports three method names for backward compatibility. It looks for methods in this order: `analyze`, `scan`, `run`. The first one found is called.

```javascript
class MyAnalyzer {
  // Primary method -- preferred
  analyze(document, url) {
    return [];
  }
}
```

The method can be synchronous or asynchronous. The coordinator awaits the result in both cases.

```javascript
class AsyncAnalyzer {
  async analyze(document, url) {
    // Async operations are supported
    const data = await this.gatherData(document);
    return this.processFindings(data);
  }
}
```

The coordinator wraps each plugin execution in a try/catch. If your analyzer throws, the error is logged and an empty result set is recorded for your plugin. The scan pipeline continues regardless.


## Finding Severity Levels

Use severity levels consistently to maintain signal quality across the plugin ecosystem.

| Level | When to Use | Example |
|-------|-------------|---------|
| `CRITICAL` | Data that enables immediate exploitation or violates regulations. Exposed credentials, payment card numbers, SSNs. | Credit card number in page source |
| `HIGH` | Significant security risk requiring prompt attention. Exploitable weaknesses, authentication flaws. | Internal API endpoint exposed in client-side code |
| `MEDIUM` | Moderate risk that should be addressed in normal development cycles. Information disclosure, missing hardening. | Internal IP address in JavaScript |
| `LOW` | Minor risk or hygiene issue. Not directly exploitable but worth tracking. | Email address in HTML comment |
| `INFO` | Informational observation. No direct risk but useful context for security assessment. | Technology version detected |


## Installing a Plugin

### Via the Plugins Tab (Recommended)

1. Open Origami by clicking the extension icon.
2. Navigate to the **Plugins** tab.
3. Click **Import Plugin**.
4. Select a JSON file containing your plugin data.

The import file must be a JSON object with this structure:

```json
{
  "manifest": {
    "id": "my-plugin",
    "name": "My Plugin",
    "version": "1.0.0",
    "analyzerClass": "MyPluginAnalyzer",
    "resultCategory": "custom",
    "description": "What this plugin does"
  },
  "code": "class MyPluginAnalyzer { analyze(document, url) { return []; } }"
}
```

The `manifest` field contains the full plugin.json content. The `code` field contains the analyzer JavaScript as a single string.

### Preparing the Import File

If you have separate `plugin.json` and `analyzer.js` files, combine them into a single importable JSON file. You can do this manually or with a script:

```bash
# Combine plugin.json and analyzer.js into an importable file
jq --arg code "$(cat analyzer.js)" '. as $manifest | {manifest: $manifest, code: $code}' plugin.json > my-plugin-import.json
```

### Enable and Disable

After import, plugins appear in the Plugins tab with a toggle switch. Disabled plugins remain in storage but are not loaded or executed during scans. Removing a plugin deletes it from storage entirely.


## Sample Plugin Reference

A complete working sample is included at `plugins/samples/sensitive-data-detector/`. This plugin detects sensitive personal data patterns exposed in page content.

### File Structure

```
plugins/samples/sensitive-data-detector/
  plugin.json    -- Plugin manifest
  analyzer.js    -- Analyzer class with detection logic
```

### What It Detects

| Check | Pattern | Severity |
|-------|---------|----------|
| `credit-card-visa` | Visa card numbers (4xxx) | CRITICAL |
| `credit-card-mastercard` | Mastercard numbers (5[1-5]xx) | CRITICAL |
| `credit-card-amex` | Amex numbers (3[47]xx) | CRITICAL |
| `ssn-exposure` | US Social Security Numbers (xxx-xx-xxxx) | CRITICAL |
| `email-in-source` | Email addresses in scripts and comments | LOW |
| `phone-number-us` | US phone number patterns | MEDIUM |
| `ipv4-exposure` | IPv4 addresses in page content | MEDIUM |

### How It Works

The analyzer scans three content sources for each pattern:

1. **Page body text** -- Visible text rendered on the page via `document.body.innerText`
2. **Inline scripts** -- Content of `<script>` tags without a `src` attribute
3. **HTML comments** -- Comment nodes found via `TreeWalker`

For each match, the analyzer applies false-positive filters before reporting:

- **Credit cards** must pass the Luhn checksum algorithm
- **SSNs** are filtered against date-like patterns (e.g., 2024-01-15)
- **Emails** with known placeholder domains (example.com, test.com) are skipped
- **IPs** in localhost, link-local, and public DNS ranges are excluded

Sensitive values are masked in the output (credit cards show only the last four digits, SSNs show only the last four digits).

### Code Walkthrough

The `SensitiveDataAnalyzer` class defines detection in its constructor via a `patterns` array. Each entry specifies the regex, severity, check name, and remediation text.

The `analyze(document, url)` method orchestrates scanning across the three content sources. All regex scanning is delegated to `_scanContent()`, which iterates over the patterns array, deduplicates matches per location, applies the appropriate filter method, and pushes valid findings to the results array.

Helper methods handle the filtering and masking logic:

- `_passesLuhn(cardNumber)` -- Validates credit card numbers using the Luhn algorithm
- `_looksLikeDateOrVersion(value)` -- Rejects SSN matches that resemble dates
- `_isIgnoredIP(ip)` -- Filters well-known non-sensitive IP addresses
- `_isIgnoredEmail(email)` -- Filters placeholder email domains
- `_maskValue(value, check)` -- Redacts sensitive data before including it in findings


## Best Practices

**Keep plugins focused.** Each plugin should target one specific analysis domain. A plugin that detects PII should not also check for SQL injection.

**Wrap detection logic in try/catch.** The coordinator catches top-level errors, but internal failures inside loops or callbacks can produce partial results or silent data loss. Catch errors at the scanning level and log them.

```javascript
analyze(document, url) {
  const findings = [];
  try {
    // scanning logic
  } catch (e) {
    console.error('MyPlugin: scan error:', e);
  }
  return findings;
}
```

**Always return an array.** Return `[]` when no findings are detected. Returning `undefined`, `null`, or a non-array value forces the coordinator to wrap or discard your output.

**Use descriptive check names.** Check names appear in exports and reports. Use lowercase hyphenated names that describe the finding type: `exposed-api-key`, `missing-csrf-token`, `hardcoded-password`.

**Write clear messages.** The `message` field is the primary text shown to users. Include what was found and where: "Hardcoded database password detected in inline script #3".

**Follow severity guidelines.** Overly aggressive severity (marking everything CRITICAL) erodes user trust. Reserve CRITICAL for findings that represent immediate exploitation risk or regulatory violations.

**Deduplicate matches.** If your regex matches the same value multiple times in the same content block, report it once. Use a Set to track seen values per scan location.

**Filter false positives.** Invest in reducing noise. A plugin that produces ten false positives per page will be disabled by users regardless of how good its true positive rate is.

**Mask sensitive output.** If your plugin detects truly sensitive data (card numbers, SSNs), mask the value in the `details.pattern` field. Never expose full sensitive values in findings.

**Test on real pages.** Synthetic test pages are useful for development, but always validate against real-world sites before distributing. Edge cases in HTML structure, encoding, and dynamic content will surface in production.


## Limitations

- **Content script context.** Plugins run in the content script sandbox. They have access to the page DOM but operate under same-origin restrictions. Cross-origin script contents cannot be read directly.

- **No network requests.** Plugins cannot make fetch or XMLHttpRequest calls to external services. If your plugin needs network access, use `chrome.runtime.sendMessage` to delegate the request to the background service worker, which requires additional extension-level integration beyond the plugin system.

- **Code validation.** Plugin code is checked for basic syntax validity before injection. The validator does not perform deep static analysis. Avoid `eval()` and the `Function` constructor in plugin code.

- **Storage constraints.** Plugin data is stored in `chrome.storage.local`, which has a 10MB quota across all extension data. Large plugins with extensive code or many stored results can impact available storage for other Origami features.

- **Execution order.** Plugins run after all 12 built-in analysis stages. You cannot control the order in which multiple plugins execute relative to each other.

- **No persistent state.** Plugins do not have a dedicated storage API. Each invocation of `analyze()` starts fresh. If you need to persist data between scans, use `chrome.storage.local` with a namespaced key.

- **Global scope requirement.** The analyzer class must be defined in the global scope (`window`). Module syntax (`export`, `import`) is not supported in plugin code.
