# Origami — Privacy Policy

**Last updated:** February 17, 2026

## Overview

Origami is a browser extension that scans web pages for hardcoded secrets, security vulnerabilities, and misconfigurations. This privacy policy explains what data Origami collects, how it is stored, and when it is transmitted externally.

## Data Collection

### What Origami collects

- **Scan results**: Detected secrets, security header findings, vulnerability indicators, and technology fingerprints from pages you visit.
- **User settings**: Your configuration preferences (notification toggles, custom patterns, whitelisted domains, LLM provider settings).
- **Scan history**: A log of past scan results (up to 100 entries), if you enable the history feature.

### What Origami does NOT collect

- No browsing history beyond scan results
- No personally identifiable information (PII)
- No telemetry, analytics, or usage tracking
- No passwords, form data, or authentication tokens
- No data from pages on your whitelisted domains

## Data Storage

All data is stored **locally in your browser** using Chrome's built-in storage APIs:

- **`chrome.storage.sync`** — Settings and preferences (~100 KB limit)
- **`chrome.storage.local`** — Scan history (~10 MB limit)

No data is stored on external servers. Uninstalling the extension removes all stored data.

## External Data Transmission

Origami does **not** transmit any data to external servers by default. Data leaves your browser only when **you** explicitly configure one of these optional features:

### Webhooks (optional)
If you configure a webhook URL in Settings, scan findings are sent to that URL via HTTP. You control the destination, HTTP method, and payload.

### AI / LLM Analysis (optional)
If you configure an AI provider (OpenAI, Anthropic, Google Gemini, or Ollama), finding context is sent to that provider's API for analysis. For maximum privacy, use Ollama with a locally hosted model — no data leaves your machine.

### Google API Validation (optional)
If you choose to validate a discovered Google API key, a test request is sent to Google's public APIs to check which services the key can access.

No data is ever sold, shared with third parties, or used for advertising.

## Permissions

| Permission | Why it's needed |
|------------|----------------|
| `activeTab` | Access the current tab's URL and page content for scanning |
| `scripting` | Inject content scripts that analyze page source code |
| `<all_urls>` | Scan JavaScript files on any website you visit |
| `storage` | Store your settings, scan history, and whitelisted patterns locally |
| `notifications` | Alert you when critical secrets or vulnerabilities are detected |
| `localhost:11434` | Connect to a local Ollama server for private AI analysis |

## Third-Party Services

Origami does not integrate with any third-party service unless you explicitly configure it. The supported optional integrations are:

- **OpenAI API** (api.openai.com)
- **Anthropic API** (api.anthropic.com)
- **Google Gemini API** (generativelanguage.googleapis.com)
- **Ollama** (localhost only — no external transmission)
- **User-configured webhook URL**

## Data Retention

- Settings persist until you change them or uninstall the extension.
- Scan history is capped at 100 entries and can be cleared at any time from Settings.
- Uninstalling Origami removes all stored data.

## Children's Privacy

Origami is a developer/security tool and is not directed at children under 13.

## Changes to This Policy

Updates to this policy will be noted in the extension's changelog. Continued use after changes constitutes acceptance.

## Contact

For questions about this privacy policy, contact: **mv@archsec.io**
