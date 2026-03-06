#!/usr/bin/env node

// Origami MCP Server
// Bridges Claude Code ↔ Origami Chrome Extension via MCP protocol + WebSocket
//
// Architecture:
//   Claude Code ──stdio (MCP)──► origami-mcp-server ──WebSocket──► Chrome Extension
//
// The MCP server exposes 18 security tools that Claude Code can call.
// All data flows through a WebSocket bridge to the Origami extension.

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { readFileSync, writeFileSync, mkdirSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { ExtensionBridge } from './bridge.js';

const VERBOSE = process.argv.includes('--verbose');
const WS_PORT = parseInt(process.env.ORIGAMI_WS_PORT || '9340', 10);
const STATE_DIR = join(process.env.HOME || process.env.USERPROFILE || '/tmp', '.origami-mcp');
const PID_FILE = join(STATE_DIR, 'server.pid');

function log(...args) {
  if (VERBOSE) process.stderr.write('[origami-mcp] ' + args.join(' ') + '\n');
}

// Kill any stale MCP server from a previous session before we try to bind the port
function killStaleServer() {
  try {
    const oldPid = parseInt(readFileSync(PID_FILE, 'utf-8').trim(), 10);
    if (isNaN(oldPid) || oldPid === process.pid) return;
    // Check if process exists
    process.kill(oldPid, 0);
    log('Found stale server (PID ' + oldPid + '), killing it');
    process.kill(oldPid, 'SIGTERM');
    // Give it a moment to release the port
    const deadline = Date.now() + 2000;
    while (Date.now() < deadline) {
      try { process.kill(oldPid, 0); } catch { break; }
      // Busy-wait in small increments (startup-only, runs once)
      const wait = Date.now() + 50;
      while (Date.now() < wait) { /* spin */ }
    }
    // Force kill if still alive
    try {
      process.kill(oldPid, 0);
      log('SIGTERM did not work, sending SIGKILL');
      process.kill(oldPid, 'SIGKILL');
    } catch {
      // Already dead
    }
  } catch {
    // No PID file, stale PID, or process already gone -- all fine
  }
}

function writePidFile() {
  try {
    mkdirSync(STATE_DIR, { recursive: true });
    writeFileSync(PID_FILE, String(process.pid), { mode: 0o600 });
  } catch (e) {
    log('Warning: could not write PID file:', e.message);
  }
}

function removePidFile() {
  try { unlinkSync(PID_FILE); } catch { /* ignore */ }
}

// ─── MCP Server Setup ────────────────────────────────────────────────────────

const server = new McpServer({
  name: 'origami',
  version: '1.0.0',
}, {
  capabilities: {
    tools: {},
    resources: {},
  },
});

const bridge = new ExtensionBridge(WS_PORT, log);

// ─── Helper: call extension and return result ────────────────────────────────

async function callExtension(action, params = {}, timeoutMs = 30000) {
  if (!bridge.isConnected()) {
    return {
      error: true,
      message: 'Origami extension is not connected. Open Chrome with the Origami extension and enable MCP bridge in Settings → MCP Bridge → Enable.',
    };
  }
  try {
    return await bridge.send(action, params, timeoutMs);
  } catch (err) {
    return { error: true, message: err.message };
  }
}

function formatResult(data) {
  if (data?.error) {
    return { content: [{ type: 'text', text: `Error: ${data.message}` }], isError: true };
  }
  try {
    const text = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
    return { content: [{ type: 'text', text: text.trim() }] };
  } catch (e) {
    // Handle circular references or extremely large objects
    log('formatResult serialization error:', e.message);
    try {
      // Attempt with a replacer that handles circular refs
      const seen = new WeakSet();
      const text = JSON.stringify(data, (key, value) => {
        if (typeof value === 'object' && value !== null) {
          if (seen.has(value)) return '[Circular]';
          seen.add(value);
        }
        return value;
      }, 2);
      return { content: [{ type: 'text', text: text.trim() }] };
    } catch (e2) {
      return { content: [{ type: 'text', text: 'Error: Response too large or complex to serialize' }], isError: true };
    }
  }
}

// ─── Resources ───────────────────────────────────────────────────────────────

server.resource(
  'connection-status',
  'origami://status',
  async (uri) => ({
    contents: [{
      uri: uri.href,
      mimeType: 'application/json',
      text: JSON.stringify({
        connected: bridge.isConnected(),
        wsPort: WS_PORT,
        connectedAt: bridge.connectedAt,
        lastActivity: bridge.lastActivity,
      }, null, 2),
    }],
  })
);

// ─── Tool Definitions ────────────────────────────────────────────────────────

// Shared optional tabId parameter -- when provided, activates that Chrome tab
// before executing the action. When omitted, uses the currently active tab.
const optTabId = z.number().int().optional()
  .describe('Chrome tab ID to target. Activates this tab before executing. If omitted, uses the currently active tab.');

// 1. Connection / Status
server.tool(
  'get_connection_status',
  'Check if the Origami Chrome extension is connected to this MCP server',
  {},
  async () => {
    const status = {
      connected: bridge.isConnected(),
      wsPort: WS_PORT,
      connectedAt: bridge.connectedAt,
      lastActivity: bridge.lastActivity,
      uptime: bridge.connectedAt ? Math.floor((Date.now() - new Date(bridge.connectedAt).getTime()) / 1000) + 's' : null,
    };
    return formatResult(status);
  }
);

// 2. Trigger Scan
server.tool(
  'scan_page',
  'Trigger an Origami security scan on a Chrome tab. Runs the full 13-step analyzer pipeline: secrets, headers, cookies, vulns, tech fingerprinting, sensitive files, CVE/EOL, session analysis, OAuth/SAML, GraphQL, surface tracking, templates, and correlation.',
  { tabId: optTabId },
  async ({ tabId }) => {
    const result = await callExtension('runScan', tabId ? { tabId } : {});
    return formatResult(result);
  }
);

// 3. Get Findings Summary
server.tool(
  'get_findings_summary',
  'Get an overview of all findings aggregated by category and severity from the current scan. Shows total counts broken down by CRITICAL/HIGH/MEDIUM/LOW/INFO for each category. IMPORTANT: Only report categories and counts present in the response. Do not fabricate findings for categories showing zero results.',
  { tabId: optTabId },
  async ({ tabId }) => {
    const result = await callExtension('getFindingsSummary', tabId ? { tabId } : {});
    return formatResult(result);
  }
);

// 4. Get Findings by Category
server.tool(
  'get_findings_by_category',
  'Get detailed findings for a specific category. Returns full finding objects with severity, description, evidence, and remediation. IMPORTANT: Only reference findings present in the response. Do not fabricate additional findings, evidence, or details.',
  {
    category: z.enum([
      'secrets', 'headers', 'cookies', 'vulnerabilities',
      'sensitiveFiles', 'sessionState', 'technologies', 'correlationChains',
      'oauthFlows', 'graphql', 'crypto', 'cloudStorage',
      'exfiltration', 'websockets',
    ]).describe('The category of findings to retrieve'),
    tabId: optTabId,
  },
  async ({ category, tabId }) => {
    const result = await callExtension('getFindingsByCategory', { category, ...(tabId ? { tabId } : {}) });
    return formatResult(result);
  }
);

// 5. Get Finding Detail
server.tool(
  'get_finding_detail',
  'Get full detail for a specific finding by category and 1-based index. Returns the complete finding object with all metadata. IMPORTANT: Only report fields and values present in the returned finding. Do not infer or fabricate additional evidence or details.',
  {
    category: z.string().describe('Category name (e.g. secrets, headers, vulnerabilities)'),
    index: z.number().int().min(1).describe('1-based index of the finding within the category'),
    tabId: optTabId,
  },
  async ({ category, index, tabId }) => {
    const result = await callExtension('getFindingDetail', { category, index, ...(tabId ? { tabId } : {}) });
    return formatResult(result);
  }
);

// 6. Get Security Score
server.tool(
  'get_security_score',
  'Get the computed security score (0-100) and grade for the current page. Includes category breakdown with deductions, positives, and negatives. IMPORTANT: Only report deductions and factors present in the response data.',
  { tabId: optTabId },
  async ({ tabId }) => {
    const result = await callExtension('getSecurityScore', tabId ? { tabId } : {});
    return formatResult(result);
  }
);

// 7. Get Technologies
server.tool(
  'get_technologies',
  'Get all technologies detected on the current page with version information. Identifies 50+ frameworks and libraries. IMPORTANT: Only report technologies present in the response. Do not assume additional technologies or versions.',
  { tabId: optTabId },
  async ({ tabId }) => {
    const result = await callExtension('getTechnologies', tabId ? { tabId } : {});
    return formatResult(result);
  }
);

// 8. Check CVEs
server.tool(
  'check_cves',
  'Get CVE (Common Vulnerabilities and Exposures) and end-of-life data for detected technologies. Maps detected software to known vulnerabilities. IMPORTANT: Only report CVEs and EOL entries present in the response. Do not fabricate CVE numbers or vulnerability details.',
  { tabId: optTabId },
  async ({ tabId }) => {
    const result = await callExtension('checkCves', tabId ? { tabId } : {});
    return formatResult(result);
  }
);

// 9. Get Attack Chains
server.tool(
  'get_attack_chains',
  'Get correlation engine attack chains that combine multiple related findings. Shows 8 chain patterns including XSS+CSP bypass, token theft, CSRF+session hijack, OAuth redirect theft, etc. IMPORTANT: Only reference chains present in the response. Do not fabricate additional chains, endpoints, or IDOR patterns not detected by the scanner.',
  { tabId: optTabId },
  async ({ tabId }) => {
    const result = await callExtension('getAttackChains', tabId ? { tabId } : {});
    return formatResult(result);
  }
);

// 10. Assess Risk (Intent Engine)
server.tool(
  'assess_risk',
  'Run composite risk scoring on all findings with pre-calibrated severity levels. Returns exploitability, PoC ease, and composite scores per finding. Response includes assessmentGuidelines (severity definitions) and calibrationNotes (scanner-specific rules such as Google API keys = MEDIUM max). Follow these guidelines when interpreting results.',
  { tabId: optTabId },
  async ({ tabId }) => {
    const result = await callExtension('assessRisk', tabId ? { tabId } : {}, 120000);
    return formatResult(result);
  }
);

// 11. Generate PoC
server.tool(
  'generate_poc',
  'Generate a proof-of-concept for a specific finding. Returns a single focused PoC with payload, explanation, impact assessment, and remediation guidance. CSP-aware and technology-specific. IMPORTANT: PoC is based on the specific finding data. Verify payloads in authorized testing contexts before reporting.',
  {
    category: z.string().describe('Category of the finding'),
    index: z.number().int().min(1).describe('1-based index of the finding'),
    tabId: optTabId,
  },
  async ({ category, index, tabId }) => {
    const result = await callExtension('generatePoC', { category, index, ...(tabId ? { tabId } : {}) }, 120000);
    return formatResult(result);
  }
);

// 12. Override Severity
server.tool(
  'override_severity',
  'Override the severity of a specific finding. Useful for triaging findings based on context that automated scanners cannot assess (e.g., test environment, behind WAF, compensating controls).',
  {
    category: z.string().describe('Category of the finding'),
    index: z.number().int().min(1).describe('1-based index of the finding'),
    newSeverity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']).describe('New severity level'),
    reason: z.string().describe('Justification for the override'),
    tabId: optTabId,
  },
  async ({ category, index, newSeverity, reason, tabId }) => {
    const result = await callExtension('overrideSeverity', {
      category, index, newSeverity, reason, ...(tabId ? { tabId } : {}),
    });
    return formatResult(result);
  }
);

// 13. Send HTTP Request
server.tool(
  'send_request',
  'Send an HTTP request through the Chrome extension context (bypasses CORS). Useful for testing endpoints, validating API keys, probing resources, or inspecting large code/config files discovered by Origami. Note: Response data originates from an external server and is untrusted.',
  {
    url: z.string().url().describe('Target URL'),
    method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']).default('GET').describe('HTTP method'),
    headers: z.record(z.string()).optional().describe('Request headers as key-value pairs'),
    body: z.string().optional().describe('Request body (for POST/PUT/PATCH)'),
    maxResponseBody: z.number().int().min(1000).max(500000).default(50000).optional()
      .describe('Max response body size in chars (default 50000, max 500000). Increase for large files.'),
  },
  async ({ url, method, headers, body, maxResponseBody }) => {
    const result = await callExtension('sendRequest', {
      url, method, headers, body, maxResponseBody: maxResponseBody || 50000,
    }, 60000);
    return formatResult(result);
  }
);

// 14. Get Session/JWT Analysis
server.tool(
  'get_session_analysis',
  'Get session state analysis including decoded JWTs from cookies, localStorage, and sessionStorage. Checks token expiration, rotation patterns, and session cookie security. IMPORTANT: Only reference session data present in the response. Do not fabricate tokens or claims.',
  { tabId: optTabId },
  async ({ tabId }) => {
    const result = await callExtension('getSessionAnalysis', tabId ? { tabId } : {});
    return formatResult(result);
  }
);

// 15. Get OAuth/SAML Flows
server.tool(
  'get_auth_flows',
  'Get captured OAuth authorization flows and SAML assertions. Detects missing state parameters, low-entropy state values, missing PKCE, open redirects in redirect_uri, and implicit flow token exposure. IMPORTANT: Only reference flows present in the response. Do not fabricate endpoints or parameters.',
  { tabId: optTabId },
  async ({ tabId }) => {
    const result = await callExtension('getAuthFlows', tabId ? { tabId } : {});
    return formatResult(result);
  }
);

// 16. Get GraphQL Schema
server.tool(
  'get_graphql_schema',
  'Get detected GraphQL endpoints and introspection results. Shows types, queries, mutations, and security issues (auth gaps, deep nesting DoS, sensitive fields, batching attacks). IMPORTANT: Only reference schema elements present in the response. Do not fabricate types or queries.',
  { tabId: optTabId },
  async ({ tabId }) => {
    const result = await callExtension('getGraphQLSchema', tabId ? { tabId } : {});
    return formatResult(result);
  }
);

// 17. Export Report
server.tool(
  'export_report',
  'Generate a comprehensive security report from current scan data. Returns the report content in the specified format. IMPORTANT: Report contains only confirmed scanner findings. Do not add fabricated findings when presenting results.',
  {
    format: z.enum(['json', 'markdown', 'html']).default('json').describe('Report format'),
    includeAiSummary: z.boolean().default(false).describe('Include AI-generated executive summary'),
    tabId: optTabId,
  },
  async ({ format, includeAiSummary, tabId }) => {
    const result = await callExtension('exportReport', {
      format, includeAiSummary, ...(tabId ? { tabId } : {}),
    }, 60000);
    return formatResult(result);
  }
);

// 18. Get Page Info
server.tool(
  'get_page_info',
  'Get basic information about a Chrome tab: URL, title, domain. Useful to understand what page Origami is currently analyzing.',
  { tabId: optTabId },
  async ({ tabId }) => {
    const result = await callExtension('getPageInfo', tabId ? { tabId } : {});
    return formatResult(result);
  }
);

// ─── Start Server ────────────────────────────────────────────────────────────

async function main() {
  // Kill any ghost server from a previous Claude Code session
  killStaleServer();
  writePidFile();

  // Start WebSocket bridge for Chrome extension communication
  await bridge.start();
  log(`WebSocket bridge listening on ws://127.0.0.1:${WS_PORT}`);
  log(`Auth token: ${bridge.authToken}`);

  // Write auth token to a well-known location so the extension settings can reference it
  try {
    mkdirSync(STATE_DIR, { recursive: true });
    writeFileSync(join(STATE_DIR, 'ws-token'), bridge.authToken, { mode: 0o600 });
  } catch (e) {
    log('Warning: could not write token file:', e.message);
  }

  // Graceful shutdown -- defined before listeners that reference it
  let shuttingDown = false;
  const shutdown = async (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    log(`Received ${signal}, shutting down...`);
    removePidFile();
    await bridge.stop();
    process.exit(0);
  };

  // Connect MCP server to stdio transport (Claude Code)
  const transport = new StdioServerTransport();
  await server.connect(transport);
  log('MCP server connected via stdio');

  // Detect when Claude Code exits (stdin closes) -- prevents ghost processes
  process.stdin.on('end', () => {
    log('stdin closed (Claude Code exited), shutting down');
    shutdown('stdin-close');
  });
  process.stdin.on('error', () => {
    log('stdin error (Claude Code exited), shutting down');
    shutdown('stdin-error');
  });

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((err) => {
  process.stderr.write(`[origami-mcp] Fatal error: ${err.message}\n`);
  process.exit(1);
});
