#!/usr/bin/env node

// Origami MCP Server
// Exposes Origami security scanner findings to Claude Code via the Model Context Protocol.
//
// The extension writes scan results to a known JSON file (configurable via
// ORIGAMI_FINDINGS_PATH env var). This server reads that file and exposes
// tools for querying findings by category, severity, and more.

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

// Default paths where the extension exports findings (checked in order)
const FINDINGS_PATHS = [
  join(homedir(), '.origami', 'findings.json'),
  join(homedir(), 'Downloads', '.origami', 'findings.json'),
  join(homedir(), 'Downloads', 'origami-findings.json')
];

function getFindingsPath() {
  if (process.env.ORIGAMI_FINDINGS_PATH) {
    return process.env.ORIGAMI_FINDINGS_PATH;
  }
  // Check each default path, return the first that exists
  for (const p of FINDINGS_PATHS) {
    if (existsSync(p)) return p;
  }
  // Fall back to primary default
  return FINDINGS_PATHS[0];
}

async function loadFindings() {
  const filePath = getFindingsPath();
  if (!existsSync(filePath)) {
    return null;
  }
  try {
    const raw = await readFile(filePath, 'utf-8');
    return JSON.parse(raw);
  } catch (e) {
    return null;
  }
}

function flattenIssues(data) {
  if (!data) return [];
  const issues = [];

  // Extract issues from each analyzer category
  const categories = {
    headers: data.headers,
    cookies: data.cookies,
    vulnerabilities: data.vulnerabilities,
    sensitiveFiles: data.sensitiveFiles,
    secrets: data.secrets,
    session: data.sessionState?.issues || data.sessionState?.allIssues,
    oauth: data.oauthFlows?.issues,
    graphql: data.graphql?.issues,
    crypto: data.crypto?.issues,
    cloudStorage: data.cloudStorage?.issues,
    exfiltration: data.exfiltration?.issues,
    websockets: data.websockets?.issues,
    jsObfuscation: data.jsObfuscation?.issues,
    templateFindings: data.templateFindings
  };

  for (const [category, items] of Object.entries(categories)) {
    if (!Array.isArray(items)) continue;
    for (const item of items) {
      issues.push({
        category,
        severity: item.severity || item.risk || item.status || 'INFO',
        type: item.type || item.check || item.name || item.header || 'unknown',
        message: item.message || item.description || item.issue || '',
        recommendation: item.recommendation || '',
        cwe: item.cwe || '',
        details: item.details || {}
      });
    }
  }

  return issues;
}

function formatIssueForDisplay(issue) {
  let output = `[${issue.severity}] ${issue.category}: ${issue.message}`;
  if (issue.type) output += `\n  Type: ${issue.type}`;
  if (issue.cwe) output += `\n  CWE: ${issue.cwe}`;
  if (issue.recommendation) output += `\n  Recommendation: ${issue.recommendation}`;
  return output;
}

// Create the MCP server
const server = new McpServer({
  name: 'origami-security-scanner',
  version: '0.5.0'
});

// Tool: Get all findings (optionally filtered)
server.tool(
  'get_findings',
  'Retrieve security findings from the Origami scanner. Can filter by severity, category, or type.',
  {
    severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']).optional()
      .describe('Filter findings by severity level'),
    category: z.string().optional()
      .describe('Filter by category (headers, cookies, vulnerabilities, secrets, jsObfuscation, crypto, exfiltration, etc.)'),
    type: z.string().optional()
      .describe('Filter by finding type (e.g., js-obfuscation, eval-usage, missing-csp)')
  },
  async ({ severity, category, type }) => {
    const data = await loadFindings();
    if (!data) {
      return {
        content: [{
          type: 'text',
          text: 'No findings available. Ensure the Origami extension has exported findings to: ' + getFindingsPath()
        }]
      };
    }

    let issues = flattenIssues(data);

    if (severity) {
      issues = issues.filter(i => i.severity === severity);
    }
    if (category) {
      issues = issues.filter(i => i.category.toLowerCase() === category.toLowerCase());
    }
    if (type) {
      issues = issues.filter(i => i.type.toLowerCase().includes(type.toLowerCase()));
    }

    if (issues.length === 0) {
      return {
        content: [{
          type: 'text',
          text: 'No findings match the specified filters.'
        }]
      };
    }

    // Sort by severity
    issues.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5));

    const output = issues.map(formatIssueForDisplay).join('\n\n');
    return {
      content: [{
        type: 'text',
        text: `Found ${issues.length} finding(s):\n\n${output}`
      }]
    };
  }
);

// Tool: Get findings summary
server.tool(
  'get_findings_summary',
  'Get a summary of all Origami security findings grouped by severity and category.',
  {},
  async () => {
    const data = await loadFindings();
    if (!data) {
      return {
        content: [{
          type: 'text',
          text: 'No findings available. Ensure the Origami extension has exported findings to: ' + getFindingsPath()
        }]
      };
    }

    const issues = flattenIssues(data);

    // Count by severity
    const bySeverity = {};
    for (const issue of issues) {
      bySeverity[issue.severity] = (bySeverity[issue.severity] || 0) + 1;
    }

    // Count by category
    const byCategory = {};
    for (const issue of issues) {
      byCategory[issue.category] = (byCategory[issue.category] || 0) + 1;
    }

    const url = data.url || 'unknown';
    const timestamp = data.timestamp || 'unknown';

    let output = `Origami Security Scan Summary\n`;
    output += `URL: ${url}\n`;
    output += `Scanned: ${timestamp}\n`;
    output += `Total findings: ${issues.length}\n\n`;

    output += `By Severity:\n`;
    for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']) {
      if (bySeverity[sev]) {
        output += `  ${sev}: ${bySeverity[sev]}\n`;
      }
    }

    output += `\nBy Category:\n`;
    for (const [cat, count] of Object.entries(byCategory).sort((a, b) => b[1] - a[1])) {
      output += `  ${cat}: ${count}\n`;
    }

    return {
      content: [{
        type: 'text',
        text: output
      }]
    };
  }
);

// Tool: Get JS obfuscation findings specifically
server.tool(
  'get_js_obfuscation_findings',
  'Get JavaScript obfuscation detection results from the Origami scanner. Shows detected obfuscation patterns, scores, and types.',
  {},
  async () => {
    const data = await loadFindings();
    if (!data) {
      return {
        content: [{
          type: 'text',
          text: 'No findings available. Ensure the Origami extension has exported findings to: ' + getFindingsPath()
        }]
      };
    }

    const jsObfuscation = data.jsObfuscation;
    if (!jsObfuscation || (!jsObfuscation.scripts?.length && !jsObfuscation.issues?.length)) {
      return {
        content: [{
          type: 'text',
          text: 'No JavaScript obfuscation detected on the scanned page.'
        }]
      };
    }

    let output = `JavaScript Obfuscation Detection Results\n`;
    output += `=========================================\n\n`;

    if (jsObfuscation.scripts && jsObfuscation.scripts.length > 0) {
      output += `Detected ${jsObfuscation.scripts.length} obfuscated script(s):\n\n`;
      for (const script of jsObfuscation.scripts) {
        output += `Script: ${script.identifier}\n`;
        output += `  Severity: ${script.severity}\n`;
        output += `  Score: ${script.score}\n`;
        output += `  Type: ${script.obfuscationType}\n`;
        output += `  Code length: ${script.codeLength} chars\n`;
        if (script.signals && script.signals.length > 0) {
          output += `  Signals:\n`;
          for (const signal of script.signals) {
            output += `    - ${signal.indicator}: ${signal.detail}\n`;
          }
        }
        output += `\n`;
      }
    }

    if (jsObfuscation.issues && jsObfuscation.issues.length > 0) {
      output += `Issues:\n`;
      for (const issue of jsObfuscation.issues) {
        output += formatIssueForDisplay({
          severity: issue.severity,
          category: 'jsObfuscation',
          message: issue.message,
          type: issue.type,
          cwe: issue.cwe,
          recommendation: issue.recommendation
        });
        output += `\n\n`;
      }
    }

    return {
      content: [{
        type: 'text',
        text: output
      }]
    };
  }
);

// Tool: Get scan metadata
server.tool(
  'get_scan_info',
  'Get metadata about the latest Origami security scan (URL, timestamp, available categories).',
  {},
  async () => {
    const data = await loadFindings();
    if (!data) {
      return {
        content: [{
          type: 'text',
          text: 'No scan data available. Ensure the Origami extension has exported findings to: ' + getFindingsPath()
        }]
      };
    }

    const availableCategories = [];
    const categoryChecks = {
      headers: data.headers,
      cookies: data.cookies,
      vulnerabilities: data.vulnerabilities,
      technologies: data.technologies,
      sensitiveFiles: data.sensitiveFiles,
      secrets: data.secrets,
      sessionState: data.sessionState,
      oauthFlows: data.oauthFlows,
      graphql: data.graphql,
      crypto: data.crypto,
      cloudStorage: data.cloudStorage,
      exfiltration: data.exfiltration,
      websockets: data.websockets,
      jsObfuscation: data.jsObfuscation,
      templateFindings: data.templateFindings,
      plugins: data.plugins
    };

    for (const [cat, val] of Object.entries(categoryChecks)) {
      if (val && (Array.isArray(val) ? val.length > 0 : Object.keys(val).length > 0)) {
        availableCategories.push(cat);
      }
    }

    let output = `Origami Scan Info\n`;
    output += `URL: ${data.url || 'unknown'}\n`;
    output += `Timestamp: ${data.timestamp || 'unknown'}\n`;
    output += `Available categories: ${availableCategories.join(', ') || 'none'}\n`;
    output += `Findings path: ${getFindingsPath()}\n`;

    return {
      content: [{
        type: 'text',
        text: output
      }]
    };
  }
);

// Resource: Findings file
server.resource(
  'findings',
  'file://' + getFindingsPath(),
  async (uri) => {
    const data = await loadFindings();
    return {
      contents: [{
        uri: uri.href,
        mimeType: 'application/json',
        text: data ? JSON.stringify(data, null, 2) : '{"error": "No findings file found"}'
      }]
    };
  }
);

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error('Origami MCP server error:', error);
  process.exit(1);
});
