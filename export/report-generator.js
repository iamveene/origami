// Origami Report Generator
// Generates professional security reports in various formats

class ReportGenerator {
  constructor() {
    this.reportData = null;
    this.llmSummary = null;
    this.llmRiskAnalysis = null;
    this.llmRemediation = null;
    this.llmCompliance = null;
  }

  // Generate report from all findings
  generate(data) {
    this.reportData = {
      ...data,
      generatedAt: new Date().toISOString(),
      reportId: this.generateReportId()
    };
  }
  
  // Generate LLM-enhanced report (on-demand)
  async generateWithLLM(llmManager, options = {}) {
    const {
      includeSummary = true,
      includeRiskAnalysis = true,
      includeRemediation = true,
      includeCompliance = false,
      individual = false,
      templateOverride = null,
      progressCallback = null
    } = options;
    
    try {
      // Generate executive summary
      if (includeSummary) {
        if (progressCallback) progressCallback(25, 'Generating executive summary...');
        this.llmSummary = await this.generateLLMSummary(llmManager, templateOverride);
      }
      
      // Generate risk analysis
      if (includeRiskAnalysis) {
        if (progressCallback) progressCallback(50, 'Analyzing risks...');
        this.llmRiskAnalysis = await this.generateLLMRiskAnalysis(llmManager);
      }
      
      // Generate remediation roadmap
      if (includeRemediation) {
        if (progressCallback) progressCallback(75, 'Creating remediation roadmap...');
        this.llmRemediation = await this.generateLLMRemediation(llmManager, { individual, progressCallback });
      }
      
      // Generate compliance assessment
      if (includeCompliance) {
        if (progressCallback) progressCallback(90, 'Assessing compliance...');
        this.llmCompliance = await this.generateLLMCompliance(llmManager);
      }
      
      if (progressCallback) progressCallback(100, 'LLM analysis complete!');
      
    } catch (error) {
      console.error('LLM report generation error:', error);
      throw error;
    }
  }
  
  // Generate executive summary
  async generateLLMSummary(llmManager, templateOverride = null) {
    const summary = this.calculateSummary();
    const allFindings = this.getAllFindings();

    // Truncate findings for LLM context to avoid token limits
    const truncatedFindings = this.truncateFindingsForLLM(allFindings, 50000); // ~12k tokens max

    const wasTruncated = truncatedFindings.length < allFindings.length;
    const truncationNotice = wasTruncated
      ? `\n\nNote: ${allFindings.length - truncatedFindings.length} lower-severity findings were excluded from AI analysis due to token limits. ${truncatedFindings.length} of ${allFindings.length} findings were analyzed (prioritized by severity).`
      : '';

    // Use custom template if provided
    if (templateOverride && templateOverride.prompt) {
      const context = JSON.stringify({
        summary,
        findings: truncatedFindings,
        note: wasTruncated ?
          `Note: Showing ${truncatedFindings.length} of ${allFindings.length} findings (prioritized by severity)` : null
      }, null, 2);

      // Replace template variables
      let prompt = templateOverride.prompt;
      prompt = prompt.replace(/{findings_count}/g, summary.total);
      prompt = prompt.replace(/{critical_count}/g, summary.critical);
      prompt = prompt.replace(/{high_count}/g, summary.high);
      prompt = prompt.replace(/{url}/g, this.reportData.url || 'Unknown');
      prompt = prompt.replace(/{domain}/g, this.extractDomain(this.reportData.url));

      const result = await llmManager.analyze(prompt, context, { temperature: 0.3, maxTokens: 2000 });
      return result.response + truncationNotice;
    }

    // Use default prompt
    const promptData = SecurityPrompts.comprehensiveReport({
      total: summary.total,
      critical: summary.critical,
      high: summary.high,
      medium: summary.medium,
      low: summary.low,
      details: truncatedFindings
    });

    const result = await llmManager.analyze(promptData.prompt, promptData.context, promptData.options);
    return result.response + truncationNotice;
  }
  
  // Extract domain from URL
  extractDomain(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname;
    } catch {
      return 'Unknown';
    }
  }
  
  // Generate risk analysis
  async generateLLMRiskAnalysis(llmManager) {
    const findings = this.getAllFindings();
    if (findings.length === 0) return 'No findings to analyze';

    // Truncate findings to avoid token limits
    const truncatedFindings = this.truncateFindingsForLLM(findings, 30000); // ~7.5k tokens max

    const promptData = SecurityPrompts.riskScoring(truncatedFindings);
    const result = await llmManager.analyze(promptData.prompt, promptData.context, promptData.options);
    return result.response;
  }
  
  // Generate remediation roadmap
  async generateLLMRemediation(llmManager, options = {}) {
    const { individual = false, progressCallback = null } = options;
    
    const criticalFindings = this.getCriticalFindings();
    if (criticalFindings.length === 0) return 'No critical findings requiring immediate remediation';
    
    if (individual) {
      // Analyze each finding individually with full context
      const remediations = [];
      const totalFindings = criticalFindings.length;

      for (let i = 0; i < totalFindings; i++) {
        const finding = criticalFindings[i];

        if (progressCallback) {
          const progress = 75 + Math.floor((i / totalFindings) * 15);
          progressCallback(progress, `Analyzing finding ${i + 1}/${totalFindings}...`);
        }

        // Include full context in the analysis
        const contextualFinding = this.enrichFindingWithContext(finding);
        const promptData = SecurityPrompts.remediationAdvice(contextualFinding);

        try {
          const result = await llmManager.analyze(promptData.prompt, promptData.context, promptData.options);

          // Store AI assessment in the finding itself so it shows up in the finding's section
          if (!finding.aiAssessment) {
            finding.aiAssessment = {};
          }
          finding.aiAssessment.analysis = result.response;
          finding.aiAssessment.timestamp = new Date().toISOString();

          // For CVE/SCA findings, also store assessment in the original technology object
          if (finding.findingType === 'cve' && finding._techRef) {
            if (!finding._techRef.aiAssessment) {
              finding._techRef.aiAssessment = {};
            }
            finding._techRef.aiAssessment.analysis = result.response;
            finding._techRef.aiAssessment.timestamp = new Date().toISOString();
            console.log(`Origami: Stored AI assessment for ${finding.check} in technology object`);
          }

          remediations.push({
            finding: finding.check || finding.pattern_matched,
            severity: finding.severity || finding.risk,
            source: finding.source || 'Unknown',
            lineNumber: finding.lineNumber,
            remediation: result.response
          });
        } catch (error) {
          console.error(`Error analyzing finding ${i + 1}:`, error);
          remediations.push({
            finding: finding.check || finding.pattern_matched,
            severity: finding.severity || finding.risk,
            remediation: `Error analyzing: ${error.message}`
          });
        }
      }

      return remediations;
    } else {
      // Analyze top 5 critical findings (to avoid token limits)
      const top5 = criticalFindings.slice(0, 5);
      const remediations = [];
      
      for (const finding of top5) {
        const promptData = SecurityPrompts.remediationAdvice(finding);
        const result = await llmManager.analyze(promptData.prompt, promptData.context, promptData.options);
        remediations.push({
          finding: finding.check || finding.pattern_matched,
          remediation: result.response
        });
      }
      
      return remediations;
    }
  }
  
  // Enrich finding with full context for LLM analysis
  enrichFindingWithContext(finding) {
    const enriched = { ...finding };

    // Handle CVE/SCA findings specially
    if (finding.findingType === 'cve' && finding.cveDetails) {
      enriched.fullContext = `
Technology: ${finding.check}
Total Vulnerabilities: ${finding.cveDetails.length}

Known CVEs:
${finding.cveDetails.map((cve, idx) => `
${idx + 1}. ${cve.id} [${cve.severity}${cve.score ? ` - CVSS ${cve.score}` : ''}]
   Summary: ${cve.summary}
   ${cve.fixedVersion ? `Fix Available: Upgrade to version ${cve.fixedVersion} or higher` : 'No fix version specified'}
`).join('\n')}
${finding.eolStatus ? `
End-of-Life Status:
- Status: ${finding.eolStatus.status}
${finding.eolStatus.eolDate ? `- EOL Date: ${finding.eolStatus.eolDate}` : ''}
${finding.eolStatus.latestVersion ? `- Latest Version: ${finding.eolStatus.latestVersion}` : ''}
` : ''}
`;
    }

    // Add context if available
    if (finding.codeContext) {
      enriched.fullContext = (enriched.fullContext || '') + `
Code Context (${finding.source || 'unknown'}${finding.lineNumber ? ` line ${finding.lineNumber}` : ''}):
\`\`\`
${finding.codeContext}
\`\`\`
`;
    }

    // Add matched pattern details
    if (finding.matchedText) {
      enriched.matchDetails = `Matched Pattern: ${finding.matchedText}`;
    }

    // Add URI/endpoint if available
    if (finding.uri) {
      enriched.endpoint = `Endpoint: ${finding.uri}`;
    }

    return enriched;
  }

  // Estimate token count (rough approximation: 1 token ≈ 4 characters)
  estimateTokens(text) {
    if (!text) return 0;
    if (typeof text !== 'string') {
      text = JSON.stringify(text);
    }
    return Math.ceil(text.length / 4);
  }

  // Truncate findings to stay within token limits
  truncateFindingsForLLM(findings, maxChars = 50000) {
    if (!findings || findings.length === 0) return [];

    // Sort by severity priority: CRITICAL > HIGH > MEDIUM > LOW
    const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };
    const sortedFindings = [...findings].sort((a, b) => {
      const severityA = (a.severity || a.risk || 'LOW').toUpperCase();
      const severityB = (b.severity || b.risk || 'LOW').toUpperCase();
      return (severityOrder[severityA] || 5) - (severityOrder[severityB] || 5);
    });

    const truncatedFindings = [];
    let currentSize = 0;

    for (const finding of sortedFindings) {
      // Create lightweight version of finding (without full code context)
      const lightFinding = {
        check: finding.check || finding.pattern_matched,
        severity: finding.severity || finding.risk,
        message: finding.message || finding.key,
        source: finding.source || finding.url,
        lineNumber: finding.lineNumber
      };

      // Add truncated code context (max 500 chars)
      if (finding.codeContext) {
        const context = String(finding.codeContext);
        lightFinding.codeContext = context.length > 500 ?
          context.substring(0, 500) + '... [truncated]' :
          context;
      }

      // Estimate size
      const findingSize = JSON.stringify(lightFinding).length;

      // Check if adding this finding would exceed limit
      if (currentSize + findingSize > maxChars) {
        // If we haven't added any findings yet, add at least one (truncated more)
        if (truncatedFindings.length === 0) {
          const minimalFinding = {
            check: lightFinding.check,
            severity: lightFinding.severity,
            message: lightFinding.message
          };
          truncatedFindings.push(minimalFinding);
        }
        break;
      }

      truncatedFindings.push(lightFinding);
      currentSize += findingSize;
    }

    console.log(`Origami: Truncated ${findings.length} findings to ${truncatedFindings.length} (${currentSize}/${maxChars} chars)`);
    return truncatedFindings;
  }
  
  // Generate compliance assessment
  async generateLLMCompliance(llmManager) {
    const findings = this.getAllFindings();

    // Truncate findings to avoid token limits
    const truncatedFindings = this.truncateFindingsForLLM(findings, 30000); // ~7.5k tokens max

    const compliancePrompt = {
      prompt: `Assess this application's security posture against major compliance frameworks:

1. OWASP Top 10 (2021)
2. CIS Controls
3. NIST Cybersecurity Framework
4. PCI-DSS (if applicable)
5. GDPR/Privacy requirements

Based on these findings, provide:
1. Compliance gaps identified
2. Framework coverage percentage
3. High-priority gaps
4. Remediation priorities
5. Compliance roadmap`,
      context: JSON.stringify(truncatedFindings, null, 2),
      options: { temperature: 0.2, maxTokens: 2500 }
    };

    const result = await llmManager.analyze(compliancePrompt.prompt, compliancePrompt.context, compliancePrompt.options);
    return result.response;
  }
  
  // Get all findings
  getAllFindings() {
    if (!this.reportData) return [];
    const findings = [];

    if (this.reportData.secrets) {
      findings.push(...this.reportData.secrets.map(s => ({
        ...s,
        check: s.pattern_matched,
        severity: s.risk,
        message: `Exposed secret: ${s.key}`
      })));
    }

    if (this.reportData.securityAnalysis) {
      if (this.reportData.securityAnalysis.headers) {
        findings.push(...this.reportData.securityAnalysis.headers);
      }
      if (this.reportData.securityAnalysis.cookies) {
        findings.push(...this.reportData.securityAnalysis.cookies);
      }
      if (this.reportData.securityAnalysis.vulnerabilities) {
        findings.push(...this.reportData.securityAnalysis.vulnerabilities);
      }
    }

    // Add CVE/SCA vulnerabilities (flatten nested structure)
    if (this.reportData.vulnerabilities) {
      for (const category in this.reportData.vulnerabilities) {
        const techArray = this.reportData.vulnerabilities[category];
        if (Array.isArray(techArray)) {
          techArray.forEach(tech => {
            if (tech.vulnerabilities && tech.vulnerabilities.length > 0) {
              // Create a finding for this technology's vulnerabilities
              // Use the highest severity from all CVEs
              const severities = tech.vulnerabilities.map(v => v.severity);
              const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };
              const highestSeverity = severities.reduce((highest, current) => {
                const highestOrder = severityOrder[highest] ?? 5;
                const currentOrder = severityOrder[current] ?? 5;
                return currentOrder < highestOrder ? current : highest;
              }, 'LOW');

              // Count vulnerabilities by severity
              const vulnCounts = tech.vulnerabilities.reduce((acc, v) => {
                acc[v.severity] = (acc[v.severity] || 0) + 1;
                return acc;
              }, {});

              const vulnSummary = Object.entries(vulnCounts)
                .map(([sev, count]) => `${count} ${sev}`)
                .join(', ');

              // Create finding object
              const finding = {
                check: `${tech.name} ${tech.version || 'Unknown Version'} - Known Vulnerabilities`,
                severity: highestSeverity,
                status: 'Vulnerable',
                message: `${tech.name} version ${tech.version || 'Unknown'} has ${tech.vulnerabilities.length} known vulnerabilit${tech.vulnerabilities.length === 1 ? 'y' : 'ies'} (${vulnSummary})`,
                source: 'SCA',
                findingType: 'cve',
                // Store reference to original technology object for updating with AI assessment
                _techRef: tech,
                _category: category,
                // Include vulnerability details for LLM context
                cveDetails: tech.vulnerabilities.map(v => ({
                  id: v.id,
                  severity: v.severity,
                  summary: v.summary,
                  score: v.score,
                  fixedVersion: v.fixedVersion
                })),
                eolStatus: tech.eolStatus
              };

              // If technology already has AI assessment, include it
              if (tech.aiAssessment) {
                finding.aiAssessment = tech.aiAssessment;
              }

              findings.push(finding);
            }
          });
        }
      }
    }

    // Session analysis findings
    if (this.reportData.sessionAnalysis) {
      const sessionIssues = this.reportData.sessionAnalysis.issues || this.reportData.sessionAnalysis.allIssues || [];
      findings.push(...sessionIssues.map(s => ({
        ...s,
        check: s.check || s.type || 'Session Issue',
        severity: s.severity || 'MEDIUM',
        message: s.message || s.details || '',
        source: 'Session Analysis'
      })));
    }

    // OAuth/SAML findings
    if (this.reportData.oauthAnalysis) {
      const oauthIssues = this.reportData.oauthAnalysis.issues || [];
      findings.push(...oauthIssues.map(o => ({
        ...o,
        check: o.check || o.type || 'OAuth/SAML Issue',
        severity: o.severity || 'MEDIUM',
        message: o.message || o.details || '',
        source: 'OAuth/SAML Analysis'
      })));
    }

    // GraphQL findings
    if (this.reportData.graphqlAnalysis) {
      const graphqlIssues = this.reportData.graphqlAnalysis.issues || [];
      findings.push(...graphqlIssues.map(g => ({
        ...g,
        check: g.check || g.type || 'GraphQL Issue',
        severity: g.severity || 'MEDIUM',
        message: g.message || g.details || '',
        source: 'GraphQL Analysis'
      })));
    }

    // Crypto audit findings
    if (this.reportData.cryptoAnalysis) {
      const cryptoIssues = this.reportData.cryptoAnalysis.issues || [];
      findings.push(...cryptoIssues.map(c => ({
        ...c,
        check: c.check || c.type || 'Crypto Issue',
        severity: c.severity || 'MEDIUM',
        message: c.message || c.details || '',
        source: 'Crypto Audit'
      })));
    }

    // Cloud storage findings
    if (this.reportData.cloudStorageAnalysis) {
      const cloudIssues = this.reportData.cloudStorageAnalysis.issues || [];
      findings.push(...cloudIssues.map(cs => ({
        ...cs,
        check: cs.check || cs.type || 'Cloud Storage Issue',
        severity: cs.severity || 'MEDIUM',
        message: cs.message || cs.details || '',
        source: 'Cloud Storage Mapping'
      })));
    }

    // Exfiltration findings
    if (this.reportData.exfiltrationAnalysis) {
      const exfilIssues = this.reportData.exfiltrationAnalysis.issues || [];
      findings.push(...exfilIssues.map(e => ({
        ...e,
        check: e.check || e.type || 'Exfiltration Issue',
        severity: e.severity || 'MEDIUM',
        message: e.message || e.details || '',
        source: 'Exfiltration Detection'
      })));
    }

    // WebSocket findings
    if (this.reportData.websocketAnalysis) {
      const wsIssues = this.reportData.websocketAnalysis.issues || [];
      findings.push(...wsIssues.map(w => ({
        ...w,
        check: w.check || w.type || 'WebSocket Issue',
        severity: w.severity || 'MEDIUM',
        message: w.message || w.details || '',
        source: 'WebSocket Audit'
      })));
    }

    // Sensitive/Exposed file findings
    if (this.reportData.sensitiveFiles && Array.isArray(this.reportData.sensitiveFiles)) {
      findings.push(...this.reportData.sensitiveFiles.map(f => ({
        ...f,
        check: f.check || f.path || 'Sensitive File',
        severity: f.severity || f.risk || 'MEDIUM',
        message: f.message || f.details || `Exposed file found: ${f.path || f.url || ''}`,
        source: 'Sensitive File Scanner'
      })));
    }

    // Correlation chain findings
    if (this.reportData.correlationChains && Array.isArray(this.reportData.correlationChains)) {
      findings.push(...this.reportData.correlationChains.map(chain => ({
        check: chain.name || 'Attack Chain',
        severity: chain.severity || 'HIGH',
        message: chain.attackFlow || chain.description || '',
        source: 'Correlation Engine',
        details: { findings: chain.findings, remediation: chain.remediation }
      })));
    }

    // Debug log for CVE/SCA findings
    const cveFindings = findings.filter(f => f.findingType === 'cve');
    if (cveFindings.length > 0) {
      console.log(`Origami Report Generator: Added ${cveFindings.length} CVE/SCA findings to getAllFindings()`,
        cveFindings.map(f => ({ tech: f.check, severity: f.severity, cveCount: f.cveDetails.length })));
    }

    return findings;
  }
  
  // Get critical findings (only CRITICAL severity by default)
  getCriticalFindings() {
    return this.getAllFindings().filter(f => {
      const effectiveSeverity = (f.severityOverride?.overriddenSeverity ||
                                  f.aiAssessment?.suggestedSeverity ||
                                  f.severity ||
                                  f.risk ||
                                  '').toUpperCase();
      return effectiveSeverity === 'CRITICAL' || effectiveSeverity === 'HIGH';
    });
  }

  // Generate HTML report
  toHTML() {
    if (!this.reportData) {
      throw new Error('No report data available');
    }

    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Origami Security Report - ${this.escapeHTML(this.reportData.url)}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      line-height: 1.6;
      color: #333;
      max-width: 1200px;
      margin: 0 auto;
      padding: 20px;
      background: #f5f5f5;
    }
    .report-container {
      background: white;
      padding: 40px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
      border-radius: 8px;
    }
    .header {
      background: linear-gradient(135deg, #6B46C1 0%, #9333EA 100%);
      padding: 30px;
      margin: -40px -40px 30px -40px;
      border-radius: 8px 8px 0 0;
      color: white;
    }
    h1 {
      color: white;
      font-size: 2.5em;
      margin-bottom: 15px;
      text-shadow: 0 2px 4px rgba(0,0,0,0.2);
    }
    .meta { color: rgba(255,255,255,0.9); font-size: 0.9em; }
    .meta strong { color: white; }
    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin: 30px 0;
    }
    .summary-card {
      background: #f8f9fa;
      padding: 20px;
      border-radius: 8px;
      text-align: center;
      border-left: 4px solid #6B46C1;
      box-shadow: 0 2px 4px rgba(107, 70, 193, 0.1);
    }
    .summary-card.critical { border-left-color: #dc3545; }
    .summary-card.high { border-left-color: #fd7e14; }
    .summary-card.medium { border-left-color: #ffc107; }
    .summary-label {
      text-transform: uppercase;
      font-size: 0.8em;
      color: #666;
      margin-bottom: 10px;
    }
    .summary-value {
      font-size: 2.5em;
      font-weight: bold;
      color: #333;
    }
    .section {
      margin: 40px 0;
      padding: 20px;
      background: #f8f9fa;
      border-radius: 8px;
    }
    .section h2 {
      background: linear-gradient(135deg, #6B46C1, #9333EA);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      margin-bottom: 20px;
      font-size: 1.8em;
      font-weight: 700;
    }
    .finding {
      background: white;
      padding: 15px;
      margin: 15px 0;
      border-left: 4px solid #ccc;
      border-radius: 4px;
    }
    .finding.critical { border-left-color: #dc3545; }
    .finding.high { border-left-color: #fd7e14; }
    .finding.medium { border-left-color: #ffc107; }
    .finding.low { border-left-color: #28a745; }
    .badge {
      display: inline-block;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 0.8em;
      font-weight: bold;
      text-transform: uppercase;
      color: white;
    }
    .badge.critical { background: #dc3545; }
    .badge.high { background: #fd7e14; }
    .badge.medium { background: #ffc107; color: #000; }
    .badge.low { background: #28a745; }
    .footer {
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid #ddd;
      text-align: center;
      color: #666;
      font-size: 0.9em;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 20px 0;
    }
    th, td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid #ddd;
    }
    th {
      background: linear-gradient(135deg, #6B46C1, #9333EA);
      color: white;
      font-weight: 600;
    }
    code {
      background: #f4f4f4;
      padding: 2px 6px;
      border-radius: 3px;
      font-family: 'Courier New', monospace;
      font-size: 0.9em;
    }
  </style>
</head>
<body>
  <div class="report-container">
    <div class="header">
      <h1>
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="32" height="32" style="display: inline-block; vertical-align: middle; margin-right: 8px;">
          <defs>
            <linearGradient id="reportGradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" style="stop-color:#FFFFFF;stop-opacity:1" />
              <stop offset="100%" style="stop-color:#E0D4F7;stop-opacity:1" />
            </linearGradient>
          </defs>
          <g stroke="url(#reportGradient)" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round">
            <path d="M 12 6 L 15 12 L 12 18 L 9 12 Z"/>
            <path d="M 9 12 L 4 9 L 6 12 L 4 15 Z"/>
            <path d="M 15 12 L 20 9 L 18 12 L 20 15 Z"/>
            <path d="M 12 6 L 12 3 L 12.75 3.75"/>
            <path d="M 12 18 L 12 21"/>
          </g>
        </svg>
        Origami Security Report
      </h1>
      <div class="meta">
        <p><strong>Target:</strong> ${this.escapeHTML(this.reportData.url)}</p>
        <p><strong>Report ID:</strong> ${this.reportData.reportId}</p>
        <p><strong>Generated:</strong> ${new Date(this.reportData.generatedAt).toLocaleString()}</p>
      </div>
    </div>

    ${this.generateSummaryHTML()}
    ${this.generateLLMExecutiveSummaryHTML()}
    ${this.generateSecretsHTML()}
    ${this.generateSecurityHTML()}
    ${this.generateLLMRiskAnalysisHTML()}
    ${this.generateTechStackHTML()}
    ${this.generateLLMRemediationHTML()}
    ${this.generateLLMComplianceHTML()}

    <div class="footer">
      <p>Generated by <strong>Origami</strong> - Complete Cyber Security Toolkit</p>
      <p>This report contains sensitive security information. Handle with care.</p>
    </div>
  </div>
</body>
</html>
    `;

    return html;
  }
  
  // Generate LLM Executive Summary HTML
  generateLLMExecutiveSummaryHTML() {
    if (!this.llmSummary) return '';
    
    return `
    <div class="section llm-section">
      <h2>${origamiIcon('sparkles')} AI-Powered Executive Summary</h2>
      <div class="llm-insight">
        ${this.formatHTMLContent(this.llmSummary)}
      </div>
    </div>
    `;
  }
  
  // Generate LLM Risk Analysis HTML
  generateLLMRiskAnalysisHTML() {
    if (!this.llmRiskAnalysis) return '';
    
    return `
    <div class="section">
      <h2>${origamiIcon('chart')} Risk Prioritization Matrix</h2>
      <div class="llm-insight">
        ${this.formatHTMLContent(this.llmRiskAnalysis)}
      </div>
    </div>
    `;
  }
  
  // Generate LLM Remediation HTML
  generateLLMRemediationHTML() {
    if (!this.llmRemediation) return '';
    
    if (Array.isArray(this.llmRemediation)) {
      let html = `
      <div class="section">
        <h2>${origamiIcon('wrench')} Remediation Roadmap</h2>
        <div class="timeline">
      `;

      this.llmRemediation.forEach((item, index) => {
        html += `
          <div class="timeline-item">
            <h3>Phase ${index + 1}: ${this.escapeHTML(item.finding)}</h3>
            <div class="llm-insight">
              ${this.formatHTMLContent(item.remediation)}
            </div>
          </div>
        `;
      });
      
      html += '</div></div>';
      return html;
    } else {
      return `
      <div class="section">
        <h2>${origamiIcon('wrench')} Remediation Roadmap</h2>
        <div class="llm-insight">
          ${this.formatHTMLContent(this.llmRemediation)}
        </div>
      </div>
      `;
    }
  }
  
  // Generate LLM Compliance HTML
  generateLLMComplianceHTML() {
    if (!this.llmCompliance) return '';
    
    return `
    <div class="section">
      <h2>${origamiIcon('checkCircle')} Compliance Assessment</h2>
      <div class="llm-insight">
        ${this.formatHTMLContent(this.llmCompliance)}
      </div>
    </div>
    `;
  }
  
  // Format text content for HTML (preserve newlines and basic formatting)
  formatHTMLContent(text) {
    if (!text) return '';

    // Store code blocks to protect them from further processing
    const codeBlocks = [];
    let formatted = this.escapeHTML(text);

    // Extract and protect code blocks
    formatted = formatted.replace(/```([^\n]*)\n([\s\S]*?)```/g, (match, lang, code) => {
      const placeholder = `__CODE_BLOCK_${codeBlocks.length}__`;
      codeBlocks.push(`<pre style="background: #1a1d23; color: #d4d4d4; padding: 12px; border-radius: 4px; overflow-x: auto; margin: 8px 0;"><code class="language-${lang}">${code.trim()}</code></pre>`);
      return placeholder;
    });

    // Convert **bold** to <strong>
    formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');

    // Convert *italic* to <em> (but not standalone asterisks for lists)
    formatted = formatted.replace(/(?<!\s)\*([^\*\n]+)\*(?!\*)/g, '<em>$1</em>');

    // Convert `inline code` to <code>
    formatted = formatted.replace(/`([^`]+)`/g, '<code style="background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: monospace;">$1</code>');

    // Convert headers (only true markdown headers, not code comments)
    formatted = formatted.replace(/^#### (.+)$/gm, '<h5 style="margin-top: 12px; margin-bottom: 6px; color: #9333ea;">$1</h5>');
    formatted = formatted.replace(/^### (.+)$/gm, '<h4 style="margin-top: 16px; margin-bottom: 8px; color: #9333ea;">$1</h4>');
    formatted = formatted.replace(/^## (.+)$/gm, '<h3 style="margin-top: 20px; margin-bottom: 10px; color: #9333ea;">$1</h3>');
    formatted = formatted.replace(/^# (.+)$/gm, '<h2 style="margin-top: 24px; margin-bottom: 12px; color: #9333ea;">$1</h2>');

    // Convert bullet lists (- item or * item)
    formatted = formatted.replace(/^[\*\-]\s+(.+)$/gm, '<li style="margin-left: 20px;">$1</li>');

    // Convert numbered lists
    formatted = formatted.replace(/^(\d+)\.\s+(.+)$/gm, '<li style="margin-left: 20px;" value="$1">$2</li>');

    // Wrap consecutive list items
    formatted = formatted.replace(/(<li[^>]*>.*?<\/li>(\s*<br>)*)+/g, (match) => {
      if (match.includes('value=')) {
        return '<ol style="margin: 8px 0;">' + match.replace(/<br>/g, '') + '</ol>';
      } else {
        return '<ul style="margin: 8px 0;">' + match.replace(/<br>/g, '') + '</ul>';
      }
    });

    // Convert links [text](url) - only allow http/https URLs to prevent javascript: injection
    formatted = formatted.replace(/\[([^\]]+)\]\(([^\)]+)\)/g, (match, text, url) => {
      const trimmedUrl = url.trim().toLowerCase();
      if (trimmedUrl.startsWith('http://') || trimmedUrl.startsWith('https://')) {
        return '<a href="' + url + '" style="color: #9333EA; text-decoration: underline;" target="_blank">' + text + '</a>';
      }
      return text + ' (' + url + ')';
    });

    // Convert newlines to <br> (but not inside lists or code blocks)
    formatted = formatted.replace(/(?<!<\/li>|<\/ol>|<\/ul>|<\/pre>|<\/h[1-6]>)\n(?!<)/g, '<br>');

    // Clean up extra breaks
    formatted = formatted.replace(/(<br>){3,}/g, '<br><br>');

    // Restore code blocks
    codeBlocks.forEach((block, i) => {
      formatted = formatted.replace(`__CODE_BLOCK_${i}__`, block);
    });

    return formatted;
  }

  // Generate summary section
  generateSummaryHTML() {
    const summary = this.calculateSummary();
    
    return `
    <div class="summary">
      <div class="summary-card critical">
        <div class="summary-label">Critical</div>
        <div class="summary-value">${summary.critical}</div>
      </div>
      <div class="summary-card high">
        <div class="summary-label">High</div>
        <div class="summary-value">${summary.high}</div>
      </div>
      <div class="summary-card medium">
        <div class="summary-label">Medium</div>
        <div class="summary-value">${summary.medium}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">Total</div>
        <div class="summary-value">${summary.total}</div>
      </div>
    </div>
    `;
  }

  // Normalize secret key by extracting the actual secret value
  normalizeSecretKey(secretValue) {
    if (!secretValue) return '';

    // Remove common variable assignments and quotes
    let normalized = secretValue
      .replace(/^.*?[=:]\s*["'`]?/, '')  // Remove "api_key = " or "apiKey: " etc.
      .replace(/["'`].*$/, '')            // Remove trailing quotes and anything after
      .trim();

    // If the original value looks like it contains the key inside, extract it
    // Pattern: Look for common API key patterns (AIza, sk_, pk_, etc.)
    const keyPatterns = [
      /AIza[A-Za-z0-9_-]{35}/,           // Google API keys
      /sk_(?:live|test)_[A-Za-z0-9]{24,}/,  // Stripe keys
      /pk_(?:live|test)_[A-Za-z0-9]{24,}/,  // Stripe public keys
      /AKIA[A-Z0-9]{16}/,                // AWS Access keys
      /ghp_[A-Za-z0-9]{36}/,             // GitHub tokens
      /xox[baprs]-[A-Za-z0-9-]+/         // Slack tokens
    ];

    for (const pattern of keyPatterns) {
      const match = secretValue.match(pattern);
      if (match) {
        normalized = match[0];
        break;
      }
    }

    if (normalized.length === 0) return secretValue.trim();
    return normalized;
  }

  // Generate secrets section
  generateSecretsHTML() {
    console.log('Origami Report Generator v2.2 - Normalized Deduplication Active');

    if (!this.reportData.secrets || this.reportData.secrets.length === 0) {
      return '';
    }

    let html = '<div class="section"><h2>' + origamiIcon('key') + ' Exposed Secrets</h2>';

    console.log('Origami Report: Input secrets:', this.reportData.secrets.length, this.reportData.secrets.map(s => ({
      pattern: s.pattern_matched,
      risk: s.risk,
      key_preview: (s.full_key || s.key).substring(0, 30)
    })));

    // Deduplicate secrets by value, keeping highest severity
    const secretMap = new Map();
    this.reportData.secrets.forEach(secret => {
      // Use normalized key for deduplication
      const secretKey = this.normalizeSecretKey(secret.full_key || secret.key);

      // Debug: Log normalization for Google API keys
      if ((secret.full_key || secret.key).includes('AIza')) {
        console.log('Origami Report: Normalizing secret:', {
          original: (secret.full_key || secret.key).substring(0, 60),
          normalized: secretKey.substring(0, 60),
          pattern: secret.pattern_matched,
          risk: secret.risk
        });
      }

      if (secretMap.has(secretKey)) {
        const existing = secretMap.get(secretKey);
        const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };

        // Add pattern to the list
        if (!existing.patterns_matched) {
          existing.patterns_matched = [existing.pattern_matched];
        }
        if (secret.pattern_matched && !existing.patterns_matched.includes(secret.pattern_matched)) {
          existing.patterns_matched.push(secret.pattern_matched);
        }

        // Keep the finding with higher severity
        const currentSeverity = severityOrder[secret.risk] || 5;
        const existingSeverity = severityOrder[existing.risk] || 5;

        if (currentSeverity < existingSeverity) {
          // Current secret has higher severity, replace but keep patterns and merge assessments
          secret.patterns_matched = existing.patterns_matched;

          // Preserve AI assessment and severity override if existing has them but current doesn't
          if (!secret.aiAssessment && existing.aiAssessment) {
            secret.aiAssessment = existing.aiAssessment;
          }
          if (!secret.severityOverride && existing.severityOverride) {
            secret.severityOverride = existing.severityOverride;
          }

          secretMap.set(secretKey, secret);
        } else if (currentSeverity === existingSeverity) {
          // Same severity, keep existing but merge AI assessment from current if needed
          if (!existing.aiAssessment && secret.aiAssessment) {
            existing.aiAssessment = secret.aiAssessment;
          }
          if (!existing.severityOverride && secret.severityOverride) {
            existing.severityOverride = secret.severityOverride;
          }

          secretMap.set(secretKey, existing);
        } else {
          // Existing has higher severity, keep it but merge AI assessment from current if needed
          if (!existing.aiAssessment && secret.aiAssessment) {
            existing.aiAssessment = secret.aiAssessment;
          }
          if (!existing.severityOverride && secret.severityOverride) {
            existing.severityOverride = secret.severityOverride;
          }

          secretMap.set(secretKey, existing);
        }
      } else {
        secretMap.set(secretKey, secret);
      }
    });

    const uniqueSecrets = Array.from(secretMap.values());

    console.log('Origami Report: Deduplication results:');
    console.log(`  - Original secrets: ${this.reportData.secrets.length}`);
    console.log(`  - After deduplication: ${uniqueSecrets.length}`);
    console.log('  - Unique secrets:', uniqueSecrets.map(s => ({
      pattern: s.pattern_matched,
      patterns_matched: s.patterns_matched,
      risk: s.risk,
      key_preview: (s.full_key || s.key).substring(0, 20)
    })));

    // Sort secrets by effective severity (higher first)
    const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };
    const getEffectiveSeverity = (finding) => {
      return (finding.severityOverride?.overriddenSeverity ||
              finding.aiAssessment?.suggestedSeverity ||
              finding.risk ||
              'LOW').toUpperCase();
    };
    const sortedSecrets = [...uniqueSecrets].sort((a, b) => {
      const severityA = getEffectiveSeverity(a);
      const severityB = getEffectiveSeverity(b);
      const orderA = severityOrder[severityA] || 5;
      const orderB = severityOrder[severityB] || 5;
      const severityDiff = orderA - orderB;

      // If same severity, sort by pattern name for consistency
      if (severityDiff === 0) {
        const patternA = a.pattern_matched || '';
        const patternB = b.pattern_matched || '';
        return patternA.localeCompare(patternB);
      }

      return severityDiff;
    });

    console.log('Origami Report: After sorting:');
    console.log('  - Sorted order:', sortedSecrets.map(s => ({
      pattern: s.pattern_matched,
      patterns_matched: s.patterns_matched,
      effective_severity: (s.severityOverride?.overriddenSeverity || s.aiAssessment?.suggestedSeverity || s.risk),
      risk: s.risk,
      key_preview: (s.full_key || s.key).substring(0, 20)
    })));

    sortedSecrets.forEach((secret, index) => {
      // Handle severity with override, AI assessment, and original
      const originalSeverity = secret.risk;
      const aiSeverity = secret.aiAssessment?.suggestedSeverity;
      const overriddenSeverity = secret.severityOverride?.overriddenSeverity;
      const effectiveSeverity = overriddenSeverity || aiSeverity || originalSeverity;
      const isFalsePositive = effectiveSeverity === 'NONE';

      if (isFalsePositive) {
        // Skip false positives in report
        return;
      }

      // Severity display - show original, AI (if exists), and override (if exists)
      let severityBadge = '';
      if (overriddenSeverity) {
        // Show original (strikethrough) → overridden
        severityBadge = `
          <span class="badge ${originalSeverity.toLowerCase()}" style="text-decoration: line-through; opacity: 0.6;" title="Original severity (overridden)">${originalSeverity}</span>
          <span style="margin: 0 4px;">→</span>
          <span class="badge ${overriddenSeverity.toLowerCase()}" title="Manual override on ${secret.severityOverride.timestamp ? new Date(secret.severityOverride.timestamp).toLocaleString() : 'unknown date'}">${overriddenSeverity} ${origamiIcon('wrench')}</span>
        `;
      } else if (aiSeverity && aiSeverity !== originalSeverity) {
        // Show original → AI-assessed
        severityBadge = `
          <span class="badge ${originalSeverity.toLowerCase()}" title="Original severity">${originalSeverity}</span>
          <span style="margin: 0 4px;">→</span>
          <span class="badge ${aiSeverity.toLowerCase()}" title="AI-assessed severity${secret.aiAssessment.severityReasoning ? ': ' + secret.aiAssessment.severityReasoning.substring(0, 100) + '...' : ''}">${aiSeverity} ${origamiIcon('sparkles')}</span>
        `;
      } else {
        // Show only original
        severityBadge = `<span class="badge ${originalSeverity.toLowerCase()}">${originalSeverity}</span>`;
      }
      
      html += `
      <div class="finding ${effectiveSeverity.toLowerCase()}">
        <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 10px;">
          <strong>${secret.patterns_matched && secret.patterns_matched.length > 1 ?
            `Multiple Patterns (${secret.patterns_matched.length})` :
            this.escapeHTML(secret.pattern_matched || 'Secret')
          }</strong>
          ${severityBadge}
        </div>
        ${secret.patterns_matched && secret.patterns_matched.length > 1 ? `
        <p><strong>Matched Patterns:</strong> ${secret.patterns_matched.map(p => this.escapeHTML(p)).join(', ')}</p>
        ` : ''}
        <p><strong>Value:</strong> 
          <button class="toggle-secret-btn" onclick="toggleSecret(event, 'secret-${index}')" style="cursor: pointer; background: #4a5568; color: white; border: none; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-right: 8px;">
            Show Secret
          </button>
          <code id="secret-${index}" class="secret-value" style="display: none;">${this.escapeHTML(secret.full_key || secret.key)}</code>
          <code id="secret-${index}-redacted" class="secret-redacted">********</code>
        </p>
        <p><strong>Location:</strong> ${this.escapeHTML(secret.url)}</p>
        ${secret.lineNumber ? `<p><strong>Line:</strong> ${secret.lineNumber}</p>` : ''}
        ${secret.codeContext ? `
        <details style="margin-top: 10px;">
          <summary style="cursor: pointer; font-weight: 600; color: #9333ea;">${origamiIcon('clipboard')} Code Context</summary>
          <pre style="background: #1a1d23; padding: 12px; border-radius: 4px; overflow-x: auto; margin-top: 8px;"><code>${this.escapeHTML(secret.codeContext)}</code></pre>
        </details>
        ` : ''}
        ${secret.aiAssessment ? `
        <details style="margin-top: 10px;">
          <summary style="cursor: pointer; font-weight: 600; color: #10b981;">${origamiIcon('sparkles')} AI Security Assessment</summary>
          <div style="background: #f0fdf4; border-left: 4px solid #10b981; padding: 12px; margin-top: 8px; border-radius: 4px;">
            ${this.formatHTMLContent(secret.aiAssessment.analysis)}
            ${secret.aiAssessment.suggestedSeverity ? `<p style="margin-top: 8px;"><strong>AI Recommended Severity:</strong> <span class="badge ${secret.aiAssessment.suggestedSeverity.toLowerCase()}">${secret.aiAssessment.suggestedSeverity}</span></p>` : ''}
          </div>
        </details>
        ` : ''}
        ${this.generateAPITestResultsForSecret(secret)}
      </div>
      `;
    });
    
    // Add JavaScript for toggle functionality
    html += `
    <script>
    function toggleSecret(event, id) {
      const secretEl = document.getElementById(id);
      const redactedEl = document.getElementById(id + '-redacted');
      const btn = event.target;
      
      if (secretEl.style.display === 'none') {
        secretEl.style.display = 'inline';
        redactedEl.style.display = 'none';
        btn.textContent = 'Hide Secret';
      } else {
        secretEl.style.display = 'none';
        redactedEl.style.display = 'inline';
        btn.textContent = 'Show Secret';
      }
    }
    </script>
    `;
    
    html += '</div>';
    return html;
  }

  // Generate API test results section
  generateAPITestResultsHTML() {
    if (!this.reportData.apiTestResults || this.reportData.apiTestResults.length === 0) {
      return '';
    }

    let html = '<div class="section"><h2>' + origamiIcon('key') + ' API Key Testing Results</h2>';
    html += '<p style="margin-bottom: 20px;">Testing results for discovered Google API keys:</p>';

    this.reportData.apiTestResults.forEach((testResult, index) => {
      const hasError = !!testResult.error;
      const results = testResult.results || [];

      // Count passed and failed tests based on status
      // Results is an array of { service, status, code, message }
      const passed = Array.isArray(results) ?
        results.filter(r => r.status && (r.status.includes('ENABLED') || r.status.includes('200'))).length : 0;
      const failed = Array.isArray(results) ?
        results.filter(r => r.status && (r.status === 'DISABLED' || r.status === 'ERROR')).length : 0;
      const total = Array.isArray(results) ? results.length : 0;

      html += `
      <div class="finding ${hasError ? 'medium' : (passed > 0 ? 'critical' : 'low')}" style="margin-bottom: 20px;">
        <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 10px;">
          <strong>API Key ${index + 1}</strong>
          ${hasError ?
            '<span class="badge medium">ERROR</span>' :
            passed > 0 ?
              `<span class="badge critical">ACTIVE (${passed}/${total} services)</span>` :
              '<span class="badge low">INACTIVE</span>'
          }
        </div>
        <p><strong>Key:</strong> <code>${this.escapeHTML(testResult.apiKey.substring(0, 20))}...${this.escapeHTML(testResult.apiKey.substring(testResult.apiKey.length - 4))}</code></p>

        ${hasError ?
          `<p style="color: #fd7e14;"><strong>Error:</strong> ${this.escapeHTML(testResult.error)}</p>` :
          `
          <details style="margin-top: 10px;">
            <summary style="cursor: pointer; font-weight: 600; color: #9333ea;">
              ${origamiIcon('chart')} Test Results (${passed} passed, ${failed} failed, ${total} total)
            </summary>
            <div style="margin-top: 12px;">
              <table style="width: 100%; border-collapse: collapse;">
                <thead>
                  <tr>
                    <th style="text-align: left; padding: 8px; background: #f8f9fa; border: 1px solid #ddd;">Service</th>
                    <th style="text-align: left; padding: 8px; background: #f8f9fa; border: 1px solid #ddd;">Status</th>
                    <th style="text-align: left; padding: 8px; background: #f8f9fa; border: 1px solid #ddd;">Details</th>
                  </tr>
                </thead>
                <tbody>
                  ${Array.isArray(results) ? results.map(result => `
                    <tr>
                      <td style="padding: 8px; border: 1px solid #ddd;">${this.escapeHTML(result.service || 'Unknown')}</td>
                      <td style="padding: 8px; border: 1px solid #ddd;">
                        ${result.status && (result.status.includes('ENABLED') || result.status.includes('200')) ?
                            '<span style="color: #28a745; font-weight: bold;">✓ ' + this.escapeHTML(result.status) + '</span>' :
                          result.status === 'DISABLED' ?
                            '<span style="color: #6c757d;">○ ' + this.escapeHTML(result.status) + '</span>' :
                          result.status === 'ERROR' ?
                            '<span style="color: #dc3545;">✕ ERROR</span>' :
                            '<span style="color: #aaa;">- ' + this.escapeHTML(result.status || 'Unknown') + '</span>'
                        }
                      </td>
                      <td style="padding: 8px; border: 1px solid #ddd; font-size: 0.9em;">
                        ${this.escapeHTML(result.message || 'N/A')}
                      </td>
                    </tr>
                  `).join('') : '<tr><td colspan="3">No results</td></tr>'}
                </tbody>
              </table>
            </div>
          </details>
          `
        }
      </div>
      `;
    });

    html += '</div>';
    return html;
  }

  // Generate API test results for a single secret
  generateAPITestResultsForSecret(secret) {
    if (!this.reportData.apiTestResults || this.reportData.apiTestResults.length === 0) {
      return '';
    }

    // Find test results matching this secret's API key
    const secretKey = secret.full_key || secret.key;
    const testResult = this.reportData.apiTestResults.find(tr => tr.apiKey === secretKey);

    if (!testResult) {
      return '';
    }

    const hasError = !!testResult.error;
    const results = testResult.results || [];

    // Count passed and failed tests
    const passed = Array.isArray(results) ?
      results.filter(r => r.status && (r.status.includes('ENABLED') || r.status.includes('200'))).length : 0;
    const failed = Array.isArray(results) ?
      results.filter(r => r.status && (r.status === 'DISABLED' || r.status === 'ERROR')).length : 0;
    const total = Array.isArray(results) ? results.length : 0;

    return `
    <details style="margin-top: 10px;">
      <summary style="cursor: pointer; font-weight: 600; color: #9333ea;">
        ${origamiIcon('key')} API Testing Results ${hasError ? '(Error)' : passed > 0 ? `(${passed}/${total} Active)` : '(Inactive)'}
      </summary>
      <div style="background: ${hasError ? '#fff3cd' : passed > 0 ? '#ffe6e6' : '#f8f9fa'}; border-left: 4px solid ${hasError ? '#ffc107' : passed > 0 ? '#dc3545' : '#6c757d'}; padding: 12px; margin-top: 8px; border-radius: 4px;">
        ${hasError ?
          `<p style="color: #fd7e14;"><strong>Error:</strong> ${this.escapeHTML(testResult.error)}</p>` :
          `
          <table style="width: 100%; border-collapse: collapse; margin-top: 8px;">
            <thead>
              <tr>
                <th style="text-align: left; padding: 8px; background: #f8f9fa; border: 1px solid #ddd; font-size: 0.9em;">Service</th>
                <th style="text-align: left; padding: 8px; background: #f8f9fa; border: 1px solid #ddd; font-size: 0.9em;">Status</th>
                <th style="text-align: left; padding: 8px; background: #f8f9fa; border: 1px solid #ddd; font-size: 0.9em;">Details</th>
              </tr>
            </thead>
            <tbody>
              ${Array.isArray(results) ? results.map(result => `
                <tr>
                  <td style="padding: 6px; border: 1px solid #ddd; font-size: 0.85em;">${this.escapeHTML(result.service || 'Unknown')}</td>
                  <td style="padding: 6px; border: 1px solid #ddd; font-size: 0.85em;">
                    ${result.status && (result.status.includes('ENABLED') || result.status.includes('200')) ?
                        '<span style="color: #28a745; font-weight: bold;">✓ ' + this.escapeHTML(result.status) + '</span>' :
                      result.status === 'DISABLED' ?
                        '<span style="color: #6c757d;">○ ' + this.escapeHTML(result.status) + '</span>' :
                      result.status === 'ERROR' ?
                        '<span style="color: #dc3545;">✕ ERROR</span>' :
                        '<span style="color: #aaa;">- ' + this.escapeHTML(result.status || 'Unknown') + '</span>'
                    }
                  </td>
                  <td style="padding: 6px; border: 1px solid #ddd; font-size: 0.8em;">
                    ${this.escapeHTML(result.message || 'N/A')}
                  </td>
                </tr>
              `).join('') : '<tr><td colspan="3">No results</td></tr>'}
            </tbody>
          </table>
          `
        }
      </div>
    </details>
    `;
  }

  // Generate security analysis section
  generateSecurityHTML() {
    if (!this.reportData.securityAnalysis) {
      return '';
    }

    let html = '<div class="section"><h2>' + origamiIcon('shield') + ' Security Analysis</h2>';

    const sa = this.reportData.securityAnalysis;
    const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };

    // Helper function to get effective severity
    const getEffectiveSeverity = (finding) => {
      return (finding.severityOverride?.overriddenSeverity ||
              finding.aiAssessment?.suggestedSeverity ||
              finding.severity ||
              finding.risk ||
              'INFO').toUpperCase();
    };

    // Headers - sorted by effective severity
    if (sa.headers && sa.headers.length > 0) {
      html += '<h3>Security Headers</h3>';
      const sortedHeaders = [...sa.headers].sort((a, b) => {
        const sevA = getEffectiveSeverity(a);
        const sevB = getEffectiveSeverity(b);
        return (severityOrder[sevA] || 5) - (severityOrder[sevB] || 5);
      });
      sortedHeaders.forEach(h => {
        html += this.generateFindingHTML(h);
      });
    }

    // Cookies - sorted by effective severity
    if (sa.cookies && sa.cookies.length > 0) {
      html += '<h3>Cookie Security</h3>';
      const sortedCookies = [...sa.cookies].sort((a, b) => {
        const sevA = getEffectiveSeverity(a);
        const sevB = getEffectiveSeverity(b);
        return (severityOrder[sevA] || 5) - (severityOrder[sevB] || 5);
      });
      sortedCookies.forEach(c => {
        html += this.generateFindingHTML(c);
      });
    }

    // Vulnerabilities - sorted by effective severity
    if (sa.vulnerabilities && sa.vulnerabilities.length > 0) {
      html += '<h3>Vulnerabilities</h3>';
      const sortedVulns = [...sa.vulnerabilities].sort((a, b) => {
        const sevA = getEffectiveSeverity(a);
        const sevB = getEffectiveSeverity(b);
        return (severityOrder[sevA] || 5) - (severityOrder[sevB] || 5);
      });
      sortedVulns.forEach(v => {
        html += this.generateFindingHTML(v);
      });
    }

    // Sensitive/Exposed Files
    if (this.reportData.sensitiveFiles && this.reportData.sensitiveFiles.length > 0) {
      html += '<h3>Exposed Files</h3>';
      const sortedFiles = [...this.reportData.sensitiveFiles].sort((a, b) => {
        const sevA = getEffectiveSeverity(a);
        const sevB = getEffectiveSeverity(b);
        return (severityOrder[sevA] || 5) - (severityOrder[sevB] || 5);
      });
      sortedFiles.forEach(f => {
        html += this.generateFindingHTML({
          check: f.check || f.path || 'Sensitive File',
          severity: f.severity || f.risk || 'MEDIUM',
          status: f.status || 'Found',
          message: f.message || f.details || `Exposed file found: ${f.path || f.url || ''}`,
          recommendation: f.recommendation,
          details: f.details,
          aiAssessment: f.aiAssessment,
          severityOverride: f.severityOverride
        });
      });
    }

    html += '</div>';

    // Advanced security analysis categories
    html += this.generateAdvancedSecurityHTML();

    return html;
  }

  // Generate HTML for advanced security analysis categories
  generateAdvancedSecurityHTML() {
    let html = '';
    const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };
    const getEffectiveSeverity = (finding) => {
      return (finding.severityOverride?.overriddenSeverity ||
              finding.aiAssessment?.suggestedSeverity ||
              finding.severity ||
              'INFO').toUpperCase();
    };

    const categories = [
      { key: 'sessionAnalysis', title: 'Session Analysis', icon: 'shield', issuesKey: ['issues', 'allIssues'] },
      { key: 'oauthAnalysis', title: 'OAuth/SAML Analysis', icon: 'key', issuesKey: ['issues'] },
      { key: 'graphqlAnalysis', title: 'GraphQL Analysis', icon: 'search', issuesKey: ['issues'] },
      { key: 'cryptoAnalysis', title: 'Crypto Audit', icon: 'shield', issuesKey: ['issues'] },
      { key: 'cloudStorageAnalysis', title: 'Cloud Storage Mapping', icon: 'folder', issuesKey: ['issues'] },
      { key: 'exfiltrationAnalysis', title: 'Exfiltration Detection', icon: 'warning', issuesKey: ['issues'] },
      { key: 'websocketAnalysis', title: 'WebSocket Audit', icon: 'search', issuesKey: ['issues'] }
    ];

    for (const cat of categories) {
      const data = this.reportData[cat.key];
      if (!data) continue;

      let issues = [];
      for (const k of cat.issuesKey) {
        if (data[k] && Array.isArray(data[k]) && data[k].length > 0) {
          issues = data[k];
          break;
        }
      }
      if (issues.length === 0) continue;

      const sortedIssues = [...issues].sort((a, b) => {
        const sevA = getEffectiveSeverity(a);
        const sevB = getEffectiveSeverity(b);
        return (severityOrder[sevA] || 5) - (severityOrder[sevB] || 5);
      });

      html += `<div class="section"><h2>${origamiIcon(cat.icon)} ${cat.title}</h2>`;
      sortedIssues.forEach(f => {
        html += this.generateFindingHTML({
          check: f.check || f.type || cat.title + ' Issue',
          severity: f.severity || 'MEDIUM',
          status: f.status || 'Found',
          message: f.message || f.details || '',
          recommendation: f.recommendation,
          details: f.details,
          evidence: f.evidence,
          codeContext: f.codeContext,
          aiAssessment: f.aiAssessment,
          severityOverride: f.severityOverride
        });
      });
      html += '</div>';
    }

    // Correlation chains
    if (this.reportData.correlationChains && Array.isArray(this.reportData.correlationChains) && this.reportData.correlationChains.length > 0) {
      html += `<div class="section"><h2>${origamiIcon('chart')} Attack Chain Correlations</h2>`;
      this.reportData.correlationChains.forEach(chain => {
        html += this.generateFindingHTML({
          check: chain.name || 'Attack Chain',
          severity: chain.severity || 'HIGH',
          status: 'Correlated',
          message: chain.attackFlow || chain.description || '',
          details: chain.remediation ? { remediation: chain.remediation } : null
        });
      });
      html += '</div>';
    }

    return html;
  }

  // Generate finding HTML
  generateFindingHTML(finding) {
    // Handle severity with override, AI assessment, and original
    const originalSeverity = (finding.severity || 'info').toLowerCase();
    const aiSeverity = finding.aiAssessment?.suggestedSeverity?.toLowerCase();
    const overriddenSeverity = finding.severityOverride?.overriddenSeverity?.toLowerCase();
    const effectiveSeverity = overriddenSeverity || aiSeverity || originalSeverity;
    const isFalsePositive = effectiveSeverity === 'none';

    if (isFalsePositive) {
      // Skip false positives
      return '';
    }

    // Severity display - show original, AI (if exists), and override (if exists)
    let severityBadge = '';
    if (overriddenSeverity) {
      // Show original (strikethrough) → overridden
      severityBadge = `
        <span class="badge ${originalSeverity}" style="text-decoration: line-through; opacity: 0.6;" title="Original severity (overridden)">${originalSeverity.toUpperCase()}</span>
        <span style="margin: 0 4px;">→</span>
        <span class="badge ${overriddenSeverity}" title="Manual override on ${finding.severityOverride.timestamp ? new Date(finding.severityOverride.timestamp).toLocaleString() : 'unknown date'}">${overriddenSeverity.toUpperCase()} ${origamiIcon('wrench')}</span>
      `;
    } else if (aiSeverity && aiSeverity !== originalSeverity) {
      // Show original → AI-assessed
      severityBadge = `
        <span class="badge ${originalSeverity}" title="Original severity">${originalSeverity.toUpperCase()}</span>
        <span style="margin: 0 4px;">→</span>
        <span class="badge ${aiSeverity}" title="AI-assessed severity${finding.aiAssessment.severityReasoning ? ': ' + finding.aiAssessment.severityReasoning.substring(0, 100) + '...' : ''}">${aiSeverity.toUpperCase()} ${origamiIcon('sparkles')}</span>
      `;
    } else {
      // Show only original
      severityBadge = `<span class="badge ${originalSeverity}">${originalSeverity.toUpperCase()}</span>`;
    }
    
    return `
    <div class="finding ${effectiveSeverity}">
      <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 10px;">
        <strong>${this.escapeHTML(finding.check)}</strong>
        ${severityBadge}
      </div>
      <p>${this.escapeHTML(finding.message)}</p>
      ${finding.recommendation ? `<p><strong>${origamiIcon('lightbulb')} Recommendation:</strong> ${this.escapeHTML(finding.recommendation)}</p>` : ''}
      ${finding.details ? this.renderDetailsSection(finding.details) : ''}
      ${finding.evidence ? `
      <details style="margin-top: 10px;">
        <summary style="cursor: pointer; font-weight: 600; color: #9333ea;">${origamiIcon('search')} Evidence</summary>
        <pre style="background: #1a1d23; padding: 12px; border-radius: 4px; overflow-x: auto; margin-top: 8px;"><code>${this.escapeHTML(JSON.stringify(finding.evidence, null, 2))}</code></pre>
      </details>
      ` : ''}
      ${finding.codeContext ? `
      <details style="margin-top: 10px;">
        <summary style="cursor: pointer; font-weight: 600; color: #9333ea;">${origamiIcon('clipboard')} Code Context</summary>
        <pre style="background: #1a1d23; padding: 12px; border-radius: 4px; overflow-x: auto; margin-top: 8px;"><code>${this.escapeHTML(finding.codeContext)}</code></pre>
      </details>
      ` : ''}
      ${finding.aiAssessment ? `
      <details style="margin-top: 10px;">
        <summary style="cursor: pointer; font-weight: 600; color: #10b981;">${origamiIcon('sparkles')} AI Security Assessment</summary>
        <div style="background: #f0fdf4; border-left: 4px solid #10b981; padding: 12px; margin-top: 8px; border-radius: 4px;">
          ${this.formatHTMLContent(finding.aiAssessment.analysis)}
          ${finding.aiAssessment.suggestedSeverity ? `<p style="margin-top: 8px;"><strong>AI Recommended Severity:</strong> <span class="badge ${finding.aiAssessment.suggestedSeverity.toLowerCase()}">${finding.aiAssessment.suggestedSeverity}</span></p>` : ''}
        </div>
      </details>
      ` : ''}
    </div>
    `;
  }

  // Generate tech stack section
  generateTechStackHTML() {
    if (!this.reportData.technologies) {
      return '';
    }

    const tech = this.reportData.technologies;
    const vulnerabilities = this.reportData.vulnerabilities || {};

    // Check if there's any technology data
    const hasFrameworks = tech.frameworks && tech.frameworks.length > 0;
    const hasLibraries = tech.libraries && tech.libraries.length > 0;
    const hasBackend = tech.backend && tech.backend.length > 0;
    const hasOther = tech.other && tech.other.length > 0;

    if (!hasFrameworks && !hasLibraries && !hasBackend && !hasOther) {
      return ''; // No technology data to display
    }

    let html = '<div class="section"><h2>' + origamiIcon('folder') + ' Software Composition Analysis (SCA)</h2>';

    // Helper function to find CVE/EOL data for a technology
    const findVulnData = (techName, techVersion) => {
      // Search through all vulnerability categories
      for (const category in vulnerabilities) {
        const techsInCategory = vulnerabilities[category];
        const match = techsInCategory.find(t =>
          t.name === techName && (!techVersion || t.version === techVersion)
        );
        if (match) return match;
      }
      return null;
    };

    // Helper function to render technology with CVE/EOL details
    const renderTech = (t, category) => {
      const vulnData = findVulnData(t.name, t.version);
      let html = `<tr><td>${this.escapeHTML(t.name)}</td><td>${this.escapeHTML(t.version || 'Unknown')}</td><td>`;

      if (vulnData) {
        // Count vulnerabilities by severity
        let critical = 0, high = 0, medium = 0, low = 0;
        if (vulnData.vulnerabilities) {
          vulnData.vulnerabilities.forEach(v => {
            if (v.severity === 'CRITICAL') critical++;
            else if (v.severity === 'HIGH') high++;
            else if (v.severity === 'MEDIUM') medium++;
            else if (v.severity === 'LOW') low++;
          });
        }

        // Show vulnerability counts
        if (critical > 0) html += `<span class="badge critical">${critical} Critical</span> `;
        if (high > 0) html += `<span class="badge high">${high} High</span> `;
        if (medium > 0) html += `<span class="badge medium">${medium} Medium</span> `;
        if (low > 0) html += `<span class="badge low">${low} Low</span> `;

        // Show EOL status
        if (vulnData.eolStatus && vulnData.eolStatus.status === 'EOL') {
          html += `<span class="badge" style="background: #dc3545;">${origamiIcon('warning')} EOL</span>`;
        } else if (vulnData.eolStatus && vulnData.eolStatus.status === 'ENDING_SOON') {
          html += `<span class="badge" style="background: #ffc107;">${origamiIcon('hourglass')} Support Ending</span>`;
        }

        html += '</td></tr>';

        // Add detailed vulnerability information below
        if (vulnData.vulnerabilities && vulnData.vulnerabilities.length > 0) {
          html += `<tr><td colspan="3" class="vulnerability-details" style="background: #f8f9fa; padding: 12px; border-left: 3px solid #dc3545;">`;
          html += `<strong>Vulnerabilities:</strong><ul style="margin: 8px 0;">`;

          vulnData.vulnerabilities.forEach(v => {
            html += `<li><strong>${this.escapeHTML(v.id)}</strong> - ${this.escapeHTML(v.severity)}`;
            if (v.score) html += ` (CVSS: ${v.score})`;
            html += `<br>${this.escapeHTML(v.summary)}`;
            if (v.fixedVersion) {
              html += `<br><em>Fix: Upgrade to ${this.escapeHTML(v.fixedVersion)}+</em>`;
            }
            html += `</li>`;
          });

          html += `</ul>`;

          // Add EOL details if present
          if (vulnData.eolStatus) {
            html += `<strong>End-of-Life Information:</strong><ul style="margin: 8px 0;">`;
            if (vulnData.eolStatus.eolDate) {
              html += `<li>EOL Date: ${this.escapeHTML(vulnData.eolStatus.eolDate)}</li>`;
            }
            if (vulnData.eolStatus.latestVersion) {
              html += `<li>Recommended: Upgrade to ${this.escapeHTML(vulnData.eolStatus.latestVersion)}</li>`;
            }
            html += `</ul>`;
          }

          // Add AI assessment if present
          if (vulnData.aiAssessment && vulnData.aiAssessment.analysis) {
            html += `<div class="ai-assessment" style="margin-top: 12px; padding: 12px; background: #e3f2fd; border-left: 3px solid #2196f3; border-radius: 4px;">`;
            html += `<strong>${origamiIcon('sparkles')} AI Security Assessment</strong>`;
            html += `<div style="margin-top: 8px; font-size: 13px; line-height: 1.6;">`;
            html += this.formatAIAssessmentHTML(vulnData.aiAssessment.analysis);
            html += `</div>`;
            html += `<div style="margin-top: 8px; font-size: 11px; color: #666;">`;
            html += `<em>Generated: ${new Date(vulnData.aiAssessment.timestamp).toLocaleString()}</em>`;
            html += `</div></div>`;
          }

          html += `</td></tr>`;
        }
      } else {
        html += 'No known vulnerabilities</td></tr>';
      }

      return html;
    };

    // Frameworks
    if (hasFrameworks) {
      html += '<h3>Frontend Frameworks</h3><table><tr><th>Name</th><th>Version</th><th>Security Status</th></tr>';
      tech.frameworks.forEach(t => {
        html += renderTech(t, 'frameworks');
      });
      html += '</table>';
    }

    // Libraries
    if (hasLibraries) {
      html += '<h3>Libraries</h3><table><tr><th>Name</th><th>Version</th><th>Security Status</th></tr>';
      tech.libraries.forEach(t => {
        html += renderTech(t, 'libraries');
      });
      html += '</table>';
    }

    // Backend
    if (hasBackend) {
      html += '<h3>Backend Technologies</h3><table><tr><th>Name</th><th>Version</th><th>Security Status</th></tr>';
      tech.backend.forEach(t => {
        html += renderTech(t, 'backend');
      });
      html += '</table>';
    }

    // Other
    if (hasOther) {
      html += '<h3>Other Technologies</h3><table><tr><th>Name</th><th>Version</th><th>Security Status</th></tr>';
      tech.other.forEach(t => {
        html += renderTech(t, 'other');
      });
      html += '</table>';
    }

    html += '</div>';
    return html;
  }

  // Format AI assessment for HTML display
  formatAIAssessmentHTML(text) {
    if (!text) return '';

    let formatted = this.escapeHTML(text);

    // Convert markdown-style formatting
    formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    formatted = formatted.replace(/\*(.*?)\*/g, '<em>$1</em>');
    formatted = formatted.replace(/`([^`]+)`/g, '<code>$1</code>');

    // Convert newlines
    formatted = formatted.replace(/\n\n/g, '<br><br>');
    formatted = formatted.replace(/\n/g, '<br>');

    return formatted;
  }

  // Calculate summary statistics
  calculateSummary() {
    const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };

    // Count secrets - use effective severity (override > AI > original)
    if (this.reportData.secrets) {
      this.reportData.secrets.forEach(s => {
        // Skip false positives (NONE severity)
        const effectiveSeverity = s.severityOverride?.overriddenSeverity ||
                                  s.aiAssessment?.suggestedSeverity ||
                                  s.risk;
        if (effectiveSeverity && effectiveSeverity.toUpperCase() !== 'NONE') {
          const risk = effectiveSeverity.toLowerCase();
          if (summary.hasOwnProperty(risk)) summary[risk]++;
          summary.total++;
        }
      });
    }

    // Count security findings - use effective severity (override > AI > original)
    if (this.reportData.securityAnalysis) {
      const findings = [
        ...(this.reportData.securityAnalysis.headers || []),
        ...(this.reportData.securityAnalysis.cookies || []),
        ...(this.reportData.securityAnalysis.vulnerabilities || [])
      ];

      findings.forEach(f => {
        // Skip false positives (NONE severity)
        const effectiveSeverity = f.severityOverride?.overriddenSeverity ||
                                  f.aiAssessment?.suggestedSeverity ||
                                  f.severity;
        if (effectiveSeverity && effectiveSeverity.toUpperCase() !== 'NONE') {
          const sev = effectiveSeverity.toLowerCase();
          if (summary.hasOwnProperty(sev)) summary[sev]++;
          summary.total++;
        }
      });
    }

    // Count new analyzer category findings
    const newCategories = [
      'sessionAnalysis', 'oauthAnalysis', 'graphqlAnalysis',
      'cryptoAnalysis', 'cloudStorageAnalysis', 'exfiltrationAnalysis',
      'websocketAnalysis'
    ];
    for (const cat of newCategories) {
      if (this.reportData[cat]) {
        const issues = this.reportData[cat].issues || this.reportData[cat].allIssues || [];
        issues.forEach(f => {
          const effectiveSeverity = f.severityOverride?.overriddenSeverity ||
                                    f.aiAssessment?.suggestedSeverity ||
                                    f.severity || 'MEDIUM';
          if (effectiveSeverity.toUpperCase() !== 'NONE') {
            const sev = effectiveSeverity.toLowerCase();
            if (summary.hasOwnProperty(sev)) summary[sev]++;
            summary.total++;
          }
        });
      }
    }

    // Count sensitive file findings
    if (this.reportData.sensitiveFiles && Array.isArray(this.reportData.sensitiveFiles)) {
      this.reportData.sensitiveFiles.forEach(f => {
        const effectiveSeverity = f.severityOverride?.overriddenSeverity ||
                                  f.aiAssessment?.suggestedSeverity ||
                                  f.severity || f.risk || 'MEDIUM';
        if (effectiveSeverity.toUpperCase() !== 'NONE') {
          const sev = effectiveSeverity.toLowerCase();
          if (summary.hasOwnProperty(sev)) summary[sev]++;
          summary.total++;
        }
      });
    }

    // Count CVE/SCA findings from vulnerabilities
    if (this.reportData.vulnerabilities) {
      for (const category in this.reportData.vulnerabilities) {
        const techArray = this.reportData.vulnerabilities[category];
        if (Array.isArray(techArray)) {
          techArray.forEach(tech => {
            if (tech.vulnerabilities && tech.vulnerabilities.length > 0) {
              tech.vulnerabilities.forEach(v => {
                const sev = (v.severity || 'MEDIUM').toLowerCase();
                if (summary.hasOwnProperty(sev)) summary[sev]++;
                summary.total++;
              });
            }
          });
        }
      }
    }

    // Count correlation chain findings
    if (this.reportData.correlationChains && Array.isArray(this.reportData.correlationChains)) {
      this.reportData.correlationChains.forEach(chain => {
        const sev = (chain.severity || 'HIGH').toLowerCase();
        if (summary.hasOwnProperty(sev)) summary[sev]++;
        summary.total++;
      });
    }

    return summary;
  }

  // Generate report ID
  generateReportId() {
    return 'ORIG-' + Date.now().toString(36) + '-' + Math.random().toString(36).substr(2, 9);
  }

  // Render details section with collapse/expand for long content
  renderDetailsSection(details) {
    const detailsStr = typeof details === 'string' ? details : JSON.stringify(details);
    const maxLength = 500; // Show first 500 chars inline, rest in collapsible

    if (detailsStr.length <= maxLength) {
      // Short details - show inline
      return `<p><strong>Details:</strong> ${this.escapeHTML(detailsStr)}</p>`;
    } else {
      // Long details - use collapsible
      return `
      <details style="margin-top: 10px;">
        <summary style="cursor: pointer; font-weight: 600; color: #9333ea;">${origamiIcon('document')} Details (${detailsStr.length} characters)</summary>
        <pre style="background: #1a1d23; color: #e0e0e0; padding: 12px; border-radius: 4px; overflow-x: auto; margin-top: 8px; max-height: 400px; overflow-y: auto;"><code>${this.escapeHTML(detailsStr)}</code></pre>
      </details>
      `;
    }
  }

  // Escape HTML
  escapeHTML(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
  }

  // Generate Markdown report
  toMarkdown() {
    if (!this.reportData) {
      throw new Error('No report data available');
    }
    
    let md = `# Origami Security Report\n\n`;
    md += `**Target:** ${this.reportData.url}\n`;
    md += `**Report ID:** ${this.reportData.reportId}\n`;
    md += `**Generated:** ${new Date(this.reportData.generatedAt).toLocaleString()}\n\n`;
    md += `---\n\n`;
    
    // LLM Executive Summary
    if (this.llmSummary) {
      md += `## [AI] AI-Powered Executive Summary\n\n`;
      md += `${this.llmSummary}\n\n`;
      md += `---\n\n`;
    }
    
    // Summary Stats
    md += this.summaryToMarkdown();
    
    // Secrets
    md += this.secretsToMarkdown();
    
    // Security Analysis
    md += this.securityToMarkdown();
    
    // LLM Risk Analysis
    if (this.llmRiskAnalysis) {
      md += `## [STATS] Risk Prioritization\n\n`;
      md += `${this.llmRiskAnalysis}\n\n`;
      md += `---\n\n`;
    }
    
    // Tech Stack
    md += this.techStackToMarkdown();
    
    // LLM Remediation Roadmap
    if (this.llmRemediation) {
      md += `## [OVERRIDE] Remediation Roadmap\n\n`;
      
      if (Array.isArray(this.llmRemediation)) {
        this.llmRemediation.forEach((item, index) => {
          md += `### Phase ${index + 1}: ${item.finding}\n\n`;
          md += `${item.remediation}\n\n`;
        });
      } else {
        md += `${this.llmRemediation}\n\n`;
      }
      
      md += `---\n\n`;
    }
    
    // LLM Compliance
    if (this.llmCompliance) {
      md += `## [PASS] Compliance Assessment\n\n`;
      md += `${this.llmCompliance}\n\n`;
      md += `---\n\n`;
    }
    
    md += `\n---\n\n`;
    md += `*Generated by Origami - Complete Cyber Security Toolkit*\n`;
    md += `*This report contains sensitive security information. Handle with care.*\n`;
    
    return md;
  }
  
  // Summary to Markdown
  summaryToMarkdown() {
    const summary = this.calculateSummary();
    
    let md = `## [STATS] Summary Statistics\n\n`;
    md += `| Severity | Count |\n`;
    md += `|----------|-------|\n`;
    md += `| [!!] Critical | ${summary.critical} |\n`;
    md += `| [!] High | ${summary.high} |\n`;
    md += `| [~] Medium | ${summary.medium} |\n`;
    md += `| [-] Low | ${summary.low} |\n`;
    md += `| **Total** | **${summary.total}** |\n\n`;
    
    return md;
  }
  
  // Secrets to Markdown
  secretsToMarkdown() {
    if (!this.reportData.secrets || this.reportData.secrets.length === 0) {
      return '';
    }

    let md = `## [KEY] Exposed Secrets\n\n`;

    // Deduplicate secrets (same as HTML version)
    const secretMap = new Map();
    this.reportData.secrets.forEach(secret => {
      const secretKey = this.normalizeSecretKey(secret.full_key || secret.key);

      if (secretMap.has(secretKey)) {
        const existing = secretMap.get(secretKey);
        const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };

        if (!existing.patterns_matched) {
          existing.patterns_matched = [existing.pattern_matched];
        }
        if (secret.pattern_matched && !existing.patterns_matched.includes(secret.pattern_matched)) {
          existing.patterns_matched.push(secret.pattern_matched);
        }

        const currentSeverity = severityOrder[secret.risk] || 5;
        const existingSeverity = severityOrder[existing.risk] || 5;

        if (currentSeverity < existingSeverity) {
          secret.patterns_matched = existing.patterns_matched;
          if (!secret.aiAssessment && existing.aiAssessment) {
            secret.aiAssessment = existing.aiAssessment;
          }
          if (!secret.severityOverride && existing.severityOverride) {
            secret.severityOverride = existing.severityOverride;
          }
          secretMap.set(secretKey, secret);
        } else {
          if (!existing.aiAssessment && secret.aiAssessment) {
            existing.aiAssessment = secret.aiAssessment;
          }
          if (!existing.severityOverride && secret.severityOverride) {
            existing.severityOverride = secret.severityOverride;
          }
          secretMap.set(secretKey, existing);
        }
      } else {
        secretMap.set(secretKey, secret);
      }
    });

    const uniqueSecrets = Array.from(secretMap.values());

    // Sort by effective severity
    const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };
    const getEffectiveSeverity = (finding) => {
      return (finding.severityOverride?.overriddenSeverity ||
              finding.aiAssessment?.suggestedSeverity ||
              finding.risk ||
              'LOW').toUpperCase();
    };

    const sortedSecrets = [...uniqueSecrets].sort((a, b) => {
      const severityA = getEffectiveSeverity(a);
      const severityB = getEffectiveSeverity(b);
      const orderA = severityOrder[severityA] || 5;
      const orderB = severityOrder[severityB] || 5;
      const severityDiff = orderA - orderB;

      if (severityDiff === 0) {
        const patternA = a.pattern_matched || '';
        const patternB = b.pattern_matched || '';
        return patternA.localeCompare(patternB);
      }

      return severityDiff;
    });

    sortedSecrets.forEach((secret, index) => {
      // Handle severity with override, AI assessment, and original
      const originalSeverity = secret.risk;
      const aiSeverity = secret.aiAssessment?.suggestedSeverity;
      const overriddenSeverity = secret.severityOverride?.overriddenSeverity;
      const effectiveSeverity = overriddenSeverity || aiSeverity || originalSeverity;
      const isFalsePositive = effectiveSeverity === 'NONE';

      if (isFalsePositive) {
        // Skip false positives in report
        return;
      }

      // Build severity display
      let severityDisplay = '';
      if (overriddenSeverity) {
        // Show original → overridden
        severityDisplay = `[~~${originalSeverity}~~ -> **${overriddenSeverity}** [OVERRIDE]]`;
        if (secret.severityOverride.timestamp) {
          severityDisplay += ` *(Manually overridden on ${new Date(secret.severityOverride.timestamp).toLocaleString()})*`;
        }
      } else if (aiSeverity && aiSeverity !== originalSeverity) {
        // Show original → AI-assessed
        severityDisplay = `[${originalSeverity} -> **${aiSeverity}** [AI]]`;
      } else {
        // Show only original
        severityDisplay = `[${originalSeverity}]`;
      }

      const patternName = secret.patterns_matched && secret.patterns_matched.length > 1 ?
        `Multiple Patterns (${secret.patterns_matched.length})` :
        (secret.pattern_matched || 'Secret');

      md += `### ${index + 1}. ${patternName} ${severityDisplay}\n\n`;

      if (secret.patterns_matched && secret.patterns_matched.length > 1) {
        md += `**Matched Patterns:** ${secret.patterns_matched.join(', ')}\n\n`;
      }

      md += `- **Value:** \`${secret.full_key || secret.key}\`\n`;
      md += `- **Location:** ${secret.url}\n`;
      if (secret.lineNumber) {
        md += `- **Line:** ${secret.lineNumber}\n`;
      }

      // Add code context if available
      if (secret.codeContext) {
        md += `\n**Code Context:**\n\`\`\`\n${secret.codeContext}\n\`\`\`\n`;
      }

      // Add AI assessment if available
      if (secret.aiAssessment) {
        md += `\n**AI Security Assessment:**\n${secret.aiAssessment.analysis}\n`;
        if (secret.aiAssessment.suggestedSeverity) {
          md += `\n*AI Recommended Severity: ${secret.aiAssessment.suggestedSeverity}*\n`;
        }
      }

      md += `\n`;
    });

    md += `---\n\n`;
    return md;
  }
  
  // Security analysis to Markdown
  securityToMarkdown() {
    if (!this.reportData.securityAnalysis) {
      return '';
    }

    const sa = this.reportData.securityAnalysis;
    let md = `## [SEC] Security Analysis\n\n`;

    const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };

    // Helper function to get effective severity
    const getEffectiveSeverity = (finding) => {
      return (finding.severityOverride?.overriddenSeverity ||
              finding.aiAssessment?.suggestedSeverity ||
              finding.severity ||
              finding.risk ||
              'INFO').toUpperCase();
    };

    // Helper function to format finding with override information
    const formatFinding = (finding) => {
      // Handle severity with override, AI assessment, and original
      const originalSeverity = (finding.severity || 'INFO').toUpperCase();
      const aiSeverity = finding.aiAssessment?.suggestedSeverity?.toUpperCase();
      const overriddenSeverity = finding.severityOverride?.overriddenSeverity?.toUpperCase();
      const effectiveSeverity = overriddenSeverity || aiSeverity || originalSeverity;
      const isFalsePositive = effectiveSeverity === 'NONE';

      if (isFalsePositive) {
        // Skip false positives
        return null;
      }

      // Build severity display
      let severityDisplay = '';
      if (overriddenSeverity) {
        // Show original → overridden
        severityDisplay = `[~~${originalSeverity}~~ -> **${overriddenSeverity}** [OVERRIDE]]`;
        if (finding.severityOverride.timestamp) {
          severityDisplay += ` *(Manually overridden on ${new Date(finding.severityOverride.timestamp).toLocaleString()})*`;
        }
      } else if (aiSeverity && aiSeverity !== originalSeverity) {
        // Show original → AI-assessed
        severityDisplay = `[${originalSeverity} -> **${aiSeverity}** [AI]]`;
      } else {
        // Show only original
        severityDisplay = `[${originalSeverity}]`;
      }

      let output = `#### ${finding.check} ${severityDisplay}\n\n`;
      output += `- **Status:** ${finding.status}\n`;
      output += `- **Message:** ${finding.message}\n`;

      if (finding.recommendation) {
        output += `- **Tip: Recommendation:** ${finding.recommendation}\n`;
      }

      if (finding.details) {
        const detailsStr = typeof finding.details === 'string' ? finding.details : JSON.stringify(finding.details);
        output += `- **Details:** ${detailsStr}\n`;
      }

      if (finding.codeContext) {
        output += `\n**Code Context:**\n\`\`\`\n${finding.codeContext}\n\`\`\`\n`;
      }

      if (finding.evidence) {
        output += `\n**Evidence:**\n\`\`\`json\n${JSON.stringify(finding.evidence, null, 2)}\n\`\`\`\n`;
      }

      // Add AI assessment if available
      if (finding.aiAssessment) {
        output += `\n**AI Security Assessment:**\n${finding.aiAssessment.analysis}\n`;
        if (finding.aiAssessment.suggestedSeverity) {
          output += `\n*AI Recommended Severity: ${finding.aiAssessment.suggestedSeverity}*\n`;
        }
      }

      output += `\n`;
      return output;
    };

    // Headers - sorted by effective severity
    if (sa.headers && sa.headers.length > 0) {
      md += `### Security Headers\n\n`;
      const sortedHeaders = [...sa.headers].sort((a, b) => {
        const sevA = getEffectiveSeverity(a);
        const sevB = getEffectiveSeverity(b);
        return (severityOrder[sevA] || 5) - (severityOrder[sevB] || 5);
      });

      sortedHeaders.forEach(h => {
        const formatted = formatFinding(h);
        if (formatted) md += formatted;
      });
    }

    // Cookies - sorted by effective severity
    if (sa.cookies && sa.cookies.length > 0) {
      md += `### Cookie Security\n\n`;
      const sortedCookies = [...sa.cookies].sort((a, b) => {
        const sevA = getEffectiveSeverity(a);
        const sevB = getEffectiveSeverity(b);
        return (severityOrder[sevA] || 5) - (severityOrder[sevB] || 5);
      });

      sortedCookies.forEach(c => {
        const formatted = formatFinding(c);
        if (formatted) md += formatted;
      });
    }

    // Vulnerabilities - sorted by effective severity
    if (sa.vulnerabilities && sa.vulnerabilities.length > 0) {
      md += `### Vulnerabilities\n\n`;
      const sortedVulns = [...sa.vulnerabilities].sort((a, b) => {
        const sevA = getEffectiveSeverity(a);
        const sevB = getEffectiveSeverity(b);
        return (severityOrder[sevA] || 5) - (severityOrder[sevB] || 5);
      });

      sortedVulns.forEach(v => {
        const formatted = formatFinding(v);
        if (formatted) md += formatted;
      });
    }

    // Sensitive/Exposed Files
    if (this.reportData.sensitiveFiles && this.reportData.sensitiveFiles.length > 0) {
      md += `### Exposed Files\n\n`;
      const sortedFiles = [...this.reportData.sensitiveFiles].sort((a, b) => {
        const sevA = getEffectiveSeverity(a);
        const sevB = getEffectiveSeverity(b);
        return (severityOrder[sevA] || 5) - (severityOrder[sevB] || 5);
      });
      sortedFiles.forEach(f => {
        const finding = {
          check: f.check || f.path || 'Sensitive File',
          severity: f.severity || f.risk || 'MEDIUM',
          status: f.status || 'Found',
          message: f.message || f.details || `Exposed file found: ${f.path || f.url || ''}`,
          recommendation: f.recommendation,
          details: f.details,
          aiAssessment: f.aiAssessment,
          severityOverride: f.severityOverride
        };
        const formatted = formatFinding(finding);
        if (formatted) md += formatted;
      });
    }

    // Advanced security categories
    md += this.advancedSecurityToMarkdown(getEffectiveSeverity, severityOrder, formatFinding);

    md += `---\n\n`;
    return md;
  }

  // Advanced security categories to Markdown
  advancedSecurityToMarkdown(getEffectiveSeverity, severityOrder, formatFinding) {
    let md = '';

    const categories = [
      { key: 'sessionAnalysis', title: 'Session Analysis', issuesKey: ['issues', 'allIssues'] },
      { key: 'oauthAnalysis', title: 'OAuth/SAML Analysis', issuesKey: ['issues'] },
      { key: 'graphqlAnalysis', title: 'GraphQL Analysis', issuesKey: ['issues'] },
      { key: 'cryptoAnalysis', title: 'Crypto Audit', issuesKey: ['issues'] },
      { key: 'cloudStorageAnalysis', title: 'Cloud Storage Mapping', issuesKey: ['issues'] },
      { key: 'exfiltrationAnalysis', title: 'Exfiltration Detection', issuesKey: ['issues'] },
      { key: 'websocketAnalysis', title: 'WebSocket Audit', issuesKey: ['issues'] }
    ];

    for (const cat of categories) {
      const data = this.reportData[cat.key];
      if (!data) continue;

      let issues = [];
      for (const k of cat.issuesKey) {
        if (data[k] && Array.isArray(data[k]) && data[k].length > 0) {
          issues = data[k];
          break;
        }
      }
      if (issues.length === 0) continue;

      md += `### ${cat.title}\n\n`;
      const sortedIssues = [...issues].sort((a, b) => {
        const sevA = getEffectiveSeverity(a);
        const sevB = getEffectiveSeverity(b);
        return (severityOrder[sevA] || 5) - (severityOrder[sevB] || 5);
      });

      sortedIssues.forEach(f => {
        const finding = {
          check: f.check || f.type || cat.title + ' Issue',
          severity: f.severity || 'MEDIUM',
          status: f.status || 'Found',
          message: f.message || f.details || '',
          recommendation: f.recommendation,
          details: f.details,
          evidence: f.evidence,
          codeContext: f.codeContext,
          aiAssessment: f.aiAssessment,
          severityOverride: f.severityOverride
        };
        const formatted = formatFinding(finding);
        if (formatted) md += formatted;
      });
    }

    // Correlation chains
    if (this.reportData.correlationChains && Array.isArray(this.reportData.correlationChains) && this.reportData.correlationChains.length > 0) {
      md += `### Attack Chain Correlations\n\n`;
      this.reportData.correlationChains.forEach(chain => {
        const finding = {
          check: chain.name || 'Attack Chain',
          severity: chain.severity || 'HIGH',
          status: 'Correlated',
          message: chain.attackFlow || chain.description || '',
          details: chain.remediation ? { remediation: chain.remediation } : null
        };
        const formatted = formatFinding(finding);
        if (formatted) md += formatted;
      });
    }

    return md;
  }
  
  // Tech stack to Markdown
  techStackToMarkdown() {
    if (!this.reportData.technologies) {
      return '';
    }
    
    const tech = this.reportData.technologies;
    let md = `## [OVERRIDE] Technology Stack\n\n`;
    
    if (tech.frameworks && tech.frameworks.length > 0) {
      md += `### Frameworks\n\n`;
      tech.frameworks.forEach(t => {
        md += `- ${t.name}${t.version ? ` (v${t.version})` : ''}\n`;
      });
      md += `\n`;
    }
    
    if (tech.libraries && tech.libraries.length > 0) {
      md += `### Libraries\n\n`;
      tech.libraries.forEach(t => {
        md += `- ${t.name}${t.version ? ` (v${t.version})` : ''}\n`;
      });
      md += `\n`;
    }
    
    if (tech.backend && tech.backend.length > 0) {
      md += `### Backend\n\n`;
      tech.backend.forEach(t => {
        md += `- ${t.name}${t.version ? ` (v${t.version})` : ''}\n`;
      });
      md += `\n`;
    }
    
    md += `---\n\n`;
    return md;
  }

  // Export as JSON
  toJSON() {
    const output = { ...this.reportData };
    if (this.llmSummary) output.llmSummary = this.llmSummary;
    if (this.llmRiskAnalysis) output.llmRiskAnalysis = this.llmRiskAnalysis;
    if (this.llmRemediation) output.llmRemediation = this.llmRemediation;
    if (this.llmCompliance) output.llmCompliance = this.llmCompliance;
    return JSON.stringify(output, null, 2);
  }

  // Download report
  download(format = 'html') {
    let content, filename, mimeType;

    if (format === 'html') {
      content = this.toHTML();
      filename = `origami-report-${this.reportData.reportId}.html`;
      mimeType = 'text/html';
    } else if (format === 'markdown') {
      content = this.toMarkdown();
      filename = `origami-report-${this.reportData.reportId}.md`;
      mimeType = 'text/markdown';
    } else if (format === 'json') {
      content = this.toJSON();
      filename = `origami-report-${this.reportData.reportId}.json`;
      mimeType = 'application/json';
    } else {
      throw new Error(`Unsupported format: ${format}`);
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  }
}

// Export for use in extension
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ReportGenerator;
}

