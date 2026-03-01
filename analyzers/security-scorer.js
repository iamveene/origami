// Origami Security Scorer
// Calculates a composite security score (0-100) from all scan results

class SecurityScorer {

  static calculate(data, config) {
    const secrets = data.secrets || [];
    const headers = data.headers || [];
    const cookies = data.cookies || [];
    const vulnerabilities = data.vulnerabilities || [];
    const technologies = data.technologies || null;
    const sensitiveFiles = data.sensitiveFiles || [];
    const session = Array.isArray(data.session) ? data.session : (data.session?.issues || data.session?.allIssues || []);
    const oauth = Array.isArray(data.oauth) ? data.oauth : (data.oauth?.issues || data.oauth?.flows || []);
    const graphql = Array.isArray(data.graphql) ? data.graphql : (data.graphql?.issues || []);
    const crypto = Array.isArray(data.crypto) ? data.crypto : (data.crypto?.issues || []);
    const cloudStorage = Array.isArray(data.cloudStorage) ? data.cloudStorage : (data.cloudStorage?.issues || []);
    const exfiltration = Array.isArray(data.exfiltration) ? data.exfiltration : (data.exfiltration?.issues || []);
    const websocket = Array.isArray(data.websocket) ? data.websocket : (data.websocket?.issues || []);
    let score = 100;
    const positives = [];
    const negatives = [];

    const breakdown = {
      secrets: { score: 100, findings: 0, deductions: 0 },
      headers: { score: 100, findings: 0, deductions: 0 },
      cookies: { score: 100, findings: 0, deductions: 0 },
      vulnerabilities: { score: 100, findings: 0, deductions: 0 },
      sensitiveFiles: { score: 100, findings: 0, deductions: 0 },
      sca: { score: 100, findings: 0, deductions: 0 },
      session: { score: 100, findings: 0, deductions: 0 },
      oauth: { score: 100, findings: 0, deductions: 0 },
      graphql: { score: 100, findings: 0, deductions: 0 },
      crypto: { score: 100, findings: 0, deductions: 0 },
      cloudStorage: { score: 100, findings: 0, deductions: 0 },
      exfiltration: { score: 100, findings: 0, deductions: 0 },
      websocket: { score: 100, findings: 0, deductions: 0 },
    };

    // Deduction caps per severity (raised for better score discrimination)
    const caps = { CRITICAL: 50, HIGH: 35, MEDIUM: 15, LOW: 5 };
    const points = { CRITICAL: 20, HIGH: 8, MEDIUM: 3, LOW: 1 };

    // Per-category max weighted deduction -- prevents any single noisy category from tanking the score
    // Secrets and vulnerabilities get a higher cap (40) because multiple CRITICAL/HIGH findings
    // in these categories reflect genuine exploitation risk that should not be masked
    const CATEGORY_WEIGHTED_CAP = 30;
    const HIGH_IMPACT_CAP = 40;

    // Category weights calibrated for adversarial exploitation impact:
    //  - High weight: findings enabling direct exploitation (secrets, vulns, SCA with known exploits)
    //  - Medium weight: findings requiring chaining (session, oauth, cloud storage, graphql)
    //  - Low weight: defense-in-depth recommendations (headers, cookies, exfiltration patterns)
    const categoryWeights = {
      secrets: 1.5,
      sca: 1.4,
      vulnerabilities: 1.2,
      sensitiveFiles: 1.2,
      headers: 0.3,      // Reduced: missing headers are defense-in-depth, not directly exploitable
      cookies: 0.2,      // Reduced: cookie flag issues require chaining (XSS, MITM) to exploit
      crypto: 0.8,
      exfiltration: 0.4,
      cloudStorage: 1.0,
      session: 1.0,
      oauth: 1.0,
      websocket: 0.5,
      graphql: 0.8
    };

    // Helper: get effective severity for a finding, excluding false positives (NONE)
    // Priority: exploitation validation > manual override > AI assessment > pattern severity
    function getEffectiveSeverity(finding) {
      // Exploitation validation results take highest priority (TP/FP classification)
      if (finding.validationResult?.classification === 'FP_CONFIRMED') {
        return 'NONE';
      }
      if (finding.validationResult?.severityOverride) {
        return finding.validationResult.severityOverride.toUpperCase();
      }
      const sev = (
        finding.severityOverride?.overriddenSeverity ||
        finding.aiAssessment?.suggestedSeverity ||
        finding.risk ||
        finding.severity ||
        'INFO'
      ).toUpperCase();
      return sev;
    }

    // Helper: apply deductions for a category
    function applyDeductions(findings, categoryKey) {
      if (config && config.types && config.types[categoryKey] === false) {
        breakdown[categoryKey].findings = 0;
        breakdown[categoryKey].deductions = 0;
        breakdown[categoryKey].score = 100;
        return 0;
      }

      const totals = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
      const uniqueByPattern = { CRITICAL: new Set(), HIGH: new Set(), MEDIUM: new Set(), LOW: new Set() };

      findings.forEach(f => {
        const sev = getEffectiveSeverity(f);
        if (sev === 'NONE' || sev === 'INFO' || sev === 'OK') return;
        if (config && config.severities && config.severities[sev.toLowerCase()] === false) return;
        if (totals.hasOwnProperty(sev)) {
          totals[sev]++;
          const pattern = f.type || f.details?.type || f.details?.pattern || f.check || f.pattern_matched || f.message?.substring(0, 60) || 'unknown';
          uniqueByPattern[sev].add(pattern);
        }
      });

      let categoryDeduction = 0;
      for (const [severity, count] of Object.entries(totals)) {
        if (count === 0) continue;
        // Diminishing returns: unique patterns at full weight, duplicates at half
        const uniqueCount = uniqueByPattern[severity].size;
        const raw = uniqueCount * points[severity] + (count - uniqueCount) * Math.floor(points[severity] / 2);
        const capped = Math.min(raw, caps[severity]);
        categoryDeduction += capped;

        if (count > 0) {
          negatives.push(`${count} ${severity} ${categoryKey} finding${count > 1 ? 's' : ''} (-${capped} pts)`);
        }
      }

      const totalFindings = Object.values(totals).reduce((a, b) => a + b, 0);
      breakdown[categoryKey].findings = totalFindings;
      breakdown[categoryKey].deductions = categoryDeduction;
      breakdown[categoryKey].score = Math.max(0, 100 - categoryDeduction);

      return categoryDeduction;
    }

    // Collect weighted deductions per category before subtracting
    const weightedDeductions = [
      { key: 'secrets', raw: applyDeductions(secrets, 'secrets'), weight: categoryWeights.secrets },
      { key: 'headers', raw: applyDeductions(headers, 'headers'), weight: categoryWeights.headers },
      { key: 'cookies', raw: applyDeductions(cookies, 'cookies'), weight: categoryWeights.cookies },
      { key: 'vulnerabilities', raw: applyDeductions(vulnerabilities, 'vulnerabilities'), weight: categoryWeights.vulnerabilities },
      { key: 'sensitiveFiles', raw: applyDeductions(sensitiveFiles, 'sensitiveFiles'), weight: categoryWeights.sensitiveFiles },
      { key: 'session', raw: applyDeductions(session, 'session'), weight: categoryWeights.session },
      { key: 'oauth', raw: applyDeductions(oauth, 'oauth'), weight: categoryWeights.oauth },
      { key: 'graphql', raw: applyDeductions(graphql, 'graphql'), weight: categoryWeights.graphql },
      { key: 'crypto', raw: applyDeductions(crypto, 'crypto'), weight: categoryWeights.crypto },
      { key: 'cloudStorage', raw: applyDeductions(cloudStorage, 'cloudStorage'), weight: categoryWeights.cloudStorage },
      { key: 'exfiltration', raw: applyDeductions(exfiltration, 'exfiltration'), weight: categoryWeights.exfiltration },
      { key: 'websocket', raw: applyDeductions(websocket, 'websocket'), weight: categoryWeights.websocket },
    ];

    // SCA scoring: CVE/EOL data from technology fingerprinting
    if (technologies && typeof technologies === 'object' && !(config && config.types && config.types.sca === false)) {
      const scaFindings = [];
      const categories = Array.isArray(technologies) ? [technologies] : Object.values(technologies);
      for (const category of categories) {
        if (!Array.isArray(category)) continue;
        for (const tech of category) {
          if (tech.endOfLife || tech.eolStatus?.status === 'EOL') {
            // EOL alone = HIGH, not CRITICAL: indicates no more patches but no confirmed exploit yet
            scaFindings.push({ severity: 'HIGH', check: `${tech.name} is end-of-life` });
          }
          if (Array.isArray(tech.vulnerabilities)) {
            for (const vuln of tech.vulnerabilities) {
              const cvss = vuln.score || vuln.severity_score || 0;
              let sev = 'LOW';
              if (cvss >= 9.0) sev = 'CRITICAL';
              else if (cvss >= 7.0) sev = 'HIGH';
              else if (cvss >= 4.0) sev = 'MEDIUM';
              scaFindings.push({ severity: sev, check: `${tech.name}: ${vuln.id || 'CVE'}` });
            }
          }
        }
      }
      weightedDeductions.push({ key: 'sca', raw: applyDeductions(scaFindings, 'sca'), weight: categoryWeights.sca });
    }

    // Apply per-category weighted cap, then proportional normalization
    const MAX_DEDUCTIONS = 95;
    const highImpactCategories = new Set(['secrets', 'vulnerabilities']);
    const totalWeighted = weightedDeductions.reduce((sum, d) => {
      const cap = highImpactCategories.has(d.key) ? HIGH_IMPACT_CAP : CATEGORY_WEIGHTED_CAP;
      return sum + Math.min(Math.round(d.raw * d.weight), cap);
    }, 0);
    if (totalWeighted > MAX_DEDUCTIONS && totalWeighted > 0) {
      const scale = MAX_DEDUCTIONS / totalWeighted;
      score -= Math.round(totalWeighted * scale);
    } else {
      score -= totalWeighted;
    }

    // Bonuses (only if the relevant check was actually run)
    // Accumulated separately and capped to prevent overwhelming deductions
    const hasHeaders = headers.length > 0;
    const hasCookies = cookies.length > 0;
    const hasSecrets = secrets !== undefined && secrets !== null;
    let totalBonus = 0;

    if (hasHeaders && !(config && config.types && config.types.headers === false)) {
      // Strict CSP check
      const cspFinding = headers.find(h =>
        h.check && h.check.toLowerCase().includes('content-security-policy')
      );
      if (cspFinding) {
        const cspValue = (cspFinding.details?.value || cspFinding.message || '').toLowerCase();
        const cspSev = getEffectiveSeverity(cspFinding);
        const hasStrictCSP = cspSev === 'OK' || cspSev === 'INFO' ||
          (cspValue && !cspValue.includes('unsafe-inline') && !cspValue.includes('unsafe-eval') && !cspValue.includes("'*'") && !cspValue.includes(' * '));
        if (hasStrictCSP && cspSev !== 'CRITICAL' && cspSev !== 'HIGH' && cspSev !== 'MEDIUM') {
          totalBonus += 5;
          positives.push('Strict Content Security Policy (+5)');
        }
      }

      // HSTS with includeSubDomains
      const hstsFinding = headers.find(h =>
        h.check && h.check.toLowerCase().includes('strict-transport-security')
      );
      if (hstsFinding) {
        const hstsValue = (hstsFinding.details?.value || hstsFinding.message || '').toLowerCase();
        const hstsSev = getEffectiveSeverity(hstsFinding);
        if ((hstsSev === 'OK' || hstsSev === 'INFO') && hstsValue.includes('includesubdomains')) {
          totalBonus += 3;
          positives.push('HSTS with includeSubDomains (+3)');
        }
      }

      // X-Content-Type-Options: nosniff
      const xctFinding = headers.find(h =>
        h.check && h.check.toLowerCase().includes('x-content-type-options')
      );
      if (xctFinding) {
        const xctSev = getEffectiveSeverity(xctFinding);
        if (xctSev === 'OK' || xctSev === 'INFO') {
          totalBonus += 2;
          positives.push('X-Content-Type-Options: nosniff (+2)');
        }
      }

      // Good Referrer-Policy
      const refFinding = headers.find(h =>
        h.check && h.check.toLowerCase().includes('referrer-policy')
      );
      if (refFinding) {
        const refSev = getEffectiveSeverity(refFinding);
        if (refSev === 'OK' || refSev === 'INFO') {
          totalBonus += 2;
          positives.push('Good Referrer-Policy (+2)');
        }
      }

      // Permissions-Policy present
      const permFinding = headers.find(h =>
        h.check && h.check.toLowerCase().includes('permissions-policy')
      );
      if (permFinding) {
        const permSev = getEffectiveSeverity(permFinding);
        if (permSev === 'OK' || permSev === 'INFO') {
          totalBonus += 2;
          positives.push('Permissions-Policy present (+2)');
        }
      }

      // SRI on cross-origin scripts
      const sriFinding = headers.find(h =>
        h.check && (h.check.toLowerCase().includes('subresource integrity') || h.check.toLowerCase().includes('sri'))
      );
      if (sriFinding) {
        const sriSev = getEffectiveSeverity(sriFinding);
        if (sriSev === 'OK' || sriSev === 'INFO') {
          totalBonus += 3;
          positives.push('Subresource Integrity on cross-origin scripts (+3)');
        }
      }
    }

    if (hasCookies && !(config && config.types && config.types.cookies === false)) {
      const actionableCookies = cookies.filter(c => {
        const sev = getEffectiveSeverity(c);
        return sev !== 'OK' && sev !== 'INFO' && sev !== 'NONE';
      });

      const hasSecureIssue = actionableCookies.some(c =>
        (c.check || c.message || '').toLowerCase().includes('secure')
      );
      const hasHttpOnlyIssue = actionableCookies.some(c =>
        (c.check || c.message || '').toLowerCase().includes('httponly')
      );

      if (!hasSecureIssue) {
        totalBonus += 2;
        positives.push('All cookies have Secure flag (+2)');
      }
      if (!hasHttpOnlyIssue) {
        totalBonus += 2;
        positives.push('All cookies have HttpOnly flag (+2)');
      }
    }

    if (hasSecrets && !(config && config.types && config.types.secrets === false) && secrets.length === 0) {
      totalBonus += 5;
      positives.push('No exposed secrets detected (+5)');
    }

    // Apply capped bonus
    score += Math.min(totalBonus, 25);

    // Clamp score
    score = Math.max(0, Math.min(100, score));

    // Grade mapping (wider bands for low-end differentiation)
    let grade;
    if (score >= 90) grade = 'A+';
    else if (score >= 78) grade = 'A';
    else if (score >= 60) grade = 'B';
    else if (score >= 40) grade = 'C';
    else if (score >= 20) grade = 'D';
    else grade = 'F';

    return { score, grade, breakdown, positives, negatives };
  }
}
