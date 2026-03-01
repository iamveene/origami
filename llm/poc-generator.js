// Origami AI Exploitation PoC Generator
// Generates tiered proof-of-concept exploits via LLM for findings from any analyzer

class PoCGenerator {

  // Generate tiered PoC exploits for a specific finding
  // finding: a single finding object from any analyzer
  // context: { csp, technologies, url, dom }
  async generate(finding, context) {
    try {
      const prompt = this.buildPrompt(finding, context);
      const response = await this._sendToLLM(prompt);

      return {
        finding: {
          type: finding.check || finding.type || 'Unknown',
          severity: finding.severity || finding.risk || 'MEDIUM',
          message: finding.message || ''
        },
        tiers: this._parseTiers(response.text),
        chainPoc: null,
        model: response.model || 'unknown',
        generatedAt: new Date().toISOString()
      };
    } catch (e) {
      console.error('Origami: PoCGenerator.generate error:', e);
      throw new Error('PoC generation failed: ' + e.message);
    }
  }

  // Generate PoC for an entire attack chain (from ChainBuilder)
  // chain: the chain object from ChainBuilder.getChain()
  async generateForChain(chain) {
    try {
      if (!chain || !chain.steps || chain.steps.length === 0) {
        throw new Error('Empty or invalid chain provided');
      }

      const prompt = this._buildChainPrompt(chain);
      const response = await this._sendToLLM(prompt);

      return {
        finding: {
          type: 'Attack Chain: ' + (chain.meta?.name || 'Unnamed'),
          severity: chain.meta?.severity || 'HIGH',
          message: 'Multi-step attack chain with ' + chain.steps.length + ' findings'
        },
        tiers: this._parseTiers(response.text),
        chainPoc: response.text,
        model: response.model || 'unknown',
        generatedAt: new Date().toISOString()
      };
    } catch (e) {
      console.error('Origami: PoCGenerator.generateForChain error:', e);
      throw new Error('Chain PoC generation failed: ' + e.message);
    }
  }

  // Sanitize attacker-controlled data before including in LLM prompts
  _sanitize(text) {
    if (!text || typeof text !== 'string') return '';
    return text
      .replace(/\[TOOL_CALL\]/gi, '[T00L_CALL]')
      .replace(/\[\/TOOL_CALL\]/gi, '[/T00L_CALL]')
      .replace(/\[TOOL_RESULT\]/gi, '[T00L_RESULT]')
      .replace(/\[\/TOOL_RESULT\]/gi, '[/T00L_RESULT]')
      .replace(/^(system|assistant|user):\s/gim, (m) => m.replace(/:/, ': '));
  }

  // Build the prompt for a single finding -- separated for testability
  buildPrompt(finding, context) {
    const findingType = this._sanitize(finding.check || finding.type || finding.details?.type || 'Unknown');
    const findingSeverity = finding.severity || finding.risk || 'MEDIUM';
    const findingMessage = this._sanitize(finding.message || '');
    const findingPattern = this._sanitize(finding.pattern || finding.details?.pattern || finding.matchedText || finding.details?.matchedText || '');
    const findingLocation = this._sanitize(finding.uri || finding.url || finding.details?.uri || finding.source || '');
    const findingContext = this._sanitize(finding.codeContext || finding.details?.context || '');

    // Extract structured details for richer prompt context (storage findings, etc.)
    const findingDetails = finding.details || {};
    const detailEntries = [];
    if (findingDetails.storageName) detailEntries.push('Storage: ' + findingDetails.storageName);
    if (findingDetails.key) detailEntries.push('Key: ' + findingDetails.key);
    if (findingDetails.valuePreview) detailEntries.push('Value Preview: ' + findingDetails.valuePreview);
    if (findingDetails.entropy) detailEntries.push('Entropy: ' + findingDetails.entropy);
    if (findingDetails.type) detailEntries.push('Finding Type: ' + findingDetails.type);

    let prompt = 'AUTHORIZED PENETRATION TESTING -- PoC EXPLOIT GENERATION\n';
    prompt += '=========================================================\n\n';
    prompt += 'You are assisting an authorized penetration tester. Generate proof-of-concept exploits\n';
    prompt += 'for the vulnerability described below. This is for educational and authorized security\n';
    prompt += 'testing purposes only. Include explanations alongside each payload so the tester\n';
    prompt += 'understands both the attack and defense perspective.\n\n';

    prompt += '## Target Vulnerability\n\n';
    prompt += '- Type: ' + findingType + '\n';
    prompt += '- Severity: ' + findingSeverity + '\n';
    if (findingMessage) {
      prompt += '- Description: ' + findingMessage + '\n';
    }
    if (findingPattern) {
      prompt += '- Matched Pattern/Value: ' + this._truncate(findingPattern, 300) + '\n';
    }
    if (findingLocation) {
      prompt += '- Location: ' + findingLocation + '\n';
    }
    if (findingContext) {
      prompt += '- Code Context:\n```\n' + this._truncate(findingContext, 500) + '\n```\n';
    }
    if (detailEntries.length > 0) {
      prompt += '- Additional Details:\n';
      detailEntries.forEach(d => { prompt += '  - ' + this._sanitize(d) + '\n'; });
    }

    prompt += '\n## Environment Context\n\n';

    if (context) {
      if (context.url) {
        prompt += '- Page URL: ' + context.url + '\n';
      }

      if (context.csp) {
        prompt += '- Content-Security-Policy: ' + this._truncate(String(context.csp), 500) + '\n';
        prompt += '  (Consider CSP bypass techniques if applicable)\n';
      } else {
        prompt += '- Content-Security-Policy: Not set (no CSP restrictions)\n';
      }

      if (context.technologies && context.technologies.length > 0) {
        const techList = context.technologies.map(t => {
          if (typeof t === 'string') return t;
          return (t.name || '') + (t.version ? ' ' + t.version : '');
        }).filter(Boolean).join(', ');
        prompt += '- Detected Technologies: ' + techList + '\n';
        prompt += '  (Tailor payloads to these specific frameworks/libraries)\n';
      }

      if (context.dom) {
        prompt += '- Relevant DOM Context:\n```html\n' + this._truncate(context.dom, 500) + '\n```\n';
      }
    }

    prompt += '\n## Required Output: 3 Tiers of PoC Exploits\n\n';

    prompt += 'For each tier, include the following fields in the text:\n';
    prompt += '- level: "basic", "intermediate", or "advanced"\n';
    prompt += '- payload: the actual exploit payload or code\n';
    prompt += '- explanation: educational explanation of how and why the payload works\n';
    prompt += '- prerequisites: what conditions or access are needed\n';
    prompt += '- risk: impact rating and what damage this could cause\n\n';

    prompt += '### Tier 1 -- Basic\n';
    prompt += 'Simple proof-of-concept that demonstrates the vulnerability exists.\n';
    prompt += 'Examples: alert(1) for XSS, \' OR 1=1-- for SQLi, basic cookie theft.\n';
    prompt += 'Minimal complexity, easy to reproduce.\n\n';

    prompt += '### Tier 2 -- Intermediate\n';
    prompt += 'Bypass attempts that evade common defenses.\n';
    prompt += 'Examples: CSP bypass payloads, WAF evasion with encoding tricks, filter circumvention.\n';
    prompt += 'Consider the specific technology stack and security controls in place.\n\n';

    prompt += '### Tier 3 -- Advanced\n';
    prompt += 'Full exploitation chain demonstrating maximum impact.\n';
    prompt += 'Examples: cookie exfiltration, keylogging injection, CSRF chaining, session hijacking.\n';
    prompt += 'Show the complete attack from initial vector to data compromise.\n\n';

    prompt += 'Format your response as:\n\n';
    prompt += '```\n';
    prompt += 'TIER_BASIC:\n';
    prompt += 'PAYLOAD: [payload here]\n';
    prompt += 'EXPLANATION: [explanation here]\n';
    prompt += 'PREREQUISITES: [prerequisites here]\n';
    prompt += 'RISK: [risk assessment here]\n\n';
    prompt += 'TIER_INTERMEDIATE:\n';
    prompt += 'PAYLOAD: [payload here]\n';
    prompt += 'EXPLANATION: [explanation here]\n';
    prompt += 'PREREQUISITES: [prerequisites here]\n';
    prompt += 'RISK: [risk assessment here]\n\n';
    prompt += 'TIER_ADVANCED:\n';
    prompt += 'PAYLOAD: [payload here]\n';
    prompt += 'EXPLANATION: [explanation here]\n';
    prompt += 'PREREQUISITES: [prerequisites here]\n';
    prompt += 'RISK: [risk assessment here]\n';
    prompt += '```\n\n';

    prompt += 'Consider both detection and exploitation perspectives. ';
    prompt += 'Include how a defender would detect each payload.';

    return prompt;
  }

  // Build prompt for an entire attack chain
  _buildChainPrompt(chain) {
    let prompt = 'AUTHORIZED PENETRATION TESTING -- ATTACK CHAIN PoC GENERATION\n';
    prompt += '==============================================================\n\n';
    prompt += 'You are assisting an authorized penetration tester. Generate a step-by-step\n';
    prompt += 'exploitation walkthrough for the following attack chain. This is for educational\n';
    prompt += 'and authorized security testing purposes only.\n\n';

    prompt += '## Attack Chain: ' + this._sanitize(chain.meta?.name || 'Unnamed Chain') + '\n';
    prompt += '- Escalated Severity: ' + (chain.meta?.severity || 'HIGH') + '\n';
    if (chain.meta?.description) {
      prompt += '- Description: ' + this._sanitize(chain.meta.description) + '\n';
    }
    prompt += '- Total Steps: ' + chain.steps.length + '\n\n';

    prompt += '## Chain Steps\n\n';
    chain.steps.forEach((step, i) => {
      prompt += '### Step ' + (i + 1) + ': ' + this._sanitize(step.type || 'Unknown') + '\n';
      prompt += '- Severity: ' + (step.severity || 'MEDIUM') + '\n';
      prompt += '- Category: ' + this._sanitize(step.category || 'unknown') + '\n';
      prompt += '- Finding: ' + this._sanitize(step.message || 'No details') + '\n';
      if (step.recommendation) {
        prompt += '- Current Mitigation: ' + this._sanitize(step.recommendation) + '\n';
      }
      if (step.uri) {
        prompt += '- Location: ' + this._sanitize(step.uri) + '\n';
      }
      prompt += '\n';
    });

    prompt += '## Required Output\n\n';
    prompt += 'Provide a complete exploitation walkthrough that chains these findings together:\n\n';
    prompt += '1. For each step, explain how the finding is exploited and how it enables the next step\n';
    prompt += '2. Provide concrete payloads for each step in the chain\n';
    prompt += '3. Explain the cumulative impact at each stage\n';
    prompt += '4. Show how individual low/medium findings escalate to higher impact when combined\n';
    prompt += '5. Include detection opportunities at each step (for defensive perspective)\n';
    prompt += '6. Provide the final combined impact assessment\n\n';

    prompt += 'Additionally, provide the same 3-tier structure as individual findings:\n\n';
    prompt += '```\n';
    prompt += 'TIER_BASIC:\n';
    prompt += 'PAYLOAD: [basic chain exploitation]\n';
    prompt += 'EXPLANATION: [how the basic chain works]\n';
    prompt += 'PREREQUISITES: [what is needed]\n';
    prompt += 'RISK: [basic impact]\n\n';
    prompt += 'TIER_INTERMEDIATE:\n';
    prompt += 'PAYLOAD: [intermediate chain exploitation with bypass techniques]\n';
    prompt += 'EXPLANATION: [how bypasses enable deeper exploitation]\n';
    prompt += 'PREREQUISITES: [what is needed]\n';
    prompt += 'RISK: [intermediate impact]\n\n';
    prompt += 'TIER_ADVANCED:\n';
    prompt += 'PAYLOAD: [full chain exploitation for maximum impact]\n';
    prompt += 'EXPLANATION: [complete walkthrough]\n';
    prompt += 'PREREQUISITES: [what is needed]\n';
    prompt += 'RISK: [maximum impact assessment]\n';
    prompt += '```';

    return prompt;
  }

  // Send prompt to LLM via background service worker
  async _sendToLLM(prompt) {
    try {
      if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) {
        throw new Error('Chrome runtime not available. PoCGenerator must run inside the extension.');
      }

      return new Promise((resolve, reject) => {
        chrome.runtime.sendMessage({
          action: 'llmAnalyze',
          prompt: prompt,
          systemPrompt: 'You are a senior penetration tester generating proof-of-concept exploits for authorized security testing. Provide detailed, actionable payloads with educational explanations.',
          options: { temperature: 0.3, maxTokens: 8192 }
        }, (response) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          if (!response || !response.success) {
            reject(new Error(response?.error || 'LLM request failed'));
            return;
          }
          const data = response.data;
          const text = data?.candidates?.[0]?.content?.parts?.[0]?.text || // Gemini
                       data?.choices?.[0]?.message?.content || // OpenAI
                       data?.content?.[0]?.text || // Anthropic
                       data?.response || // Ollama
                       (typeof data === 'string' ? data : JSON.stringify(data));
          resolve({
            text: text,
            model: data?.model || data?.modelVersion || 'unknown'
          });
        });
      });
    } catch (e) {
      console.error('Origami: PoCGenerator._sendToLLM error:', e);
      throw e;
    }
  }

  // Detect if LLM response is a safety refusal rather than a PoC
  _isRefusal(text) {
    if (!text) return false;
    const first500 = text.substring(0, 500);
    return /i (cannot|can't|won't|will not|am unable|am not able) (help|assist|generate|create|provide)/i.test(first500) ||
      /against my (guidelines|policy|values|principles)/i.test(first500) ||
      /(not (appropriate|ethical)|decline to (generate|create|provide|assist)|could cause harm)/i.test(first500) ||
      /^unfortunately[,\s]/i.test(first500) ||
      /i'?m not able to/i.test(first500) ||
      /i'?m unable to/i.test(first500) ||
      /i'?m afraid i/i.test(first500) ||
      /cannot assist/i.test(first500) ||
      /not something i can/i.test(first500) ||
      /i must decline/i.test(first500) ||
      /i'?m sorry,? i can'?t/i.test(first500) ||
      /i apologize,? but/i.test(first500);
  }

  // Parse LLM response into structured tiers
  _parseTiers(text) {
    if (!text) return this._emptyTiers();

    try {
      const tiers = [];
      const tierLabels = [
        { level: 'basic', marker: 'TIER_BASIC' },
        { level: 'intermediate', marker: 'TIER_INTERMEDIATE' },
        { level: 'advanced', marker: 'TIER_ADVANCED' }
      ];

      // If no tier markers present, LLM either refused or produced wrong format.
      // Surface the raw response rather than returning empty tiers.
      const hasTierMarkers = tierLabels.some(t => text.includes(t.marker));
      if (!hasTierMarkers) {
        if (this._isRefusal(text)) {
          const label = 'LLM declined to generate this PoC.';
          return [
            { level: 'basic', payload: label, explanation: text.substring(0, 2000), prerequisites: '', risk: '' },
            { level: 'intermediate', payload: label, explanation: '', prerequisites: '', risk: '' },
            { level: 'advanced', payload: label, explanation: '', prerequisites: '', risk: '' },
          ];
        }

        // JSON fallback: try to parse if response looks like JSON
        const trimmed = text.trim();
        if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
          try {
            // Strip markdown code fences if present
            const jsonStr = trimmed.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '');
            const parsed = JSON.parse(jsonStr);
            const items = Array.isArray(parsed) ? parsed : (parsed.tiers || parsed.exploits || parsed.pocs || [parsed]);
            const levelMap = ['basic', 'intermediate', 'advanced'];
            const mapped = items.slice(0, 3).map((item, idx) => ({
              level: item.level || levelMap[idx] || 'basic',
              payload: item.payload || item.code || item.exploit || '',
              explanation: item.explanation || item.description || '',
              prerequisites: item.prerequisites || '',
              risk: item.risk || item.impact || ''
            }));
            while (mapped.length < 3) {
              mapped.push({ level: levelMap[mapped.length] || 'advanced', payload: '', explanation: '', prerequisites: '', risk: '' });
            }
            return mapped;
          } catch (e) {
            // JSON parse failed, fall through to default
          }
        }

        const label = 'LLM response did not follow the expected format.';
        return [
          { level: 'basic', payload: label, explanation: text.substring(0, 2000), prerequisites: '', risk: '' },
          { level: 'intermediate', payload: label, explanation: '', prerequisites: '', risk: '' },
          { level: 'advanced', payload: label, explanation: '', prerequisites: '', risk: '' },
        ];
      }

      for (let i = 0; i < tierLabels.length; i++) {
        const current = tierLabels[i];
        const next = tierLabels[i + 1];

        const startIdx = text.indexOf(current.marker);
        if (startIdx === -1) {
          tiers.push({
            level: current.level,
            payload: '',
            explanation: '',
            prerequisites: '',
            risk: ''
          });
          continue;
        }

        let endIdx = next ? text.indexOf(next.marker) : -1;
        if (endIdx === -1) endIdx = text.length;
        const section = endIdx > startIdx ? text.substring(startIdx, endIdx) : text.substring(startIdx);

        tiers.push({
          level: current.level,
          payload: this._extractField(section, 'PAYLOAD'),
          explanation: this._extractField(section, 'EXPLANATION'),
          prerequisites: this._extractField(section, 'PREREQUISITES'),
          risk: this._extractField(section, 'RISK')
        });
      }

      return tiers;
    } catch (e) {
      console.error('Origami: PoCGenerator._parseTiers error:', e);
      return this._emptyTiers();
    }
  }

  // Extract a named field from a tier section
  _extractField(section, fieldName) {
    try {
      const pattern = new RegExp(fieldName + ':\\s*(.+?)(?=\\n(?:PAYLOAD|EXPLANATION|PREREQUISITES|RISK|TIER_)|$)', 's');
      const match = section.match(pattern);
      if (match && match[1]) {
        return match[1].trim();
      }
      return '';
    } catch (e) {
      return '';
    }
  }

  // Return empty tier structure
  _emptyTiers() {
    return [
      { level: 'basic', payload: '', explanation: '', prerequisites: '', risk: '' },
      { level: 'intermediate', payload: '', explanation: '', prerequisites: '', risk: '' },
      { level: 'advanced', payload: '', explanation: '', prerequisites: '', risk: '' }
    ];
  }

  // Truncate a string to a maximum length
  _truncate(str, maxLen) {
    if (!str) return '';
    const s = String(str);
    if (s.length <= maxLen) return s;
    return s.substring(0, maxLen) + '... [truncated]';
  }
}

window.PoCGenerator = PoCGenerator;
