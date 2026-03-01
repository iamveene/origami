// Origami Secret Validator
// Validates detected secrets against provider APIs to determine if they are active

class SecretValidator {

  // Classification result: { provider, valid, risk, classification, exploitConfidence, severityOverride }
  //   classification: 'TP_CONFIRMED' | 'TP_LIKELY' | 'FP_CONFIRMED' | 'FP_LIKELY' | 'INCONCLUSIVE'
  //   exploitConfidence: 0-100 (how confident we are this is immediately exploitable)
  //   severityOverride: recommended severity based on validation outcome
  static async validate(key, patternName) {
    const provider = SecretValidator.detectProvider(key, patternName);
    if (!provider) return null;

    const validator = SecretValidator.VALIDATORS[provider];
    if (!validator) return null;

    try {
      const result = await validator.test(key);
      // Classify TP/FP based on validation outcome
      const classified = SecretValidator._classifyResult(result, provider);
      return { provider, ...result, ...classified };
    } catch (e) {
      return {
        provider,
        valid: false,
        error: e.message,
        classification: 'INCONCLUSIVE',
        exploitConfidence: 0,
        severityOverride: null
      };
    }
  }

  // Classify validation result as TP/FP with confidence scoring
  static _classifyResult(result, provider) {
    if (!result) return { classification: 'INCONCLUSIVE', exploitConfidence: 0, severityOverride: null };

    if (result.valid === true) {
      // API confirmed the key works — true positive confirmed
      const hasWriteAccess = (result.permissions || []).some(p =>
        /write|admin|send|create|delete|push|deploy|manage/i.test(p)
      );
      return {
        classification: 'TP_CONFIRMED',
        exploitConfidence: hasWriteAccess ? 95 : 80,
        severityOverride: hasWriteAccess ? 'CRITICAL' : 'HIGH'
      };
    }

    if (result.valid === false) {
      // API explicitly rejected the key
      if (result.error && /network|timeout|dns|connect/i.test(result.error)) {
        // Network error — can't determine validity
        return { classification: 'INCONCLUSIVE', exploitConfidence: 30, severityOverride: null };
      }
      return {
        classification: 'FP_CONFIRMED',
        exploitConfidence: 0,
        // Revoked/invalid keys get severity override to INFO
        severityOverride: 'INFO'
      };
    }

    // valid === null — structural match but no API confirmation
    return {
      classification: 'TP_LIKELY',
      exploitConfidence: 50,
      severityOverride: null // Keep original severity
    };
  }

  static detectProvider(key, patternName) {
    if (!key) return null;
    const name = (patternName || '').toLowerCase();

    if (/^AKIA[0-9A-Z]{16}/.test(key) || name.includes('aws')) return 'aws';
    if (key.startsWith('sk_live_')) return 'stripe';
    if (key.startsWith('sk_test_')) return 'stripe_test';
    if (/^(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)/.test(key)) return 'github';
    if (/^sk-ant-/.test(key)) return 'anthropic';
    if (/^sk-/.test(key) && (key.includes('T3BlbkFJ') || key.startsWith('sk-proj-'))) return 'openai';
    if (/^xox[baprs]-/.test(key)) return 'slack';
    if (key.startsWith('SG.')) return 'sendgrid';
    if (/^key-[0-9a-zA-Z]{32}/.test(key) && name.includes('mailgun')) return 'mailgun';
    if (key.startsWith('glpat-')) return 'gitlab';

    return null;
  }

  static async fetchViaBackground(url, options) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({
        action: 'validateSecret',
        url,
        method: options.method || 'GET',
        headers: options.headers || {},
        body: options.body || null
      }, (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        if (!response) {
          reject(new Error('No response from background'));
          return;
        }
        resolve(response);
      });
    });
  }
}

SecretValidator.VALIDATORS = {

  aws: {
    name: 'AWS',
    test: async (accessKey) => {
      return {
        valid: null,
        message: 'AWS Access Key detected (structural match). Full validation requires the corresponding secret key.',
        permissions: [],
        risk: 'HIGH',
        details: {
          accountId: accessKey.substring(4, 16),
          keyType: accessKey.startsWith('AKIA') ? 'Long-term' : 'Temporary'
        }
      };
    }
  },

  stripe: {
    name: 'Stripe',
    test: async (key) => {
      const response = await SecretValidator.fetchViaBackground('https://api.stripe.com/v1/balance', {
        method: 'GET',
        headers: { 'Authorization': `Bearer ${key}` }
      });
      const data = JSON.parse(response.body || '{}');
      if (response.status === 200) {
        return {
          valid: true,
          message: 'Stripe live key is ACTIVE with balance access',
          permissions: ['balance:read'],
          risk: 'CRITICAL',
          details: { livemode: data.livemode, available: data.available }
        };
      } else if (response.status === 401) {
        return { valid: false, message: 'Stripe key is invalid or revoked', permissions: [], risk: 'LOW' };
      }
      return { valid: null, message: `Stripe returned status ${response.status}`, permissions: [], risk: 'MEDIUM' };
    }
  },

  stripe_test: {
    name: 'Stripe (Test)',
    test: async (key) => {
      const response = await SecretValidator.fetchViaBackground('https://api.stripe.com/v1/balance', {
        method: 'GET',
        headers: { 'Authorization': `Bearer ${key}` }
      });
      const data = JSON.parse(response.body || '{}');
      if (response.status === 200) {
        return {
          valid: true,
          message: 'Stripe test key is ACTIVE (sandbox only, no real financial impact)',
          permissions: ['balance:read'],
          risk: 'LOW',
          details: { livemode: data.livemode }
        };
      } else if (response.status === 401) {
        return { valid: false, message: 'Stripe test key is invalid or revoked', permissions: [], risk: 'LOW' };
      }
      return { valid: null, message: `Stripe returned status ${response.status}`, permissions: [], risk: 'LOW' };
    }
  },

  github: {
    name: 'GitHub',
    test: async (token) => {
      const response = await SecretValidator.fetchViaBackground('https://api.github.com/user', {
        method: 'GET',
        headers: {
          'Authorization': `token ${token}`,
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'Origami-Security-Scanner'
        }
      });
      const data = JSON.parse(response.body || '{}');
      if (response.status === 200) {
        const scopes = (response.headers || {})['x-oauth-scopes'] || '';
        return {
          valid: true,
          message: `GitHub token is ACTIVE (user: ${data.login})`,
          permissions: scopes.split(',').map(s => s.trim()).filter(Boolean),
          risk: 'CRITICAL',
          details: { login: data.login, type: data.type, scopes }
        };
      } else if (response.status === 401) {
        return { valid: false, message: 'GitHub token is invalid or revoked', permissions: [], risk: 'LOW' };
      }
      return { valid: null, message: `GitHub returned status ${response.status}`, permissions: [], risk: 'MEDIUM' };
    }
  },

  openai: {
    name: 'OpenAI',
    test: async (key) => {
      const response = await SecretValidator.fetchViaBackground('https://api.openai.com/v1/models', {
        method: 'GET',
        headers: { 'Authorization': `Bearer ${key}` }
      });
      if (response.status === 200) {
        const data = JSON.parse(response.body || '{}');
        const models = (data.data || []).map(m => m.id).slice(0, 10);
        return {
          valid: true,
          message: `OpenAI key is ACTIVE with access to ${(data.data || []).length} models`,
          permissions: ['models:read'],
          risk: 'CRITICAL',
          details: { modelCount: (data.data || []).length, sampleModels: models }
        };
      } else if (response.status === 401) {
        return { valid: false, message: 'OpenAI key is invalid or revoked', permissions: [], risk: 'LOW' };
      }
      return { valid: null, message: `OpenAI returned status ${response.status}`, permissions: [], risk: 'MEDIUM' };
    }
  },

  anthropic: {
    name: 'Anthropic',
    test: async (key) => {
      const response = await SecretValidator.fetchViaBackground('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'x-api-key': key,
          'anthropic-version': '2023-06-01',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 1, messages: [{ role: 'user', content: 'hi' }] })
      });
      if (response.status === 200 || response.status === 201) {
        return {
          valid: true,
          message: 'Anthropic API key is ACTIVE',
          permissions: ['messages:create'],
          risk: 'CRITICAL',
          details: {}
        };
      } else if (response.status === 401) {
        return { valid: false, message: 'Anthropic key is invalid or revoked', permissions: [], risk: 'LOW' };
      } else if (response.status === 400) {
        const data = JSON.parse(response.body || '{}');
        if (data.type === 'error' && data.error && data.error.type !== 'authentication_error') {
          return { valid: true, message: 'Anthropic API key is ACTIVE (confirmed via error response)', permissions: ['messages:create'], risk: 'CRITICAL', details: {} };
        }
        return { valid: false, message: 'Anthropic key validation inconclusive', permissions: [], risk: 'MEDIUM' };
      }
      return { valid: null, message: `Anthropic returned status ${response.status}`, permissions: [], risk: 'MEDIUM' };
    }
  },

  slack: {
    name: 'Slack',
    test: async (token) => {
      const response = await SecretValidator.fetchViaBackground('https://slack.com/api/auth.test', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      });
      const data = JSON.parse(response.body || '{}');
      if (data.ok) {
        return {
          valid: true,
          message: `Slack token is ACTIVE (team: ${data.team}, user: ${data.user})`,
          permissions: [],
          risk: 'CRITICAL',
          details: { team: data.team, user: data.user, teamId: data.team_id }
        };
      }
      return { valid: false, message: `Slack token invalid: ${data.error}`, permissions: [], risk: 'LOW' };
    }
  },

  sendgrid: {
    name: 'SendGrid',
    test: async (key) => {
      const response = await SecretValidator.fetchViaBackground('https://api.sendgrid.com/v3/scopes', {
        method: 'GET',
        headers: { 'Authorization': `Bearer ${key}` }
      });
      if (response.status === 200) {
        const data = JSON.parse(response.body || '{}');
        const scopes = data.scopes || [];
        return {
          valid: true,
          message: `SendGrid key is ACTIVE with ${scopes.length} scopes`,
          permissions: scopes.slice(0, 20),
          risk: scopes.includes('mail.send') ? 'CRITICAL' : 'HIGH',
          details: { scopeCount: scopes.length }
        };
      } else if (response.status === 401 || response.status === 403) {
        return { valid: false, message: 'SendGrid key is invalid or revoked', permissions: [], risk: 'LOW' };
      }
      return { valid: null, message: `SendGrid returned status ${response.status}`, permissions: [], risk: 'MEDIUM' };
    }
  },

  mailgun: {
    name: 'Mailgun',
    test: async (key) => {
      const response = await SecretValidator.fetchViaBackground('https://api.mailgun.net/v3/domains', {
        method: 'GET',
        headers: { 'Authorization': 'Basic ' + btoa('api:' + key) }
      });
      if (response.status === 200) {
        const data = JSON.parse(response.body || '{}');
        const domains = (data.items || []).map(d => d.name);
        return {
          valid: true,
          message: `Mailgun key is ACTIVE with ${domains.length} domain(s)`,
          permissions: ['domains:read'],
          risk: 'CRITICAL',
          details: { domainCount: domains.length, domains: domains.slice(0, 5) }
        };
      } else if (response.status === 401) {
        return { valid: false, message: 'Mailgun key is invalid or revoked', permissions: [], risk: 'LOW' };
      }
      return { valid: null, message: `Mailgun returned status ${response.status}`, permissions: [], risk: 'MEDIUM' };
    }
  },

  gitlab: {
    name: 'GitLab',
    test: async (token) => {
      const response = await SecretValidator.fetchViaBackground('https://gitlab.com/api/v4/user', {
        method: 'GET',
        headers: { 'PRIVATE-TOKEN': token }
      });
      const data = JSON.parse(response.body || '{}');
      if (response.status === 200) {
        return {
          valid: true,
          message: `GitLab token is ACTIVE (user: ${data.username})`,
          permissions: [],
          risk: 'CRITICAL',
          details: { username: data.username, isAdmin: data.is_admin }
        };
      } else if (response.status === 401) {
        return { valid: false, message: 'GitLab token is invalid or revoked', permissions: [], risk: 'LOW' };
      }
      return { valid: null, message: `GitLab returned status ${response.status}`, permissions: [], risk: 'MEDIUM' };
    }
  }
};
