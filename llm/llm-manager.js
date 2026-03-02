// Origami LLM Manager
// Manages multiple LLM providers for security analysis

class LLMManager {
  constructor(provider, apiKey, endpoint = null) {
    this.provider = provider; // 'openai', 'anthropic', 'ollama', 'gemini'
    this.apiKey = apiKey;
    this.endpoint = endpoint || null;
    this.model = null;
  }

  // Set model for the provider
  setModel(model) {
    this.model = model;
  }

  // Truncate context to prevent token limit errors
  truncateContext(context, maxLength = 3000) {
    if (!context || context.length <= maxLength) {
      return context;
    }

    const halfLength = Math.floor(maxLength / 2);
    const firstHalf = context.substring(0, halfLength);
    const lastHalf = context.substring(context.length - halfLength);

    return `${firstHalf}\n\n... [truncated ${context.length - maxLength} characters] ...\n\n${lastHalf}`;
  }

  // Proxy fetch through background service worker to avoid CORS issues
  // Chrome extension popups send Origin: chrome-extension://[id] which local servers like Ollama reject
  async fetchViaBackground(endpoint, options) {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      return new Promise((resolve, reject) => {
        chrome.runtime.sendMessage({
          action: 'llmRequest',
          endpoint,
          method: options.method || 'POST',
          headers: options.headers || {},
          body: options.body ? JSON.parse(options.body) : undefined
        }, (response) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          if (!response || !response.success) {
            const status = response?.status || 0;
            const errorText = response?.error || 'Request failed';
            reject(new Error(`HTTP ${status}: ${errorText}`));
            return;
          }
          resolve(response.data);
        });
      });
    }
    // Fallback: direct fetch (for non-extension contexts or testing)
    const response = await fetch(endpoint, options);
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorText.substring(0, 200)}`);
    }
    return response.json();
  }

  // Analyze code/findings with LLM
  async analyze(prompt, context, options = {}) {
    const { temperature = 0.3, maxTokens = 1000, systemPrompt } = options;

    try {
      switch (this.provider) {
        case 'openai':
          return await this.analyzeWithOpenAI(prompt, context, temperature, maxTokens, systemPrompt);
        case 'anthropic':
          return await this.analyzeWithAnthropic(prompt, context, temperature, maxTokens, systemPrompt);
        case 'gemini':
          return await this.analyzeWithGemini(prompt, context, temperature, maxTokens, systemPrompt);
        case 'ollama':
          return await this.analyzeWithOllama(prompt, context, temperature, maxTokens, systemPrompt);
        default:
          throw new Error(`Unknown provider: ${this.provider}`);
      }
    } catch (error) {
      throw new Error(`LLM analysis failed: ${error.message}`);
    }
  }

  // OpenAI API
  async analyzeWithOpenAI(prompt, context, temperature, maxTokens, systemPrompt) {
    const model = this.model || 'gpt-4o';
    const endpoint = this.endpoint || 'https://api.openai.com/v1/chat/completions';
    const sysMsg = systemPrompt || 'You are a cybersecurity expert analyzing code for vulnerabilities and security issues. Provide clear, actionable insights.';

    try {
      const data = await this.fetchViaBackground(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`
        },
        body: JSON.stringify({
          model,
          messages: [
            {
              role: 'system',
              content: sysMsg
            },
            {
              role: 'user',
              content: `${prompt}\n\nContext:\n${this.truncateContext(context, 3000)}`
            }
          ],
          temperature,
          max_tokens: maxTokens
        })
      });

      return {
        provider: 'openai',
        model,
        response: data.choices[0].message.content,
        usage: data.usage
      };
    } catch (error) {
      throw new Error(error.message || 'OpenAI API request failed');
    }
  }

  // Anthropic Claude API
  async analyzeWithAnthropic(prompt, context, temperature, maxTokens, systemPrompt) {
    const model = this.model || 'claude-sonnet-4-6';
    const endpoint = this.endpoint || 'https://api.anthropic.com/v1/messages';
    const sysMsg = systemPrompt || 'You are a cybersecurity expert analyzing code for vulnerabilities and security issues. Provide clear, actionable insights.';

    try {
      const data = await this.fetchViaBackground(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': this.apiKey,
          'anthropic-version': '2023-06-01',
          'anthropic-dangerous-direct-browser-access': 'true'
        },
        body: JSON.stringify({
          model,
          max_tokens: maxTokens,
          temperature,
          system: sysMsg,
          messages: [
            {
              role: 'user',
              content: `${prompt}\n\nContext:\n${this.truncateContext(context, 3000)}`
            }
          ]
        })
      });

      return {
        provider: 'anthropic',
        model,
        response: data.content[0].text,
        usage: data.usage
      };
    } catch (error) {
      throw new Error(error.message || 'Anthropic API request failed');
    }
  }

  // Google Gemini API
  async analyzeWithGemini(prompt, context, temperature, maxTokens, systemPrompt) {
    const model = this.model || 'gemini-2.5-flash-lite';
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;
    const sysMsg = systemPrompt || 'You are a cybersecurity expert analyzing code for vulnerabilities and security issues. Provide clear, actionable insights.';

    try {
      const data = await this.fetchViaBackground(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-goog-api-key': this.apiKey
        },
        body: JSON.stringify({
          systemInstruction: {
            parts: [{ text: sysMsg }]
          },
          contents: [{
            parts: [{
              text: `${prompt}\n\nContext:\n${this.truncateContext(context, 3000)}`
            }]
          }],
          generationConfig: {
            temperature,
            maxOutputTokens: maxTokens,
            topP: 0.95,
            topK: 40
          },
          thinkingConfig: { thinkingBudget: 0 },
          safetySettings: [
            { category: "HARM_CATEGORY_HARASSMENT", threshold: "BLOCK_NONE" },
            { category: "HARM_CATEGORY_HATE_SPEECH", threshold: "BLOCK_NONE" },
            { category: "HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold: "BLOCK_NONE" },
            { category: "HARM_CATEGORY_DANGEROUS_CONTENT", threshold: "BLOCK_NONE" }
          ]
        })
      });

      // Check finish reason for various issues
      const finishReason = data.candidates?.[0]?.finishReason;
      const textResponse = data.candidates?.[0]?.content?.parts?.[0]?.text;

      if (finishReason === 'SAFETY') {
        throw new Error('Gemini blocked the response due to safety settings. Try a different prompt.');
      }

      if (finishReason === 'MAX_TOKENS' && textResponse) {
        return {
          provider: 'gemini',
          model,
          response: textResponse + '\n\n[Response truncated due to token limit]',
          usage: data.usageMetadata || null,
          truncated: true
        };
      }

      if (finishReason === 'MAX_TOKENS') {
        throw new Error('Response truncated due to token limit. Try reducing input size or increasing max tokens.');
      }

      if (textResponse) {
        if (finishReason && finishReason !== 'STOP') {
          console.warn('Origami: Gemini finish reason:', finishReason, 'but response received');
        }
        return {
          provider: 'gemini',
          model,
          response: textResponse,
          usage: data.usageMetadata || null
        };
      }

      const promptFeedback = data.promptFeedback?.blockReason;
      if (promptFeedback) {
        throw new Error(`Gemini blocked request: ${promptFeedback}. Try a different prompt or model.`);
      }

      if (data.error) {
        throw new Error(data.error.message || 'Gemini API error');
      }

      throw new Error(`Model ${model} may not be available or API key is invalid. Try gemini-2.5-flash-lite instead.`);
    } catch (error) {
      if (error.message.includes('Gemini')) throw error;
      throw new Error(`Gemini connection failed: ${error.message}`);
    }
  }

  // Ollama (local)
  async analyzeWithOllama(prompt, context, temperature, maxTokens, systemPrompt) {
    const model = this.model || 'llama3.1:8b';
    // Ensure endpoint has /api/generate path - restrict to localhost only
    let endpoint = this.endpoint || 'http://127.0.0.1:11434';
    try {
      const parsed = new URL(endpoint);
      if (parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1') {
        throw new Error('Ollama endpoint must be localhost or 127.0.0.1');
      }
    } catch (e) {
      if (e.message.includes('Ollama endpoint')) throw e;
      endpoint = 'http://127.0.0.1:11434';
    }
    if (!endpoint.includes('/api/')) {
      endpoint = endpoint.replace(/\/$/, '') + '/api/generate';
    }

    try {
      const data = await this.fetchViaBackground(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model,
          prompt: `${systemPrompt || 'You are a cybersecurity expert analyzing code for vulnerabilities and security issues. Provide clear, actionable insights.'}\n\n${prompt}\n\nContext:\n${this.truncateContext(context, 3000)}`,
          stream: false,
          options: {
            temperature,
            num_predict: maxTokens
          }
        })
      });

      if (!data.response) {
        console.error('Origami: Ollama response missing data:', data);
        throw new Error('Ollama response missing required field');
      }

      return {
        provider: 'ollama',
        model,
        response: data.response,
        usage: null
      };
    } catch (error) {
      console.error('Origami: Ollama fetch error:', error);
      throw new Error(`Ollama connection failed: ${error.message}. Make sure Ollama is running on ${endpoint}`);
    }
  }

  // Test connection to provider
  async testConnection() {
    try {
      const testPrompt = 'Respond with exactly: Connection successful';
      const result = await this.analyze(testPrompt, 'Test', { maxTokens: 256 });
      return { success: true, response: result.response };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  // Get available models for provider
  static getAvailableModels(provider) {
    const models = {
      openai: [
        { id: 'gpt-5.2', name: 'GPT-5.2' },
        { id: 'gpt-4o', name: 'GPT-4o' },
        { id: 'gpt-4o-mini', name: 'GPT-4o Mini' },
        { id: 'gpt-4.1', name: 'GPT-4.1' },
        { id: 'gpt-4.1-mini', name: 'GPT-4.1 Mini' },
        { id: 'gpt-4-turbo', name: 'GPT-4 Turbo' }
      ],
      anthropic: [
        { id: 'claude-sonnet-4-6', name: 'Claude Sonnet 4.6' },
        { id: 'claude-opus-4-6', name: 'Claude Opus 4.6' },
        { id: 'claude-sonnet-4-5-20250929', name: 'Claude Sonnet 4.5' },
        { id: 'claude-haiku-4-5-20251001', name: 'Claude Haiku 4.5' }
      ],
      gemini: [
        { id: 'gemini-2.5-flash', name: 'Gemini 2.5 Flash' },
        { id: 'gemini-2.5-flash-lite', name: 'Gemini 2.5 Flash Lite' },
        { id: 'gemini-2.5-pro', name: 'Gemini 2.5 Pro' }
      ],
      ollama: [
        { id: 'gemma3:4b', name: 'Gemma 3 4B' },
        { id: 'llama3.1:8b', name: 'Llama 3.1 8B' },
        { id: 'llama3.2:3b', name: 'Llama 3.2 3B' },
        { id: 'qwen2.5-coder:14b', name: 'Qwen 2.5 Coder 14B' },
        { id: 'phi4:latest', name: 'Phi-4' },
        { id: 'phi4-reasoning:plus', name: 'Phi-4 Reasoning Plus' },
        { id: 'mistral', name: 'Mistral' },
        { id: 'codellama', name: 'Code Llama' },
        { id: 'deepseek-coder', name: 'DeepSeek Coder' }
      ]
    };

    return models[provider] || [];
  }
}

// Rate limiter to prevent API abuse
class RateLimiter {
  constructor(requestsPerMinute = 10) {
    this.requestsPerMinute = requestsPerMinute;
    this.requests = [];
  }

  async waitForSlot() {
    while (true) {
      const now = Date.now();
      this.requests = this.requests.filter(time => time > now - 60000);
      if (this.requests.length < this.requestsPerMinute) {
        this.requests.push(Date.now());
        return;
      }
      const oldestRequest = this.requests[0];
      const waitTime = oldestRequest + 60000 - now;
      if (waitTime > 0) {
        await new Promise(resolve => setTimeout(resolve, waitTime));
      }
    }
  }
}

// Export for use in extension
if (typeof module !== 'undefined' && module.exports) {
  module.exports = LLMManager;
}
