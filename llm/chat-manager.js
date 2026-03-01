// Origami AI Partner Chat Manager
// Core conversation orchestrator: message assembly, tool call loop, history persistence

class ChatManager {
  constructor(tabId, domain) {
    this.tabId = tabId;
    this.domain = domain || 'unknown';
    this.contextBuilder = new ContextBuilder();
    this.chatTools = new ChatTools(tabId);
    this.rateLimiter = new RateLimiter(10);
    this.conversation = {
      id: this._generateId(),
      domain: this.domain,
      tabId: tabId,
      messages: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    // Token budget constants
    this.TOKEN_BUDGET = {
      systemPrompt: 2000,
      tier1Context: 400,
      responseReservation: 2000,
      maxTotal: 16000
    };

    this.MAX_TOOL_ITERATIONS = 5;

    // Optional cached context passed from popup.js
    this._securityResults = null;
    this._currentFindings = null;
  }

  // Set context data from popup.js globals (avoids redundant storage reads)
  setContext(securityResults, currentFindings) {
    this._securityResults = securityResults;
    this._currentFindings = currentFindings;
    // Also pass to tools layer so tool executions can use local data
    if (this.chatTools) {
      this.chatTools._cachedResults = securityResults;
      this.chatTools._cachedFindings = currentFindings ? { secrets: currentFindings } : null;
      this.chatTools._cachedFindingsTimestamp = Date.now();
      this.chatTools._cachedResultsTimestamp = Date.now();
    }
  }

  // Main entry point: send a user message and get a response
  // onChunk: optional callback for future streaming support
  async sendMessage(userMessage, onChunk) {
    if (!userMessage || typeof userMessage !== 'string') {
      return { response: 'Please enter a message.', toolsUsed: [] };
    }

    try {
      await this.rateLimiter.waitForSlot();
    } catch (e) {
      return { response: 'Rate limit reached. Please wait a moment before sending another message.', toolsUsed: [] };
    }

    // Add user message to conversation (enforce size limit to prevent cost amplification)
    const MAX_USER_MESSAGE_LENGTH = 32000;
    const truncatedMessage = userMessage.length > MAX_USER_MESSAGE_LENGTH
      ? userMessage.substring(0, MAX_USER_MESSAGE_LENGTH) + '\n\n[Message truncated - exceeded maximum length]'
      : userMessage;
    this.conversation.messages.push({
      role: 'user',
      content: truncatedMessage,
      timestamp: new Date().toISOString()
    });

    const toolsUsed = [];
    let iterations = 0;
    let finalResponse = '';

    try {
      // Fetch fresh context data
      const securityResults = await this.chatTools._getSecurityResults();
      const allFindings = await this.chatTools._getAllFindings();
      const secrets = allFindings?.secrets || [];
      const scanSummary = this.contextBuilder.buildScanSummary(securityResults, secrets);

      // Build system prompt
      const systemPrompt = this.contextBuilder.buildSystemPrompt(
        this.domain,
        securityResults?.timestamp || new Date().toISOString(),
        scanSummary
      );

      // Tool call loop
      let currentResponse = '';
      let toolMessages = [];

      while (iterations < this.MAX_TOOL_ITERATIONS) {
        iterations++;

        // Build message array
        const messages = this._buildMessages(systemPrompt, toolMessages);

        // Get provider config and send to LLM
        const config = await this.getProviderConfig();
        if (!config.enabled) {
          finalResponse = 'LLM not configured. Go to Settings to set up an AI provider.';
          break;
        }

        const providerPayload = this.formatForProvider(messages, config.provider, config);
        const endpoint = this.getProviderEndpoint(config.provider, config.model, config.apiKey, config.endpoint);
        const headers = this.getProviderHeaders(config.provider, config.apiKey);

        const responseData = await this._sendRequest(endpoint, headers, providerPayload);
        currentResponse = this.parseProviderResponse(responseData, config.provider);

        if (!currentResponse) {
          finalResponse = 'No response from LLM. Check your provider configuration.';
          break;
        }

        // Check for tool calls
        const toolCalls = this.chatTools.parseToolCalls(currentResponse);

        if (toolCalls.length === 0) {
          // No more tool calls -- we have our final response
          finalResponse = currentResponse;
          break;
        }

        // Execute tool calls and collect results
        const naturalText = this.chatTools.stripToolCalls(currentResponse);
        let toolResultsText = '';

        for (const tc of toolCalls) {
          toolsUsed.push(tc.tool);
          const result = await this.chatTools.executeTool(tc.tool, tc.params);
          // Sanitize tool results to prevent prompt injection from attacker-controlled scan data
          const sanitized = this.contextBuilder.sanitizeForPrompt(result);
          toolResultsText += sanitized + '\n';
        }

        // Append assistant partial response and tool results for next iteration
        // Tool results always go in a user message so the conversation ends with user role
        // (Anthropic requires the last message to be a user message, not assistant prefill)
        if (naturalText) {
          toolMessages.push({ role: 'assistant', content: naturalText.trim() });
        } else {
          toolMessages.push({ role: 'assistant', content: currentResponse.trim() });
        }
        toolMessages.push({ role: 'user', content: '[Tool Results]\n' + toolResultsText.trim() });
      }

      if (iterations >= this.MAX_TOOL_ITERATIONS && !finalResponse) {
        finalResponse = currentResponse || 'Maximum tool call iterations reached.';
      }
    } catch (e) {
      console.error('Origami: ChatManager.sendMessage error:', e);
      finalResponse = 'Error: ' + e.message;
    }

    // Add final assistant message to conversation
    this.conversation.messages.push({
      role: 'assistant',
      content: finalResponse,
      toolsUsed: toolsUsed,
      timestamp: new Date().toISOString()
    });

    this.conversation.updatedAt = new Date().toISOString();

    // Save history asynchronously
    this.saveHistory().catch(e => console.error('Origami: Failed to save chat history:', e));

    return { response: finalResponse, toolsUsed: toolsUsed };
  }

  // Build the full message array for the LLM
  _buildMessages(systemPrompt, toolMessages) {
    const messages = [];

    // System prompt
    messages.push({ role: 'system', content: systemPrompt });

    // Calculate remaining token budget for conversation history
    const systemTokens = this.estimateTokens(systemPrompt);
    const toolTokens = toolMessages.reduce((sum, m) => sum + this.estimateTokens(m.content), 0);
    const remaining = this.TOKEN_BUDGET.maxTotal - systemTokens - this.TOKEN_BUDGET.responseReservation - toolTokens;

    // Add conversation history within budget
    const history = this.conversation.messages.slice(0, -1); // Exclude the latest user message (added via toolMessages or below)
    if (history.length > 0) {
      const recentMessages = [];
      let tokenCount = 0;
      const latestUserMsg = this.conversation.messages[this.conversation.messages.length - 1];
      const latestTokens = this.estimateTokens(latestUserMsg.content);

      // Walk backward through history, collecting messages that fit
      for (let i = history.length - 1; i >= 0; i--) {
        const msg = history[i];
        const msgTokens = this.estimateTokens(msg.content);
        if (tokenCount + msgTokens + latestTokens > remaining) {
          // Summarize older messages
          const olderMessages = history.slice(0, i + 1);
          if (olderMessages.length > 0) {
            const summary = this.summarizeOlderMessages(olderMessages);
            if (summary) {
              messages.push({ role: 'user', content: 'Previous discussion:\n' + summary });
              messages.push({ role: 'assistant', content: 'Understood, I have context from our previous discussion.' });
            }
          }
          break;
        }
        recentMessages.unshift({ role: msg.role, content: msg.content });
        tokenCount += msgTokens;
      }

      // Add recent history messages
      recentMessages.forEach(m => messages.push(m));
    }

    // Add the latest user message
    const latestMsg = this.conversation.messages[this.conversation.messages.length - 1];
    if (latestMsg && latestMsg.role === 'user') {
      messages.push({ role: 'user', content: latestMsg.content });
    }

    // Add tool call continuation messages
    toolMessages.forEach(m => messages.push(m));

    return messages;
  }

  // Heuristic summarization of older messages (no LLM call)
  summarizeOlderMessages(messages) {
    if (!messages || messages.length === 0) return '';

    const summaryParts = [];
    messages.forEach(msg => {
      if (msg.role === 'user') {
        summaryParts.push('Q: ' + this._firstSentence(msg.content));
      } else if (msg.role === 'assistant') {
        summaryParts.push('A: ' + this._firstSentence(msg.content));
      }
    });

    return summaryParts.join('\n');
  }

  // Estimate token count from text (rough heuristic)
  estimateTokens(text) {
    if (!text) return 0;
    return Math.ceil(text.length / 4);
  }

  // Read LLM settings from chrome.storage.sync
  async getProviderConfig() {
    try {
      const data = await new Promise((resolve, reject) => {
        chrome.storage.sync.get(['settings'], (result) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          resolve(result);
        });
      });

      const settings = data.settings || {};
      const llm = settings.llm || {};

      return {
        enabled: !!llm.enabled,
        provider: llm.provider || 'ollama',
        apiKey: llm.apiKey || '',
        model: llm.model || '',
        endpoint: llm.endpoint || 'http://127.0.0.1:11434',
        temperature: llm.temperature ?? 0.3,
        maxTokens: llm.maxTokens ?? 4096
      };
    } catch (e) {
      console.error('Origami: Failed to read LLM settings:', e);
      return { enabled: false, provider: 'ollama', apiKey: '', model: '', endpoint: '', temperature: 0.3, maxTokens: 4096 };
    }
  }

  // Convert message array to provider-specific format
  formatForProvider(messages, provider, config) {
    const temperature = config.temperature ?? 0.3;
    const maxTokens = config.maxTokens ?? 4096;

    if (provider === 'openai') {
      const formatted = messages.map(m => ({ role: m.role, content: m.content }));
      return {
        model: config.model || 'gpt-4o',
        messages: formatted,
        temperature: temperature,
        max_tokens: maxTokens
      };
    }

    if (provider === 'anthropic') {
      // Anthropic: system prompt goes in separate field, messages are user/assistant only
      let systemContent = '';
      const formatted = [];

      messages.forEach(m => {
        if (m.role === 'system') {
          systemContent += (systemContent ? '\n\n' : '') + m.content;
        } else {
          formatted.push({ role: m.role, content: m.content });
        }
      });

      // Anthropic requires alternating user/assistant messages; merge consecutive same-role
      const merged = this._mergeConsecutiveRoles(formatted);
      merged.forEach(m => { m.content = m.content.trim(); });

      const payload = {
        model: config.model || 'claude-sonnet-4-5-20250929',
        messages: merged,
        temperature: temperature,
        max_tokens: maxTokens
      };
      if (systemContent) payload.system = systemContent.trim();
      return payload;
    }

    if (provider === 'gemini') {
      // Gemini: flatten all messages into a single text
      let systemText = '';
      const parts = [];

      messages.forEach(m => {
        if (m.role === 'system') {
          systemText += m.content + '\n\n';
        } else {
          const prefix = m.role === 'user' ? 'User: ' : 'Assistant: ';
          parts.push(prefix + m.content);
        }
      });

      const fullText = parts.join('\n\n');
      const model = config.model || 'gemini-2.5-flash-lite';

      return {
        systemInstruction: systemText ? { parts: [{ text: systemText }] } : undefined,
        contents: [{ parts: [{ text: fullText }] }],
        generationConfig: {
          temperature: temperature,
          maxOutputTokens: maxTokens
        },
        thinkingConfig: { thinkingBudget: 0 },
        safetySettings: [
          { category: 'HARM_CATEGORY_HARASSMENT', threshold: 'BLOCK_NONE' },
          { category: 'HARM_CATEGORY_HATE_SPEECH', threshold: 'BLOCK_NONE' },
          { category: 'HARM_CATEGORY_SEXUALLY_EXPLICIT', threshold: 'BLOCK_NONE' },
          { category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_NONE' }
        ]
      };
    }

    if (provider === 'ollama') {
      // Ollama: flatten all into a single prompt
      const parts = [];
      messages.forEach(m => {
        if (m.role === 'system') {
          parts.push('[System]\n' + m.content);
        } else if (m.role === 'user') {
          parts.push('[User]\n' + m.content);
        } else {
          parts.push('[Assistant]\n' + m.content);
        }
      });

      return {
        model: config.model || 'llama3.1:8b',
        prompt: parts.join('\n\n'),
        stream: false,
        options: {
          temperature: temperature,
          num_predict: maxTokens
        }
      };
    }

    throw new Error('Unknown provider: ' + provider);
  }

  // Get the API endpoint URL for a provider
  getProviderEndpoint(provider, model, apiKey, customEndpoint) {
    if (provider === 'openai') {
      return 'https://api.openai.com/v1/chat/completions';
    }
    if (provider === 'anthropic') {
      return 'https://api.anthropic.com/v1/messages';
    }
    if (provider === 'gemini') {
      const m = model || 'gemini-2.5-flash-lite';
      return 'https://generativelanguage.googleapis.com/v1beta/models/' + m + ':generateContent';
    }
    if (provider === 'ollama') {
      const base = (customEndpoint || 'http://127.0.0.1:11434').replace(/\/+$/, '');
      return base + '/api/generate';
    }
    throw new Error('Unknown provider: ' + provider);
  }

  // Get request headers for a provider
  getProviderHeaders(provider, apiKey) {
    if (provider === 'openai') {
      return {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + apiKey
      };
    }
    if (provider === 'anthropic') {
      return {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'anthropic-dangerous-direct-browser-access': 'true'
      };
    }
    if (provider === 'gemini') {
      return { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey };
    }
    if (provider === 'ollama') {
      return { 'Content-Type': 'application/json' };
    }
    return { 'Content-Type': 'application/json' };
  }

  // Parse the response text from provider-specific response format
  parseProviderResponse(data, provider) {
    if (!data) return '';

    if (provider === 'openai') {
      return data.choices?.[0]?.message?.content || '';
    }
    if (provider === 'anthropic') {
      return data.content?.[0]?.text || '';
    }
    if (provider === 'gemini') {
      return data.candidates?.[0]?.content?.parts?.[0]?.text || '';
    }
    if (provider === 'ollama') {
      return data.response || '';
    }

    // Fallback: try all known shapes
    return data.choices?.[0]?.message?.content ||
           data.content?.[0]?.text ||
           data.candidates?.[0]?.content?.parts?.[0]?.text ||
           data.response ||
           (typeof data === 'string' ? data : '');
  }

  // Send request to LLM via background.js proxy
  async _sendRequest(endpoint, headers, body) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({
        action: 'llmRequest',
        endpoint: endpoint,
        method: 'POST',
        headers: headers,
        body: body
      }, (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        if (!response || !response.success) {
          const errorMsg = response?.error || 'LLM request failed';
          reject(new Error(errorMsg));
          return;
        }
        resolve(response.data);
      });
    });
  }

  // Save conversation history to chrome.storage.local
  async saveHistory() {
    try {
      const key = 'chat_history_' + this.domain;
      const data = await new Promise((resolve, reject) => {
        chrome.storage.local.get([key], (result) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          resolve(result);
        });
      });

      let histories = data[key] || [];

      // Find existing conversation or add new one
      const existingIdx = histories.findIndex(h => h.id === this.conversation.id);
      const trimmed = this._trimConversation(this.conversation);

      if (existingIdx >= 0) {
        histories[existingIdx] = trimmed;
      } else {
        histories.push(trimmed);
      }

      // Keep max 5 conversations, evict oldest
      if (histories.length > 5) {
        histories.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
        histories = histories.slice(0, 5);
      }

      await new Promise((resolve, reject) => {
        chrome.storage.local.set({ [key]: histories }, () => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          resolve();
        });
      });
    } catch (e) {
      console.error('Origami: saveHistory error:', e);
    }
  }

  // Load conversation history from chrome.storage.local
  async loadHistory() {
    try {
      const key = 'chat_history_' + this.domain;
      const data = await new Promise((resolve, reject) => {
        chrome.storage.local.get([key], (result) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          resolve(result);
        });
      });

      const histories = data[key] || [];
      if (histories.length === 0) return null;

      // Find most recent conversation that is less than 1 hour old
      const oneHourAgo = new Date(Date.now() - 3600000).toISOString();
      const recent = histories
        .filter(h => h.updatedAt > oneHourAgo)
        .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));

      if (recent.length > 0) {
        this.conversation = recent[0];
        return this.conversation;
      }

      return null;
    } catch (e) {
      console.error('Origami: loadHistory error:', e);
      return null;
    }
  }

  // Clear current conversation and start fresh
  clearConversation() {
    this.conversation = {
      id: this._generateId(),
      domain: this.domain,
      tabId: this.tabId,
      messages: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    // Reset tool caches
    this.chatTools._cachedResults = null;
    this.chatTools._cachedFindings = null;
    this.chatTools._cachedFindingsTimestamp = 0;
    this.chatTools._cachedResultsTimestamp = 0;
  }

  // Return current conversation for UI rendering
  getConversation() {
    return this.conversation;
  }

  // -- Private helpers --

  // Trim conversation to max 50 message pairs (100 messages)
  _trimConversation(conv) {
    const trimmed = { ...conv };
    if (trimmed.messages.length > 100) {
      trimmed.messages = trimmed.messages.slice(-100);
    }
    return trimmed;
  }

  // Merge consecutive messages with the same role (required for Anthropic)
  _mergeConsecutiveRoles(messages) {
    if (messages.length === 0) return messages;

    const merged = [messages[0]];
    for (let i = 1; i < messages.length; i++) {
      const prev = merged[merged.length - 1];
      if (messages[i].role === prev.role) {
        prev.content += '\n\n' + messages[i].content;
      } else {
        merged.push({ ...messages[i] });
      }
    }

    // Anthropic requires first message to be user role
    if (merged.length > 0 && merged[0].role !== 'user') {
      merged.unshift({ role: 'user', content: 'Hello.' });
    }

    return merged;
  }

  // Extract first sentence from text
  _firstSentence(text) {
    if (!text) return '';
    const clean = text.replace(/\n+/g, ' ').trim();
    const match = clean.match(/^(.+?[.!?])\s/);
    if (match) return match[1];
    return clean.substring(0, 120) + (clean.length > 120 ? '...' : '');
  }

  // Generate a simple unique ID
  _generateId() {
    return 'chat_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
  }
}

window.ChatManager = ChatManager;
