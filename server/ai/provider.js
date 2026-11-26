// Minimal OpenAI-compatible chat client. Works with any gateway that speaks the
// /chat/completions shape — OpenRouter, DeepSeek, OpenAI, Ollama, or a custom
// URL — so users bring their own key and model. We deliberately avoid a vendor
// SDK to keep "connect any model" a one-adapter promise.

const PRESETS = {
  openrouter: { baseURL: 'https://openrouter.ai/api/v1', label: 'OpenRouter', keyHint: 'sk-or-...' },
  deepseek:   { baseURL: 'https://api.deepseek.com/v1',  label: 'DeepSeek',   keyHint: 'sk-...' },
  openai:     { baseURL: 'https://api.openai.com/v1',    label: 'OpenAI',     keyHint: 'sk-...' },
  ollama:     { baseURL: 'http://127.0.0.1:11434/v1',    label: 'Ollama (local)', keyHint: '(not needed)' },
  custom:     { baseURL: '',                             label: 'Custom',     keyHint: 'your key' },
};

// Curated starting points per task tier (decided with the owner: Chinese models
// are enough, Gemini Flash is the step-up, Anthropic is skipped on cost). These
// are suggestions for the UI; the live list should come from the gateway.
const SUGGESTED_MODELS = {
  openrouter: ['deepseek/deepseek-chat', 'qwen/qwen-2.5-72b-instruct', 'google/gemini-flash-1.5'],
  deepseek:   ['deepseek-chat', 'deepseek-reasoner'],
  openai:     ['gpt-4o-mini', 'gpt-4o'],
  ollama:     ['llama3.1', 'qwen2.5'],
  custom:     [],
};

class AIError extends Error {
  constructor(message, code) { super(message); this.name = 'AIError'; this.code = code || 'error'; }
}

class OpenAICompatProvider {
  constructor({ baseURL, apiKey, model, referer, title, timeoutMs } = {}) {
    this.baseURL = String(baseURL || '').replace(/\/+$/, '');
    this.apiKey = apiKey || '';
    this.model = model || '';
    this.referer = referer || 'https://github.com/webkiller'; // OpenRouter attribution
    this.title = title || 'WebKiller';
    this.timeoutMs = timeoutMs || 60000;
  }

  async chat({ system, user, messages, temperature = 0.2, maxTokens, model, tools, toolChoice, signal } = {}) {
    if (!this.baseURL) throw new AIError('AI endpoint is not configured', 'no_base_url');

    let msgs = messages;
    if (!msgs) {
      msgs = [];
      if (system) msgs.push({ role: 'system', content: system });
      msgs.push({ role: 'user', content: user || '' });
    }

    const body = { model: model || this.model, messages: msgs, temperature };
    if (maxTokens) body.max_tokens = maxTokens;
    if (tools && tools.length) { body.tools = tools; if (toolChoice) body.tool_choice = toolChoice; }
    if (!body.model) throw new AIError('no model selected', 'no_model');

    const payload = JSON.stringify(body);
    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
      // Harmless on gateways that ignore them; expected by OpenRouter.
      'HTTP-Referer': this.referer,
      'X-Title': this.title,
    };
    if (this.apiKey) headers['Authorization'] = `Bearer ${this.apiKey}`;

    const { status, text } = await this._request(`${this.baseURL}/chat/completions`, headers, payload, signal);
    if (status < 200 || status >= 300) {
      let detail = text.slice(0, 300);
      try { detail = JSON.parse(text).error?.message || detail; } catch { /* keep raw */ }
      throw new AIError(`provider returned ${status}: ${detail}`, `http_${status}`);
    }

    let data;
    try { data = JSON.parse(text); } catch { throw new AIError('provider returned invalid JSON', 'bad_json'); }
    const content = data?.choices?.[0]?.message?.content || '';
    const toolCalls = data?.choices?.[0]?.message?.tool_calls || [];
    return { content, usage: data?.usage || null, model: data?.model || body.model, toolCalls };
  }

  // Raw https/http so the request is immune to a process-global
  // NODE_TLS_REJECT_UNAUTHORIZED=0 that scan modules toggle while probing
  // targets: the API key travels here, so TLS verification is forced ON with an
  // explicit agent. One timeout covers headers AND body.
  _request(urlStr, headers, payload, signal) {
    return new Promise((resolve, reject) => {
      if (signal && signal.aborted) { reject(new AIError('aborted', 'aborted')); return; }
      let u;
      try { u = new URL(urlStr); } catch { reject(new AIError('invalid endpoint URL', 'bad_url')); return; }
      const https = require('https');
      const http = require('http');
      const isHttps = u.protocol === 'https:';
      const mod = isHttps ? https : http;
      const opts = { method: 'POST', headers };
      if (isHttps) opts.agent = new https.Agent({ rejectUnauthorized: true });

      const req = mod.request(u, opts, (res) => {
        const chunks = [];
        let size = 0;
        res.on('data', (c) => {
          size += c.length;
          if (size > 16 * 1024 * 1024) req.destroy(new AIError('response too large', 'too_large'));
          else chunks.push(c);
        });
        res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
      });
      if (signal) signal.addEventListener('abort', () => req.destroy(new AIError('aborted', 'aborted')), { once: true });
      req.on('error', (e) => reject(e instanceof AIError ? e : new AIError(`network error: ${e.message}`, 'network')));
      req.setTimeout(this.timeoutMs, () => req.destroy(new AIError('request timed out', 'timeout')));
      req.end(payload);
    });
  }
}

module.exports = { OpenAICompatProvider, PRESETS, SUGGESTED_MODELS, AIError };
