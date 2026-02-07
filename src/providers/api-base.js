// ============================================================
//  AceCLI – Base HTTP API Provider (Streaming + Vault Keys)
//  Direct HTTP integration — no CLI binary required
// ============================================================
import https from 'https';
import http from 'http';
import chalk from 'chalk';
import { classifyError } from '../errors.js';

export class ApiProvider {
    constructor(name, options = {}) {
        this.name = name;
        this.sanitizer = options.sanitizer;
        this.fingerprint = options.fingerprint;
        this.proxy = options.proxy;
        this.audit = options.audit;
        this.trackerBlocker = options.trackerBlocker;
        this.encryption = options.encryption;
        this.ephemeral = options.ephemeral || false;
        this.configManager = options.configManager || null;

        // Provider-specific
        this.apiKeyName = options.apiKeyName || null;     // vault key name, e.g. 'openai'
        this.envVarName = options.envVarName || null;      // e.g. 'OPENAI_API_KEY'
        this.defaultModel = options.defaultModel || null;
        this.model = options.model || this.defaultModel;
        this.maxTokens = options.maxTokens || 4096;
        this.temperature = options.temperature ?? 0.7;
        this.systemPrompt = options.systemPrompt || null;
    }

    // ── API Key Resolution ──────────────────────────────────────
    getApiKey() {
        // 1. Try encrypted vault
        if (this.configManager && this.apiKeyName) {
            const vaultKey = this.configManager.getApiKey(this.apiKeyName);
            if (vaultKey) return vaultKey;
        }
        // 2. Fall back to environment variable
        if (this.envVarName && process.env[this.envVarName]) {
            return process.env[this.envVarName];
        }
        return null;
    }

    // ── Provider Availability Check ─────────────────────────────
    async isInstalled() {
        // API providers are "installed" if we have an API key
        return !!this.getApiKey();
    }

    // ── Sanitization Pipeline ───────────────────────────────────
    sanitizePrompt(prompt) {
        if (!this.sanitizer) return { text: prompt, redactions: [] };
        return this.sanitizer.sanitize(prompt);
    }

    checkInjection(text) {
        if (!this.sanitizer) return { detected: false };
        return this.sanitizer.detectInjection(text);
    }

    // ── HTTP Request with Proxy Support ─────────────────────────
    _makeRequest(url, options, body) {
        return new Promise((resolve, reject) => {
            const parsed = new URL(url);
            const isHttps = parsed.protocol === 'https:';
            const transport = isHttps ? https : http;

            const reqOpts = {
                hostname: parsed.hostname,
                port: parsed.port || (isHttps ? 443 : 80),
                path: parsed.pathname + parsed.search,
                method: options.method || 'POST',
                headers: options.headers || {},
                timeout: options.timeout || 120000,
            };

            // Route through SOCKS proxy if enabled
            if (this.proxy?.enabled && isHttps) {
                reqOpts.agent = this.proxy.getAgent();
            }

            const req = transport.request(reqOpts, (res) => {
                resolve(res);
            });

            req.on('error', reject);
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timed out'));
            });

            if (body) {
                req.write(body);
            }
            req.end();
        });
    }

    // ── Streaming SSE Parser ────────────────────────────────────
    async _streamSSE(res, onToken, onDone) {
        let fullText = '';
        let buffer = '';

        return new Promise((resolve, reject) => {
            res.on('data', (chunk) => {
                buffer += chunk.toString();
                const lines = buffer.split('\n');
                buffer = lines.pop(); // keep incomplete line

                for (const line of lines) {
                    if (line.startsWith('data: ')) {
                        const data = line.slice(6).trim();
                        if (data === '[DONE]') continue;
                        try {
                            const parsed = JSON.parse(data);
                            const token = this._extractToken(parsed);
                            if (token) {
                                fullText += token;
                                onToken(token);
                            }
                        } catch {
                            // Skip malformed JSON chunks
                        }
                    }
                }
            });

            res.on('end', () => {
                if (onDone) onDone(fullText);
                resolve(fullText);
            });

            res.on('error', reject);
        });
    }

    // ── NDJSON Stream Parser (for Ollama) ───────────────────────
    async _streamNDJSON(res, onToken, onDone) {
        let fullText = '';
        let buffer = '';

        return new Promise((resolve, reject) => {
            res.on('data', (chunk) => {
                buffer += chunk.toString();
                const lines = buffer.split('\n');
                buffer = lines.pop();

                for (const line of lines) {
                    if (!line.trim()) continue;
                    try {
                        const parsed = JSON.parse(line);
                        const token = this._extractToken(parsed);
                        if (token) {
                            fullText += token;
                            onToken(token);
                        }
                    } catch {
                        // Skip malformed lines
                    }
                }
            });

            res.on('end', () => {
                if (onDone) onDone(fullText);
                resolve(fullText);
            });

            res.on('error', reject);
        });
    }

    // Override in subclasses to extract token from SSE/NDJSON chunk
    _extractToken(parsed) {
        return null;
    }

    // ── Build Messages Array ────────────────────────────────────
    buildMessages(prompt, conversationHistory = []) {
        const messages = [];

        // System prompt
        if (this.systemPrompt) {
            messages.push({ role: 'system', content: this.systemPrompt });
        }

        // Conversation history
        for (const msg of conversationHistory) {
            messages.push({ role: msg.role, content: msg.content });
        }

        // Current prompt
        messages.push({ role: 'user', content: prompt });

        return messages;
    }

    // ── Full Execution Pipeline ─────────────────────────────────
    async execute(prompt, options = {}) {
        const startTime = Date.now();

        // 1. Check for API key
        const apiKey = this.getApiKey();
        if (!apiKey && this.apiKeyName) {
            return {
                success: false,
                output: '',
                error: `No API key found for ${this.name}. Add one via 🔑 API Key Vault or set ${this.envVarName}.`,
                errorType: 'AUTHENTICATION',
            };
        }

        // 2. Check for prompt injection
        const injection = this.checkInjection(prompt);
        if (injection.detected) {
            this.audit?.log({
                type: 'INJECTION_DETECTED',
                provider: this.name,
                details: { severity: injection.severity, score: injection.score },
            });

            if (injection.severity === 'HIGH' || injection.severity === 'CRITICAL') {
                return {
                    success: false,
                    error: `Prompt injection detected (${injection.severity}, score: ${injection.score}). Blocked.`,
                    injection,
                };
            }
            console.log(chalk.red(`  ⚠ Prompt injection warning (${injection.severity}, score: ${injection.score})`));
        }

        // 3. Sanitize prompt
        const sanitized = this.sanitizePrompt(prompt);
        if (sanitized.redactions.length > 0) {
            console.log(this.sanitizer.formatWarning(sanitized.redactions));
            this.audit?.log({
                type: 'PII_REDACTED',
                provider: this.name,
                details: { count: sanitized.redactions.length },
            });
        }

        // 4. Log the action
        this.audit?.log({
            type: 'PROMPT_SENT',
            provider: this.name,
            details: { length: sanitized.text.length, model: options.model || this.model, mode: 'api' },
        });

        // 5. Execute API call
        let result;
        try {
            const messages = this.buildMessages(sanitized.text, options.conversationHistory || []);
            result = await this._callApi(messages, apiKey, {
                model: options.model || this.model,
                stream: options.stream !== false, // default to streaming
                maxTokens: options.maxTokens || this.maxTokens,
                temperature: options.temperature ?? this.temperature,
            });
        } catch (err) {
            const classified = classifyError(err, { provider: this.name });
            this.audit?.log({
                type: 'PROVIDER_ERROR',
                provider: this.name,
                details: { errorType: classified.type, message: classified.message },
            });
            return {
                success: false,
                output: '',
                error: classified.message,
                advice: classified.advice,
                errorType: classified.type,
            };
        }

        // 6. Sanitize response
        if (result.output && this.sanitizer) {
            const sanitizedResponse = this.sanitizer.sanitize(result.output);
            if (sanitizedResponse.redactions.length > 0) {
                this.audit?.log({
                    type: 'PII_REDACTED_RESPONSE',
                    provider: this.name,
                    details: { count: sanitizedResponse.redactions.length },
                });
            }
            result.output = sanitizedResponse.text;
        }

        // 7. Performance metrics
        const latency = Date.now() - startTime;
        result.latency = latency;

        this.audit?.log({
            type: 'RESPONSE_RECEIVED',
            provider: this.name,
            details: { length: result.output?.length || 0, latencyMs: latency, model: result.model },
        });

        return result;
    }

    // Override in subclasses — makes the actual HTTP API call
    async _callApi(messages, apiKey, options) {
        throw new Error('_callApi() must be implemented by subclass');
    }

    // ── Non-streaming fallback for error responses ──────────────
    async _readFullResponse(res) {
        return new Promise((resolve, reject) => {
            let data = '';
            res.on('data', (chunk) => (data += chunk.toString()));
            res.on('end', () => resolve(data));
            res.on('error', reject);
        });
    }

    // ── Provider Info ───────────────────────────────────────────
    getInfo() {
        return {
            name: this.name,
            command: 'API',
            model: this.model,
            type: this.apiKeyName ? 'cloud' : 'local',
            mode: 'api',
            hasKey: !!this.getApiKey(),
        };
    }
}
