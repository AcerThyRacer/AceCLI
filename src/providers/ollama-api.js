// ============================================================
//  AceCLI – Ollama Local API Provider (Streaming via NDJSON)
// ============================================================
import { ApiProvider } from './api-base.js';
import chalk from 'chalk';

export class OllamaApiProvider extends ApiProvider {
    constructor(options = {}) {
        super('Ollama API', {
            apiKeyName: null,   // No API key needed (local)
            envVarName: null,
            defaultModel: 'llama3',
            ...options,
        });
        this.baseUrl = options.baseUrl || 'http://localhost:11434';
    }

    // Ollama is "installed" if the server is responding
    async isInstalled() {
        try {
            const res = await this._makeRequest(`${this.baseUrl}/api/tags`, {
                method: 'GET',
                headers: {},
                timeout: 3000,
            });
            const data = await this._readFullResponse(res);
            return res.statusCode === 200;
        } catch {
            return false;
        }
    }

    // Override getApiKey — Ollama doesn't need one
    getApiKey() {
        return 'local';
    }

    _extractToken(parsed) {
        // Ollama NDJSON format: { message: { content: "token" }, done: false }
        if (parsed?.done) return null;
        return parsed?.message?.content || null;
    }

    async _callApi(messages, _apiKey, options) {
        const body = JSON.stringify({
            model: options.model || this.model,
            messages,
            stream: options.stream,
            options: {
                num_predict: options.maxTokens,
                temperature: options.temperature,
            },
        });

        const url = `${this.baseUrl}/api/chat`;

        const res = await this._makeRequest(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            timeout: 300000, // Ollama can be slow on first load
        }, body);

        // Handle error responses
        if (res.statusCode !== 200) {
            const errorBody = await this._readFullResponse(res);
            let errorMsg = `Ollama API error (${res.statusCode})`;
            try {
                const parsed = JSON.parse(errorBody);
                errorMsg = parsed.error || errorMsg;
            } catch { }
            throw new Error(errorMsg);
        }

        if (options.stream) {
            process.stdout.write(chalk.white('\n  '));
            let col = 2;

            // Ollama uses NDJSON, not SSE
            const output = await this._streamNDJSON(res, (token) => {
                for (const char of token) {
                    if (char === '\n') {
                        process.stdout.write('\n  ');
                        col = 2;
                    } else {
                        process.stdout.write(chalk.white(char));
                        col++;
                        if (col > 100 && char === ' ') {
                            process.stdout.write('\n  ');
                            col = 2;
                        }
                    }
                }
            });

            process.stdout.write('\n\n');

            return {
                success: true,
                output,
                model: options.model || this.model,
                streamed: true,
            };
        } else {
            const data = await this._readFullResponse(res);
            const parsed = JSON.parse(data);
            const content = parsed.message?.content || '';

            return {
                success: true,
                output: content,
                model: parsed.model || options.model || this.model,
                streamed: false,
            };
        }
    }

    // List available models from the Ollama server
    async listModels() {
        try {
            const res = await this._makeRequest(`${this.baseUrl}/api/tags`, {
                method: 'GET',
                headers: {},
                timeout: 5000,
            });
            const data = await this._readFullResponse(res);
            const parsed = JSON.parse(data);
            return parsed.models || [];
        } catch {
            return [];
        }
    }

    getInfo() {
        return { ...super.getInfo(), name: 'Ollama API', provider: 'ollama', type: 'local' };
    }
}
