// ============================================================
//  AceCLI – Anthropic Claude Messages API Provider (Streaming)
// ============================================================
import { ApiProvider } from './api-base.js';
import chalk from 'chalk';

export class ClaudeApiProvider extends ApiProvider {
    constructor(options = {}) {
        super('Claude API', {
            apiKeyName: 'claude',
            envVarName: 'ANTHROPIC_API_KEY',
            defaultModel: 'claude-sonnet-4-20250514',
            ...options,
        });
        this.baseUrl = options.baseUrl || 'https://api.anthropic.com';
        this.apiVersion = options.apiVersion || '2023-06-01';
    }

    _extractToken(parsed) {
        // Anthropic SSE format: { type: "content_block_delta", delta: { text: "token" } }
        if (parsed?.type === 'content_block_delta') {
            return parsed.delta?.text || null;
        }
        return null;
    }

    async _callApi(messages, apiKey, options) {
        // Anthropic uses a separate system parameter, not in messages array
        let systemPrompt = null;
        const filteredMessages = [];

        for (const msg of messages) {
            if (msg.role === 'system') {
                systemPrompt = msg.content;
            } else {
                filteredMessages.push({ role: msg.role, content: msg.content });
            }
        }

        const bodyObj = {
            model: options.model || this.model,
            messages: filteredMessages,
            max_tokens: options.maxTokens,
            stream: options.stream,
        };

        if (systemPrompt) {
            bodyObj.system = systemPrompt;
        }

        if (options.temperature !== undefined) {
            bodyObj.temperature = options.temperature;
        }

        const body = JSON.stringify(bodyObj);
        const url = `${this.baseUrl}/v1/messages`;

        const res = await this._makeRequest(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': apiKey,
                'anthropic-version': this.apiVersion,
                'User-Agent': 'AceCLI/1.0',
            },
        }, body);

        // Handle error responses
        if (res.statusCode !== 200) {
            const errorBody = await this._readFullResponse(res);
            let errorMsg = `Anthropic API error (${res.statusCode})`;
            try {
                const parsed = JSON.parse(errorBody);
                errorMsg = parsed.error?.message || errorMsg;
            } catch { }
            throw new Error(errorMsg);
        }

        if (options.stream) {
            process.stdout.write(chalk.white('\n  '));
            let col = 2;

            const output = await this._streamSSE(res, (token) => {
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
            const content = parsed.content?.[0]?.text || '';

            return {
                success: true,
                output: content,
                model: parsed.model || options.model || this.model,
                usage: parsed.usage,
                streamed: false,
            };
        }
    }

    getInfo() {
        return { ...super.getInfo(), name: 'Claude API', provider: 'claude' };
    }
}
