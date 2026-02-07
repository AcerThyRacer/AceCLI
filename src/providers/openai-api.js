// ============================================================
//  AceCLI – OpenAI Chat Completions API Provider (Streaming)
// ============================================================
import { ApiProvider } from './api-base.js';
import chalk from 'chalk';

export class OpenAIApiProvider extends ApiProvider {
    constructor(options = {}) {
        super('OpenAI API', {
            apiKeyName: 'openai',
            envVarName: 'OPENAI_API_KEY',
            defaultModel: 'gpt-4o',
            ...options,
        });
        this.baseUrl = options.baseUrl || 'https://api.openai.com';
    }

    _extractToken(parsed) {
        // OpenAI SSE format: { choices: [{ delta: { content: "token" } }] }
        return parsed?.choices?.[0]?.delta?.content || null;
    }

    async _callApi(messages, apiKey, options) {
        const body = JSON.stringify({
            model: options.model || this.model,
            messages,
            stream: options.stream,
            max_tokens: options.maxTokens,
            temperature: options.temperature,
        });

        const url = `${this.baseUrl}/v1/chat/completions`;

        const res = await this._makeRequest(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`,
                'User-Agent': 'AceCLI/1.0',
            },
        }, body);

        // Handle error responses
        if (res.statusCode !== 200) {
            const errorBody = await this._readFullResponse(res);
            let errorMsg = `OpenAI API error (${res.statusCode})`;
            try {
                const parsed = JSON.parse(errorBody);
                errorMsg = parsed.error?.message || errorMsg;
            } catch { }
            throw new Error(errorMsg);
        }

        if (options.stream) {
            // Stream tokens to terminal in real-time
            process.stdout.write(chalk.white('\n  '));
            let col = 2;

            const output = await this._streamSSE(res, (token) => {
                // Word-wrap at ~80 cols
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
            // Non-streaming
            const data = await this._readFullResponse(res);
            const parsed = JSON.parse(data);
            const content = parsed.choices?.[0]?.message?.content || '';

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
        return { ...super.getInfo(), name: 'OpenAI API', provider: 'openai' };
    }
}
