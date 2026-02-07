// ============================================================
//  AceCLI – Google Gemini API Provider (Streaming)
// ============================================================
import { ApiProvider } from './api-base.js';
import chalk from 'chalk';

export class GeminiApiProvider extends ApiProvider {
    constructor(options = {}) {
        super('Gemini API', {
            apiKeyName: 'gemini',
            envVarName: 'GEMINI_API_KEY',
            defaultModel: 'gemini-2.0-flash',
            ...options,
        });
        this.baseUrl = options.baseUrl || 'https://generativelanguage.googleapis.com';
    }

    _extractToken(parsed) {
        // Gemini SSE format: { candidates: [{ content: { parts: [{ text: "token" }] } }] }
        return parsed?.candidates?.[0]?.content?.parts?.[0]?.text || null;
    }

    async _callApi(messages, apiKey, options) {
        // Convert OpenAI-style messages to Gemini format
        const contents = [];
        let systemInstruction = null;

        for (const msg of messages) {
            if (msg.role === 'system') {
                systemInstruction = { parts: [{ text: msg.content }] };
            } else {
                contents.push({
                    role: msg.role === 'assistant' ? 'model' : 'user',
                    parts: [{ text: msg.content }],
                });
            }
        }

        const bodyObj = {
            contents,
            generationConfig: {
                maxOutputTokens: options.maxTokens,
                temperature: options.temperature,
            },
        };

        if (systemInstruction) {
            bodyObj.systemInstruction = systemInstruction;
        }

        const body = JSON.stringify(bodyObj);
        const model = options.model || this.model;

        // Gemini uses different endpoints for streaming vs non-streaming
        const action = options.stream ? 'streamGenerateContent' : 'generateContent';
        const streamParam = options.stream ? '&alt=sse' : '';
        const url = `${this.baseUrl}/v1beta/models/${model}:${action}?key=${apiKey}${streamParam}`;

        const res = await this._makeRequest(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': 'AceCLI/1.0',
            },
        }, body);

        // Handle error responses
        if (res.statusCode !== 200) {
            const errorBody = await this._readFullResponse(res);
            let errorMsg = `Gemini API error (${res.statusCode})`;
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
                model,
                streamed: true,
            };
        } else {
            const data = await this._readFullResponse(res);
            const parsed = JSON.parse(data);
            const content = parsed.candidates?.[0]?.content?.parts?.[0]?.text || '';

            return {
                success: true,
                output: content,
                model,
                streamed: false,
            };
        }
    }

    getInfo() {
        return { ...super.getInfo(), name: 'Gemini API', provider: 'gemini' };
    }
}
