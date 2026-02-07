// ============================================================
//  AceCLI – Token Usage & Cost Tracker
//  - Per-provider token counting (GPT tokenizer approximation)
//  - Cost estimation based on published API pricing
//  - Session and cumulative totals
// ============================================================

// Approximate pricing per 1M tokens (USD) — as of early 2026
const PRICING = {
    openai: {
        name: 'OpenAI GPT-4',
        input: 30.00,   // $30/1M input tokens
        output: 60.00,  // $60/1M output tokens
    },
    'openai-mini': {
        name: 'OpenAI GPT-4o-mini',
        input: 0.15,
        output: 0.60,
    },
    claude: {
        name: 'Claude 3.5 Sonnet',
        input: 3.00,
        output: 15.00,
    },
    'claude-opus': {
        name: 'Claude 3 Opus',
        input: 15.00,
        output: 75.00,
    },
    gemini: {
        name: 'Gemini 1.5 Pro',
        input: 7.00,
        output: 21.00,
    },
    'gemini-flash': {
        name: 'Gemini 1.5 Flash',
        input: 0.075,
        output: 0.30,
    },
    ollama: {
        name: 'Ollama (Local)',
        input: 0,
        output: 0,
    },
    copilot: {
        name: 'GitHub Copilot',
        input: 0,   // Subscription-based
        output: 0,
    },
};

export class CostTracker {
    constructor(options = {}) {
        this._usage = new Map(); // provider → { inputTokens, outputTokens, requests }
        this._customPricing = options.pricing || {};
        this._sessionStart = new Date().toISOString();
    }

    /**
     * Estimate token count from text using GPT tokenizer approximation.
     * Approximation: ~4 characters per token for English text.
     * @param {string} text
     * @returns {number}
     */
    static estimateTokens(text) {
        if (!text) return 0;
        return Math.ceil(text.length / 4);
    }

    /**
     * Track token usage for a provider.
     * @param {string} provider - Provider name
     * @param {number} inputTokens - Number of input tokens
     * @param {number} outputTokens - Number of output tokens
     */
    trackUsage(provider, inputTokens, outputTokens) {
        const key = provider.toLowerCase();
        if (!this._usage.has(key)) {
            this._usage.set(key, { inputTokens: 0, outputTokens: 0, requests: 0 });
        }
        const entry = this._usage.get(key);
        entry.inputTokens += inputTokens;
        entry.outputTokens += outputTokens;
        entry.requests++;
    }

    /**
     * Track usage by raw text (auto-estimates tokens).
     * @param {string} provider
     * @param {string} inputText
     * @param {string} outputText
     */
    trackText(provider, inputText, outputText) {
        const input = CostTracker.estimateTokens(inputText);
        const output = CostTracker.estimateTokens(outputText);
        this.trackUsage(provider, input, output);
    }

    /**
     * Get pricing for a provider.
     * @param {string} provider
     * @returns {{ name: string, input: number, output: number }}
     */
    getPricing(provider) {
        const key = provider.toLowerCase();
        return this._customPricing[key] || PRICING[key] || PRICING.ollama;
    }

    /**
     * Calculate cost for a specific usage.
     * @param {string} provider
     * @param {number} inputTokens
     * @param {number} outputTokens
     * @returns {number} Cost in USD
     */
    calculateCost(provider, inputTokens, outputTokens) {
        const pricing = this.getPricing(provider);
        const inputCost = (inputTokens / 1_000_000) * pricing.input;
        const outputCost = (outputTokens / 1_000_000) * pricing.output;
        return inputCost + outputCost;
    }

    /**
     * Get a full cost report for all providers.
     * @returns {{ providers: Object, totalCost: number, totalTokens: number, sessionStart: string }}
     */
    getCostReport() {
        const providers = {};
        let totalCost = 0;
        let totalTokens = 0;

        for (const [key, usage] of this._usage) {
            const cost = this.calculateCost(key, usage.inputTokens, usage.outputTokens);
            const pricing = this.getPricing(key);
            providers[key] = {
                name: pricing.name,
                inputTokens: usage.inputTokens,
                outputTokens: usage.outputTokens,
                totalTokens: usage.inputTokens + usage.outputTokens,
                requests: usage.requests,
                cost,
                costFormatted: cost > 0 ? `$${cost.toFixed(4)}` : 'Free',
            };
            totalCost += cost;
            totalTokens += usage.inputTokens + usage.outputTokens;
        }

        return {
            providers,
            totalCost,
            totalCostFormatted: totalCost > 0 ? `$${totalCost.toFixed(4)}` : 'Free',
            totalTokens,
            sessionStart: this._sessionStart,
        };
    }

    /**
     * Get usage for a specific provider.
     * @param {string} provider
     * @returns {{ inputTokens: number, outputTokens: number, requests: number, cost: number } | null}
     */
    getProviderUsage(provider) {
        const key = provider.toLowerCase();
        const usage = this._usage.get(key);
        if (!usage) return null;
        return {
            ...usage,
            cost: this.calculateCost(key, usage.inputTokens, usage.outputTokens),
        };
    }

    /**
     * Reset all tracked usage.
     */
    reset() {
        this._usage.clear();
        this._sessionStart = new Date().toISOString();
    }

    /**
     * Format cost status for dashboard display.
     * @returns {string}
     */
    formatCostStatus() {
        const report = this.getCostReport();
        const lines = [`  💰 Cost Tracker: ${report.totalCostFormatted} (${report.totalTokens.toLocaleString()} tokens)`];

        for (const [, data] of Object.entries(report.providers)) {
            lines.push(`     ${data.name}: ${data.costFormatted} (${data.totalTokens.toLocaleString()} tokens, ${data.requests} req)`);
        }

        if (Object.keys(report.providers).length === 0) {
            lines.push('     No usage recorded yet');
        }

        return lines.join('\n');
    }

    /**
     * Get all available pricing tiers.
     * @returns {Object}
     */
    static getPricingTable() {
        return { ...PRICING };
    }
}
