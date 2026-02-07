// ============================================================
//  AceCLI – Cost Estimation Table
//  Pricing per 1M tokens (input / output) in USD
// ============================================================

const MODEL_PRICING = {
    // OpenAI
    'gpt-4o': { input: 2.50, output: 10.00, provider: 'openai' },
    'gpt-4o-mini': { input: 0.15, output: 0.60, provider: 'openai' },
    'gpt-4-turbo': { input: 10.00, output: 30.00, provider: 'openai' },
    'gpt-4': { input: 30.00, output: 60.00, provider: 'openai' },
    'gpt-3.5-turbo': { input: 0.50, output: 1.50, provider: 'openai' },
    'o1': { input: 15.00, output: 60.00, provider: 'openai' },
    'o1-mini': { input: 3.00, output: 12.00, provider: 'openai' },
    'o3-mini': { input: 1.10, output: 4.40, provider: 'openai' },

    // Anthropic Claude
    'claude-3-5-sonnet-20241022': { input: 3.00, output: 15.00, provider: 'anthropic' },
    'claude-3-5-haiku-20241022': { input: 0.80, output: 4.00, provider: 'anthropic' },
    'claude-3-opus-20240229': { input: 15.00, output: 75.00, provider: 'anthropic' },
    'claude-3-sonnet': { input: 3.00, output: 15.00, provider: 'anthropic' },
    'claude-3-haiku': { input: 0.25, output: 1.25, provider: 'anthropic' },
    'claude-sonnet': { input: 3.00, output: 15.00, provider: 'anthropic' },
    'claude-haiku': { input: 0.80, output: 4.00, provider: 'anthropic' },

    // Google Gemini
    'gemini-2.0-flash': { input: 0.10, output: 0.40, provider: 'google' },
    'gemini-1.5-flash': { input: 0.075, output: 0.30, provider: 'google' },
    'gemini-1.5-pro': { input: 1.25, output: 5.00, provider: 'google' },
    'gemini-pro': { input: 0.50, output: 1.50, provider: 'google' },
    'gemini-flash': { input: 0.075, output: 0.30, provider: 'google' },

    // Ollama (local — free)
    'llama3': { input: 0, output: 0, provider: 'ollama' },
    'llama3.1': { input: 0, output: 0, provider: 'ollama' },
    'llama3.2': { input: 0, output: 0, provider: 'ollama' },
    'mistral': { input: 0, output: 0, provider: 'ollama' },
    'mixtral': { input: 0, output: 0, provider: 'ollama' },
    'codellama': { input: 0, output: 0, provider: 'ollama' },
    'phi3': { input: 0, output: 0, provider: 'ollama' },
    'qwen2': { input: 0, output: 0, provider: 'ollama' },
    'deepseek-r1': { input: 0, output: 0, provider: 'ollama' },
};

/**
 * Estimate the cost of a request based on model and token counts.
 * @param {string} model - Model identifier
 * @param {number} inputTokens - Number of input tokens
 * @param {number} outputTokens - Number of output tokens
 * @returns {{cost: number, inputCost: number, outputCost: number, model: string, found: boolean}}
 */
export function estimateCost(model, inputTokens, outputTokens) {
    // Try exact match first
    let pricing = MODEL_PRICING[model];

    // Try partial match (e.g., 'gpt-4o' matches 'gpt-4o-2024-01-01')
    if (!pricing) {
        for (const [key, value] of Object.entries(MODEL_PRICING)) {
            if (model.startsWith(key) || key.startsWith(model)) {
                pricing = value;
                break;
            }
        }
    }

    if (!pricing) {
        return { cost: 0, inputCost: 0, outputCost: 0, model, found: false };
    }

    const inputCost = (inputTokens / 1_000_000) * pricing.input;
    const outputCost = (outputTokens / 1_000_000) * pricing.output;

    return {
        cost: inputCost + outputCost,
        inputCost,
        outputCost,
        model,
        found: true,
    };
}

/**
 * Estimate token count from text (rough: ~4 chars per token for English).
 * @param {string} text
 * @returns {number}
 */
export function estimateTokens(text) {
    if (!text) return 0;
    // Rough heuristic: ~4 characters per token for English
    return Math.ceil(text.length / 4);
}

/**
 * Format cost for display.
 * @param {number} cost - Cost in USD
 * @returns {string}
 */
export function formatCost(cost) {
    if (cost === 0) return 'free';
    if (cost < 0.001) return `<$0.001`;
    if (cost < 0.01) return `$${cost.toFixed(4)}`;
    if (cost < 1) return `$${cost.toFixed(3)}`;
    return `$${cost.toFixed(2)}`;
}

export { MODEL_PRICING };
