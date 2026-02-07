// ============================================================
//  AceCLI – Per-Provider Rate Limiter (Sliding Window)
//  - Token bucket with burst allowance
//  - Configurable per-provider limits
//  - Dashboard-ready statistics
// ============================================================

const DEFAULT_LIMITS = {
    openai: { maxRequests: 60, windowMs: 60_000 },  // 60 req/min
    claude: { maxRequests: 60, windowMs: 60_000 },
    gemini: { maxRequests: 60, windowMs: 60_000 },
    ollama: { maxRequests: 120, windowMs: 60_000 },  // Local — generous
    copilot: { maxRequests: 30, windowMs: 60_000 },
    default: { maxRequests: 60, windowMs: 60_000 },
};

export class RateLimiter {
    constructor(options = {}) {
        this.limits = { ...DEFAULT_LIMITS, ...options.limits };
        this._windows = new Map(); // provider → [timestamps]
        this._totalRequests = 0;
        this._totalThrottled = 0;
    }

    /**
     * Try to acquire a slot for the given provider.
     * @param {string} provider - Provider name (e.g., 'openai')
     * @returns {{ allowed: boolean, remaining: number, retryAfterMs: number, limit: number }}
     */
    tryAcquire(provider) {
        const key = provider.toLowerCase();
        const config = this.limits[key] || this.limits.default;
        const now = Date.now();

        // Initialize window if needed
        if (!this._windows.has(key)) {
            this._windows.set(key, []);
        }

        const window = this._windows.get(key);

        // Evict timestamps outside the sliding window
        const cutoff = now - config.windowMs;
        while (window.length > 0 && window[0] <= cutoff) {
            window.shift();
        }

        const remaining = config.maxRequests - window.length;

        if (remaining <= 0) {
            // Throttled — calculate when the oldest request expires
            const retryAfterMs = window[0] + config.windowMs - now;
            this._totalThrottled++;
            return {
                allowed: false,
                remaining: 0,
                retryAfterMs: Math.max(0, retryAfterMs),
                limit: config.maxRequests,
            };
        }

        // Allow the request
        window.push(now);
        this._totalRequests++;

        return {
            allowed: true,
            remaining: remaining - 1,
            retryAfterMs: 0,
            limit: config.maxRequests,
        };
    }

    /**
     * Get rate limit status for a provider without consuming a slot.
     * @param {string} provider
     * @returns {{ remaining: number, limit: number, windowMs: number, used: number }}
     */
    getStatus(provider) {
        const key = provider.toLowerCase();
        const config = this.limits[key] || this.limits.default;
        const now = Date.now();

        if (!this._windows.has(key)) {
            return { remaining: config.maxRequests, limit: config.maxRequests, windowMs: config.windowMs, used: 0 };
        }

        const window = this._windows.get(key);
        const cutoff = now - config.windowMs;
        const active = window.filter(t => t > cutoff).length;

        return {
            remaining: Math.max(0, config.maxRequests - active),
            limit: config.maxRequests,
            windowMs: config.windowMs,
            used: active,
        };
    }

    /**
     * Reset rate limit window for a specific provider or all providers.
     * @param {string} [provider] - Optional provider name; omit to reset all
     */
    reset(provider) {
        if (provider) {
            this._windows.delete(provider.toLowerCase());
        } else {
            this._windows.clear();
        }
    }

    /**
     * Get aggregate statistics.
     * @returns {{ totalRequests: number, totalThrottled: number, providers: Object }}
     */
    getStats() {
        const providers = {};
        for (const [key, window] of this._windows) {
            const config = this.limits[key] || this.limits.default;
            const now = Date.now();
            const cutoff = now - config.windowMs;
            const active = window.filter(t => t > cutoff).length;
            providers[key] = {
                used: active,
                limit: config.maxRequests,
                remaining: Math.max(0, config.maxRequests - active),
            };
        }

        return {
            totalRequests: this._totalRequests,
            totalThrottled: this._totalThrottled,
            providers,
        };
    }

    /**
     * Set custom limits for a provider.
     * @param {string} provider
     * @param {{ maxRequests: number, windowMs: number }} config
     */
    setLimit(provider, config) {
        this.limits[provider.toLowerCase()] = { ...config };
    }

    /**
     * Format rate limit status for dashboard display.
     * @returns {string}
     */
    formatStatus() {
        const stats = this.getStats();
        const lines = [
            `  ⏱ Rate Limiter: ${this._totalThrottled > 0 ? 'ACTIVE (throttled: ' + this._totalThrottled + ')' : 'ACTIVE'}`,
        ];

        for (const [provider, data] of Object.entries(stats.providers)) {
            lines.push(`     ${provider}: ${data.used}/${data.limit} (${data.remaining} remaining)`);
        }

        if (Object.keys(stats.providers).length === 0) {
            lines.push('     No requests yet');
        }

        return lines.join('\n');
    }
}
