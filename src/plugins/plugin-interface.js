// ============================================================
//  AceCLI – Plugin Interface (Base Class for Plugin Authors)
//  Extend this class to create custom provider plugins.
// ============================================================

/**
 * @typedef {Object} AceProviderPlugin
 * @property {string} name - Display name of the provider
 * @property {Function} execute - Execute a prompt and return result
 * @property {Function} isInstalled - Check if the provider is available
 * @property {Function} getInfo - Return provider metadata
 * @property {Function} [init] - Optional initialization hook
 * @property {Function} [validate] - Optional validation hook
 * @property {Function} [getCapabilities] - Optional capabilities listing
 * @property {Function} [getModels] - Optional model listing
 * @property {Function} [destroy] - Optional cleanup hook
 */

export class AceProviderInterface {
    constructor(name, options = {}) {
        if (new.target === AceProviderInterface) {
            throw new Error('AceProviderInterface is abstract — extend it in your plugin');
        }
        this.name = name;
        this.version = options.version || '1.0.0';
        this.author = options.author || 'unknown';
        this.description = options.description || '';
        this.audit = options.audit || null;
        this._initialized = false;
    }

    // ── Required Methods (override in plugin) ───────────────────

    /**
     * Check if this provider is available and ready to use.
     * @returns {Promise<boolean>}
     */
    async isInstalled() {
        throw new Error(`${this.name}: isInstalled() not implemented`);
    }

    /**
     * Execute a prompt and return the response.
     * @param {string} prompt - The user's prompt
     * @param {Object} options - Execution options
     * @returns {Promise<{success: boolean, output: string, error?: string}>}
     */
    async execute(prompt, options = {}) {
        throw new Error(`${this.name}: execute() not implemented`);
    }

    /**
     * Return metadata about this provider.
     * @returns {Object}
     */
    getInfo() {
        return {
            name: this.name,
            version: this.version,
            author: this.author,
            description: this.description,
            mode: 'plugin',
            type: 'custom',
        };
    }

    // ── Optional Lifecycle Hooks ────────────────────────────────

    /**
     * Initialize the plugin with the AceCLI context.
     * Called once when the plugin is loaded.
     * @param {Object} ctx - AceCLI session context
     */
    async init(ctx) {
        this.audit = ctx?.audit || null;
        this._initialized = true;
    }

    /**
     * Validate that the plugin is correctly configured.
     * @returns {Promise<{valid: boolean, errors?: string[]}>}
     */
    async validate() {
        return { valid: true };
    }

    /**
     * Return a list of capabilities this provider supports.
     * @returns {string[]}
     */
    getCapabilities() {
        return ['text-generation'];
    }

    /**
     * Return available models for this provider.
     * @returns {Promise<string[]>}
     */
    async getModels() {
        return [];
    }

    /**
     * Clean up resources when the plugin is unloaded.
     */
    async destroy() {
        this._initialized = false;
    }

    // ── Audit Helper ────────────────────────────────────────────

    log(event, details = {}) {
        this.audit?.log({
            type: `PLUGIN_${event}`,
            provider: this.name,
            details,
        });
    }
}
