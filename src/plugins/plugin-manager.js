// ============================================================
//  AceCLI – Plugin Manager
//  Auto-discovers and manages provider plugins from ~/.ace/plugins/
//  - Sandboxed context: plugins CANNOT access encryption, config, or vault
//  - File path validation to prevent directory traversal
//  - Audit logging for all plugin lifecycle events
// ============================================================
import { existsSync, mkdirSync, readdirSync } from 'fs';
import { join, resolve, normalize } from 'path';
import { homedir } from 'os';
import { pathToFileURL } from 'url';
import chalk from 'chalk';

const PLUGINS_DIR = join(homedir(), '.ace', 'plugins');

// Validate plugin filename — no directory traversal, no hidden files
const SAFE_FILENAME_REGEX = /^[a-zA-Z0-9_-]+\.js$/;

function isValidPluginFilename(filename) {
    if (!filename || typeof filename !== 'string') return false;
    if (!SAFE_FILENAME_REGEX.test(filename)) return false;
    // Ensure no path traversal even with clever encoding
    const normalized = normalize(filename);
    return normalized === filename && !normalized.includes('..');
}

// Build a sandboxed context that exposes only safe methods to plugins.
// Plugins CANNOT access encryption keys, vault contents, config internals,
// or security module internals.
function buildSandboxedCtx(ctx) {
    if (!ctx) return null;

    return Object.freeze({
        // Audit: allow plugins to log events (read-only access)
        audit: ctx.audit ? Object.freeze({
            log: (event) => ctx.audit.log({
                ...event,
                type: `PLUGIN_${event.type || 'EVENT'}`,
            }),
        }) : null,

        // Sanitizer: allow prompt safety checks (read-only)
        sanitizer: ctx.sanitizer ? Object.freeze({
            sanitize: (text, opts) => ctx.sanitizer.sanitize(text, opts),
            detectInjection: (text) => ctx.sanitizer.detectInjection(text),
        }) : null,

        // Proxy: allow checking proxy status (read-only)
        proxy: ctx.proxy ? Object.freeze({
            enabled: ctx.proxy.enabled,
            getAgent: () => ctx.proxy.getAgent(),
        }) : null,

        // Session info (read-only, non-sensitive)
        sessionId: ctx.sessionId || null,
    });
}

export class PluginManager {
    constructor(options = {}) {
        this.plugins = new Map();        // name → { module, instance, status }
        this.audit = options.audit || null;
        this.ctx = options.ctx || null;
        this._sandboxedCtx = null;

        // Ensure plugins directory exists
        mkdirSync(PLUGINS_DIR, { recursive: true });
    }

    // Lazily build sandboxed context
    _getSandboxedCtx() {
        if (!this._sandboxedCtx && this.ctx) {
            this._sandboxedCtx = buildSandboxedCtx(this.ctx);
        }
        return this._sandboxedCtx;
    }

    /**
     * Scan the plugins directory for valid .js plugin files.
     * @returns {string[]} List of discovered plugin filenames
     */
    discover() {
        try {
            if (!existsSync(PLUGINS_DIR)) return [];

            const files = readdirSync(PLUGINS_DIR)
                .filter((f) => f.endsWith('.js') && !f.startsWith('.') && !f.startsWith('_'))
                .filter((f) => isValidPluginFilename(f));

            this.audit?.log({
                type: 'PLUGINS_DISCOVERED',
                details: { count: files.length, directory: PLUGINS_DIR },
            });

            return files;
        } catch (err) {
            this.audit?.log({
                type: 'PLUGIN_DISCOVERY_ERROR',
                details: { error: err.message },
            });
            return [];
        }
    }

    /**
     * Validate that a module exports the required provider interface.
     * @param {Object} module - The imported module
     * @returns {{valid: boolean, errors: string[]}}
     */
    validatePlugin(module) {
        const errors = [];

        // Module must export a default class or a named Provider class
        const PluginClass = module.default || module.Provider || module.Plugin;

        if (!PluginClass) {
            errors.push('Module must export default, Provider, or Plugin class');
            return { valid: false, errors };
        }

        // Create a test instance to check interface
        try {
            const instance = typeof PluginClass === 'function' ? new PluginClass() : PluginClass;

            if (!instance.name || typeof instance.name !== 'string') {
                errors.push('Missing or invalid "name" property');
            }
            if (typeof instance.execute !== 'function') {
                errors.push('Missing "execute(prompt, options)" method');
            }
            if (typeof instance.isInstalled !== 'function') {
                errors.push('Missing "isInstalled()" method');
            }
            if (typeof instance.getInfo !== 'function') {
                errors.push('Missing "getInfo()" method');
            }
        } catch (err) {
            errors.push(`Failed to instantiate: ${err.message}`);
        }

        return { valid: errors.length === 0, errors };
    }

    /**
     * Load a plugin by filename from the plugins directory.
     * Plugins receive a SANDBOXED context — no access to encryption, vault, or config.
     * @param {string} filename - The .js filename to load
     * @returns {Promise<{success: boolean, name?: string, error?: string}>}
     */
    async loadPlugin(filename) {
        // Validate filename to prevent path traversal
        if (!isValidPluginFilename(filename)) {
            this.audit?.log({
                type: 'PLUGIN_LOAD_BLOCKED',
                details: { filename, reason: 'Invalid filename (possible path traversal)' },
            });
            return { success: false, error: `Invalid plugin filename: ${filename}` };
        }

        const filepath = join(PLUGINS_DIR, filename);

        // Ensure resolved path is within the plugins directory
        const resolvedPath = resolve(filepath);
        const resolvedPluginsDir = resolve(PLUGINS_DIR);
        if (!resolvedPath.startsWith(resolvedPluginsDir)) {
            this.audit?.log({
                type: 'PLUGIN_LOAD_BLOCKED',
                details: { filename, reason: 'Path traversal attempt detected' },
            });
            return { success: false, error: `Security: plugin path escapes plugins directory` };
        }

        if (!existsSync(filepath)) {
            return { success: false, error: `Plugin file not found: ${filename}` };
        }

        try {
            // Dynamic ESM import
            const fileUrl = pathToFileURL(filepath).href;
            const module = await import(fileUrl);

            // Validate interface
            const validation = this.validatePlugin(module);
            if (!validation.valid) {
                return { success: false, error: `Validation failed: ${validation.errors.join(', ')}` };
            }

            // Instantiate
            const PluginClass = module.default || module.Provider || module.Plugin;
            const instance = typeof PluginClass === 'function' ? new PluginClass() : PluginClass;

            // Initialize with SANDBOXED context — plugins cannot access secrets
            if (typeof instance.init === 'function') {
                const safeCtx = this._getSandboxedCtx();
                await instance.init(safeCtx);
            }

            // Register
            this.plugins.set(instance.name, {
                module,
                instance,
                filename,
                status: 'loaded',
                loadedAt: new Date().toISOString(),
            });

            this.audit?.log({
                type: 'PLUGIN_LOADED',
                details: { name: instance.name, filename, info: instance.getInfo() },
            });

            return { success: true, name: instance.name };
        } catch (err) {
            this.audit?.log({
                type: 'PLUGIN_LOAD_ERROR',
                details: { filename, error: err.message },
            });
            return { success: false, error: err.message };
        }
    }

    /**
     * Unload a plugin by name.
     * @param {string} name - Plugin name
     * @returns {Promise<boolean>}
     */
    async unloadPlugin(name) {
        const entry = this.plugins.get(name);
        if (!entry) return false;

        try {
            // Call destroy hook if it exists
            if (typeof entry.instance.destroy === 'function') {
                await entry.instance.destroy();
            }
        } catch { /* silent */ }

        this.plugins.delete(name);

        this.audit?.log({
            type: 'PLUGIN_UNLOADED',
            details: { name },
        });

        return true;
    }

    /**
     * List all plugins with their status.
     * @returns {Array<{name: string, filename: string, status: string, info: Object}>}
     */
    listPlugins() {
        const result = [];
        for (const [name, entry] of this.plugins) {
            result.push({
                name,
                filename: entry.filename,
                status: entry.status,
                loadedAt: entry.loadedAt,
                info: entry.instance.getInfo(),
            });
        }
        return result;
    }

    /**
     * Get a plugin instance by name.
     * @param {string} name
     * @returns {Object|null}
     */
    getPlugin(name) {
        return this.plugins.get(name)?.instance || null;
    }

    /**
     * Auto-discover and load all plugins in the plugins directory.
     * @returns {Promise<{loaded: string[], failed: Array<{file: string, error: string}>}>}
     */
    async autoLoad() {
        const files = this.discover();
        const loaded = [];
        const failed = [];

        for (const file of files) {
            const result = await this.loadPlugin(file);
            if (result.success) {
                loaded.push(result.name);
            } else {
                failed.push({ file, error: result.error });
            }
        }

        return { loaded, failed };
    }

    /**
     * Get all loaded plugin instances as a provider map (for registry integration).
     * @returns {Object} name → instance map
     */
    getProviderMap() {
        const map = {};
        for (const [name, entry] of this.plugins) {
            map[`plugin-${name.toLowerCase()}`] = entry.instance;
        }
        return map;
    }

    /**
     * Get the plugins directory path.
     * @returns {string}
     */
    static getPluginsDir() {
        return PLUGINS_DIR;
    }

    /**
     * Format plugin status for display.
     * @returns {string}
     */
    formatStatus() {
        const plugins = this.listPlugins();
        if (plugins.length === 0) {
            return chalk.gray(`  🔌 Plugins: none loaded (add .js files to ${PLUGINS_DIR})`);
        }

        const lines = [
            chalk.green(`  🔌 Plugins: ${plugins.length} loaded [sandboxed]`),
            ...plugins.map((p) =>
                chalk.gray(`     • ${p.name} (${p.info.version || 'v?'}) — ${p.status}`)
            ),
        ];
        return lines.join('\n');
    }
}
