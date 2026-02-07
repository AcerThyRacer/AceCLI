// ============================================================
//  AceCLI – CLI Integrity Verification (Supply Chain Security)
//  - SHA-256 checksums of AI CLI binaries
//  - Known-good hash baseline with encrypted storage
//  - Self-integrity checking for ACE's own source files
//  - Automatic baseline on first run
// ============================================================
import { createHash } from 'crypto';
import { createReadStream, existsSync, readFileSync, writeFileSync, readdirSync, statSync } from 'fs';
import { join, dirname } from 'path';
import { homedir } from 'os';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { Encryption } from './encryption.js';

const IS_WIN = process.platform === 'win32';
const INTEGRITY_FILE = join(homedir(), '.ace', 'integrity.enc');

// ACE's own source files to monitor for tampering
const __dirname_ace = dirname(fileURLToPath(import.meta.url));
const ACE_SRC_DIR = join(__dirname_ace, '..');

// Provider CLI commands to check
const PROVIDER_COMMANDS = {
    claude: 'claude',
    gemini: 'gemini',
    openai: 'openai',       // OpenAI CLI (if installed)
    codex: 'codex',         // OpenAI Codex CLI
    ollama: 'ollama',
    aider: 'aider',
    interpreter: 'interpreter',
    sgpt: 'sgpt',
};

/**
 * IntegrityChecker — Supply chain security for AI CLI tools.
 * Verifies that provider binaries haven't been modified since baseline.
 */
export class IntegrityChecker {
    #encryption;
    #hashDb;
    #audit;
    #enabled;

    /**
     * @param {Object} options
     * @param {string} [options.masterPassword] - For encrypted hash storage
     * @param {Object} [options.audit] - Audit logger instance
     * @param {boolean} [options.enabled=true] - Whether checking is enabled
     * @param {boolean} [options.autoBaseline=true] - Auto-record baselines on first run
     */
    constructor(options = {}) {
        this.#enabled = options.enabled !== false;
        this.#encryption = options.masterPassword ? new Encryption(options.masterPassword) : null;
        this.#audit = options.audit || null;
        this.#hashDb = {
            providers: {},   // { providerKey: { path, hash, recordedAt, version } }
            selfFiles: {},   // { relativePath: hash }
            recordedAt: null,
        };

        if (this.#enabled) {
            this._loadHashDb();
        }
    }

    /**
     * Compute SHA-256 hash of a file using streaming (handles large binaries).
     * @param {string} filePath - Absolute path to the file
     * @returns {Promise<string>} Hex-encoded SHA-256 hash
     */
    async computeHash(filePath) {
        return new Promise((resolve, reject) => {
            if (!existsSync(filePath)) {
                return reject(new Error(`File not found: ${filePath}`));
            }

            const hash = createHash('sha256');
            const stream = createReadStream(filePath);

            stream.on('data', (chunk) => hash.update(chunk));
            stream.on('end', () => resolve(hash.digest('hex')));
            stream.on('error', reject);
        });
    }

    /**
     * Compute SHA-256 hash of a file synchronously (for smaller files).
     * @param {string} filePath - Absolute path
     * @returns {string} Hex-encoded SHA-256 hash
     */
    computeHashSync(filePath) {
        const data = readFileSync(filePath);
        return createHash('sha256').update(data).digest('hex');
    }

    /**
     * Find the absolute path to a CLI binary (cross-platform).
     * @param {string} command - Command name (e.g., 'claude', 'gemini')
     * @returns {string|null} Absolute path or null if not found
     */
    findBinary(command) {
        try {
            const cmd = IS_WIN ? `where ${command}` : `which ${command}`;
            const result = execSync(cmd, { stdio: 'pipe', encoding: 'utf8' }).trim();
            // `where` on Windows may return multiple lines; take the first
            const firstLine = result.split(/\r?\n/)[0].trim();
            if (firstLine && existsSync(firstLine)) {
                return firstLine;
            }
            return null;
        } catch {
            return null;
        }
    }

    /**
     * Verify a single provider's CLI binary against its baseline hash.
     * @param {string} providerKey - Provider key (e.g., 'claude', 'gemini')
     * @returns {Promise<{ status: string, provider: string, path?: string, hash?: string, baseline?: string, message: string }>}
     */
    async verifyProvider(providerKey) {
        const command = PROVIDER_COMMANDS[providerKey];
        if (!command) {
            return {
                status: 'skipped',
                provider: providerKey,
                message: `Unknown provider: ${providerKey}`,
            };
        }

        const binaryPath = this.findBinary(command);
        if (!binaryPath) {
            return {
                status: 'not_found',
                provider: providerKey,
                message: `${command} binary not found in PATH`,
            };
        }

        try {
            const currentHash = await this.computeHash(binaryPath);
            const baseline = this.#hashDb.providers[providerKey];

            if (!baseline) {
                return {
                    status: 'no_baseline',
                    provider: providerKey,
                    path: binaryPath,
                    hash: currentHash,
                    message: `No baseline recorded for ${providerKey}`,
                };
            }

            if (currentHash === baseline.hash) {
                return {
                    status: 'ok',
                    provider: providerKey,
                    path: binaryPath,
                    hash: currentHash,
                    baseline: baseline.hash,
                    message: `✔ ${providerKey}: integrity verified`,
                };
            } else {
                this.#audit?.log({
                    type: 'INTEGRITY_MISMATCH',
                    details: {
                        provider: providerKey,
                        path: binaryPath,
                        expected: baseline.hash.substring(0, 16) + '...',
                        actual: currentHash.substring(0, 16) + '...',
                    },
                });

                return {
                    status: 'mismatch',
                    provider: providerKey,
                    path: binaryPath,
                    hash: currentHash,
                    baseline: baseline.hash,
                    message: `⚠ ${providerKey}: HASH MISMATCH — binary may have been modified!`,
                };
            }
        } catch (err) {
            return {
                status: 'error',
                provider: providerKey,
                path: binaryPath,
                message: `Error verifying ${providerKey}: ${err.message}`,
            };
        }
    }

    /**
     * Record the current hash of a provider binary as the trusted baseline.
     * @param {string} providerKey - Provider key
     * @returns {Promise<{ success: boolean, hash?: string, path?: string }>}
     */
    async recordBaseline(providerKey) {
        const command = PROVIDER_COMMANDS[providerKey];
        if (!command) return { success: false };

        const binaryPath = this.findBinary(command);
        if (!binaryPath) return { success: false };

        try {
            const hash = await this.computeHash(binaryPath);
            this.#hashDb.providers[providerKey] = {
                path: binaryPath,
                hash,
                recordedAt: new Date().toISOString(),
            };
            this._saveHashDb();

            this.#audit?.log({
                type: 'INTEGRITY_BASELINE_RECORDED',
                details: { provider: providerKey, hash: hash.substring(0, 16) + '...' },
            });

            return { success: true, hash, path: binaryPath };
        } catch {
            return { success: false };
        }
    }

    /**
     * Verify all known provider binaries.
     * Auto-records baselines for providers that don't have one yet.
     * @param {boolean} [autoBaseline=true] - Record baseline if missing
     * @returns {Promise<{ results: Array, summary: { ok: number, mismatch: number, notFound: number, baselined: number } }>}
     */
    async verifyAll(autoBaseline = true) {
        const results = [];
        const summary = { ok: 0, mismatch: 0, notFound: 0, baselined: 0, errors: 0 };

        for (const providerKey of Object.keys(PROVIDER_COMMANDS)) {
            const result = await this.verifyProvider(providerKey);
            results.push(result);

            switch (result.status) {
                case 'ok':
                    summary.ok++;
                    break;
                case 'mismatch':
                    summary.mismatch++;
                    break;
                case 'not_found':
                    summary.notFound++;
                    break;
                case 'no_baseline':
                    if (autoBaseline) {
                        const baselined = await this.recordBaseline(providerKey);
                        if (baselined.success) {
                            result.status = 'baselined';
                            result.message = `📝 ${providerKey}: baseline recorded`;
                            summary.baselined++;
                        }
                    }
                    break;
                case 'error':
                    summary.errors++;
                    break;
            }
        }

        return { results, summary };
    }

    /**
     * Verify ACE's own source files haven't been modified.
     * @returns {{ status: string, total: number, modified: string[], message: string }}
     */
    verifySelfIntegrity() {
        try {
            const srcFiles = this._getSourceFiles(ACE_SRC_DIR);
            const modified = [];

            for (const { relative, absolute } of srcFiles) {
                try {
                    const currentHash = this.computeHashSync(absolute);
                    const baseline = this.#hashDb.selfFiles[relative];

                    if (baseline && baseline !== currentHash) {
                        modified.push(relative);
                    }
                } catch {
                    // Skip files that can't be read
                }
            }

            if (modified.length > 0) {
                this.#audit?.log({
                    type: 'SELF_INTEGRITY_MISMATCH',
                    details: { modifiedFiles: modified },
                });

                return {
                    status: 'mismatch',
                    total: srcFiles.length,
                    modified,
                    message: `⚠ ${modified.length} ACE source file(s) modified since baseline!`,
                };
            }

            return {
                status: 'ok',
                total: srcFiles.length,
                modified: [],
                message: `✔ All ${srcFiles.length} ACE source files verified`,
            };
        } catch (err) {
            return {
                status: 'error',
                total: 0,
                modified: [],
                message: `Error checking self-integrity: ${err.message}`,
            };
        }
    }

    /**
     * Record baselines for ACE's own source files.
     * @returns {number} Number of files baselined
     */
    recordSelfBaseline() {
        try {
            const srcFiles = this._getSourceFiles(ACE_SRC_DIR);
            let count = 0;

            for (const { relative, absolute } of srcFiles) {
                try {
                    this.#hashDb.selfFiles[relative] = this.computeHashSync(absolute);
                    count++;
                } catch {
                    // Skip unreadable files
                }
            }

            this.#hashDb.recordedAt = new Date().toISOString();
            this._saveHashDb();

            this.#audit?.log({
                type: 'SELF_BASELINE_RECORDED',
                details: { fileCount: count },
            });

            return count;
        } catch {
            return 0;
        }
    }

    /**
     * Recursively list JS source files in a directory.
     * @param {string} dir - Directory to scan
     * @param {string} [base] - Base directory for relative paths
     * @returns {Array<{relative: string, absolute: string}>}
     * @private
     */
    _getSourceFiles(dir, base = dir) {
        const results = [];
        try {
            const entries = readdirSync(dir);
            for (const entry of entries) {
                if (entry === 'node_modules' || entry.startsWith('.')) continue;
                const fullPath = join(dir, entry);
                try {
                    const stat = statSync(fullPath);
                    if (stat.isDirectory()) {
                        results.push(...this._getSourceFiles(fullPath, base));
                    } else if (entry.endsWith('.js')) {
                        results.push({
                            relative: fullPath.substring(base.length + 1).replace(/\\/g, '/'),
                            absolute: fullPath,
                        });
                    }
                } catch {
                    // Skip inaccessible files
                }
            }
        } catch {
            // Skip inaccessible directories
        }
        return results;
    }

    /**
     * Load the encrypted hash database from disk.
     * @private
     */
    _loadHashDb() {
        try {
            if (existsSync(INTEGRITY_FILE) && this.#encryption) {
                const raw = readFileSync(INTEGRITY_FILE, 'utf8');
                this.#hashDb = this.#encryption.decryptJSON(raw);
            }
        } catch {
            // Start fresh if can't decrypt
            this.#hashDb = { providers: {}, selfFiles: {}, recordedAt: null };
        }
    }

    /**
     * Save the hash database to encrypted storage.
     * @private
     */
    _saveHashDb() {
        if (!this.#encryption) return;
        try {
            const encrypted = this.#encryption.encryptJSON(this.#hashDb);
            writeFileSync(INTEGRITY_FILE, encrypted, 'utf8');
        } catch {
            // Silent fail — don't crash on save error
        }
    }

    /**
     * Get current status for dashboard display.
     * @returns {{ enabled: boolean, providerCount: number, selfFileCount: number, lastChecked: string|null }}
     */
    getStatus() {
        return {
            enabled: this.#enabled,
            providerCount: Object.keys(this.#hashDb.providers).length,
            selfFileCount: Object.keys(this.#hashDb.selfFiles).length,
            lastChecked: this.#hashDb.recordedAt,
        };
    }

    /**
     * Format a status string for the security dashboard.
     * @returns {string}
     */
    formatStatus() {
        const status = this.getStatus();
        if (!this.#enabled) return '  Integrity Checker: DISABLED';
        const providers = status.providerCount > 0
            ? `${status.providerCount} providers baselined`
            : 'no baselines';
        const self = status.selfFileCount > 0
            ? `${status.selfFileCount} ACE files tracked`
            : 'self-check pending';
        return `  Integrity Checker: ${providers} | ${self}`;
    }

    /**
     * Clear all baseline data.
     */
    clearBaselines() {
        this.#hashDb = { providers: {}, selfFiles: {}, recordedAt: null };
        this._saveHashDb();
        this.#audit?.log({ type: 'INTEGRITY_BASELINES_CLEARED' });
    }

    /**
     * Get list of baselined providers.
     * @returns {Array<{ provider: string, hash: string, recordedAt: string, path: string }>}
     */
    getBaselinedProviders() {
        return Object.entries(this.#hashDb.providers).map(([key, val]) => ({
            provider: key,
            hash: val.hash,
            recordedAt: val.recordedAt,
            path: val.path,
        }));
    }
}

// Export for testing
export { PROVIDER_COMMANDS };
