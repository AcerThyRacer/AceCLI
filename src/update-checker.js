// ============================================================
//  AceCLI – Auto-Update Checker
//  - Non-blocking npm registry version check
//  - Respects proxy settings
//  - 5s timeout to avoid blocking startup
// ============================================================
import https from 'https';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REGISTRY_URL = 'https://registry.npmjs.org/acecli/latest';
const TIMEOUT_MS = 5000;

export class UpdateChecker {
    /**
     * Get the current installed version from package.json.
     * @returns {string}
     */
    static getCurrentVersion() {
        try {
            const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8'));
            return pkg.version || '0.0.0';
        } catch {
            return '0.0.0';
        }
    }

    /**
     * Compare two semver version strings.
     * @param {string} a
     * @param {string} b
     * @returns {number} -1 if a < b, 0 if equal, 1 if a > b
     */
    static compareVersions(a, b) {
        const pa = a.split('.').map(Number);
        const pb = b.split('.').map(Number);
        for (let i = 0; i < 3; i++) {
            const va = pa[i] || 0;
            const vb = pb[i] || 0;
            if (va < vb) return -1;
            if (va > vb) return 1;
        }
        return 0;
    }

    /**
     * Check for updates from the npm registry.
     * @param {Object} [options] - Optional { agent } for proxy support
     * @returns {Promise<{ current: string, latest: string, updateAvailable: boolean, url: string } | null>}
     */
    static async checkForUpdates(options = {}) {
        const current = UpdateChecker.getCurrentVersion();

        try {
            const latest = await UpdateChecker._fetchLatestVersion(options);
            if (!latest) return null;

            return {
                current,
                latest,
                updateAvailable: UpdateChecker.compareVersions(current, latest) < 0,
                url: 'https://www.npmjs.com/package/acecli',
            };
        } catch {
            return null;
        }
    }

    /**
     * Fetch the latest version from npm registry.
     * @param {Object} options
     * @returns {Promise<string|null>}
     */
    static _fetchLatestVersion(options = {}) {
        return new Promise((resolve) => {
            const timeout = setTimeout(() => resolve(null), TIMEOUT_MS);

            const reqOptions = {
                timeout: TIMEOUT_MS,
            };

            if (options.agent) {
                reqOptions.agent = options.agent;
            }

            try {
                const req = https.get(REGISTRY_URL, reqOptions, (res) => {
                    let data = '';
                    res.on('data', (chunk) => { data += chunk; });
                    res.on('end', () => {
                        clearTimeout(timeout);
                        try {
                            const pkg = JSON.parse(data);
                            resolve(pkg.version || null);
                        } catch {
                            resolve(null);
                        }
                    });
                });

                req.on('error', () => {
                    clearTimeout(timeout);
                    resolve(null);
                });

                req.on('timeout', () => {
                    req.destroy();
                    clearTimeout(timeout);
                    resolve(null);
                });
            } catch {
                clearTimeout(timeout);
                resolve(null);
            }
        });
    }

    /**
     * Parse a version response from npm (for testing).
     * @param {string} jsonString
     * @returns {string|null}
     */
    static parseVersionResponse(jsonString) {
        try {
            const data = JSON.parse(jsonString);
            return data.version || null;
        } catch {
            return null;
        }
    }

    /**
     * Format an update notification banner.
     * @param {{ current: string, latest: string }} info
     * @returns {string}
     */
    static formatUpdateBanner(info) {
        return [
            '',
            `  ╔══════════════════════════════════════════════╗`,
            `  ║  Update available: ${info.current} → ${info.latest}`.padEnd(49) + '║',
            `  ║  Run: npm update -g acecli`.padEnd(49) + '║',
            `  ╚══════════════════════════════════════════════╝`,
            '',
        ].join('\n');
    }
}
