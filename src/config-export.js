// ============================================================
//  AceCLI – Config Export/Import (Encrypted Portable Backup)
//  - Exports config + vault as a single encrypted blob
//  - Password-protected for safe transport
//  - Version-tagged for forward compatibility
// ============================================================
import { Encryption } from './security/encryption.js';

const EXPORT_VERSION = 1;
const EXPORT_TYPE = 'ace-config-export';

export class ConfigExport {
    /**
     * Export current config and vault as an encrypted JSON blob.
     * @param {Object} configManager - ConfigManager instance (must be loaded)
     * @param {string} exportPassword - Password to encrypt the export with
     * @returns {string} Encrypted export blob
     */
    static exportConfig(configManager, exportPassword) {
        if (!exportPassword || exportPassword.length < 4) {
            throw new Error('Export password must be at least 4 characters');
        }

        const enc = new Encryption(exportPassword);

        const payload = {
            version: EXPORT_VERSION,
            type: EXPORT_TYPE,
            exportedAt: new Date().toISOString(),
            config: { ...configManager.config },
            vault: { ...configManager.vault },
        };

        const encrypted = enc.encrypt(JSON.stringify(payload));

        return JSON.stringify({
            version: EXPORT_VERSION,
            type: EXPORT_TYPE,
            encrypted,
        });
    }

    /**
     * Import config and vault from an encrypted export blob.
     * @param {Object} configManager - ConfigManager instance
     * @param {string} blob - The encrypted export blob (JSON string)
     * @param {string} exportPassword - Password used to encrypt the export
     * @returns {{ success: boolean, error?: string, imported?: { configKeys: number, vaultKeys: number } }}
     */
    static importConfig(configManager, blob, exportPassword) {
        try {
            // Parse outer envelope
            const envelope = JSON.parse(blob);

            if (envelope.type !== EXPORT_TYPE) {
                return { success: false, error: 'Invalid export file: wrong type' };
            }
            if (envelope.version > EXPORT_VERSION) {
                return { success: false, error: `Unsupported export version: ${envelope.version}` };
            }

            // Decrypt inner payload
            const enc = new Encryption(exportPassword);
            const decrypted = enc.decrypt(envelope.encrypted);
            const payload = JSON.parse(decrypted);

            // Validate payload
            if (payload.type !== EXPORT_TYPE) {
                return { success: false, error: 'Invalid export payload' };
            }

            // Apply config (merge, don't overwrite non-exported keys)
            if (payload.config) {
                for (const [section, values] of Object.entries(payload.config)) {
                    if (typeof values === 'object' && values !== null) {
                        for (const [key, value] of Object.entries(values)) {
                            configManager.set(`${section}.${key}`, value);
                        }
                    }
                }
            }

            // Apply vault keys
            let vaultKeys = 0;
            if (payload.vault) {
                for (const [provider, key] of Object.entries(payload.vault)) {
                    configManager.setApiKey(provider, key);
                    vaultKeys++;
                }
            }

            return {
                success: true,
                imported: {
                    configKeys: payload.config ? Object.keys(payload.config).length : 0,
                    vaultKeys,
                    exportedAt: payload.exportedAt,
                },
            };
        } catch (err) {
            if (err.message?.includes('Unsupported state') || err.message?.includes('decrypt')) {
                return { success: false, error: 'Wrong export password' };
            }
            return { success: false, error: `Import failed: ${err.message}` };
        }
    }

    /**
     * Validate an export blob without importing.
     * @param {string} blob
     * @returns {{ valid: boolean, version?: number, type?: string, error?: string }}
     */
    static validate(blob) {
        try {
            const envelope = JSON.parse(blob);
            if (envelope.type !== EXPORT_TYPE) {
                return { valid: false, error: 'Wrong type' };
            }
            if (!envelope.encrypted) {
                return { valid: false, error: 'Missing encrypted data' };
            }
            return { valid: true, version: envelope.version, type: envelope.type };
        } catch {
            return { valid: false, error: 'Invalid JSON' };
        }
    }
}
