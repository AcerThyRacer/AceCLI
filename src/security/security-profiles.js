// ============================================================
//  AceCLI – Security Profiles (Paranoid / Balanced / Minimal)
//  One-click security presets that configure all modules at once
// ============================================================

export const PROFILES = {
    paranoid: {
        name: 'Paranoid',
        description: 'Maximum security — all protections enabled, proxy required, ephemeral mode',
        settings: {
            security: {
                piiRedaction: true,
                strictMode: true,
                fingerprintMasking: true,
                metadataStripping: true,
                clipboardAutoClear: true,
                clipboardClearDelay: 10,
                promptInjectionDetection: true,
                trackerBlocking: true,
            },
            proxy: {
                enabled: true,
                type: 'socks5',
                host: '127.0.0.1',
                port: 9050,
            },
            dns: {
                enabled: true,
                provider: 'https://doh.applied-privacy.net/query',
                method: 'doh',
            },
            trackerBlocker: {
                enabled: true,
                blockDomains: true,
                stripParams: true,
                blockHeaders: true,
                sanitizeEnv: true,
                detectFingerprinting: true,
            },
            audit: {
                enabled: true,
                ephemeral: true,
                encrypted: true,
            },
        },
    },

    balanced: {
        name: 'Balanced',
        description: 'Standard protection — PII redaction, fingerprint masking, tracker blocking',
        settings: {
            security: {
                piiRedaction: true,
                strictMode: false,
                fingerprintMasking: true,
                metadataStripping: true,
                clipboardAutoClear: true,
                clipboardClearDelay: 30,
                promptInjectionDetection: true,
                trackerBlocking: true,
            },
            proxy: {
                enabled: false,
                type: 'socks5',
                host: '127.0.0.1',
                port: 9050,
            },
            dns: {
                enabled: true,
                provider: 'https://doh.applied-privacy.net/query',
                method: 'doh',
            },
            trackerBlocker: {
                enabled: true,
                blockDomains: true,
                stripParams: true,
                blockHeaders: true,
                sanitizeEnv: true,
                detectFingerprinting: true,
            },
            audit: {
                enabled: true,
                ephemeral: false,
                encrypted: true,
            },
        },
    },

    minimal: {
        name: 'Minimal',
        description: 'Lightweight — PII redaction only, no proxy, no network privacy features',
        settings: {
            security: {
                piiRedaction: true,
                strictMode: false,
                fingerprintMasking: false,
                metadataStripping: false,
                clipboardAutoClear: false,
                clipboardClearDelay: 30,
                promptInjectionDetection: true,
                trackerBlocking: false,
            },
            proxy: {
                enabled: false,
                type: 'socks5',
                host: '127.0.0.1',
                port: 9050,
            },
            dns: {
                enabled: false,
                provider: 'https://doh.applied-privacy.net/query',
                method: 'doh',
            },
            trackerBlocker: {
                enabled: false,
                blockDomains: false,
                stripParams: false,
                blockHeaders: false,
                sanitizeEnv: false,
                detectFingerprinting: false,
            },
            audit: {
                enabled: true,
                ephemeral: false,
                encrypted: true,
            },
        },
    },
};

export class SecurityProfiles {
    /**
     * Get a named security profile.
     * @param {string} name - 'paranoid', 'balanced', or 'minimal'
     * @returns {Object|null} The profile object or null
     */
    static getProfile(name) {
        return PROFILES[name.toLowerCase()] || null;
    }

    /**
     * List all available profiles.
     * @returns {Array<{name: string, description: string}>}
     */
    static listProfiles() {
        return Object.entries(PROFILES).map(([key, profile]) => ({
            key,
            name: profile.name,
            description: profile.description,
        }));
    }

    /**
     * Apply a security profile to a ConfigManager.
     * Overwrites all relevant config sections with the profile's settings.
     * @param {Object} configManager - A ConfigManager instance
     * @param {string} profileName - Profile name to apply
     * @returns {{ applied: boolean, profile: string, changedKeys: string[] }}
     */
    static apply(configManager, profileName) {
        const profile = PROFILES[profileName.toLowerCase()];
        if (!profile) {
            return { applied: false, profile: profileName, changedKeys: [], error: 'Unknown profile' };
        }

        const changedKeys = [];

        // Deep-apply each section
        for (const [section, values] of Object.entries(profile.settings)) {
            for (const [key, value] of Object.entries(values)) {
                const path = `${section}.${key}`;
                const current = configManager.get(path);
                if (current !== value) {
                    configManager.set(path, value);
                    changedKeys.push(path);
                }
            }
        }

        return { applied: true, profile: profile.name, changedKeys };
    }

    /**
     * Detect which profile most closely matches the current config.
     * @param {Object} configManager
     * @returns {{ profile: string, match: number }}
     */
    static detectCurrent(configManager) {
        let bestMatch = { profile: 'custom', match: 0 };

        for (const [key, profile] of Object.entries(PROFILES)) {
            let total = 0;
            let matching = 0;

            for (const [section, values] of Object.entries(profile.settings)) {
                for (const [k, v] of Object.entries(values)) {
                    total++;
                    if (configManager.get(`${section}.${k}`) === v) matching++;
                }
            }

            const ratio = total > 0 ? matching / total : 0;
            if (ratio > bestMatch.match) {
                bestMatch = { profile: profile.name, match: ratio };
            }
        }

        return bestMatch;
    }

    /**
     * Compare two profiles and return differences.
     * @param {string} profileA
     * @param {string} profileB
     * @returns {Array<{key: string, a: any, b: any}>}
     */
    static compare(profileA, profileB) {
        const a = PROFILES[profileA.toLowerCase()];
        const b = PROFILES[profileB.toLowerCase()];
        if (!a || !b) return [];

        const diffs = [];
        for (const section of Object.keys(a.settings)) {
            const aSection = a.settings[section] || {};
            const bSection = b.settings[section] || {};
            const allKeys = new Set([...Object.keys(aSection), ...Object.keys(bSection)]);
            for (const key of allKeys) {
                if (aSection[key] !== bSection[key]) {
                    diffs.push({ key: `${section}.${key}`, a: aSection[key], b: bSection[key] });
                }
            }
        }
        return diffs;
    }
}
