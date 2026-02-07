// ============================================================
//  AceCLI – Multi-Factor Authentication (TOTP / Recovery Codes)
//  - RFC 6238 TOTP implementation (zero external dependencies)
//  - Base32 encoding/decoding for authenticator app secrets
//  - One-time recovery codes with secure generation
// ============================================================
import { createHmac, randomBytes, randomInt, timingSafeEqual } from 'crypto';

// ── Base32 Encoding (RFC 4648) ──────────────────────────────
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
    let bits = '';
    for (const byte of buffer) {
        bits += byte.toString(2).padStart(8, '0');
    }
    // Pad to multiple of 5
    while (bits.length % 5 !== 0) bits += '0';

    let result = '';
    for (let i = 0; i < bits.length; i += 5) {
        const idx = parseInt(bits.substring(i, i + 5), 2);
        result += BASE32_ALPHABET[idx];
    }
    return result;
}

function base32Decode(str) {
    const cleaned = str.replace(/[=\s]/g, '').toUpperCase();
    let bits = '';
    for (const char of cleaned) {
        const idx = BASE32_ALPHABET.indexOf(char);
        if (idx === -1) throw new Error(`Invalid base32 character: ${char}`);
        bits += idx.toString(2).padStart(5, '0');
    }
    // Convert bits to bytes
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        bytes.push(parseInt(bits.substring(i, i + 8), 2));
    }
    return Buffer.from(bytes);
}

// ── TOTP Constants ──────────────────────────────────────────
const TOTP_DIGITS = 6;
const TOTP_PERIOD = 30;        // seconds
const TOTP_ALGORITHM = 'sha1'; // RFC 6238 default
const SECRET_LENGTH = 20;      // 20 bytes = 160 bits (recommended)
const RECOVERY_CODE_LENGTH = 8;
const DEFAULT_RECOVERY_COUNT = 10;
const DRIFT_WINDOWS = 1;       // Allow ±1 time window for clock drift

/**
 * MFAProvider — TOTP-based Multi-Factor Authentication per RFC 6238.
 * Uses only Node.js crypto (no external dependencies).
 */
export class MFAProvider {

    /**
     * Generate a new random TOTP secret.
     * @returns {{ secret: Buffer, base32: string }}
     */
    static generateSecret() {
        const secret = randomBytes(SECRET_LENGTH);
        const base32 = base32Encode(secret);
        return { secret, base32 };
    }

    /**
     * Generate a TOTP code for the given secret and time.
     * @param {string|Buffer} secret - Base32-encoded secret string or raw Buffer
     * @param {number} [timeMs] - Time in milliseconds (defaults to now)
     * @returns {string} 6-digit TOTP code
     */
    static generateTOTP(secret, timeMs) {
        const secretBuffer = typeof secret === 'string'
            ? base32Decode(secret)
            : secret;

        const time = timeMs ?? Date.now();
        const counter = Math.floor(time / 1000 / TOTP_PERIOD);

        return MFAProvider._generateHOTP(secretBuffer, counter);
    }

    /**
     * Verify a TOTP code against the secret.
     * Checks current time window ± DRIFT_WINDOWS for clock drift tolerance.
     * @param {string} token - The 6-digit code entered by the user
     * @param {string|Buffer} secret - Base32-encoded secret or raw Buffer
     * @param {number} [timeMs] - Optional time override (for testing)
     * @returns {{ valid: boolean, drift: number }}
     */
    static verifyTOTP(token, secret, timeMs) {
        if (!token || typeof token !== 'string') return { valid: false, drift: 0 };

        const cleaned = token.replace(/\s/g, '');
        if (cleaned.length !== TOTP_DIGITS || !/^\d+$/.test(cleaned)) {
            return { valid: false, drift: 0 };
        }

        const time = timeMs ?? Date.now();

        for (let offset = -DRIFT_WINDOWS; offset <= DRIFT_WINDOWS; offset++) {
            const adjustedTime = time + (offset * TOTP_PERIOD * 1000);
            const expected = MFAProvider.generateTOTP(secret, adjustedTime);
            if (MFAProvider._timingSafeCompare(cleaned, expected)) {
                return { valid: true, drift: offset };
            }
        }

        return { valid: false, drift: 0 };
    }

    /**
     * Generate HOTP (HMAC-based OTP) per RFC 4226.
     * @param {Buffer} secret - Raw secret bytes
     * @param {number} counter - Counter value
     * @returns {string} 6-digit code
     * @private
     */
    static _generateHOTP(secret, counter) {
        // Convert counter to 8-byte big-endian buffer
        const counterBuffer = Buffer.alloc(8);
        // Write as 64-bit big-endian integer
        const high = Math.floor(counter / 0x100000000);
        const low = counter & 0xFFFFFFFF;
        counterBuffer.writeUInt32BE(high, 0);
        counterBuffer.writeUInt32BE(low >>> 0, 4);

        // HMAC-SHA1
        const hmac = createHmac(TOTP_ALGORITHM, secret);
        hmac.update(counterBuffer);
        const digest = hmac.digest();

        // Dynamic truncation (RFC 4226 §5.4)
        const offset = digest[digest.length - 1] & 0x0F;
        const code =
            ((digest[offset] & 0x7F) << 24) |
            ((digest[offset + 1] & 0xFF) << 16) |
            ((digest[offset + 2] & 0xFF) << 8) |
            (digest[offset + 3] & 0xFF);

        // Modulo 10^digits
        const otp = code % (10 ** TOTP_DIGITS);
        return otp.toString().padStart(TOTP_DIGITS, '0');
    }

    /**
     * Constant-time string comparison to prevent timing attacks.
     * @param {string} a
     * @param {string} b
     * @returns {boolean}
     * @private
     */
    static _timingSafeCompare(a, b) {
        if (a.length !== b.length) return false;
        const bufA = Buffer.from(a);
        const bufB = Buffer.from(b);
        return timingSafeEqual(bufA, bufB);
    }

    /**
     * Generate recovery codes for backup authentication.
     * @param {number} [count=10] - Number of recovery codes to generate
     * @returns {string[]} Array of alphanumeric recovery codes
     */
    static generateRecoveryCodes(count = DEFAULT_RECOVERY_COUNT) {
        const codes = [];
        const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Exclude ambiguous: 0,O,1,I

        for (let i = 0; i < count; i++) {
            let code = '';
            for (let j = 0; j < RECOVERY_CODE_LENGTH; j++) {
                code += chars[randomInt(chars.length)];
            }
            // Format as XXXX-XXXX for readability
            codes.push(`${code.substring(0, 4)}-${code.substring(4)}`);
        }
        return codes;
    }

    /**
     * Verify a recovery code against stored codes.
     * Recovery codes are one-time use — the used code is removed.
     * @param {string} code - The recovery code entered by the user
     * @param {string[]} storedCodes - Array of remaining valid codes
     * @returns {{ valid: boolean, remainingCodes: string[] }}
     */
    static verifyRecoveryCode(code, storedCodes) {
        if (!code || !Array.isArray(storedCodes)) {
            return { valid: false, remainingCodes: storedCodes || [] };
        }

        const normalized = code.replace(/[\s-]/g, '').toUpperCase();
        const idx = storedCodes.findIndex((c) => {
            const stored = c.replace(/[\s-]/g, '').toUpperCase();
            return stored === normalized;
        });

        if (idx === -1) {
            return { valid: false, remainingCodes: storedCodes };
        }

        // Remove the used code (one-time use)
        const remaining = [...storedCodes];
        remaining.splice(idx, 1);
        return { valid: true, remainingCodes: remaining };
    }

    /**
     * Format setup information for display to the user.
     * @param {string} base32Secret - The base32-encoded secret
     * @param {string} [issuer='AceCLI'] - Issuer name for the OTP URI
     * @param {string} [account='user'] - Account name
     * @returns {{ otpauthUri: string, displaySecret: string, instructions: string }}
     */
    static formatSetupInfo(base32Secret, issuer = 'AceCLI', account = 'user') {
        const otpauthUri = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${base32Secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${TOTP_DIGITS}&period=${TOTP_PERIOD}`;

        // Format secret in groups of 4 for readability
        const displaySecret = base32Secret.match(/.{1,4}/g)?.join(' ') || base32Secret;

        const instructions = [
            '1. Open your authenticator app (Google Authenticator, Authy, etc.)',
            '2. Add a new account manually using this secret:',
            `   ${displaySecret}`,
            `3. Or use this OTP URI:`,
            `   ${otpauthUri}`,
            '4. Enter the 6-digit code shown in your app to verify setup.',
        ].join('\n');

        return { otpauthUri, displaySecret, instructions };
    }

    /**
     * Get the remaining seconds until the current TOTP code expires.
     * @param {number} [timeMs] - Optional time override
     * @returns {number} Seconds remaining
     */
    static getTimeRemaining(timeMs) {
        const time = timeMs ?? Date.now();
        const elapsed = Math.floor(time / 1000) % TOTP_PERIOD;
        return TOTP_PERIOD - elapsed;
    }

    /**
     * Create an MFA configuration object for storage.
     * @returns {{ enabled: boolean, secret: null, recoveryCodes: [], setupComplete: boolean }}
     */
    static createDefaultConfig() {
        return {
            enabled: false,
            secret: null,
            recoveryCodes: [],
            setupComplete: false,
        };
    }
}

// Export constants for testing
export const TOTP_CONFIG = {
    digits: TOTP_DIGITS,
    period: TOTP_PERIOD,
    algorithm: TOTP_ALGORITHM,
    secretLength: SECRET_LENGTH,
    driftWindows: DRIFT_WINDOWS,
};

// Export base32 utilities for testing
export { base32Encode, base32Decode };
