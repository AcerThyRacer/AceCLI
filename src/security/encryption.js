// ============================================================
//  AceCLI – AES-256-GCM Encryption Engine (Hardened v2)
//  - scrypt N=2^17 (strong KDF)
//  - Format versioning for forward compatibility
//  - Hardened secure wipe with read-back barrier
//  - Algorithm agility header for future cipher upgrades
//  - HMAC-SHA-256 utility for audit chain
// ============================================================
import {
  createCipheriv, createDecipheriv, randomBytes, scryptSync,
  createHash, createHmac, randomInt,
} from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const SALT_LENGTH = 32;
const TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const FORMAT_VERSION = 'v2';

// Supported algorithms for future upgradability
const SUPPORTED_ALGORITHMS = {
  'aes-256-gcm': { ivLen: 16, tagLen: 16, keyLen: 32 },
};

// Hardened scrypt parameters (N=2^17, r=8, p=1)
// Memory: ~128 × N × r = 128MB — safe under Node.js limits
// ~200ms on modern hardware, well above OWASP minimum (N=2^14)
const SCRYPT_PARAMS = {
  N: 2 ** 17,  // CPU/memory cost — 131072 iterations
  r: 8,        // Block size
  p: 1,        // Parallelism
  maxmem: 256 * 1024 * 1024, // 256 MB max memory
};

// Legacy scrypt params for v1 format backwards compatibility
const SCRYPT_PARAMS_V1 = {
  // Node.js default: N=16384, r=8, p=1
};

export class Encryption {
  constructor(masterPassword) {
    // Store the password for per-operation key derivation
    // (each encrypt/decrypt uses a unique salt, so we need to re-derive each time)
    this._masterPassword = masterPassword;
  }

  // Derive key from password + salt with hardened parameters
  deriveKey(salt, legacy = false) {
    const params = legacy ? SCRYPT_PARAMS_V1 : SCRYPT_PARAMS;
    return scryptSync(this._masterPassword, salt, KEY_LENGTH, params);
  }

  // Derive a static key (for cases where we need a persistent key buffer)
  static deriveKeyFromPassword(password, salt, legacy = false) {
    const params = legacy ? SCRYPT_PARAMS_V1 : SCRYPT_PARAMS;
    return scryptSync(password, salt, KEY_LENGTH, params);
  }

  encrypt(plaintext) {
    const salt = randomBytes(SALT_LENGTH);
    const key = this.deriveKey(salt);
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, key, iv);

    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const tag = cipher.getAuthTag();

    // Wipe key from memory
    Encryption.secureWipe(key);

    // v2 format: version:salt:iv:tag:ciphertext
    return [
      FORMAT_VERSION,
      salt.toString('hex'),
      iv.toString('hex'),
      tag.toString('hex'),
      encrypted,
    ].join(':');
  }

  decrypt(encryptedBundle) {
    const parts = encryptedBundle.split(':');

    let saltHex, ivHex, tagHex, ciphertext;
    let legacy = false;

    if (parts[0] === 'v2' && parts.length === 5) {
      // v2 format: v2:salt:iv:tag:ciphertext
      [, saltHex, ivHex, tagHex, ciphertext] = parts;
    } else if (parts.length === 4) {
      // v1 legacy format: salt:iv:tag:ciphertext
      [saltHex, ivHex, tagHex, ciphertext] = parts;
      legacy = true;
    } else {
      throw new Error('Invalid encrypted data format');
    }

    const salt = Buffer.from(saltHex, 'hex');
    const iv = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');
    const key = this.deriveKey(salt, legacy);

    const decipher = createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);

    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    // Wipe key from memory
    Encryption.secureWipe(key);

    return decrypted;
  }

  // SHA-256 hash for tamper detection (legacy — use hmac() for audit)
  static hash(data) {
    return createHash('sha256').update(data).digest('hex');
  }

  // HMAC-SHA-256 for authenticated tamper detection
  // Requires the master password to recompute, unlike plain hash
  static hmac(key, data) {
    return createHmac('sha256', key).update(data).digest('hex');
  }

  // Derive an HMAC key from the master password for audit chain use
  deriveHmacKey(sessionSalt) {
    // Use a dedicated sub-key derivation with a different salt prefix
    const hmacSalt = Buffer.concat([
      Buffer.from('hmac-audit:'),
      Buffer.from(sessionSalt),
    ]);
    return scryptSync(this._masterPassword, hmacSalt, KEY_LENGTH, SCRYPT_PARAMS);
  }

  // Hardened secure memory wipe with read-back barrier
  // The read-back forces V8 to actually perform the writes,
  // defeating dead-store elimination optimization.
  static secureWipe(buffer) {
    if (Buffer.isBuffer(buffer)) {
      // Pass 1: overwrite with 0xAA pattern
      buffer.fill(0xAA);
      // Read-back barrier: force V8 to materialize the write
      /* eslint-disable no-unused-expressions */
      buffer[0]; buffer[buffer.length - 1];

      // Pass 2: overwrite with random data
      randomBytes(buffer.length).copy(buffer);
      buffer[0]; buffer[buffer.length - 1];

      // Pass 3: zero out
      buffer.fill(0);
      buffer[0]; buffer[buffer.length - 1];
      /* eslint-enable no-unused-expressions */
    }
  }

  // Encrypt JSON objects
  encryptJSON(obj) {
    return this.encrypt(JSON.stringify(obj));
  }

  decryptJSON(encryptedBundle) {
    return JSON.parse(this.decrypt(encryptedBundle));
  }

  // Get the format version
  static getFormatVersion() {
    return FORMAT_VERSION;
  }

  // Get supported algorithms (for future upgradability)
  static getSupportedAlgorithms() {
    return { ...SUPPORTED_ALGORITHMS };
  }

  // Get scrypt parameters (for display/audit)
  static getKdfParams() {
    return { ...SCRYPT_PARAMS, algorithm: 'scrypt' };
  }
}
