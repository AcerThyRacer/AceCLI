import { existsSync, readFileSync, unlinkSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { createHash, randomBytes } from 'crypto';
import { Encryption } from './encryption.js';
import { ensureSecureDir, writeSecureFile } from './fs-utils.js';

const ACE_DIR = join(homedir(), '.ace');
const AUTH_FILE = join(ACE_DIR, 'auth.enc');
const LEGACY_HASH_FILE = join(ACE_DIR, 'password.hash');
const CONFIG_FILE = join(ACE_DIR, 'config.enc');
const AUTH_TYPE = 'ace-auth-sentinel';

export const MIN_MASTER_PASSWORD_LENGTH = 12;

function verifyLegacyHash(password) {
  if (!existsSync(LEGACY_HASH_FILE)) return false;

  try {
    const { salt, hash } = JSON.parse(readFileSync(LEGACY_HASH_FILE, 'utf8'));
    const candidate = createHash('sha256').update(salt + password).digest('hex');
    return candidate === hash;
  } catch {
    return false;
  }
}

function verifyConfigPassword(password) {
  if (!existsSync(CONFIG_FILE)) return true;

  try {
    const raw = readFileSync(CONFIG_FILE, 'utf8');
    const enc = new Encryption(password);
    enc.decryptJSON(raw);
    return true;
  } catch {
    return false;
  }
}

function cleanupLegacyHash() {
  if (!existsSync(LEGACY_HASH_FILE)) return;

  try {
    unlinkSync(LEGACY_HASH_FILE);
  } catch {
    // Best-effort cleanup only.
  }
}

export class AuthManager {
  constructor() {
    ensureSecureDir(ACE_DIR);
  }

  hasAuth() {
    return existsSync(AUTH_FILE);
  }

  hasLegacyHash() {
    return existsSync(LEGACY_HASH_FILE);
  }

  hasExistingEncryptedState() {
    return existsSync(CONFIG_FILE);
  }

  createAuthSentinel(password) {
    const enc = new Encryption(password);
    const payload = {
      type: AUTH_TYPE,
      version: 1,
      createdAt: new Date().toISOString(),
      verifier: randomBytes(32).toString('hex'),
    };

    writeSecureFile(AUTH_FILE, enc.encryptJSON(payload), 'utf8');
    cleanupLegacyHash();
  }

  verifyPassword(password) {
    if (!this.hasAuth()) return false;

    try {
      const raw = readFileSync(AUTH_FILE, 'utf8');
      const enc = new Encryption(password);
      const payload = enc.decryptJSON(raw);
      return payload?.type === AUTH_TYPE;
    } catch {
      return false;
    }
  }

  migrateLegacyOrExistingState(password) {
    const legacyOk = this.hasLegacyHash() ? verifyLegacyHash(password) : true;
    const configOk = this.hasExistingEncryptedState() ? verifyConfigPassword(password) : true;

    if (!legacyOk || !configOk) return false;

    this.createAuthSentinel(password);
    return true;
  }

  writeIfMissing(password) {
    if (!this.hasAuth()) {
      this.createAuthSentinel(password);
    }
  }

  wipeAll() {
    if (!existsSync(AUTH_FILE)) return;

    try {
      const size = readFileSync(AUTH_FILE).length || 1024;
      writeSecureFile(AUTH_FILE, randomBytes(Math.max(size, 1024)));
      unlinkSync(AUTH_FILE);
    } catch {
      // Best-effort wipe.
    }
  }
}
