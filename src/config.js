// ============================================================
//  AceCLI – Configuration Manager (Encrypted Storage)
//  - Secure file wiping (randomBytes before delete)
//  - Deep-clone default config to prevent mutation
// ============================================================
import { existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { randomBytes } from 'crypto';
import { Encryption } from './security/encryption.js';

const ACE_DIR = join(homedir(), '.ace');
const CONFIG_FILE = join(ACE_DIR, 'config.enc');
const VAULT_FILE = join(ACE_DIR, 'vault.enc');

const DEFAULT_CONFIG = {
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
  providers: {
    default: 'ollama',
    openai: { model: 'gpt-4' },
    claude: {},
    gemini: {},
    copilot: {},
    ollama: { model: 'llama3' },
  },
  ui: {
    showBanner: true,
    animations: true,
    theme: 'cyber',
  },
};

// Deep-clone to prevent mutation of defaults
function cloneDefaults() {
  return JSON.parse(JSON.stringify(DEFAULT_CONFIG));
}

export class ConfigManager {
  constructor(masterPassword) {
    this.masterPassword = masterPassword;
    this.encryption = masterPassword ? new Encryption(masterPassword) : null;
    this.config = cloneDefaults();
    this.vault = {};

    mkdirSync(ACE_DIR, { recursive: true });
  }

  load() {
    try {
      if (existsSync(CONFIG_FILE) && this.encryption) {
        const raw = readFileSync(CONFIG_FILE, 'utf8');
        this.config = this.encryption.decryptJSON(raw);
      }
    } catch {
      this.config = cloneDefaults();
    }
    return this.config;
  }

  save() {
    if (this.encryption) {
      const encrypted = this.encryption.encryptJSON(this.config);
      writeFileSync(CONFIG_FILE, encrypted, 'utf8');
    } else {
      writeFileSync(CONFIG_FILE, JSON.stringify(this.config, null, 2), 'utf8');
    }
  }

  get(path) {
    return path.split('.').reduce((obj, key) => obj?.[key], this.config);
  }

  set(path, value) {
    const keys = path.split('.');
    const last = keys.pop();
    const target = keys.reduce((obj, key) => {
      if (!obj[key]) obj[key] = {};
      return obj[key];
    }, this.config);
    target[last] = value;
    this.save();
  }

  // API Key Vault – encrypted storage
  loadVault() {
    try {
      if (existsSync(VAULT_FILE) && this.encryption) {
        const raw = readFileSync(VAULT_FILE, 'utf8');
        this.vault = this.encryption.decryptJSON(raw);
      }
    } catch {
      this.vault = {};
    }
    return this.vault;
  }

  saveVault() {
    if (!this.encryption) throw new Error('Vault requires master password');
    writeFileSync(VAULT_FILE, this.encryption.encryptJSON(this.vault), 'utf8');
  }

  setApiKey(provider, key) {
    this.loadVault();
    this.vault[provider] = key;
    this.saveVault();
  }

  getApiKey(provider) {
    this.loadVault();
    return this.vault[provider] || null;
  }

  listVaultKeys() {
    this.loadVault();
    return Object.keys(this.vault).map((k) => ({
      provider: k,
      set: true,
      preview: this.vault[k].substring(0, 4) + '****',
    }));
  }

  deleteApiKey(provider) {
    this.loadVault();
    delete this.vault[provider];
    this.saveVault();
  }

  // Change master password – re-encrypt config and vault
  changePassword(oldPassword, newPassword) {
    // Decrypt with old password (already loaded in memory)
    const configData = { ...this.config };
    const vaultData = { ...this.vault };

    // Switch to new encryption
    this.masterPassword = newPassword;
    this.encryption = new Encryption(newPassword);

    // Re-encrypt and save config
    this.config = configData;
    this.save();

    // Re-encrypt and save vault
    this.vault = vaultData;
    if (Object.keys(this.vault).length > 0) {
      this.saveVault();
    }
  }

  // Secure wipe: overwrite with random data before deleting
  wipeAll() {
    this.config = cloneDefaults();
    this.vault = {};
    try {
      if (existsSync(CONFIG_FILE)) {
        // 3-pass overwrite: random → zeros → random → delete
        const size = readFileSync(CONFIG_FILE).length || 4096;
        writeFileSync(CONFIG_FILE, randomBytes(Math.max(size, 4096)));
        writeFileSync(CONFIG_FILE, Buffer.alloc(Math.max(size, 4096), 0));
        writeFileSync(CONFIG_FILE, randomBytes(Math.max(size, 4096)));
        unlinkSync(CONFIG_FILE);
      }
      if (existsSync(VAULT_FILE)) {
        const size = readFileSync(VAULT_FILE).length || 4096;
        writeFileSync(VAULT_FILE, randomBytes(Math.max(size, 4096)));
        writeFileSync(VAULT_FILE, Buffer.alloc(Math.max(size, 4096), 0));
        writeFileSync(VAULT_FILE, randomBytes(Math.max(size, 4096)));
        unlinkSync(VAULT_FILE);
      }
    } catch { /* silent */ }
  }
}
