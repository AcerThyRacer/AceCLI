// ============================================================
//  AceCLI – Encrypted Audit Logger with Tamper Detection
// ============================================================
import { writeFileSync, readFileSync, existsSync, mkdirSync, unlinkSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { randomBytes } from 'crypto';
import { Encryption } from './encryption.js';

const AUDIT_DIR = join(homedir(), '.ace', 'audit');

export class AuditLogger {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.ephemeral = options.ephemeral || false;
    this.encryption = options.masterPassword
      ? new Encryption(options.masterPassword)
      : null;
    this.memoryLog = [];
    this.sessionId = options.sessionId || 'unknown';

    if (!this.ephemeral) {
      mkdirSync(AUDIT_DIR, { recursive: true });
    }
  }

  log(event) {
    if (!this.enabled) return;

    const entry = {
      timestamp: new Date().toISOString(),
      sessionId: this.sessionId,
      event: event.type,
      provider: event.provider || 'system',
      details: event.details || {},
      hash: null,
    };

    // Chain hash for tamper detection
    const prevHash = this.memoryLog.length > 0
      ? this.memoryLog[this.memoryLog.length - 1].hash
      : '0'.repeat(64);
    entry.hash = Encryption.hash(prevHash + JSON.stringify({ ...entry, hash: undefined }));

    this.memoryLog.push(entry);

    if (!this.ephemeral) {
      this._persistEntry(entry);
    }
  }

  _persistEntry(entry) {
    try {
      const filename = `audit_${this.sessionId}.log`;
      const filepath = join(AUDIT_DIR, filename);

      let line = JSON.stringify(entry);
      if (this.encryption) {
        line = this.encryption.encrypt(line);
      }

      const existing = existsSync(filepath) ? readFileSync(filepath, 'utf8') : '';
      writeFileSync(filepath, existing + line + '\n', 'utf8');
    } catch {
      // Silent fail – audit should never crash the app
    }
  }

  verifyIntegrity() {
    const results = { valid: true, entries: this.memoryLog.length, errors: [] };

    for (let i = 0; i < this.memoryLog.length; i++) {
      const entry = this.memoryLog[i];
      const prevHash = i > 0 ? this.memoryLog[i - 1].hash : '0'.repeat(64);
      const expectedHash = Encryption.hash(
        prevHash + JSON.stringify({ ...entry, hash: undefined })
      );

      if (entry.hash !== expectedHash) {
        results.valid = false;
        results.errors.push({ index: i, expected: expectedHash, actual: entry.hash });
      }
    }

    return results;
  }

  getLog() {
    return [...this.memoryLog];
  }

  getStats() {
    const types = {};
    for (const e of this.memoryLog) {
      types[e.event] = (types[e.event] || 0) + 1;
    }
    return {
      totalEntries: this.memoryLog.length,
      eventTypes: types,
      integrityValid: this.verifyIntegrity().valid,
      ephemeral: this.ephemeral,
    };
  }

  // Kill switch: wipe all audit data
  wipeAll() {
    this.memoryLog = [];
    if (!this.ephemeral) {
      try {
        const filepath = join(AUDIT_DIR, `audit_${this.sessionId}.log`);
        if (existsSync(filepath)) {
          writeFileSync(filepath, randomBytes(1024));
          unlinkSync(filepath);
        }
      } catch { /* silent */ }
    }
  }

  // Export decrypted audit log as JSON or CSV
  export(format = 'json') {
    const log = this.getLog();

    if (format === 'csv') {
      const headers = 'timestamp,sessionId,event,provider,details,hash';
      const rows = log.map((e) =>
        [
          e.timestamp,
          e.sessionId,
          e.event,
          e.provider,
          `"${JSON.stringify(e.details).replace(/"/g, '""')}"`,
          e.hash,
        ].join(',')
      );
      return headers + '\n' + rows.join('\n');
    }

    // Default: JSON
    return JSON.stringify(log, null, 2);
  }

  // Export and write to a file
  exportToFile(filepath, format = 'json') {
    const content = this.export(format);
    writeFileSync(filepath, content, 'utf8');
    return filepath;
  }

  // Load encrypted audit log from disk and decrypt
  loadFromDisk(sessionId) {
    if (!this.encryption) return [];

    const targetId = sessionId || this.sessionId;
    const filepath = join(AUDIT_DIR, `audit_${targetId}.log`);
    if (!existsSync(filepath)) return [];

    try {
      const raw = readFileSync(filepath, 'utf8').trim();
      if (!raw) return [];

      const lines = raw.split('\n').filter(Boolean);
      return lines.map((line) => {
        try {
          const decrypted = this.encryption.decrypt(line);
          return JSON.parse(decrypted);
        } catch {
          return JSON.parse(line); // fallback: unencrypted
        }
      });
    } catch {
      return [];
    }
  }

  // List all audit sessions on disk
  listSessions() {
    try {
      if (!existsSync(AUDIT_DIR)) return [];
      const files = readdirSync(AUDIT_DIR).filter((f) => f.startsWith('audit_') && f.endsWith('.log'));
      return files.map((f) => {
        const id = f.replace('audit_', '').replace('.log', '');
        let size = 0;
        try { size = statSync(join(AUDIT_DIR, f)).size; } catch { /* */ }
        return { sessionId: id, file: f, size };
      });
    } catch {
      return [];
    }
  }
}
