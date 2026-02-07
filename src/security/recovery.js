// ============================================================
//  AceCLI – Session Recovery (Encrypted Checkpoint)
// ============================================================
import { existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { Encryption } from './encryption.js';
import { randomBytes } from 'crypto';

const RECOVERY_DIR = join(homedir(), '.ace', 'recovery');

// Validate session ID to prevent path traversal attacks
const SESSION_ID_REGEX = /^[a-f0-9]{1,64}$/;

function validateSessionId(sessionId) {
  if (!sessionId || typeof sessionId !== 'string') return false;
  return SESSION_ID_REGEX.test(sessionId);
}

export class SessionRecovery {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.masterPassword = options.masterPassword;
    this.encryption = this.masterPassword ? new Encryption(this.masterPassword) : null;
    this.sessionId = options.sessionId || randomBytes(8).toString('hex');
    this.checkpointInterval = options.checkpointInterval || 60000; // 1 min
    this.audit = options.audit || null;
    this._timer = null;

    if (this.enabled) {
      mkdirSync(RECOVERY_DIR, { recursive: true });
    }
  }

  _getFilePath() {
    return join(RECOVERY_DIR, `session_${this.sessionId}.recovery`);
  }

  // Save a checkpoint of current session state
  saveCheckpoint(state) {
    if (!this.enabled || !this.encryption) return false;

    try {
      const payload = {
        sessionId: this.sessionId,
        timestamp: new Date().toISOString(),
        state: {
          configSnapshot: state.config?.config || {},
          auditLogLength: state.audit?.memoryLog?.length || 0,
          activeProvider: state.activeProvider || null,
          proxyEnabled: state.proxy?.enabled || false,
          conversationCount: state.conversationCount || 0,
        },
      };

      const encrypted = this.encryption.encrypt(JSON.stringify(payload));
      writeFileSync(this._getFilePath(), encrypted, 'utf8');
      return true;
    } catch (err) {
      this.audit?.log({ type: 'DEBUG_ERROR', details: { op: 'saveCheckpoint', error: err.message } });
      return false;
    }
  }

  // Load a checkpoint
  loadCheckpoint(sessionId) {
    if (!this.encryption) return null;

    // Validate sessionId to prevent path traversal
    if (sessionId && !validateSessionId(sessionId)) return null;

    const filepath = sessionId
      ? join(RECOVERY_DIR, `session_${sessionId}.recovery`)
      : this._getFilePath();

    try {
      if (!existsSync(filepath)) return null;
      const encrypted = readFileSync(filepath, 'utf8');
      const payload = JSON.parse(this.encryption.decrypt(encrypted));
      return payload;
    } catch (err) {
      this.audit?.log({ type: 'DEBUG_ERROR', details: { op: 'loadCheckpoint', error: err.message } });
      return null;
    }
  }

  // List all recoverable sessions
  listRecoverableSessions() {
    try {
      if (!existsSync(RECOVERY_DIR)) return [];

      const files = readdirSync(RECOVERY_DIR).filter((f) => f.endsWith('.recovery'));
      return files.map((f) => {
        const id = f.replace('session_', '').replace('.recovery', '');
        try {
          const stat = statSync(join(RECOVERY_DIR, f));
          return { sessionId: id, modified: stat.mtime };
        } catch (err) {
          this.audit?.log({ type: 'DEBUG_ERROR', details: { op: 'listSessions.stat', error: err.message } });
          return { sessionId: id, modified: null };
        }
      });
    } catch (err) {
      this.audit?.log({ type: 'DEBUG_ERROR', details: { op: 'listRecoverableSessions', error: err.message } });
      return [];
    }
  }

  // Delete a checkpoint
  deleteCheckpoint(sessionId) {
    // Validate sessionId to prevent path traversal
    if (sessionId && !validateSessionId(sessionId)) return false;

    const filepath = sessionId
      ? join(RECOVERY_DIR, `session_${sessionId}.recovery`)
      : this._getFilePath();

    try {
      if (existsSync(filepath)) {
        // Overwrite with random data before delete
        writeFileSync(filepath, randomBytes(512));
        unlinkSync(filepath);
      }
      return true;
    } catch (err) {
      this.audit?.log({ type: 'DEBUG_ERROR', details: { op: 'deleteCheckpoint', error: err.message } });
      return false;
    }
  }

  // Start periodic auto-save
  startAutoSave(getStateFunc) {
    if (!this.enabled) return;
    this.stopAutoSave();
    this._timer = setInterval(() => {
      try {
        const state = getStateFunc();
        this.saveCheckpoint(state);
      } catch (err) { this.audit?.log({ type: 'DEBUG_ERROR', details: { op: 'autoSave', error: err.message } }); }
    }, this.checkpointInterval);

    // Don't prevent Node from exiting
    if (this._timer.unref) this._timer.unref();
  }

  stopAutoSave() {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
  }

  // Wipe all recovery data
  wipeAll() {
    this.stopAutoSave();
    try {
      if (!existsSync(RECOVERY_DIR)) return;
      const files = readdirSync(RECOVERY_DIR).filter((f) => f.endsWith('.recovery'));
      for (const f of files) {
        const fp = join(RECOVERY_DIR, f);
        writeFileSync(fp, randomBytes(512));
        unlinkSync(fp);
      }
    } catch (err) { this.audit?.log({ type: 'DEBUG_ERROR', details: { op: 'wipeAll', error: err.message } }); }
  }
}
