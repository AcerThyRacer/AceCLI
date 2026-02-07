// ============================================================
//  AceCLI – Cross-Platform Clipboard Manager
// ============================================================
import chalk from 'chalk';

let clipboardy;

async function getClipboardy() {
  if (!clipboardy) {
    try {
      clipboardy = await import('clipboardy');
    } catch (err) {
      clipboardy = null;
    }
  }
  return clipboardy;
}

export class ClipboardManager {
  constructor(options = {}) {
    this.autoClear = options.autoClear !== false;
    this.clearDelay = options.clearDelay || 30;
    this.audit = options.audit || null;
    this._timers = [];
  }

  async write(text) {
    const cb = await getClipboardy();
    if (!cb) return false;

    try {
      await cb.default.write(text);
      if (this.autoClear) {
        this.scheduleAutoClear();
      }
      return true;
    } catch (err) {
      this.audit?.log({ type: 'DEBUG_ERROR', details: { op: 'clipboard.write', error: err.message } });
      return false;
    }
  }

  async read() {
    const cb = await getClipboardy();
    if (!cb) return null;

    try {
      return await cb.default.read();
    } catch (err) {
      this.audit?.log({ type: 'DEBUG_ERROR', details: { op: 'clipboard.read', error: err.message } });
      return null;
    }
  }

  async clear() {
    const cb = await getClipboardy();
    if (!cb) return false;

    try {
      await cb.default.write('');
      return true;
    } catch (err) {
      this.audit?.log({ type: 'DEBUG_ERROR', details: { op: 'clipboard.clear', error: err.message } });
      return false;
    }
  }

  scheduleAutoClear() {
    const timer = setTimeout(async () => {
      await this.clear();
      const idx = this._timers.indexOf(timer);
      if (idx !== -1) this._timers.splice(idx, 1);
    }, this.clearDelay * 1000);
    this._timers.push(timer);
  }

  cancelAllTimers() {
    for (const t of this._timers) clearTimeout(t);
    this._timers = [];
  }

  async isAvailable() {
    const cb = await getClipboardy();
    if (!cb) return false;
    try {
      await cb.default.read();
      return true;
    } catch (err) {
      this.audit?.log({ type: 'DEBUG_ERROR', details: { op: 'clipboard.isAvailable', error: err.message } });
      return false;
    }
  }

  formatStatus() {
    return this.autoClear
      ? chalk.green(`  📋 Clipboard: auto-clear in ${this.clearDelay}s`)
      : chalk.yellow('  📋 Clipboard: auto-clear disabled');
  }
}
