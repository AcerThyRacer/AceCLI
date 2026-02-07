// ============================================================
//  AceCLI – Cross-Platform Clipboard Manager
// ============================================================
import chalk from 'chalk';

let clipboardy;

async function getClipboardy() {
  if (!clipboardy) {
    try {
      clipboardy = await import('clipboardy');
    } catch {
      clipboardy = null;
    }
  }
  return clipboardy;
}

export class ClipboardManager {
  constructor(options = {}) {
    this.autoClear = options.autoClear !== false;
    this.clearDelay = options.clearDelay || 30;
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
    } catch {
      return false;
    }
  }

  async read() {
    const cb = await getClipboardy();
    if (!cb) return null;

    try {
      return await cb.default.read();
    } catch {
      return null;
    }
  }

  async clear() {
    const cb = await getClipboardy();
    if (!cb) return false;

    try {
      await cb.default.write('');
      return true;
    } catch {
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
    } catch {
      return false;
    }
  }

  formatStatus() {
    return this.autoClear
      ? chalk.green(`  📋 Clipboard: auto-clear in ${this.clearDelay}s`)
      : chalk.yellow('  📋 Clipboard: auto-clear disabled');
  }
}
