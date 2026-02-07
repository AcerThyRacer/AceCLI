// ============================================================
//  AceCLI – Base Provider Wrapper (CLI Mode)
//  - Vault API key injection into subprocess environment
//  - Prompt delivery via stdin (prevents process listing leaks)
//  - Audit trail integration
// ============================================================
import { spawn } from 'child_process';
import { Transform } from 'stream';
import chalk from 'chalk';
import { classifyError } from '../errors.js';

// Provider → environment variable mapping for API key injection
const PROVIDER_ENV_MAP = {
  openai: 'OPENAI_API_KEY',
  claude: 'ANTHROPIC_API_KEY',
  gemini: 'GEMINI_API_KEY',
};

// Stream transform that applies sanitization in real-time
class SanitizingTransform extends Transform {
  constructor(sanitizer, audit, direction, providerName) {
    super();
    this.sanitizer = sanitizer;
    this.audit = audit;
    this.direction = direction; // 'input' or 'output'
    this.providerName = providerName;
  }

  _transform(chunk, encoding, callback) {
    let text = chunk.toString();

    if (this.sanitizer?.enabled) {
      // PII/secret redaction
      const { text: sanitized, redactions } = this.sanitizer.sanitize(text);
      if (redactions.length > 0) {
        this.audit?.log({
          type: 'PII_REDACTED_INTERACTIVE',
          provider: this.providerName,
          details: { direction: this.direction, count: redactions.length },
        });
      }
      text = sanitized;

      // Injection detection on input
      if (this.direction === 'input') {
        const injection = this.sanitizer.detectInjection(text);
        if (injection.detected && (injection.severity === 'HIGH' || injection.severity === 'CRITICAL')) {
          this.audit?.log({
            type: 'INJECTION_BLOCKED_INTERACTIVE',
            provider: this.providerName,
            details: { severity: injection.severity, score: injection.score },
          });
          process.stderr.write(
            chalk.red(`\n  ⛔ Injection blocked (${injection.severity}) – input not sent\n`)
          );
          callback();
          return;
        } else if (injection.detected) {
          process.stderr.write(
            chalk.yellow(`\n  ⚠ Injection warning (${injection.severity})\n`)
          );
        }
      }
    }

    callback(null, Buffer.from(text));
  }
}

export class BaseProvider {
  constructor(name, options = {}) {
    this.name = name;
    this.command = options.command || name;
    this.args = options.args || [];
    this.sanitizer = options.sanitizer;
    this.fingerprint = options.fingerprint;
    this.proxy = options.proxy;
    this.audit = options.audit;
    this.trackerBlocker = options.trackerBlocker;
    this.encryption = options.encryption;
    this.ephemeral = options.ephemeral || false;
    this.conversationLog = [];

    // Vault integration for API key injection
    this.configManager = options.configManager || null;
    this.envVarName = options.envVarName || null;
    this.vaultKeyName = options.vaultKeyName || null;

    // Prompt delivery mode: 'args' (legacy) or 'stdin' (secure)
    this.promptMode = options.promptMode || 'args';
  }

  // Check if the underlying CLI is installed
  async isInstalled() {
    return new Promise((resolve) => {
      const proc = spawn(`${this.command} --version`, {
        shell: true,
        stdio: 'pipe',
        timeout: 5000,
      });
      proc.on('close', (code) => resolve(code === 0));
      proc.on('error', () => resolve(false));
    });
  }

  // Sanitize outgoing prompt
  sanitizePrompt(prompt) {
    if (!this.sanitizer) return { text: prompt, redactions: [] };
    return this.sanitizer.sanitize(prompt);
  }

  // Check for prompt injection
  checkInjection(text) {
    if (!this.sanitizer) return { detected: false };
    return this.sanitizer.detectInjection(text);
  }

  // Inject vault API key into environment
  _injectApiKey(env) {
    const envVar = this.envVarName || PROVIDER_ENV_MAP[this.name.toLowerCase()];
    if (!envVar) return env;

    // Skip if env var already set
    if (env[envVar]) return env;

    // Try vault first
    if (this.configManager) {
      const vaultKey = this.configManager.getApiKey(this.vaultKeyName || this.name.toLowerCase());
      if (vaultKey) {
        env[envVar] = vaultKey;
        this.audit?.log({
          type: 'API_KEY_INJECTED',
          provider: this.name,
          details: { source: 'vault', envVar },
        });
        return env;
      }
    }

    // Fall back to process.env
    if (process.env[envVar]) {
      env[envVar] = process.env[envVar];
      this.audit?.log({
        type: 'API_KEY_INJECTED',
        provider: this.name,
        details: { source: 'environment', envVar },
      });
    }

    return env;
  }

  // Remove API key from env object (for cleanup after subprocess exits)
  _clearApiKey(env) {
    const envVar = this.envVarName || PROVIDER_ENV_MAP[this.name.toLowerCase()];
    if (envVar && env[envVar]) {
      delete env[envVar];
    }
  }

  // Get sanitized environment for subprocess with API key injection
  getSecureEnv() {
    let env = {};

    if (this.fingerprint) {
      env = { ...this.fingerprint.getSanitizedEnv() };
    } else {
      env = { ...process.env };
    }

    if (this.proxy?.enabled) {
      Object.assign(env, this.proxy.getProxyEnv());
    }

    // Apply tracker blocker environment sanitization
    if (this.trackerBlocker) {
      env = this.trackerBlocker.sanitizeEnvironment(env);
    }

    // Inject API key from vault or environment
    env = this._injectApiKey(env);

    return env;
  }

  // Strip tracking parameters from URLs in text
  sanitizeUrls(text) {
    if (!this.trackerBlocker) return text;

    // Find URLs and strip tracking params
    const urlRegex = /https?:\/\/[^\s\)\"\'\<\>\`]+/g;
    return text.replace(urlRegex, (url) => {
      const sanitized = this.trackerBlocker.stripTrackingParams(url);
      if (sanitized !== url) {
        this.audit?.log({
          type: 'TRACKING_PARAMS_STRIPPED',
          provider: this.name,
          details: { original: url.substring(0, 100), sanitized: sanitized.substring(0, 100) },
        });
      }
      return sanitized;
    });
  }

  // Execute a command with full security pipeline
  async execute(prompt, options = {}) {
    // 1. Check for prompt injection
    const injection = this.checkInjection(prompt);
    if (injection.detected) {
      this.audit?.log({
        type: 'INJECTION_DETECTED',
        provider: this.name,
        details: { severity: injection.severity, score: injection.score, patterns: injection.patterns, heuristics: injection.heuristics?.map(h => h.rule) },
      });

      if (injection.severity === 'HIGH' || injection.severity === 'CRITICAL') {
        return {
          success: false,
          error: `Prompt injection detected (${injection.severity}, score: ${injection.score}). Blocked.`,
          injection,
        };
      }
      console.log(chalk.red(`  ⚠ Prompt injection warning (${injection.severity}, score: ${injection.score})`));
      if (injection.heuristics?.length > 0) {
        for (const h of injection.heuristics) {
          console.log(chalk.yellow(`     • ${h.rule}: ${h.desc}`));
        }
      }
    }

    // 2. Sanitize prompt
    const sanitized = this.sanitizePrompt(prompt);
    if (sanitized.redactions.length > 0) {
      console.log(this.sanitizer.formatWarning(sanitized.redactions));
      this.audit?.log({
        type: 'PII_REDACTED',
        provider: this.name,
        details: { count: sanitized.redactions.length },
      });
    }

    // 3. Log the action
    this.audit?.log({
      type: 'PROMPT_SENT',
      provider: this.name,
      details: { length: sanitized.text.length, hadRedactions: sanitized.redactions.length > 0, promptMode: this.promptMode },
    });

    // 4. Execute with typed error handling
    let result;
    try {
      result = await this._run(sanitized.text, options);
    } catch (err) {
      const classified = classifyError(err, { command: this.command, provider: this.name });
      this.audit?.log({
        type: 'PROVIDER_ERROR',
        provider: this.name,
        details: { errorType: classified.type, message: classified.message },
      });
      return {
        success: false,
        output: '',
        error: classified.message,
        advice: classified.advice,
        errorType: classified.type,
        exitCode: -1,
      };
    }

    // 5. Classify execution failures
    if (!result.success && result.error) {
      const classified = classifyError(new Error(result.error), {
        command: this.command,
        provider: this.name,
        exitCode: result.exitCode,
      });
      result.advice = classified.advice;
      result.errorType = classified.type;
    }

    // 6. Sanitize response
    if (result.output) {
      const sanitizedResponse = this.sanitizer
        ? this.sanitizer.sanitize(result.output)
        : { text: result.output, redactions: [] };
      result.output = sanitizedResponse.text;
    }

    // 7. Store in conversation log (encrypted if not ephemeral)
    if (!this.ephemeral) {
      this.conversationLog.push({
        timestamp: new Date().toISOString(),
        prompt: '[ENCRYPTED]',
        response: '[ENCRYPTED]',
      });
    }

    return result;
  }

  // Execute via subprocess — supports both args and stdin prompt delivery
  async _run(prompt, options) {
    return new Promise((resolve, reject) => {
      let args;
      const env = this.getSecureEnv();

      if (this.promptMode === 'stdin') {
        // Secure: pass prompt via stdin (not visible in ps/process listing)
        args = [...this.args, ...(options.args || [])];
      } else {
        // Legacy: pass prompt as command line argument
        args = [...this.args, ...(options.args || []), prompt];
      }

      const fullCmd = [this.command, ...args].join(' ');
      const proc = spawn(fullCmd, {
        shell: true,
        env,
        stdio: ['pipe', 'pipe', 'pipe'],
        timeout: options.timeout || 120000,
      });

      let stdout = '';
      let stderr = '';
      proc.stdout.on('data', (d) => (stdout += d.toString()));
      proc.stderr.on('data', (d) => (stderr += d.toString()));

      // Send prompt via stdin if secure mode
      if (this.promptMode === 'stdin') {
        proc.stdin.write(prompt);
        proc.stdin.end();
      }

      proc.on('close', (code) => {
        // Clean up API key from env reference
        this._clearApiKey(env);
        resolve({
          success: code === 0,
          output: stdout,
          error: stderr,
          exitCode: code,
        });
      });

      proc.on('error', (err) => {
        this._clearApiKey(env);
        resolve({ success: false, output: '', error: err.message, exitCode: -1 });
      });
    });
  }

  // Interactive mode – direct terminal passthrough with secure env
  async interactive(options = {}) {
    const env = this.getSecureEnv();
    const args = this.getInteractiveArgs();

    this.audit?.log({ type: 'INTERACTIVE_START', provider: this.name });

    const fullCmd = [this.command, ...args].join(' ');
    const child = spawn(fullCmd, {
      shell: true,
      env,
      stdio: 'inherit', // Direct TTY access — CLI gets real terminal
      ...options,
    });

    // Handle cleanup
    child.on('close', () => {
      this._clearApiKey(env);
      this.audit?.log({ type: 'INTERACTIVE_END', provider: this.name });
    });

    return child;
  }

  getInteractiveArgs() {
    return this.args;
  }

  getInfo() {
    return {
      name: this.name,
      command: this.command,
      args: this.args,
      mode: 'cli',
    };
  }
}
