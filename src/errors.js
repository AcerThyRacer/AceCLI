// ============================================================
//  AceCLI – Typed Error Classes
// ============================================================

export class AceError extends Error {
  constructor(message, type, details = {}) {
    super(message);
    this.name = 'AceError';
    this.type = type;
    this.details = details;
    this.timestamp = new Date().toISOString();
  }

  get advice() {
    return 'An unexpected error occurred. Check logs for details.';
  }
}

export class NetworkError extends AceError {
  constructor(message, details = {}) {
    super(message, 'NETWORK', details);
    this.name = 'NetworkError';
  }

  get advice() {
    const hints = [
      '• Check your internet connection',
      '• If using Tor/proxy, verify the proxy service is running',
      '• Try disabling proxy to test direct connection',
      '• Run "ace doctor" to diagnose connectivity issues',
    ];
    if (this.details.proxy) {
      hints.unshift(`• Proxy endpoint: ${this.details.proxy}`);
    }
    if (this.message.includes('ECONNREFUSED')) {
      hints.unshift('• The target service refused the connection');
    }
    if (this.message.includes('ETIMEDOUT') || this.message.includes('timeout')) {
      hints.unshift('• The request timed out – Tor connections can be slow');
    }
    return hints.join('\n');
  }
}

export class AuthenticationError extends AceError {
  constructor(message, details = {}) {
    super(message, 'AUTH', details);
    this.name = 'AuthenticationError';
  }

  get advice() {
    const hints = [
      '• Verify your API key is correct and not expired',
      `• Check the key vault: Main Menu → API Key Vault`,
      '• Ensure the key has the required permissions/scopes',
    ];
    if (this.details.provider) {
      hints.unshift(`• Provider: ${this.details.provider}`);
    }
    if (this.details.statusCode === 401) {
      hints.push('• HTTP 401: The API key was rejected by the server');
    }
    if (this.details.statusCode === 403) {
      hints.push('• HTTP 403: Access forbidden – check account billing/limits');
    }
    return hints.join('\n');
  }
}

export class RuntimeError extends AceError {
  constructor(message, details = {}) {
    super(message, 'RUNTIME', details);
    this.name = 'RuntimeError';
  }

  get advice() {
    const hints = [];
    if (this.details.command) {
      hints.push(`• Command: ${this.details.command}`);
    }
    if (this.details.exitCode !== undefined) {
      hints.push(`• Exit code: ${this.details.exitCode}`);
    }
    if (this.message.includes('ENOENT') || this.message.includes('not found')) {
      hints.push('• The CLI tool is not installed or not on PATH');
      hints.push('• Run "ace doctor" to check installation status');
    }
    if (this.message.includes('EPERM') || this.message.includes('permission')) {
      hints.push('• Insufficient permissions to run this command');
    }
    hints.push('• Try running the command directly to see the full error');
    return hints.join('\n');
  }
}

export class ProviderNotFoundError extends RuntimeError {
  constructor(provider) {
    super(`CLI for "${provider}" not found on system`, {
      command: provider,
      exitCode: 127,
    });
    this.name = 'ProviderNotFoundError';
  }

  get advice() {
    const installGuides = {
      openai: 'pip install openai',
      claude: 'npm install -g @anthropic-ai/claude-code',
      gemini: 'npm install -g @google/generative-ai  OR  pip install google-generativeai',
      ollama: 'https://ollama.com/download',
      'gh copilot': 'gh extension install github/gh-copilot',
    };
    const guide = installGuides[this.details.command] || 'Check the provider documentation';
    return [
      `• "${this.details.command}" is not installed or not on PATH`,
      `• Install with: ${guide}`,
      '• After installing, restart ACE CLI',
    ].join('\n');
  }
}

// Classify raw errors into typed errors
export function classifyError(err, context = {}) {
  const msg = err.message || String(err);

  // Network errors
  if (/ECONNREFUSED|ETIMEDOUT|ENOTFOUND|ENETUNREACH|socket hang up|timeout|network/i.test(msg)) {
    return new NetworkError(msg, { ...context, originalError: err.code });
  }

  // Auth errors
  if (/401|403|unauthorized|forbidden|invalid.*key|invalid.*token|authentication/i.test(msg)) {
    return new AuthenticationError(msg, {
      ...context,
      statusCode: msg.match(/40[13]/)?.[0],
    });
  }

  // Provider not found
  if (/ENOENT|not found|not recognized|is not recognized/i.test(msg) && context.command) {
    return new ProviderNotFoundError(context.command);
  }

  // Generic runtime
  return new RuntimeError(msg, context);
}
