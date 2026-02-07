// ============================================================
//  AceCLI – Claude CLI Wrapper
//  - Vault key injection via ANTHROPIC_API_KEY
//  - Secure stdin prompt delivery
// ============================================================
import { BaseProvider } from './base.js';

export class ClaudeProvider extends BaseProvider {
  constructor(options = {}) {
    super('Claude', {
      command: 'claude',
      args: [],
      envVarName: 'ANTHROPIC_API_KEY',
      vaultKeyName: 'claude',
      promptMode: 'stdin',
      ...options,
    });
  }

  getInteractiveArgs() {
    return [];
  }

  async _run(prompt, options) {
    const args = ['-p'];
    if (options.model) args.push('--model', options.model);
    return super._run(prompt, { ...options, args });
  }

  getInfo() {
    return { ...super.getInfo(), type: 'cloud' };
  }
}
