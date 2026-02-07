// ============================================================
//  AceCLI – OpenAI CLI Wrapper
//  - Vault key injection via OPENAI_API_KEY
//  - Secure stdin prompt delivery
// ============================================================
import { BaseProvider } from './base.js';

export class OpenAIProvider extends BaseProvider {
  constructor(options = {}) {
    super('OpenAI', {
      command: 'openai',
      args: [],
      envVarName: 'OPENAI_API_KEY',
      vaultKeyName: 'openai',
      promptMode: 'stdin',
      ...options,
    });
    this.model = options.model || 'gpt-4';
  }

  getInteractiveArgs() {
    return ['api', 'chat.completions.create', '-m', this.model, '--stream'];
  }

  async _run(prompt, options) {
    const args = [
      'api', 'chat.completions.create',
      '-m', options.model || this.model,
      '-g', 'user',
    ];

    // Use stdin for prompt delivery (override promptMode temporarily)
    return super._run(prompt, { ...options, args });
  }

  getInfo() {
    return { ...super.getInfo(), model: this.model, type: 'cloud' };
  }
}
