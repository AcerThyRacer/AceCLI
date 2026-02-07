// ============================================================
//  AceCLI – Ollama (Local) Wrapper
// ============================================================
import { BaseProvider } from './base.js';

export class OllamaProvider extends BaseProvider {
  constructor(options = {}) {
    super('Ollama', {
      command: 'ollama',
      args: [],
      ...options,
    });
    this.model = options.model || 'llama3';
  }

  getInteractiveArgs() {
    return ['run', this.model];
  }

  async _run(prompt, options) {
    const args = ['run', options.model || this.model, prompt];
    return super._run(prompt, { ...options, args });
  }

  async listModels() {
    return super._run('', { args: ['list'] });
  }

  getInfo() {
    return { ...super.getInfo(), model: this.model, mode: 'cli', type: 'local' };
  }
}
