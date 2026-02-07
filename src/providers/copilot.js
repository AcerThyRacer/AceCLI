// ============================================================
//  AceCLI – GitHub Copilot CLI Wrapper
// ============================================================
import { BaseProvider } from './base.js';

export class CopilotProvider extends BaseProvider {
  constructor(options = {}) {
    super('Copilot', {
      command: 'gh',
      args: ['copilot'],
      ...options,
    });
  }

  getInteractiveArgs() {
    return ['copilot', 'suggest'];
  }

  async _run(prompt, options) {
    const subcommand = options.subcommand || 'explain';
    const args = ['copilot', subcommand, prompt];
    return super._run(prompt, { ...options, args });
  }

  getInfo() {
    return { ...super.getInfo(), mode: 'cli', type: 'cloud' };
  }
}
