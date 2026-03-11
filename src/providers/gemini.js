// ============================================================
//  AceCLI – Gemini CLI Wrapper
//  - Vault key injection via GEMINI_API_KEY
// ============================================================
import { BaseProvider } from './base.js';

export class GeminiProvider extends BaseProvider {
  constructor(options = {}) {
    super('Gemini', {
      command: 'gemini',
      args: [],
      envVarName: 'GEMINI_API_KEY',
      vaultKeyName: 'gemini',
      ...options,
    });
  }

  getInteractiveArgs() {
    return [];
  }

  async _run(prompt, options) {
    const args = [prompt];
    return super._run(prompt, { ...options, args, promptProvidedInArgs: true });
  }

  getInfo() {
    return { ...super.getInfo(), type: 'cloud' };
  }
}
