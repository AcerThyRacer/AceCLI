// ============================================================
//  AceCLI – Provider Registry (Dynamic Loading)
//  Includes both CLI wrappers and native API providers
// ============================================================
import chalk from 'chalk';
import { OpenAIProvider } from './openai.js';
import { ClaudeProvider } from './claude.js';
import { GeminiProvider } from './gemini.js';
import { CopilotProvider } from './copilot.js';
import { OllamaProvider } from './ollama.js';
import { OpenAIApiProvider } from './openai-api.js';
import { ClaudeApiProvider } from './claude-api.js';
import { GeminiApiProvider } from './gemini-api.js';
import { OllamaApiProvider } from './ollama-api.js';

// Built-in provider classes — API providers listed first (preferred)
const BUILTIN_PROVIDERS = {
  // Native API providers (no CLI binary needed — just an API key)
  'openai-api': OpenAIApiProvider,
  'claude-api': ClaudeApiProvider,
  'gemini-api': GeminiApiProvider,
  'ollama-api': OllamaApiProvider,
  // Legacy CLI wrappers (require CLI binary installed)
  openai: OpenAIProvider,
  claude: ClaudeProvider,
  gemini: GeminiProvider,
  copilot: CopilotProvider,
  ollama: OllamaProvider,
};

export class ProviderRegistry {
  constructor() {
    this._classes = { ...BUILTIN_PROVIDERS };
    this._instances = {};
  }

  // Register a custom provider class
  register(key, ProviderClass) {
    if (typeof ProviderClass !== 'function') {
      throw new Error(`Provider class for "${key}" must be a constructor`);
    }
    this._classes[key] = ProviderClass;
  }

  // Unregister a provider
  unregister(key) {
    delete this._classes[key];
    delete this._instances[key];
  }

  // Instantiate all registered providers with shared security context
  createAll(securityOpts = {}, providerConfigs = {}) {
    this._instances = {};
    for (const [key, Cls] of Object.entries(this._classes)) {
      const config = providerConfigs[key] || {};
      this._instances[key] = new Cls({ ...securityOpts, ...config });
    }
    return this._instances;
  }

  // Get a single instantiated provider
  get(key) {
    return this._instances[key] || null;
  }

  // Get all instantiated providers
  getAll() {
    return { ...this._instances };
  }

  // List registered provider keys
  listRegistered() {
    return Object.keys(this._classes);
  }

  // List instantiated provider keys
  listActive() {
    return Object.keys(this._instances);
  }

  // Check which providers are installed on the system
  async checkInstalled() {
    const results = {};
    for (const [key, provider] of Object.entries(this._instances)) {
      const info = provider.getInfo();
      results[key] = {
        name: provider.name,
        installed: await provider.isInstalled(),
        type: info.type,
        command: info.command || provider.command,
        mode: info.mode || 'cli',
      };
    }
    return results;
  }

  // Dynamic import of a plugin provider from a file path
  async loadPlugin(key, modulePath) {
    try {
      const { pathToFileURL } = await import('url');
      const mod = await import(pathToFileURL(modulePath).href);
      const ProviderClass = mod.default || mod[Object.keys(mod)[0]];
      this.register(key, ProviderClass);
      return true;
    } catch (err) {
      console.error(chalk.red(`  Failed to load plugin "${key}": ${err.message}`));
      return false;
    }
  }
}
