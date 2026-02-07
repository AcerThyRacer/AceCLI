// ============================================================
//  AceCLI – Interactive Menu System
// ============================================================
import inquirer from 'inquirer';
import chalk from 'chalk';
import gradient from 'gradient-string';

const g = gradient(['#00ff88', '#00ccff']);

export async function mainMenu() {
  console.log(chalk.gray('  ─────────────────────────────────────────────────────'));
  const { choice } = await inquirer.prompt([
    {
      type: 'list',
      name: 'choice',
      message: g('ACE Main Menu'),
      prefix: '  ◈',
      choices: [
        { name: `${chalk.magentaBright('🧙')} Setup Wizard`, value: 'setup' },
        new inquirer.Separator(chalk.gray('  ── AI ──')),
        { name: `${chalk.green('🤖')} Chat with AI Provider`, value: 'chat' },
        { name: `${chalk.cyan('⚡')} Quick Prompt (one-shot)`, value: 'quick' },
        { name: `${chalk.blue('🔌')} Launch Provider Interactive`, value: 'interactive' },
        { name: `${chalk.magenta('📦')} Install AI Tools`, value: 'install-ai' },
        { name: `${chalk.green('💬')} Conversation History`, value: 'conversations' },
        new inquirer.Separator(chalk.gray('  ── Help ──')),
        { name: `${chalk.white('❓')} Help & Documentation`, value: 'help' },
        new inquirer.Separator(chalk.gray('  ── Security ──')),
        { name: `${chalk.yellow('🛡️')}  Security Dashboard`, value: 'dashboard' },
        { name: `${chalk.yellow('🔑')} API Key Vault`, value: 'vault' },
        { name: `${chalk.yellow('🌐')} Proxy / Tor Settings`, value: 'proxy' },
        { name: `${chalk.yellow('🛡️')}  Secure DNS (DoH/DoT)`, value: 'dns' },
        { name: `${chalk.yellow('🔒')} Privacy Settings`, value: 'privacy' },
        { name: `${chalk.yellow('🔐')} Change Password`, value: 'password' },
        { name: `${chalk.yellow('🔑')} MFA (Two-Factor Auth)`, value: 'mfa' },
        { name: `${chalk.yellow('🛡️')}  Integrity Checker`, value: 'integrity' },
        new inquirer.Separator(chalk.gray('  ── System ──')),
        { name: `${chalk.magenta('📋')} Audit Log`, value: 'audit' },
        { name: `${chalk.magenta('📤')} Export Audit Log`, value: 'audit-export' },
        { name: `${chalk.magenta('🩺')} Health Check (Doctor)`, value: 'doctor' },
        { name: `${chalk.magenta('⚙️')}  Configuration`, value: 'config' },
        { name: `${chalk.magenta('🔍')} Test Sanitizer`, value: 'test-sanitizer' },
        { name: `${chalk.magenta('🔄')} Session Recovery`, value: 'recovery' },
        new inquirer.Separator(chalk.gray('  ── Danger Zone ──')),
        { name: `${chalk.red('💀')} Kill Switch (wipe session)`, value: 'kill' },
        { name: `${chalk.gray('🚪')} Exit`, value: 'exit' },
      ],
    },
  ]);
  return choice;
}

export async function selectProvider(providers) {
  const apiChoices = [];
  const cliChoices = [];

  for (const [key, provider] of Object.entries(providers)) {
    const installed = await provider.isInstalled();
    const info = provider.getInfo();
    const isApi = info.mode === 'api';
    const status = installed ? chalk.green('✓ ready') : chalk.red('✗ no key');

    const typeTag = info.type === 'local'
      ? chalk.blue('[LOCAL]')
      : chalk.yellow('[CLOUD]');

    const modeTag = isApi
      ? chalk.magenta('[API]')
      : chalk.gray('[CLI]');

    const modelStr = info.model ? chalk.gray(` (${info.model})`) : '';

    const choice = {
      name: `${modeTag} ${typeTag} ${info.name}${modelStr} ${status}`,
      value: key,
      disabled: !installed && (isApi ? 'No API key — add via Vault' : 'Not installed'),
    };

    if (isApi) {
      apiChoices.push(choice);
    } else {
      cliChoices.push(choice);
    }
  }

  const choices = [];
  if (apiChoices.length > 0) {
    choices.push(new inquirer.Separator(chalk.cyan('  ── Native API (Recommended) ──')));
    choices.push(...apiChoices);
  }
  if (cliChoices.length > 0) {
    choices.push(new inquirer.Separator(chalk.gray('  ── CLI Wrappers (Legacy) ──')));
    choices.push(...cliChoices);
  }

  const { provider } = await inquirer.prompt([
    {
      type: 'list',
      name: 'provider',
      message: g('Select AI Provider'),
      prefix: '  ◈',
      choices,
    },
  ]);
  return provider;
}

export async function chatStartMenu(conversations) {
  const threads = conversations.listThreads();
  const choices = [
    { name: `${chalk.green('✨')} New Conversation`, value: 'new' },
  ];

  if (threads.length > 0) {
    choices.push(new inquirer.Separator(chalk.gray('  ── Recent Conversations ──')));
    // Show up to 10 most recent
    for (const t of threads.slice(0, 10)) {
      const age = _timeAgo(t.updated);
      const msgs = chalk.gray(`(${t.messageCount} msgs)`);
      choices.push({
        name: `  ${chalk.cyan(t.title || '(untitled)')} ${msgs} ${chalk.gray(age)}`,
        value: t.id,
      });
    }
  }

  const { action } = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: g('Chat'),
      prefix: '  💬',
      choices,
    },
  ]);
  return action;
}

export async function conversationMenu() {
  const { action } = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: g('Conversation History'),
      prefix: '  💬',
      choices: [
        { name: 'List all conversations', value: 'list' },
        { name: 'Search conversations', value: 'search' },
        { name: 'Export conversation', value: 'export' },
        { name: 'Delete conversation', value: 'delete' },
        { name: 'Delete ALL conversations', value: 'wipe' },
        { name: chalk.gray('← Back'), value: 'back' },
      ],
    },
  ]);
  return action;
}

export async function promptInput(label = 'Prompt') {
  const { input } = await inquirer.prompt([
    {
      type: 'input',
      name: 'input',
      message: chalk.cyan(`${label}:`),
      prefix: '  ▸',
    },
  ]);
  return input;
}

export async function confirmAction(message, defaultVal = false) {
  const { confirm } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'confirm',
      message: chalk.yellow(message),
      default: defaultVal,
      prefix: '  ⚠',
    },
  ]);
  return confirm;
}

export async function vaultMenu() {
  const { action } = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: g('API Key Vault'),
      prefix: '  🔑',
      choices: [
        { name: 'View stored keys', value: 'list' },
        { name: 'Add / Update key', value: 'add' },
        { name: 'Delete key', value: 'delete' },
        { name: chalk.gray('← Back'), value: 'back' },
      ],
    },
  ]);
  return action;
}

export async function dnsMenu() {
  const { action } = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: g('Secure DNS Settings (DoH/DoT)'),
      prefix: '  🛡️',
      choices: [
        { name: 'View DNS status', value: 'status' },
        { name: 'Enable Applied Privacy (Default)', value: 'default' },
        { name: 'Set Custom DoH Provider', value: 'custom' },
        { name: 'Toggle DoH ↔ DoT', value: 'dot' },
        { name: 'Disable Secure DNS (Use System)', value: 'disable' },
        { name: 'Test DNS Resolution', value: 'test' },
        { name: '🏁 Benchmark All Providers', value: 'benchmark' },
        { name: '📦 View DNS Cache', value: 'cache' },
        { name: chalk.gray('← Back'), value: 'back' },
      ],
    },
  ]);
  return action;
}

export async function proxyMenu() {
  const { action } = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: g('Proxy / Tor Settings'),
      prefix: '  🌐',
      choices: [
        { name: 'View proxy status', value: 'status' },
        { name: 'Enable Tor (SOCKS5 on 127.0.0.1:9050)', value: 'tor' },
        { name: 'Custom SOCKS proxy', value: 'custom' },
        { name: 'Disable proxy', value: 'disable' },
        { name: 'Test connection', value: 'test' },
        { name: chalk.gray('← Back'), value: 'back' },
      ],
    },
  ]);
  return action;
}

export async function privacyMenu() {
  const { action } = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: g('Privacy Settings'),
      prefix: '  🔒',
      choices: [
        { name: 'Toggle PII redaction', value: 'pii' },
        { name: 'Toggle strict mode (hide all matches)', value: 'strict' },
        { name: 'Toggle fingerprint masking', value: 'fingerprint' },
        { name: 'Toggle metadata stripping', value: 'metadata' },
        { name: 'Toggle clipboard auto-clear', value: 'clipboard' },
        { name: 'Toggle prompt injection detection', value: 'injection' },
        { name: 'Toggle mass tracker blocking', value: 'trackerBlocker' },
        { name: 'Toggle ephemeral mode (zero disk writes)', value: 'ephemeral' },
        { name: chalk.gray('← Back'), value: 'back' },
      ],
    },
  ]);
  return action;
}

export async function auditExportMenu() {
  const { action } = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: g('Export Audit Log'),
      prefix: '  📤',
      choices: [
        { name: 'Export current session as JSON', value: 'json' },
        { name: 'Export current session as CSV', value: 'csv' },
        { name: 'Load & export previous session from disk', value: 'disk' },
        { name: chalk.gray('← Back'), value: 'back' },
      ],
    },
  ]);
  return action;
}

export async function recoveryMenu() {
  const { action } = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: g('Session Recovery'),
      prefix: '  🔄',
      choices: [
        { name: 'Save checkpoint now', value: 'save' },
        { name: 'List recoverable sessions', value: 'list' },
        { name: 'Load a previous session', value: 'load' },
        { name: 'Delete recovery data', value: 'delete' },
        { name: chalk.gray('← Back'), value: 'back' },
      ],
    },
  ]);
  return action;
}

// ── Helpers ─────────────────────────────────────────────────
function _timeAgo(isoString) {
  const now = Date.now();
  const then = new Date(isoString).getTime();
  const diff = now - then;
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(isoString).toLocaleDateString();
}

export async function mfaMenu() {
  const { action } = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: g('MFA (Two-Factor Authentication)'),
      prefix: '  🔑',
      choices: [
        { name: 'View MFA status', value: 'status' },
        { name: 'Enable / Setup MFA (TOTP)', value: 'setup' },
        { name: 'Verify MFA code (test)', value: 'verify' },
        { name: 'View recovery codes', value: 'recovery' },
        { name: 'Regenerate recovery codes', value: 'regen' },
        { name: chalk.red('Disable MFA'), value: 'disable' },
        { name: chalk.gray('← Back'), value: 'back' },
      ],
    },
  ]);
  return action;
}

export async function integrityMenu() {
  const { action } = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: g('CLI Integrity Checker'),
      prefix: '  🛡️',
      choices: [
        { name: 'View integrity status', value: 'status' },
        { name: 'Verify all provider binaries', value: 'verify-all' },
        { name: 'Verify ACE self-integrity', value: 'self-check' },
        { name: 'Record new baselines', value: 'baseline' },
        { name: 'View baselined providers', value: 'list' },
        { name: chalk.red('Clear all baselines'), value: 'clear' },
        { name: chalk.gray('← Back'), value: 'back' },
      ],
    },
  ]);
  return action;
}
