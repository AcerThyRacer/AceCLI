// ============================================================
//  AceCLI – Setup Wizard (with Feature Details)
//  Guided first-time configuration for all major features
// ============================================================
import inquirer from 'inquirer';
import chalk from 'chalk';
import gradient from 'gradient-string';
import boxen from 'boxen';

const g = gradient(['#00ff88', '#00ccff', '#8844ff']);
const c = (t) => chalk.green(t);
const d = (t) => chalk.gray(t);

// ── Feature detail descriptions ──────────────────────────────
const FEATURE_DETAILS = {
  piiRedaction: {
    name: 'PII Auto-Redaction',
    short: 'Scrubs personal data from prompts before they reach AI',
    detail: [
      'Automatically detects and replaces sensitive data before it leaves your machine:',
      '',
      '  • Email addresses      →  [REDACTED_EMAIL]',
      '  • IP addresses         →  [REDACTED_IP]',
      '  • Phone numbers        →  [REDACTED_PHONE]',
      '  • SSN / Tax IDs        →  [REDACTED_SSN]',
      '  • Credit card numbers  →  [REDACTED_CC]',
      '  • API keys / tokens    →  [REDACTED_KEY]',
      '  • File paths           →  [REDACTED_PATH]',
      '',
      'Uses 40+ regex patterns. Works on both outbound prompts and',
      'any text you paste into the chat.',
    ],
  },
  strictMode: {
    name: 'Strict Mode',
    short: 'Never shows original text — redacted copy only',
    detail: [
      'When enabled, the original unredacted text is never displayed',
      'in the terminal. You only see the sanitized version.',
      '',
      'Without strict mode, ACE shows you what was redacted so you',
      'can verify. With strict mode, the original is discarded from',
      'memory immediately after redaction.',
      '',
      'Recommended for shared screens or recording sessions.',
    ],
  },
  fingerprintMasking: {
    name: 'Fingerprint Masking',
    short: 'Spoofs hostname, username, and OS details',
    detail: [
      'Replaces identifiable system info with randomized fakes:',
      '',
      '  • Hostname     → random workstation name (e.g. "workstation-01")',
      '  • Username     → generic name (e.g. "user")',
      '  • OS version   → generic platform string',
      '  • MAC address  → randomized',
      '',
      'Prevents AI providers from building a hardware fingerprint',
      'of your machine across sessions.',
    ],
  },
  metadataStripping: {
    name: 'Metadata Stripping',
    short: 'Cleans environment variables passed to AI subprocesses',
    detail: [
      'Before spawning any AI CLI subprocess, ACE strips environment',
      'variables that could identify you:',
      '',
      '  • HOME, USERPROFILE, USERNAME, COMPUTERNAME',
      '  • SSH_*, GPG_*, AWS_*, AZURE_* credentials',
      '  • Browser history paths, shell history files',
      '  • Any variable matching known telemetry patterns',
      '',
      'The subprocess only sees a clean, minimal environment.',
    ],
  },
  clipboardAutoClear: {
    name: 'Clipboard Auto-Clear',
    short: 'Wipes clipboard after you copy sensitive output',
    detail: [
      'After you copy text from ACE (API keys, responses, etc.),',
      'the clipboard is automatically wiped after a delay.',
      '',
      'Configurable delay: 10s (paranoid), 30s, 60s, or 120s.',
      '',
      'Prevents sensitive data from sitting in your clipboard',
      'indefinitely where other apps could read it.',
    ],
  },
  promptInjectionDetection: {
    name: 'Prompt Injection Detection',
    short: 'Catches adversarial prompts that try to hijack AI behavior',
    detail: [
      'Scans outbound prompts for known injection patterns:',
      '',
      '  • "Ignore all previous instructions..."',
      '  • Base64-encoded payloads',
      '  • Hidden Unicode control characters',
      '  • Markdown/HTML injection attempts',
      '  • Role-switching attacks ("You are now...")',
      '',
      'Warns you before sending suspicious prompts.',
    ],
  },
  trackerBlocking: {
    name: 'Mass Tracker Blocking',
    short: 'Blocks 1000+ tracking domains, strips URL params',
    detail: [
      'Multi-layer anti-tracking engine:',
      '',
      '  • Domain blocking:      1000+ tracker domains (Google Analytics,',
      '                           Facebook Pixel, Mixpanel, Hotjar, etc.)',
      '  • URL param stripping:  Removes utm_*, fbclid, gclid, etc.',
      '  • Header sanitization:  Strips tracking HTTP headers',
      '  • Env var cleaning:     Removes telemetry env vars',
      '  • Fingerprint detection: Catches canvas/WebGL fingerprinting',
      '  • DNS interception:     Blocks tracker domains at DNS level',
    ],
  },
};

const PROFILE_DETAILS = {
  max: [
    chalk.yellow.bold('Maximum Security Profile'),
    '',
    'Everything is ON, no exceptions:',
    '',
    `  ${chalk.green('✓')} PII redaction with strict mode (original text never shown)`,
    `  ${chalk.green('✓')} Fingerprint masking (hostname, username, OS)`,
    `  ${chalk.green('✓')} Full metadata stripping`,
    `  ${chalk.green('✓')} Clipboard auto-clear (10 seconds)`,
    `  ${chalk.green('✓')} Prompt injection detection`,
    `  ${chalk.green('✓')} Mass tracker blocking (all layers)`,
    `  ${chalk.green('✓')} Ephemeral audit (nothing written to disk)`,
    '',
    `${chalk.yellow('Trade-off:')} Slightly slower due to aggressive scanning.`,
    'Best for: journalists, activists, high-risk environments.',
  ],
  recommended: [
    chalk.cyan.bold('Recommended Profile'),
    '',
    'Strong protection balanced for daily use:',
    '',
    `  ${chalk.green('✓')} PII redaction (shows what was caught)`,
    `  ${chalk.red('✗')} Strict mode OFF (you see originals)`,
    `  ${chalk.green('✓')} Fingerprint masking`,
    `  ${chalk.green('✓')} Metadata stripping`,
    `  ${chalk.green('✓')} Clipboard auto-clear (30 seconds)`,
    `  ${chalk.green('✓')} Prompt injection detection`,
    `  ${chalk.green('✓')} Mass tracker blocking`,
    '',
    'Best for: developers, power users, everyday privacy.',
  ],
  minimal: [
    chalk.gray.bold('Minimal Profile'),
    '',
    'Lightweight — only the essentials:',
    '',
    `  ${chalk.green('✓')} PII redaction (basic patterns only)`,
    `  ${chalk.red('✗')} Strict mode OFF`,
    `  ${chalk.red('✗')} Fingerprint masking OFF`,
    `  ${chalk.red('✗')} Metadata stripping OFF`,
    `  ${chalk.red('✗')} Clipboard auto-clear OFF`,
    `  ${chalk.red('✗')} Prompt injection detection OFF`,
    `  ${chalk.red('✗')} Tracker blocking OFF`,
    '',
    'Best for: local-only models (Ollama), trusted networks.',
  ],
};

// ── Main wizard ──────────────────────────────────────────────
export async function runSetupWizard(ctx) {
  console.log();
  console.log(g('  ╔══════════════════════════════════════════════════════╗'));
  console.log(g('  ║         🧙  ACE CLI  –  SETUP WIZARD  🧙           ║'));
  console.log(g('  ╚══════════════════════════════════════════════════════╝'));
  console.log();
  console.log(boxen(
    [
      chalk.cyan.bold('Welcome to AceCLI Setup!'),
      '',
      '  Quick guided setup — choose a security profile,',
      '  add API keys, and configure your preferences.',
      '  Re-run anytime from the main menu.',
    ].join('\n'),
    { padding: 1, margin: { left: 2 }, borderStyle: 'round', borderColor: 'green' }
  ));
  console.log();

  // ── Step 1: Security Profile ────────────────────────────────
  stepHeader(1, 'Security Profile');

  let profile;
  while (true) {
    const { choice } = await inquirer.prompt([{
      type: 'list',
      name: 'choice',
      message: chalk.cyan('Security profile:'),
      prefix: '  🛡️',
      choices: [
        {
          name: `${c('Recommended')} ${d('— Strong defaults, balanced for daily use')}`,
          value: 'recommended',
        },
        {
          name: `${c('Maximum')}     ${d('— All protections ON, strict + ephemeral')}`,
          value: 'max',
        },
        {
          name: `${c('Minimal')}     ${d('— Only encryption & basic PII redaction')}`,
          value: 'minimal',
        },
        {
          name: `${c('Custom')}      ${d('— Configure each setting individually')}`,
          value: 'custom',
        },
        new inquirer.Separator(),
        {
          name: `${chalk.blue('ℹ')}  ${chalk.blue('View details for each profile')}`,
          value: 'details',
        },
      ],
    }]);

    if (choice === 'details') {
      for (const [key, lines] of Object.entries(PROFILE_DETAILS)) {
        console.log();
        console.log(boxen(lines.join('\n'), {
          padding: 1, margin: { left: 2 }, borderStyle: 'round',
          borderColor: key === 'max' ? 'yellow' : key === 'recommended' ? 'cyan' : 'gray',
        }));
      }
      console.log();
      continue; // Re-show the prompt
    }

    profile = choice;
    break;
  }

  let securitySettings;
  if (profile === 'max') {
    securitySettings = {
      piiRedaction: true, strictMode: true, fingerprintMasking: true,
      metadataStripping: true, clipboardAutoClear: true, clipboardClearDelay: 10,
      promptInjectionDetection: true, trackerBlocking: true,
    };
    ctx.config.set('audit.ephemeral', true);
    console.log(chalk.green('  ✔ Maximum security applied. Ephemeral mode ON.\n'));
  } else if (profile === 'recommended') {
    securitySettings = {
      piiRedaction: true, strictMode: false, fingerprintMasking: true,
      metadataStripping: true, clipboardAutoClear: true, clipboardClearDelay: 30,
      promptInjectionDetection: true, trackerBlocking: true,
    };
    console.log(chalk.green('  ✔ Recommended security applied.\n'));
  } else if (profile === 'minimal') {
    securitySettings = {
      piiRedaction: true, strictMode: false, fingerprintMasking: false,
      metadataStripping: false, clipboardAutoClear: false, clipboardClearDelay: 30,
      promptInjectionDetection: false, trackerBlocking: false,
    };
    console.log(chalk.green('  ✔ Minimal security applied.\n'));
  } else {
    securitySettings = await customSecuritySetup();
  }

  // Apply security settings
  for (const [key, val] of Object.entries(securitySettings)) {
    ctx.config.set(`security.${key}`, val);
  }
  ctx.sanitizer.enabled = securitySettings.piiRedaction;
  ctx.sanitizer.strictMode = securitySettings.strictMode;
  ctx.fingerprint.enabled = securitySettings.fingerprintMasking;
  ctx.clipboard.autoClear = securitySettings.clipboardAutoClear;
  ctx.trackerBlocker.enabled = securitySettings.trackerBlocking;

  // ── Step 2: API Keys ───────────────────────────────────────
  stepHeader(2, 'API Keys');
  console.log(d('    Keys are encrypted with AES-256-GCM. Skip any you don\'t have.\n'));

  const providers = [
    { name: 'OpenAI', key: 'openai', env: 'OPENAI_API_KEY', hint: 'sk-...' },
    { name: 'Claude', key: 'claude', env: 'ANTHROPIC_API_KEY', hint: 'sk-ant-...' },
    { name: 'Gemini', key: 'gemini', env: 'GEMINI_API_KEY', hint: 'AI...' },
    { name: 'Ollama', key: 'ollama', env: '', hint: 'no key needed (local)' },
  ];

  const { wantKeys } = await inquirer.prompt([{
    type: 'confirm',
    name: 'wantKeys',
    message: chalk.cyan('Set up API keys now?'),
    default: true,
    prefix: '  🔑',
  }]);

  if (wantKeys) {
    for (const prov of providers) {
      if (!prov.env) {
        console.log(d(`  ✓ ${prov.name}: ${prov.hint}`));
        continue;
      }
      const existing = ctx.config.getApiKey(prov.key);
      const existLabel = existing ? d(` (current: ${existing.substring(0, 6)}****)`) : '';

      const { apiKey } = await inquirer.prompt([{
        type: 'password',
        name: 'apiKey',
        message: chalk.cyan(`${prov.name} API Key${existLabel}:`),
        prefix: `  🔑`,
        mask: '•',
      }]);

      if (apiKey && apiKey.trim()) {
        ctx.config.setApiKey(prov.key, apiKey.trim());
        console.log(chalk.green(`  ✔ ${prov.name} key saved (encrypted)`));
      } else {
        console.log(d(`  ⊘ ${prov.name} skipped`));
      }
    }
  } else {
    console.log(d('  Skipped. Add keys later via 🔑 API Key Vault.\n'));
  }

  // ── Step 3: Default Provider ───────────────────────────────
  stepHeader(3, 'Default AI Provider');
  console.log(d('    Which AI opens when you run `ace` or `ace chat`.\n'));

  const installedProviders = [];
  for (const [key, prov] of Object.entries(ctx.providers)) {
    const installed = await prov.isInstalled();
    const info = prov.getInfo();
    const status = installed ? chalk.green('✓') : chalk.red('✗');
    installedProviders.push({
      name: `${status} ${info.name} ${d(`(${info.command})`)}`,
      value: key,
    });
  }

  const { defaultProvider } = await inquirer.prompt([{
    type: 'list',
    name: 'defaultProvider',
    message: chalk.cyan('Default provider:'),
    prefix: '  🤖',
    choices: installedProviders,
  }]);

  ctx.config.set('providers.default', defaultProvider);
  console.log(chalk.green(`  ✔ Default provider: ${defaultProvider}\n`));

  // ── Step 4: Network Privacy ────────────────────────────────
  stepHeader(4, 'Network Privacy');

  const { proxyChoice } = await inquirer.prompt([{
    type: 'list',
    name: 'proxyChoice',
    message: chalk.cyan('Network routing:'),
    prefix: '  🌐',
    choices: [
      { name: `${c('Direct')}  ${d('— No proxy (fastest)')}`, value: 'direct' },
      { name: `${c('Tor')}     ${d('— Route through Tor (127.0.0.1:9050)')}`, value: 'tor' },
      { name: `${c('Custom')}  ${d('— Custom SOCKS5 proxy')}`, value: 'custom' },
    ],
  }]);

  if (proxyChoice === 'tor') {
    ctx.config.set('proxy.enabled', true);
    ctx.config.set('proxy.type', 'socks5');
    ctx.config.set('proxy.host', '127.0.0.1');
    ctx.config.set('proxy.port', 9050);
    ctx.proxy.enabled = true;
    ctx.proxy.proxyType = 'socks5';
    ctx.proxy.host = '127.0.0.1';
    ctx.proxy.port = 9050;
    ctx.proxy.agent = null; // reset cached agent
    console.log(chalk.green('  ✔ Tor proxy enabled (127.0.0.1:9050)'));
    console.log(d('    Make sure Tor service is running.\n'));
  } else if (proxyChoice === 'custom') {
    const { host } = await inquirer.prompt([{
      type: 'input', name: 'host',
      message: chalk.cyan('SOCKS5 host:'), default: '127.0.0.1', prefix: '  🌐',
    }]);
    const { port } = await inquirer.prompt([{
      type: 'number', name: 'port',
      message: chalk.cyan('SOCKS5 port:'), default: 1080, prefix: '  🌐',
    }]);
    ctx.config.set('proxy.enabled', true);
    ctx.config.set('proxy.type', 'socks5');
    ctx.config.set('proxy.host', host);
    ctx.config.set('proxy.port', port);
    ctx.proxy.enabled = true;
    ctx.proxy.proxyType = 'socks5';
    ctx.proxy.host = host;
    ctx.proxy.port = port;
    ctx.proxy.agent = null;
    console.log(chalk.green(`  ✔ Custom proxy: ${host}:${port}\n`));
  } else {
    ctx.config.set('proxy.enabled', false);
    ctx.proxy.enabled = false;
    ctx.proxy.agent = null;
    console.log(d('  Direct connection.\n'));
  }

  // ── Step 5: Audit Mode ─────────────────────────────────────
  stepHeader(5, 'Audit & Recovery');

  const { auditMode } = await inquirer.prompt([{
    type: 'list',
    name: 'auditMode',
    message: chalk.cyan('Audit trail mode:'),
    prefix: '  📋',
    choices: [
      { name: `${c('Persistent')} ${d('— Encrypted logs saved to disk')}`, value: 'persistent' },
      { name: `${c('Ephemeral')}  ${d('— Memory only, zero disk writes')}`, value: 'ephemeral' },
    ],
  }]);

  ctx.config.set('audit.ephemeral', auditMode === 'ephemeral');
  console.log(chalk.green(`  ✔ Audit mode: ${auditMode}\n`));

  // ── Done ───────────────────────────────────────────────────
  console.log();
  console.log(boxen(
    [
      chalk.green.bold('  ✔ Setup Complete!'),
      '',
      `  Security:   ${c(profile)}`,
      `  Provider:   ${c(defaultProvider)}`,
      `  Proxy:      ${c(proxyChoice)}`,
      `  Audit:      ${c(auditMode)}`,
      '',
      `  Quick launch:  ${chalk.cyan('ace gemini')}  ${d('or')}  ${chalk.cyan('ace openai "your prompt"')}`,
      `  Re-run:        ${chalk.cyan('ace --setup')}`,
    ].join('\n'),
    { padding: 1, margin: { left: 2 }, borderStyle: 'double', borderColor: 'green' }
  ));
  console.log();

  ctx.audit.log({ type: 'SETUP_WIZARD_COMPLETED', details: { profile, defaultProvider, proxyChoice, auditMode } });
}

// ── Custom security setup with details ───────────────────────
async function customSecuritySetup() {
  console.log(d('    Toggle features individually. Select "Details" for explanations.\n'));

  let features;
  while (true) {
    const featureKeys = Object.keys(FEATURE_DETAILS);
    const choices = featureKeys.map(key => ({
      name: `${FEATURE_DETAILS[key].name} ${d(`— ${FEATURE_DETAILS[key].short}`)}`,
      value: key,
      checked: key !== 'strictMode',
    }));

    const { action } = await inquirer.prompt([{
      type: 'list',
      name: 'action',
      message: chalk.cyan('What would you like to do?'),
      prefix: '  🔒',
      choices: [
        { name: chalk.green('Select features to enable'), value: 'select' },
        { name: chalk.blue('ℹ  View what each feature does'), value: 'details' },
      ],
    }]);

    if (action === 'details') {
      for (const [key, info] of Object.entries(FEATURE_DETAILS)) {
        console.log();
        console.log(boxen(
          [chalk.cyan.bold(`${info.name}`), '', ...info.detail].join('\n'),
          { padding: 1, margin: { left: 2 }, borderStyle: 'round', borderColor: 'cyan' }
        ));
      }
      console.log();
      continue;
    }

    const result = await inquirer.prompt([{
      type: 'checkbox',
      name: 'features',
      message: chalk.cyan('Enable security features:'),
      prefix: '  🔒',
      choices,
    }]);
    features = result.features;
    break;
  }

  const settings = {
    piiRedaction: features.includes('piiRedaction'),
    strictMode: features.includes('strictMode'),
    fingerprintMasking: features.includes('fingerprintMasking'),
    metadataStripping: features.includes('metadataStripping'),
    clipboardAutoClear: features.includes('clipboardAutoClear'),
    clipboardClearDelay: 30,
    promptInjectionDetection: features.includes('promptInjectionDetection'),
    trackerBlocking: features.includes('trackerBlocking'),
  };

  if (settings.clipboardAutoClear) {
    const { clearDelay } = await inquirer.prompt([{
      type: 'list',
      name: 'clearDelay',
      message: chalk.cyan('Clipboard auto-clear delay:'),
      prefix: '  🧹',
      choices: [
        { name: '10 seconds (paranoid)', value: 10 },
        { name: '30 seconds (recommended)', value: 30 },
        { name: '60 seconds (relaxed)', value: 60 },
        { name: '120 seconds', value: 120 },
      ],
    }]);
    settings.clipboardClearDelay = clearDelay;
  }

  console.log(chalk.green(`  ✔ Custom: ${features.length}/7 features enabled\n`));
  return settings;
}

// ── Step header ──────────────────────────────────────────────
function stepHeader(num, title) {
  const total = 5;
  const bar = '█'.repeat(num) + '░'.repeat(total - num);
  console.log(chalk.gray(`  ── Step ${num}/${total} ──`) + chalk.cyan(` ${title} `) + chalk.gray(`[${bar}]`));
  console.log();
}
