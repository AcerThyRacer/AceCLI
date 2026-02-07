// ============================================================
//  AceCLI – Comprehensive Help System
// ============================================================
import chalk from 'chalk';
import gradient from 'gradient-string';
import boxen from 'boxen';

const g = gradient(['#00ff88', '#00ccff', '#8844ff']);
const h = (text) => chalk.cyan.bold(text);
const d = (text) => chalk.gray(text);
const c = (text) => chalk.green(text);
const w = (text) => chalk.yellow(text);

export function showHelp(topic = null) {
  if (topic) {
    const handler = TOPIC_MAP[topic.toLowerCase()];
    if (handler) { handler(); return; }
    console.log(w(`\n  Unknown topic: "${topic}". Run ${c('help')} for all topics.\n`));
    return;
  }
  showFullHelp();
}

function showFullHelp() {
  console.log();
  console.log(g('  ╔══════════════════════════════════════════════════════════╗'));
  console.log(g('  ║            📖  ACE CLI  –  COMPLETE USER GUIDE          ║'));
  console.log(g('  ╚══════════════════════════════════════════════════════════╝'));
  console.log();

  // ── Quick Start ─────────────────────────────────────────────
  console.log(boxen(
    [
      h('⚡ QUICK START'),
      '',
      `  1. Type ${c('ace')} to launch AceCLI`,
      `  2. Enter your master password (encrypts all local data)`,
      `  3. Use arrow keys to navigate the main menu, Enter to select`,
      `  4. First time? Run ${c('🩺 Health Check')} to see which AI CLIs are installed`,
      `  5. Add API keys via ${c('🔑 API Key Vault')} before chatting`,
    ].join('\n'),
    { padding: 1, margin: { left: 2 }, borderStyle: 'round', borderColor: 'green' }
  ));
  console.log();

  // ── CLI Flags ───────────────────────────────────────────────
  section('COMMAND LINE FLAGS');
  row('ace', 'Launch AceCLI normally');
  row('ace --setup  |  ace setup', 'Run the guided setup wizard');
  row('ace --help  |  ace help', 'Show this help guide');
  row('ace --no-banner', 'Skip the ASCII art intro animation');
  row('ace --doctor', 'Run health check and exit');
  row('ace --version', 'Show version number');
  console.log();

  // ── Main Menu ───────────────────────────────────────────────
  section('MAIN MENU COMMANDS');
  console.log();

  subsection('🧙 Setup Wizard');
  detail([
    'Guided, step-by-step configuration for first-time users.',
    'Walks through 6 steps: Security Profile, API Keys, Proxy/Tor,',
    'Default Provider, Tracker Blocker layers, and Audit mode.',
    'Pick a preset (Maximum / Recommended / Minimal) or go Custom.',
    `Run from menu or CLI: ${c('ace --setup')}. Safe to re-run any time.`,
  ]);

  subsection('🤖 Chat with AI Provider');
  detail([
    'Start a multi-turn conversation with any installed AI CLI.',
    'HOW: Select a provider → type your prompt → responses are filtered',
    'through the PII redactor and injection detector in real-time.',
    `Security: All prompts are ${c('sanitized')} before sending. All responses are`,
    `${c('scanned for PII leaks')} and redacted if found. Tracker domains in`,
    'responses are flagged. Session is logged to the encrypted audit trail.',
  ]);

  subsection('⚡ Quick Prompt (one-shot)');
  detail([
    'Send a single prompt and get one response — no conversation history.',
    'HOW: Select provider → type your prompt → get response → return to menu.',
    'Use when you need a fast answer without maintaining context.',
  ]);

  subsection('🔌 Launch Provider Interactive');
  detail([
    'Drops you into the AI CLI\'s own interactive mode (e.g., ollama REPL).',
    'HOW: Select provider → you\'re connected directly to the CLI.',
    `Security: stdin and stdout are piped through ${c('SanitizingTransform')} streams.`,
    'Injections are blocked in real-time, PII is redacted on the fly.',
    'Unlike raw CLI usage, your data passes through Ace\'s security layer.',
  ]);

  subsection('❓ Help & Documentation');
  detail([
    'Shows this complete guide. You can also type specific topics:',
    `  ${c('help chat')}  ${c('help vault')}  ${c('help proxy')}  ${c('help privacy')}`,
    `  ${c('help audit')}  ${c('help tracker')}  ${c('help kill')}  ${c('help doctor')}`,
  ]);

  console.log();
  section('SECURITY FEATURES');
  console.log();

  subsection('🛡️ Security Dashboard');
  detail([
    'Shows a live overview of ALL security features and their status (ON/OFF).',
    'Displays: PII redaction stats, encryption status, fingerprint masking,',
    'proxy routing, clipboard settings, injection detection, tracker blocker,',
    'audit trail integrity, session recovery, and more.',
    'Also shows fingerprint masking comparison (real vs. spoofed identity)',
    'and audit chain integrity verification.',
  ]);

  subsection('🔑 API Key Vault');
  detail([
    'Encrypted storage for your AI provider API keys.',
    `Keys are encrypted with ${c('AES-256-GCM')} using your master password.`,
    'Never stored in plaintext. Never exposed in logs or audit trail.',
    '',
    'Commands inside vault:',
    `  ${c('View stored keys')}    Show which providers have keys (values masked)`,
    `  ${c('Add / Update key')}    Store a new API key for a provider`,
    `  ${c('Delete key')}          Remove a stored key permanently`,
    '',
    'Supported providers: openai, claude, gemini, copilot, ollama',
    'Keys are passed to CLIs via environment variables at runtime,',
    'stripped from env immediately after the process exits.',
  ]);

  subsection('🌐 Proxy / Tor Settings');
  detail([
    'Route all AI API traffic through a SOCKS5 proxy or Tor.',
    '',
    'Options:',
    `  ${c('View proxy status')}     See current proxy config and connection state`,
    `  ${c('Enable Tor')}            Connect via Tor (SOCKS5 on 127.0.0.1:9050)`,
    `                         Requires Tor to be running on your system`,
    `  ${c('Custom SOCKS proxy')}    Set any SOCKS5 proxy (host:port)`,
    `  ${c('Disable proxy')}         Direct connection (no proxy)`,
    `  ${c('Test connection')}       Verify proxy is working and check your IP`,
    '',
    'WHY: Hides your real IP from AI providers. When using Tor, your',
    'traffic is routed through 3+ relays. DNS leak protection is active.',
  ]);

  subsection('🔒 Privacy Settings');
  detail([
    'Fine-grained control over every privacy feature:',
    '',
    `  ${c('PII Redaction')}           Auto-detect & mask emails, IPs, SSNs,`,
    '                           phone numbers, credit cards, API keys,',
    '                           AWS keys, GitHub tokens, JWTs, and 17+',
    '                           patterns in prompts AND responses.',
    '',
    `  ${c('Strict Mode')}             When ON, original text is never shown —`,
    '                           only the redacted version. Extra paranoid.',
    '',
    `  ${c('Fingerprint Masking')}     Spoofs hostname, username, OS info sent`,
    '                           to AI CLIs. Providers can\'t identify you.',
    '',
    `  ${c('Metadata Stripping')}      Removes tracking env vars (TERM_SESSION_ID,`,
    '                           HOSTNAME, USER, etc.) from child processes.',
    '',
    `  ${c('Clipboard Auto-Clear')}    After copying sensitive data, clipboard`,
    '                           is wiped after a configurable delay (30s).',
    '',
    `  ${c('Injection Detection')}     Scans prompts for jailbreak attempts using:`,
    '                           • 17+ regex patterns (role overrides, system',
    '                             prompt extraction, etc.)',
    '                           • 8 heuristic strategies (role reassignment,',
    '                             boundary markers, base64 evasion, homoglyphs,',
    '                             language switching, fictional framing, etc.)',
    '                           Severity levels: CRITICAL / HIGH / MEDIUM / NONE',
    '',
    `  ${c('Mass Tracker Blocking')}   Blocks 500+ tracker domains, strips 80+`,
    '                           tracking URL parameters, removes tracking headers,',
    '                           sanitizes telemetry env vars, detects fingerprint',
    '                           scripts. DNS-level interception with real-time',
    '                           monitoring. See: help tracker',
    '',
    `  ${c('Ephemeral Mode')}          Zero disk writes. All data stays in memory`,
    '                           only. When you exit, everything is gone. No',
    '                           audit files, no recovery checkpoints, no traces.',
  ]);

  console.log();
  section('SYSTEM TOOLS');
  console.log();

  subsection('📋 Audit Log');
  detail([
    'View the encrypted audit trail for the current session.',
    'Shows: timestamp, event type, provider, and details for each entry.',
    'Events logged: SESSION_START, PROMPT_SENT, RESPONSE_RECEIVED,',
    'PII_REDACTED, INJECTION_DETECTED, SETTING_CHANGED, KILL_SWITCH, etc.',
    '',
    'The audit chain uses SHA-256 hash linking — each entry\'s hash depends',
    'on the previous entry. If any entry is tampered with, the chain breaks',
    'and the integrity check will show TAMPERED.',
  ]);

  subsection('📤 Export Audit Log');
  detail([
    'Export audit data for compliance, review, or backup.',
    '',
    `  ${c('Export current session (JSON)')}    Full structured data`,
    `  ${c('Export current session (CSV)')}     Spreadsheet-friendly format`,
    `  ${c('Load previous session')}            Decrypt and export old sessions`,
    '',
    'Files are saved to ~/.ace/ directory. Requires master password.',
  ]);

  subsection('🩺 Health Check (Doctor)');
  detail([
    'Diagnoses your system and reports what\'s working and what\'s missing.',
    '',
    'Checks:',
    `  • Node.js version (requires ${c('18+')})`,
    '  • Each AI CLI: openai, claude, gemini, github-copilot, ollama',
    '  • Tor availability and connection',
    '  • Clipboard manager (clipboardy)',
    '  • Security subsystems (encryption, sanitizer, fingerprint)',
    '',
    'For each missing CLI, shows the exact install command you need.',
    'Run this first to know which providers you can use.',
  ]);

  subsection('⚙️ Configuration');
  detail([
    'View the current configuration as JSON.',
    'Config is stored encrypted at ~/.ace/config.enc',
    'Includes: security toggles, proxy settings, provider preferences.',
    'Changes are made through the Privacy Settings and Proxy menus.',
  ]);

  subsection('🔍 Test Sanitizer');
  detail([
    'Interactive testing tool for the PII redaction engine.',
    'Type any text containing sensitive data and see what gets caught.',
    'Shows: original input → sanitized output → list of detections.',
    'Great for verifying your data is safe before using a provider.',
  ]);

  subsection('🔄 Session Recovery');
  detail([
    'Manage encrypted session checkpoints.',
    '',
    `  ${c('Save checkpoint')}      Manually save current session state`,
    `  ${c('List sessions')}        Show all recoverable checkpoints`,
    `  ${c('Load session')}         Restore a previous session`,
    `  ${c('Delete recovery')}      Wipe all checkpoint files`,
    '',
    'Auto-save runs every 60 seconds (encrypted with your master password).',
    'If AceCLI crashes, your session can be restored on next launch.',
  ]);

  console.log();
  section('DANGER ZONE');
  console.log();

  subsection('💀 Kill Switch');
  detail([
    'NUCLEAR OPTION — wipes ALL AceCLI data permanently.',
    '',
    'Destroys:',
    '  • All conversation history',
    '  • API key vault (all stored keys)',
    '  • Audit logs (all sessions)',
    '  • Configuration file',
    '  • Recovery checkpoints',
    '  • Clipboard contents',
    '',
    'Requires double confirmation. Cannot be undone.',
    'Use in emergencies when you need to leave no trace.',
  ]);

  console.log();
  section('DATA STORAGE');
  console.log();
  detail([
    'All data is stored under ~/.ace/ (your home directory):',
    '',
    `  ${d('~/.ace/config.enc')}     Encrypted configuration`,
    `  ${d('~/.ace/vault.enc')}      Encrypted API key vault`,
    `  ${d('~/.ace/audit/')}         Encrypted audit log files`,
    `  ${d('~/.ace/recovery/')}      Encrypted session checkpoints`,
    '',
    `Everything is encrypted with ${c('AES-256-GCM')} using ${c('scrypt')} key derivation`,
    'from your master password. Without the password, data is unreadable.',
    '',
    'In ephemeral mode, nothing is written to disk at all.',
  ]);

  console.log();
  section('KEYBOARD SHORTCUTS');
  console.log();
  detail([
    `  ${c('↑ / ↓')}        Navigate menu items`,
    `  ${c('Enter')}        Select current item`,
    `  ${c('Ctrl+C')}       Exit AceCLI (session is auto-saved)`,
    `  ${c('Ctrl+D')}       End current input`,
  ]);

  console.log();
  console.log(d('  ─────────────────────────────────────────────────────────'));
  console.log(d('  For specific help: ') + c('help <topic>'));
  console.log(d('  Topics: chat, vault, proxy, privacy, audit, tracker, kill, doctor, recovery, sanitizer'));
  console.log(d('  ─────────────────────────────────────────────────────────'));
  console.log();
}

// ── Topic Helpers ───────────────────────────────────────────
function section(title) {
  console.log(chalk.cyan.bold(`  ── ${title} ${'─'.repeat(Math.max(0, 52 - title.length))}`));
}

function subsection(title) {
  console.log(`  ${chalk.white.bold(title)}`);
}

function detail(lines) {
  for (const line of lines) {
    console.log(`    ${line}`);
  }
  console.log();
}

function row(cmd, desc) {
  console.log(`  ${c(cmd.padEnd(30))} ${d(desc)}`);
}

// ── Per-topic help ──────────────────────────────────────────
const TOPIC_MAP = {
  chat: () => {
    section('CHAT WITH AI PROVIDER');
    console.log();
    detail([
      'Multi-turn conversation with any installed AI CLI.',
      '',
      'How it works:',
      '  1. Select provider from the list (only installed ones are selectable)',
      '  2. Type your prompt and press Enter',
      '  3. Ace sanitizes your input (PII redacted, injections checked)',
      '  4. Prompt is sent to the provider CLI',
      '  5. Response is scanned for PII leaks and redacted',
      '  6. Response is displayed with security annotations',
      '  7. Type next prompt or type "exit" / "quit" / "back" to return',
      '',
      'Security layers active during chat:',
      '  • PII auto-redaction (17+ patterns)',
      '  • Prompt injection detection (regex + heuristics)',
      '  • Tracker domain flagging in responses',
      '  • Fingerprint masking (spoofed env vars)',
      '  • Metadata stripping',
      '  • Full audit logging of all exchanges',
      '',
      'Providers: openai, claude, gemini, copilot, ollama',
    ]);
  },

  vault: () => {
    section('API KEY VAULT');
    console.log();
    detail([
      'Encrypted storage for AI provider API keys.',
      '',
      `Encryption: AES-256-GCM with scrypt key derivation`,
      'Stored at: ~/.ace/vault.enc',
      '',
      'Operations:',
      `  ${c('View stored keys')}    Lists providers with keys (values are masked)`,
      `  ${c('Add / Update key')}    Prompts for provider name and key value`,
      `  ${c('Delete key')}          Removes a key from the vault`,
      '',
      'At runtime, keys are injected as environment variables',
      '(e.g., OPENAI_API_KEY) when launching provider CLIs.',
      'They are stripped from the environment immediately after.',
      '',
      'Keys are NEVER shown in plaintext, logs, or audit trails.',
    ]);
  },

  proxy: () => {
    section('PROXY / TOR SETTINGS');
    console.log();
    detail([
      'Route AI API traffic through SOCKS5 proxies or Tor.',
      '',
      'Setup for Tor:',
      '  1. Install Tor: https://www.torproject.org/download/',
      '  2. Start the Tor service (it listens on 127.0.0.1:9050)',
      '  3. In Ace, go to Proxy Settings → Enable Tor',
      '  4. Test connection to verify it works',
      '',
      'Custom proxy:',
      '  Any SOCKS5 proxy — enter host and port when prompted.',
      '',
      'What it protects:',
      '  • Hides your real IP from AI provider servers',
      '  • Traffic routed through Tor\'s 3+ relay circuit',
      '  • DNS leak protection prevents DNS requests over clearnet',
      '  • Tracker blocker prevents telemetry over proxy',
    ]);
  },

  privacy: () => {
    section('PRIVACY SETTINGS');
    console.log();
    detail([
      'Toggle individual privacy features on/off:',
      '',
      'PII Redaction         Scan & mask sensitive data in prompts/responses',
      'Strict Mode           Never show original text, only redacted version',
      'Fingerprint Masking   Spoof hostname, username, platform for CLIs',
      'Metadata Stripping    Remove tracking env vars from child processes',
      'Clipboard Auto-Clear  Wipe clipboard after copying sensitive data',
      'Injection Detection   Block/warn on jailbreak attempts in prompts',
      'Mass Tracker Blocking Block 500+ trackers, strip params, clean headers',
      'Ephemeral Mode        Zero disk writes — everything stays in memory',
    ]);
  },

  audit: () => {
    section('AUDIT TRAIL');
    console.log();
    detail([
      'Hash-chain secured audit log of all session activity.',
      '',
      'Each entry contains:',
      '  • Timestamp     When the event occurred',
      '  • Event type    SESSION_START, PROMPT_SENT, RESPONSE_RECEIVED, etc.',
      '  • Provider      Which AI CLI was used (if applicable)',
      '  • Details       Event-specific metadata',
      '  • Hash          SHA-256 linked to previous entry',
      '',
      'Integrity verification walks the entire chain — if any entry',
      'was modified, the hash chain breaks and it shows TAMPERED.',
      '',
      'Export formats: JSON (full structured data), CSV (spreadsheet)',
      'Previous sessions can be loaded from encrypted disk storage.',
    ]);
  },

  tracker: () => {
    section('MASS TRACKER BLOCKER');
    console.log();
    detail([
      'Comprehensive anti-tracking system with multiple layers:',
      '',
      `${c('Domain Blocking')}       500+ tracker domains in blocklist`,
      '                      Google Analytics, Facebook Pixel, Mixpanel,',
      '                      Amplitude, Hotjar, Segment, Sentry, DataDog,',
      '                      New Relic, ad networks, and many more.',
      '                      Subdomain matching — blocks *.tracker.com too.',
      '',
      `${c('URL Param Stripping')}   80+ tracking parameters removed:`,
      '                      utm_source, utm_medium, fbclid, gclid, mc_eid,',
      '                      msclkid, _ga, twclid, li_fat_id, etc.',
      '',
      `${c('Header Sanitization')}   Removes tracking headers from requests:`,
      '                      X-Request-ID, X-Correlation-ID, X-Trace-Id,',
      '                      X-Client-Data, referer, and more.',
      '',
      `${c('Env Var Cleaning')}      Strips telemetry env vars from child procs:`,
      '                      GOOGLE_ANALYTICS_ID, FACEBOOK_PIXEL_ID,',
      '                      SENTRY_DSN, DATADOG_API_KEY, etc.',
      '',
      `${c('Fingerprint Detection')} Detects fingerprinting scripts that try`,
      '                      to collect canvas, WebGL, audio context,',
      '                      font enumeration, and screen data.',
      '',
      `${c('DNS Interception')}      Monitors DNS lookups made by child`,
      '                      processes and blocks known tracker domains.',
      '',
      `${c('Real-time Monitor')}     Dashboard shows live stats:`,
      '                      domains blocked, URLs stripped, headers removed,',
      '                      env vars cleared, fingerprinting attempts caught.',
    ]);
  },

  kill: () => {
    section('KILL SWITCH');
    console.log();
    detail([
      '💀 EMERGENCY DATA DESTRUCTION',
      '',
      'Permanently wipes ALL AceCLI data:',
      '  • Conversation history    (gone)',
      '  • API keys in vault       (gone)',
      '  • Audit logs              (gone)',
      '  • Configuration           (gone)',
      '  • Recovery checkpoints    (gone)',
      '  • Clipboard contents      (cleared)',
      '',
      'Process:',
      '  1. First confirmation prompt',
      '  2. Second "are you ABSOLUTELY sure?" prompt',
      '  3. Wipe executes immediately',
      '  4. AceCLI exits',
      '',
      'CANNOT BE UNDONE. Use when you need to leave zero trace.',
    ]);
  },

  doctor: () => {
    section('HEALTH CHECK (DOCTOR)');
    console.log();
    detail([
      'Diagnostic tool that checks your entire setup.',
      '',
      'Checks performed:',
      `  ${c('Node.js')}          Version ≥ 18 required`,
      `  ${c('OpenAI CLI')}       npm install -g openai (needs OPENAI_API_KEY)`,
      `  ${c('Claude CLI')}       npm install -g @anthropic-ai/claude-cli`,
      `  ${c('Gemini CLI')}       npm install -g @google/gemini-cli`,
      `  ${c('GitHub Copilot')}   gh extension install github/gh-copilot`,
      `  ${c('Ollama')}           https://ollama.ai (local, no API key needed)`,
      `  ${c('Tor')}              Required for Tor proxy mode`,
      `  ${c('Clipboardy')}       Cross-platform clipboard support`,
      `  ${c('Security Core')}    Encryption, sanitizer, fingerprint modules`,
      '',
      'Each check shows ✓ (pass) or ✗ (fail) with install instructions.',
      'Run with: ace --doctor (from command line) or from the main menu.',
    ]);
  },

  recovery: () => {
    section('SESSION RECOVERY');
    console.log();
    detail([
      'Encrypted checkpoint system for session persistence.',
      '',
      'Auto-save runs every 60 seconds, saving session state',
      'to ~/.ace/recovery/ encrypted with your master password.',
      '',
      'If AceCLI crashes or you lose connection, on next launch',
      'you can restore from the checkpoint via Recovery menu.',
      '',
      'Operations:',
      `  ${c('Save checkpoint')}    Manual save of current state`,
      `  ${c('List sessions')}      Show all saved checkpoints with dates`,
      `  ${c('Load session')}       Restore a previous session`,
      `  ${c('Delete recovery')}    Wipe all checkpoints`,
    ]);
  },

  sanitizer: () => {
    section('PII SANITIZER & INJECTION DETECTOR');
    console.log();
    detail([
      'Two-layer security scanning system.',
      '',
      `${c('PII Patterns Detected (17+):')}`,
      '  • Email addresses          • IPv4 / IPv6 addresses',
      '  • Phone numbers            • SSN / national ID numbers',
      '  • Credit card numbers       • AWS access keys',
      '  • GitHub tokens (ghp_)     • Generic API keys / secrets',
      '  • JWT tokens                • Private keys (PEM)',
      '  • Base64-encoded secrets   • MAC addresses',
      '  • Passport numbers          • IBAN numbers',
      '  • Bitcoin addresses         • Connection strings',
      '  • Slack webhooks',
      '',
      `${c('Injection Detection Strategies (8):')}`,
      '  1. Role Reassignment      "You are now..." / "Ignore previous..."',
      '  2. Boundary Markers        ### / === / ``` injection boundaries',
      '  3. Context Overflow        Extremely long prompts to overflow context',
      '  4. Base64 Evasion          Encoded payloads hiding instructions',
      '  5. Homoglyph Mixing        Cyrillic/Greek chars mimicking Latin',
      '  6. Language Switching       Foreign text hiding instructions',
      '  7. Fictional Framing       "Imagine you are..." / "Pretend that..."',
      '  8. Delimiter Abuse          XML / HTML tags, JSON payloads',
      '',
      'Severity: CRITICAL (≥8 pts) / HIGH (≥5) / MEDIUM (>0) / NONE',
      'CRITICAL and HIGH block the prompt. MEDIUM shows a warning.',
    ]);
  },
};

export function showCliHelp() {
  console.log();
  console.log(chalk.white.bold('  ACE CLI') + d(' — Security & Anonymity Layer for AI Command Lines'));
  console.log();
  console.log(d('  Usage:'));
  row('ace', 'Launch AceCLI interactive mode');
  row('ace setup | --setup', 'Run guided setup wizard');
  row('ace help', 'Show complete documentation');
  row('ace --help | -h', 'Show complete documentation');
  row('ace --doctor', 'Run system health check');
  row('ace --no-banner', 'Skip startup animation');
  row('ace --version | -v', 'Show version');
  console.log();
  console.log(d('  Security features: PII redaction, AES-256 encryption, Tor proxy,'));
  console.log(d('  fingerprint masking, injection detection, 500+ tracker blocker,'));
  console.log(d('  clipboard auto-clear, audit trail, kill switch, and more.'));
  console.log();
}
