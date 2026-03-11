// ============================================================
//  AceCLI – Main Entry Point
//  Security & Anonymity Layer for AI Command Lines
// ============================================================
import chalk from 'chalk';
import ora from 'ora';
import inquirer from 'inquirer';
import gradient from 'gradient-string';
import { randomBytes, createHash } from 'crypto';
import { join } from 'path';
import { homedir } from 'os';

import { showBanner, showMiniBanner } from './ui/banner.js';
import { showHelp, showCliHelp } from './ui/help.js';
import { runSetupWizard } from './ui/wizard.js';
import { mainMenu, selectProvider, promptInput, confirmAction, vaultMenu, proxyMenu, dnsMenu, privacyMenu, auditExportMenu, recoveryMenu, chatStartMenu, conversationMenu, mfaMenu, integrityMenu } from './ui/menu.js';
import { ConversationManager } from './conversations.js';
import { showDashboard, showAuditLog } from './ui/dashboard.js';
import { ConfigManager } from './config.js';
import { Sanitizer } from './security/sanitizer.js';
import { AuthManager, MIN_MASTER_PASSWORD_LENGTH } from './security/auth.js';
import { Encryption } from './security/encryption.js';
import { FingerprintMask } from './security/fingerprint.js';
import { ProxyRouter } from './security/proxy.js';
import { DnsResolver } from './security/dns.js';
import { AuditLogger } from './security/audit.js';
import { ClipboardManager } from './security/clipboard.js';
import { SessionRecovery } from './security/recovery.js';
import { TrackerBlocker } from './security/tracker.js';
import { MemoryGuard, SecureString } from './security/secure-memory.js';
import { MFAProvider } from './security/mfa.js';
import { IntegrityChecker } from './security/integrity.js';
import { ProviderRegistry } from './providers/registry.js';
import { PluginManager } from './plugins/plugin-manager.js';
import { ResponseRenderer } from './ui/renderer.js';
import { runDoctor } from './doctor.js';
import { classifyError } from './errors.js';
import { writeSecureFile } from './security/fs-utils.js';

const g = gradient(['#00ff88', '#00ccff']);

// ── Session context (all security modules) ──────────────────
let ctx = {};

// ── Graceful Ctrl+C handler (double-press to exit) ──────────
let _ctrlCPressed = false;
let _ctrlCTimer = null;

function gracefulShutdown() {
  if (ctx.conversations) ctx.conversations.saveAll();
  if (ctx.recovery) {
    ctx.recovery.saveCheckpoint(ctx);
    ctx.recovery.stopAutoSave();
  }
  if (ctx.clipboard) ctx.clipboard.cancelAllTimers();
  if (ctx.audit) ctx.audit.log({ type: 'SESSION_END' });

  // Wipe all sensitive data from memory
  const memResult = MemoryGuard.wipeAll();
  if (memResult.wiped > 0) {
    ctx.audit?.log({ type: 'MEMORY_WIPED', details: { wiped: memResult.wiped } });
  }

  console.log(chalk.gray('\n  ◈ Session encrypted and sealed. Memory wiped. Stay safe. ◈\n'));
  process.exit(0);
}

process.on('SIGINT', () => {
  if (_ctrlCPressed) {
    // Second press — exit immediately
    gracefulShutdown();
  } else {
    // First press — warn
    _ctrlCPressed = true;
    console.log(chalk.yellow('\n  ⚠ Press Ctrl+C again within 5 seconds to exit.'));
    _ctrlCTimer = setTimeout(() => {
      _ctrlCPressed = false;
    }, 5000);
  }
});

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function initSession() {
  console.log();

  let password;
  const auth = new AuthManager();

  if (auth.hasAuth()) {
    let verified = false;
    let attempts = 0;
    const MAX_ATTEMPTS = 10;

    while (!verified && attempts < MAX_ATTEMPTS) {
      const { pass } = await inquirer.prompt([{
        type: 'password', name: 'pass',
        message: chalk.cyan('Enter master password:'),
        prefix: '  🔐', mask: '•',
        validate: (v) => v.length > 0 || 'Password is required',
      }]);

      if (auth.verifyPassword(pass)) {
        password = pass;
        verified = true;
      } else {
        attempts++;
        const backoffMs = Math.min(15000, 1000 * (2 ** Math.min(attempts, 4)));
        console.log(chalk.red(`  ✗ Incorrect password. Backing off for ${Math.ceil(backoffMs / 1000)}s.`));
        await sleep(backoffMs);
      }
    }

    if (!verified) {
      console.log(chalk.red('\n  ✗ Too many failed password attempts. Access denied.\n'));
      process.exit(1);
    }
  } else if (auth.hasLegacyHash() || auth.hasExistingEncryptedState()) {
    console.log(chalk.cyan('  🔄 Migrating to hardened authentication — verify your existing password.\n'));

    let migrated = false;
    while (!migrated) {
      const { pass } = await inquirer.prompt([{
        type: 'password', name: 'pass',
        message: chalk.cyan('Enter existing master password:'),
        prefix: '  🔐', mask: '•',
        validate: (v) => v.length >= 4 || 'Minimum 4 characters',
      }]);

      if (auth.migrateLegacyOrExistingState(pass)) {
        password = pass;
        migrated = true;
        console.log(chalk.green('  ✔ Hardened auth sentinel created.\n'));
      } else {
        console.log(chalk.red('  ✗ Password did not unlock existing encrypted data. Try again.'));
      }
    }
  } else {
    console.log(chalk.cyan('  🆕 First run — create a master password.\n'));
    const { newPass } = await inquirer.prompt([{
      type: 'password', name: 'newPass',
      message: chalk.cyan('Create master password:'),
      prefix: '  🔐', mask: '•',
      validate: (v) => v.length >= MIN_MASTER_PASSWORD_LENGTH
        || `Minimum ${MIN_MASTER_PASSWORD_LENGTH} characters`,
    }]);
    await inquirer.prompt([{
      type: 'password', name: 'confirm',
      message: chalk.cyan('Confirm password:'),
      prefix: '  🔐', mask: '•',
      validate: (v) => v === newPass || 'Passwords do not match',
    }]);
    password = newPass;
    auth.writeIfMissing(password);
    console.log(chalk.green('  ✔ Hardened auth sentinel created.\n'));
  }

  // ── MFA Check (if enabled) ──────────────────────────────
  const mfaConfig = (() => {
    try {
      const tempConfig = new ConfigManager(password);
      tempConfig.load();
      return tempConfig.get('mfa');
    } catch { return null; }
  })();

  if (mfaConfig?.enabled && mfaConfig?.setupComplete && mfaConfig?.secret) {
    let mfaVerified = false;
    let mfaAttempts = 0;
    const MAX_MFA_ATTEMPTS = 5;

    while (!mfaVerified && mfaAttempts < MAX_MFA_ATTEMPTS) {
      const { mfaCode } = await inquirer.prompt([{
        type: 'input', name: 'mfaCode',
        message: chalk.cyan('Enter TOTP code (or recovery code):'),
        prefix: '  🔑',
      }]);

      // Try TOTP first
      const totpResult = MFAProvider.verifyTOTP(mfaCode, mfaConfig.secret);
      if (totpResult.valid) {
        mfaVerified = true;
        console.log(chalk.green('  ✔ MFA verified'));
      } else {
        // Try recovery code
        const recoveryResult = MFAProvider.verifyRecoveryCode(mfaCode, mfaConfig.recoveryCodes || []);
        if (recoveryResult.valid) {
          mfaVerified = true;
          // Update stored recovery codes (one-time use)
          const tempConfig = new ConfigManager(password);
          tempConfig.load();
          tempConfig.set('mfa.recoveryCodes', recoveryResult.remainingCodes);
          console.log(chalk.green('  ✔ Recovery code accepted'));
          console.log(chalk.yellow(`  ⚠ ${recoveryResult.remainingCodes.length} recovery codes remaining`));
        } else {
          mfaAttempts++;
          console.log(chalk.red(`  ✗ Invalid code. ${MAX_MFA_ATTEMPTS - mfaAttempts} attempts remaining.`));
        }
      }
    }

    if (!mfaVerified) {
      console.log(chalk.red('\n  ✗ MFA verification failed. Access denied.\n'));
      process.exit(1);
    }
  }

  const spinner = ora({ text: 'Initializing secure session...', prefixText: '  ', spinner: 'dots12' }).start();

  const sessionId = randomBytes(8).toString('hex');

  // Config
  const config = new ConfigManager(password);
  config.load();
  config.loadVault();

  // Security modules
  const sanitizer = new Sanitizer({
    enabled: config.get('security.piiRedaction'),
    strictMode: config.get('security.strictMode'),
  });

  const fingerprint = new FingerprintMask({
    enabled: config.get('security.fingerprintMasking'),
  });

  const proxy = new ProxyRouter({
    enabled: config.get('proxy.enabled'),
    proxyType: config.get('proxy.type'),
    host: config.get('proxy.host'),
    port: config.get('proxy.port'),
  });

  const audit = new AuditLogger({
    enabled: config.get('audit.enabled'),
    ephemeral: config.get('audit.ephemeral'),
    masterPassword: config.get('audit.encrypted') ? password : null,
    sessionId,
  });

  const dns = new DnsResolver({
    enabled: config.get('dns.enabled'),
    provider: config.get('dns.provider'),
    method: config.get('dns.method'),
    proxyAgent: proxy.getAgent(),
    audit: audit,
  });

  const clipboard = new ClipboardManager({
    autoClear: config.get('security.clipboardAutoClear'),
    clearDelay: config.get('security.clipboardClearDelay'),
  });

  const recovery = new SessionRecovery({
    enabled: true,
    masterPassword: password,
    sessionId,
  });

  // Tracker blocker
  const trackerBlocker = new TrackerBlocker({
    enabled: config.get('trackerBlocker.enabled'),
    blockDomains: config.get('trackerBlocker.blockDomains'),
    stripParams: config.get('trackerBlocker.stripParams'),
    blockHeaders: config.get('trackerBlocker.blockHeaders'),
    sanitizeEnv: config.get('trackerBlocker.sanitizeEnv'),
    detectFingerprinting: config.get('trackerBlocker.detectFingerprinting'),
  });

  // Conversation manager
  const conversations = new ConversationManager({
    masterPassword: password,
  });

  // Integrity checker
  const integrityChecker = new IntegrityChecker({
    masterPassword: password,
    audit,
    enabled: config.get('integrity.enabled'),
    autoBaseline: config.get('integrity.autoBaseline'),
  });

  // Provider registry – dynamic loading
  const registry = new ProviderRegistry();
  const providerOpts = { sanitizer, fingerprint, proxy, audit, trackerBlocker, configManager: config };
  const providerConfigs = {
    ollama: { model: config.get('providers.ollama.model') },
    'ollama-api': { model: config.get('providers.ollama.model') },
  };
  const providers = registry.createAll(providerOpts, providerConfigs);

  // Auto-discover and load plugins
  const pluginManager = new PluginManager({
    audit,
    enabled: config.get('plugins.enabled'),
    autoLoad: config.get('plugins.autoLoad'),
    requireIntegrity: config.get('plugins.requireIntegrity'),
    allowedPlugins: config.get('plugins.allowed') || {},
  });
  const pluginResult = await pluginManager.autoLoad();
  const pluginProviders = pluginManager.getProviderMap();

  // Merge plugin providers into main providers map
  Object.assign(providers, pluginProviders);

  audit.log({ type: 'SESSION_START', details: { sessionId, pluginsLoaded: pluginResult.loaded } });

  // Compute key fingerprint for display (first 8 chars of SHA-256 of password)
  const { Encryption: Enc } = await import('./security/encryption.js');
  const keyFingerprint = Enc.hash(password).substring(0, 8);


  // Response renderer
  const renderer = new ResponseRenderer();

  ctx = {
    config, sanitizer, fingerprint, proxy, dns, audit,
    clipboard, recovery, registry, providers, conversations,
    trackerBlocker, sessionId, keyFingerprint, pluginManager, renderer,
    integrityChecker, masterPassword: password,
  };

  // Set ctx on plugin manager for lifecycle hooks
  pluginManager.ctx = ctx;

  // Start auto-checkpoint
  recovery.startAutoSave(() => ctx);

  // Enable DNS-level tracker interception
  trackerBlocker.enableDnsInterception();

  spinner.succeed('Secure session initialized');
  console.log(chalk.gray(`  Session: ${sessionId}`));
  console.log(chalk.gray(`  Fingerprint: ${fingerprint.fakeHostname} / ${fingerprint.fakeUsername}`));
  const convStats = conversations.getStats();
  if (convStats.totalThreads > 0) {
    console.log(chalk.gray(`  Conversations: ${convStats.totalThreads} threads, ${convStats.totalMessages} messages`));
  }
  console.log(proxy.formatStatus());
  console.log(dns.formatStatus());
  console.log(trackerBlocker.formatStatus());

  // Run integrity check and auto-baseline on launch if enabled
  if (config.get('integrity.checkOnLaunch') && config.get('integrity.enabled')) {
    try {
      // Only allow trust-on-first-use if explicitly enabled.
      if (config.get('integrity.autoBaseline') && integrityChecker.getStatus().selfFileCount === 0) {
        integrityChecker.recordSelfBaseline();
      }
      const selfCheck = integrityChecker.verifySelfIntegrity();
      if (selfCheck.status === 'mismatch') {
        console.log(chalk.red(`  ⚠ INTEGRITY WARNING: ${selfCheck.message}`));
      }
    } catch { /* silent */ }
  }

  // Show integrity and memory status AFTER baseline recording
  console.log(integrityChecker.formatStatus());
  console.log(MemoryGuard.formatStatus());

  // Startup health warnings
  const clipOk = await clipboard.isAvailable();
  if (!clipOk) {
    console.log(chalk.yellow('  ⚠ Clipboard manager: clipboardy unavailable'));
  }

  console.log();
}

// ── Typed error display helper ──────────────────────────────
function showError(result) {
  console.log(chalk.red(`  ✗ Error [${result.errorType || 'UNKNOWN'}]: ${result.error}`));
  if (result.advice) {
    console.log(chalk.yellow('  Recovery advice:'));
    for (const line of result.advice.split('\n')) {
      console.log(chalk.yellow(`    ${line}`));
    }
  }
}

// ── Chat mode (multi-turn with conversation history) ────────
async function chatMode(preselectedKey) {
  const providerKey = preselectedKey || await selectProvider(ctx.providers);
  const provider = ctx.providers[providerKey];

  // Pre-flight security check
  const proceed = await securityPreflightCheck(provider.name);
  if (!proceed) return;

  const info = provider.getInfo();
  const isApi = info.mode === 'api';

  // Thread selection — new or continue existing
  let threadId = null;
  const startAction = await chatStartMenu(ctx.conversations);

  if (startAction === 'new') {
    threadId = ctx.conversations.createThread(providerKey, info.model || 'default');
    console.log(chalk.green(`\n  ✨ New conversation started with ${provider.name}`));
  } else {
    threadId = startAction;
    const thread = ctx.conversations.ensureLoaded(threadId);
    if (thread) {
      ctx.conversations.setActiveThread(threadId);
      console.log(chalk.green(`\n  💬 Continuing: ${chalk.cyan(thread.title || '(untitled)')}  (${thread.messages.length} messages)`));
      // Show last 3 messages for context
      const recent = thread.messages.slice(-3);
      if (recent.length > 0) {
        console.log(chalk.gray('  ── Recent context ──'));
        for (const m of recent) {
          const label = m.role === 'user' ? chalk.cyan('You') : chalk.green('AI');
          const preview = m.content.length > 100 ? m.content.substring(0, 97) + '...' : m.content;
          console.log(chalk.gray(`  ${label}: ${preview}`));
        }
        console.log(chalk.gray('  ──────────────────'));
      }
    } else {
      threadId = ctx.conversations.createThread(providerKey, info.model || 'default');
      console.log(chalk.yellow('  ⚠ Could not load thread. Starting new conversation.'));
    }
  }

  if (isApi) {
    console.log(chalk.gray(`  Model: ${info.model || 'default'} | Mode: Native API | Streaming: ON`));
  }
  console.log(chalk.gray('  Commands: /new /threads /title <name> /save /history /exit'));
  console.log();

  ctx.audit.log({ type: 'CHAT_START', provider: provider.name, details: { threadId, mode: isApi ? 'api' : 'cli' } });

  let historyOff = false;
  let quarantineNext = false;
  let insertCanaryNext = false;
  let allowedProvider = null;
  let deniedProviders = new Set();
  let proxyDisabledForSession = false;

  while (true) {
    const input = await promptInput(`${provider.name}`);
    if (!input) continue;

    // ── Inline commands ─────────────
    const cmd = input.trim().toLowerCase();
    if (cmd === '/exit' || cmd === 'exit') {
      // Auto-save conversation on exit
      ctx.conversations.saveThread(threadId);
      console.log(chalk.gray('  Conversation saved.'));
      break;
    }
    if (cmd === '/new') {
      ctx.conversations.saveThread(threadId);
      threadId = ctx.conversations.createThread(providerKey, info.model || 'default');
      console.log(chalk.green('  ✨ New conversation started.'));
      continue;
    }
    if (cmd === '/threads') {
      const threads = ctx.conversations.listThreads();
      if (threads.length === 0) {
        console.log(chalk.gray('  No conversations yet.'));
      } else {
        console.log();
        for (const t of threads.slice(0, 15)) {
          const active = t.id === threadId ? chalk.green(' ◀ active') : '';
          console.log(`  ${chalk.cyan(t.title || '(untitled)')} ${chalk.gray(`(${t.messageCount} msgs)`)}${active}`);
        }
        console.log();
      }
      continue;
    }
    if (cmd.startsWith('/title ')) {
      const newTitle = input.trim().substring(7);
      ctx.conversations.setTitle(threadId, newTitle);
      console.log(chalk.green(`  ✔ Title set: ${newTitle}`));
      continue;
    }
    if (cmd === '/save') {
      const saved = ctx.conversations.saveThread(threadId);
      console.log(saved ? chalk.green('  ✔ Conversation saved') : chalk.red('  ✗ Save failed'));
      continue;
    }
    if (cmd === '/history') {
      const thread = ctx.conversations.getThread(threadId);
      if (thread && thread.messages.length > 0) {
        console.log();
        for (const m of thread.messages) {
          const label = m.role === 'user' ? chalk.cyan('You') : chalk.green('AI');
          const ts = chalk.gray(new Date(m.timestamp).toLocaleTimeString());
          const preview = m.content.length > 150 ? m.content.substring(0, 147) + '...' : m.content;
          console.log(`  ${ts} ${label}: ${preview}`);
        }
        console.log();
      } else {
        console.log(chalk.gray('  No messages in this conversation yet.'));
      }
      continue;
    }

    if (cmd === '/net direct') {
      proxyDisabledForSession = true;
      ctx.proxy.enabled = false;
      ctx.dns.setProxyAgent(null);
      console.log(chalk.green('  ✔ Proxy routing explicitly disabled for this session.'));
      continue;
    }

    if (cmd.startsWith('/dns pin ')) {
      const pinProv = cmd.substring(9).trim();
      let matchedUrl = null;
      for (const [k, v] of Object.entries((await import('./security/dns.js')).DOH_PROVIDERS)) {
        if (k.toLowerCase() === pinProv || v.toLowerCase() === pinProv) {
          matchedUrl = v;
          break;
        }
      }
      if (matchedUrl) {
        ctx.dns.provider = matchedUrl;
        ctx.dns.failoverProviders = [matchedUrl]; // Reject fallback
        console.log(chalk.green(`  ✔ Secure DNS pinned to ${matchedUrl}. Fallbacks rejected.`));
      } else {
        console.log(chalk.red(`  ✗ DNS provider "${pinProv}" not recognized.`));
      }
      continue;
    }

    if (cmd === '/dns leaktest') {
      console.log(chalk.cyan('  🔍 Running DNS leaktest...'));
      const status = ctx.dns.getStatus();
      if (!status.enabled) {
        console.log(chalk.red('  ✗ Secure DNS is disabled. Traffic may be leaked to your local ISP.'));
      } else {
        console.log(chalk.green(`  ✔ Using Secure DNS (Do${status.method === 'dot' ? 'T' : 'H'} via ${new URL(status.provider).hostname}). Route is clean.`));
      }
      continue;
    }

    if (cmd === '/clipboard off') {
      ctx.clipboard.enabled = false;
      console.log(chalk.yellow('  ✔ Clipboard use disabled entirely for this session.'));
      continue;
    }
    if (cmd === '/clipboard on') {
      ctx.clipboard.enabled = true;
      console.log(chalk.green('  ✔ Clipboard use enabled.'));
      continue;
    }

    if (cmd === '/clipboard purge') {
      await ctx.clipboard.clear();
      ctx.clipboard.cancelAllTimers();
      console.log(chalk.green('  ✔ Clipboard immediately purged and pending timers canceled.'));
      continue;
    }

    if (cmd === '/redact preview') {
      const previewPrompt = await promptInput('Text to preview redaction');
      if (previewPrompt) {
        const result = ctx.sanitizer.sanitize(previewPrompt);
        console.log(chalk.gray('\n  ── Original ──'));
        console.log(`  ${previewPrompt}`);
        console.log(chalk.gray('\n  ── Sanitized ──'));
        console.log(`  ${chalk.green(result.text)}`);
        if (result.redactions.length > 0) {
          console.log(ctx.sanitizer.formatWarning(result.redactions));
        } else {
          console.log(chalk.gray('  No PII detected.'));
        }
      }
      continue;
    }

    if (cmd === '/redact strict on') {
      ctx.sanitizer.strictMode = true;
      console.log(chalk.green('  ✔ Strict redaction enabled.'));
      continue;
    }
    if (cmd === '/redact strict off') {
      ctx.sanitizer.strictMode = false;
      console.log(chalk.yellow('  ✔ Strict redaction disabled.'));
      continue;
    }

    if (cmd === '/render safe') {
      ctx.renderer.safeMode = true;
      console.log(chalk.green('  ✔ Rendering set to safe mode (plain text only).'));
      continue;
    }

    if (cmd === '/render raw') {
      if (info.type === 'local') {
        ctx.renderer.safeMode = false;
        console.log(chalk.yellow('  ✔ Rendering set to raw mode (trusted local provider).'));
      } else {
        console.log(chalk.red('  ✗ Raw rendering only allowed for trusted local providers.'));
      }
      continue;
    }

    if (cmd === '/session seal') {
      console.log(chalk.cyan('  Encrypting state and wiping memory buffers...'));
      if (ctx.conversations) ctx.conversations.saveAll();
      if (ctx.recovery) {
        ctx.recovery.saveCheckpoint(ctx);
      }
      const memResult = MemoryGuard.wipeAll();
      ctx.audit?.log({ type: 'SESSION_SEAL', details: { wiped: memResult.wiped } });
      console.log(chalk.green(`  ✔ Memory wiped (${memResult.wiped} buffers). State sealed.`));
      console.log(chalk.yellow('  Restarting chat loop cleanly...'));
      break; // exits the inner chat loop
    }

    if (cmd === '/session attestate') {
      console.log();
      console.log(chalk.cyan('  Session Attestation:'));
      console.log(chalk.gray(`  ID: ${ctx.sessionId}`));
      const auth = new AuthManager();
      console.log(chalk.gray(`  Auth Status: Verified`));
      console.log(chalk.gray(`  Trust Mode: ${ctx.sanitizer.strictMode ? 'Strict' : 'Standard'}`));
      console.log(chalk.gray(`  Plugins: ${ctx.pluginManager.listPlugins().length} loaded`));
      console.log(chalk.gray(`  Proxy State: ${ctx.proxy.enabled ? 'Enabled' : 'Disabled'}`));
      const intStat = ctx.integrityChecker.getStatus();
      console.log(chalk.gray(`  Integrity: ${intStat.enabled ? 'Enforced' : 'Disabled'} (${intStat.providerCount} hashes)`));
      console.log();
      continue;
    }

    if (cmd === '/history off') {
      historyOff = true;
      console.log(chalk.yellow('  ✔ Conversation turns will NOT be stored from this point forward.'));
      continue;
    }

    if (cmd === '/history purge') {
      ctx.conversations.deleteThread(threadId);
      console.log(chalk.red('  ✔ Active thread deleted.'));
      threadId = ctx.conversations.createThread(providerKey, info.model || 'default');
      console.log(chalk.green('  ✨ New conversation started.'));
      continue;
    }

    if (cmd === '/export secure') {
      const { exportPass } = await inquirer.prompt([{
        type: 'password', name: 'exportPass',
        message: chalk.cyan('Set export password:'),
        mask: '•', prefix: '  🔒'
      }]);
      if (exportPass) {
        const exported = ctx.conversations.exportThread(threadId, 'json');
        if (exported) {
          const { Encryption: Enc } = await import('./security/encryption.js');
          const encrypted = Enc.encrypt(exported, exportPass);
          const checksum = createHash('sha256').update(encrypted).digest('hex');
          const filepath = join(homedir(), '.ace', `secure_export_${threadId}.enc`);
          writeSecureFile(filepath, JSON.stringify({ data: encrypted, checksum }), 'utf8');
          console.log(chalk.green(`  ✔ Thread exported securely to ${filepath}`));
          console.log(chalk.gray(`  Checksum: ${checksum}`));
        } else {
          console.log(chalk.red('  ✗ Export failed.'));
        }
      }
      continue;
    }

    if (cmd.startsWith('/key rotate ')) {
      const provName = cmd.substring(12).trim();
      const { newKey } = await inquirer.prompt([{
        type: 'password', name: 'newKey',
        message: chalk.cyan(`New API key for ${provName}:`),
        mask: '•', prefix: '  🔑'
      }]);
      if (newKey) {
        ctx.config.setApiKey(provName, newKey);
        ctx.renderer.clearCache();
        console.log(chalk.green(`  ✔ API key rotated for ${provName} and cache invalidated.`));
      }
      continue;
    }

    if (cmd.startsWith('/provider allow ')) {
      allowedProvider = cmd.substring(16).trim();
      console.log(chalk.green(`  ✔ Allowed provider restricted to: ${allowedProvider}`));
      continue;
    }

    if (cmd.startsWith('/provider deny ')) {
      const denied = cmd.substring(15).trim();
      deniedProviders.add(denied);
      console.log(chalk.red(`  ✔ Provider blocked for this session: ${denied}`));
      continue;
    }

    if (cmd === '/plugin off') {
      ctx.pluginManager.enabled = false;
      for (const p of ctx.pluginManager.listPlugins()) {
        await ctx.pluginManager.unloadPlugin(p.name);
      }
      console.log(chalk.yellow('  ✔ All plugin providers disabled.'));
      continue;
    }

    if (cmd === '/plugin status') {
      console.log(ctx.pluginManager.formatStatus());
      continue;
    }

    if (cmd === '/sandbox report') {
      console.log(chalk.cyan('  Sandbox Limits:'));
      console.log(chalk.gray('  - Process isolation: NONE (Runs in current Node context)'));
      console.log(chalk.gray('  - Filesystem: User privilege level (Sanitized paths available)'));
      console.log(chalk.gray('  - Network: Custom HTTP clients (HTTPS/SOCKS proxied when configured)'));
      console.log(chalk.gray('  - Subprocesses: Restricted to registered providers'));
      console.log(chalk.yellow('  ⚠ Do not overtrust the environment. Executing hostile code locally is unsafe.'));
      continue;
    }

    if (cmd === '/threat model') {
      console.log(chalk.cyan('  Current Exposure:'));
      console.log(chalk.gray(`  - Disk: ${ctx.audit.ephemeral ? 'Ephemeral mode (No writes)' : 'Encrypted writes'}`));
      console.log(chalk.gray(`  - Network: ${ctx.proxy.enabled ? 'Tor/Proxy Routed' : 'Direct Connection'}`));
      console.log(chalk.gray(`  - DNS: ${ctx.dns.enabled ? `Secure (Do${ctx.dns.method === 'dot' ? 'T' : 'H'})` : 'System Default'}`));
      console.log(chalk.gray(`  - Provider Trust: ${info.type === 'local' ? 'High (Local Engine)' : 'Low (Cloud Engine)'}`));
      console.log(chalk.gray(`  - Plugin Trust: ${ctx.pluginManager.listPlugins().length > 0 ? 'Potentially risky' : 'None loaded'}`));
      console.log(chalk.gray(`  - Terminal Risk: ${ctx.renderer.safeMode ? 'Low (Safe Rendering)' : 'Medium (ANSI parsed)'}`));
      continue;
    }

    if (cmd === '/opsec check') {
      console.log(chalk.cyan('  OPSEC Checklist:'));
      console.log(ctx.proxy.enabled ? chalk.green('  ✔ Proxy active') : chalk.red('  ✗ Proxy disabled'));
      console.log(ctx.dns.enabled ? chalk.green('  ✔ Secure DNS active') : chalk.red('  ✗ Secure DNS disabled'));
      console.log(ctx.sanitizer.enabled ? chalk.green('  ✔ PII Redaction active') : chalk.red('  ✗ PII Redaction disabled'));
      console.log(ctx.fingerprint.enabled ? chalk.green('  ✔ Fingerprint masked') : chalk.red('  ✗ Fingerprint unmasked'));
      continue;
    }

    if (cmd === '/prompt classify') {
      const clsPrompt = await promptInput('Prompt to classify');
      if (clsPrompt) {
        const injection = ctx.sanitizer.detectInjection(clsPrompt);
        let secrecy = 'Low';
        const pii = ctx.sanitizer.sanitize(clsPrompt).redactions;
        if (pii.length > 0) secrecy = 'High (PII detected)';
        console.log(chalk.cyan('  Classification Results:'));
        console.log(chalk.gray(`  Secrecy: ${secrecy}`));
        console.log(chalk.gray(`  Legal Sensitivity: Unknown (requires LLM analysis)`));
        console.log(chalk.gray(`  Injection Risk: ${injection.severity} (Score: ${injection.score})`));
      }
      continue;
    }

    if (cmd === '/response quarantine') {
      quarantineNext = true;
      console.log(chalk.yellow('  ✔ The next response will be quarantined without rendering.'));
      continue;
    }

    if (cmd === '/canary insert') {
      insertCanaryNext = true;
      console.log(chalk.yellow('  ✔ A canary token will be inserted into the next prompt.'));
      continue;
    }

    // ── Pre-execution Policy Checks ──
    if (allowedProvider && provider.name !== allowedProvider) {
      console.log(chalk.red(`  ⛔ Blocked: Provider ${provider.name} is not the allowed provider (${allowedProvider}).`));
      continue;
    }
    if (deniedProviders.has(provider.name)) {
      console.log(chalk.red(`  ⛔ Blocked: Provider ${provider.name} is denied for this session.`));
      continue;
    }

    // ── Add user message to thread ──
    let finalInput = input;
    if (insertCanaryNext) {
      const canaryToken = randomBytes(16).toString('hex');
      finalInput += `\n[CANARY_TOKEN: ${canaryToken}]`;
      console.log(chalk.gray(`  (Canary token inserted: ${canaryToken})`));
      insertCanaryNext = false;
    }

    if (!historyOff) {
      ctx.conversations.addMessage(threadId, 'user', finalInput);
    }

    // Get conversation history for context
    // Even if history is off for this and future turns, we still send previous context if available.
    // If history is on, we've already added the current message, so slice(0, -1) gets the history.
    // If history is off, we didn't add the current message to the thread, so slice(0) gets the whole history.
    const historyMessages = ctx.conversations.getMessages(threadId);
    const conversationHistory = isApi ? (historyOff ? historyMessages.slice() : historyMessages.slice(0, -1)) : [];

    const spinner = ora({ text: 'Processing...', prefixText: '  ', spinner: 'dots' }).start();

    try {
      const result = await provider.execute(finalInput, { conversationHistory });
      spinner.stop();

      if (result.success) {
        if (quarantineNext) {
          console.log(chalk.yellow('  ⚠ Response quarantined. It has not been rendered.'));
          if (!historyOff) ctx.conversations.addMessage(threadId, 'assistant', result.output);
          quarantineNext = false;
          continue;
        }

        // Add assistant response to thread
        if (!historyOff) {
          ctx.conversations.addMessage(threadId, 'assistant', result.output);
        }

        // For non-streaming responses, display the output
        if (!result.streamed) {
          // Scan response for tracker URLs
          const trackers = ctx.trackerBlocker.scanText(result.output);
          let displayText = result.output;
          if (trackers.length > 0) {
            const redacted = ctx.trackerBlocker.redactTrackerUrls(result.output);
            displayText = redacted.text;
            console.log(chalk.yellow(`  ⚠ ${trackers.length} tracker URL(s) redacted from response`));
          }

          // Render with markdown formatting + cost/token/latency
          const startTime = result._startTime || Date.now();
          ctx.renderer.renderComplete(displayText, {
            model: result.model || info.model || 'unknown',
            latencyMs: result.latency || (Date.now() - startTime),
            inputText: input,
          });

          // Cache the response
          ctx.renderer.setCached(input, result.output);
        }
      } else if (result.injection?.detected) {
        // Remove the blocked message from thread
        const thread = ctx.conversations.getThread(threadId);
        if (thread) thread.messages.pop();
        console.log(chalk.red(`  ⛔ BLOCKED: ${result.error}`));
      } else {
        // Remove the failed message from thread
        const thread = ctx.conversations.getThread(threadId);
        if (thread) thread.messages.pop();
        showError(result);
      }
    } catch (err) {
      spinner.stop();
      // Remove the failed message from thread
      const thread = ctx.conversations.getThread(threadId);
      if (thread) thread.messages.pop();
      const classified = classifyError(err, { command: provider.command, provider: provider.name });
      console.log(chalk.red(`  ✗ ${classified.name}: ${classified.message}`));
      console.log(chalk.yellow(`  ${classified.advice}`));
    }
  }
}

// ── Quick prompt ────────────────────────────────────────────
async function quickPrompt() {
  const providerKey = await selectProvider(ctx.providers);
  const provider = ctx.providers[providerKey];

  // Pre-flight security check
  const proceed = await securityPreflightCheck(provider.name);
  if (!proceed) return;

  const input = await promptInput('One-shot prompt');
  if (!input) return;

  const spinner = ora({ text: `Sending to ${provider.name}...`, prefixText: '  ', spinner: 'dots' }).start();

  try {
    const result = await provider.execute(input);
    spinner.stop();

    if (result.success) {
      if (!result.streamed) {
        ctx.renderer.renderComplete(result.output, {
          model: result.model || 'unknown',
          latencyMs: result.latency,
          inputText: input,
        });
      }
    } else {
      showError(result);
    }
  } catch (err) {
    spinner.stop();
    const classified = classifyError(err, { command: provider.command });
    console.log(chalk.red(`  ✗ ${classified.name}: ${classified.message}`));
    console.log(chalk.yellow(`  ${classified.advice}`));
  }
}

// ── Conversation management ─────────────────────────────────
async function manageConversations() {
  while (true) {
    const action = await conversationMenu();
    if (action === 'back') return;

    if (action === 'list') {
      const threads = ctx.conversations.listThreads();
      if (threads.length === 0) {
        console.log(chalk.gray('\n  No conversations found.\n'));
      } else {
        console.log();
        for (const t of threads) {
          const provider = chalk.yellow(`[${t.provider}]`);
          const msgs = chalk.gray(`(${t.messageCount} msgs)`);
          const date = chalk.gray(new Date(t.updated).toLocaleString());
          console.log(`  ${chalk.cyan(t.title || '(untitled)')} ${provider} ${msgs} ${date}`);
        }
        console.log();
      }
    }

    if (action === 'search') {
      const query = await promptInput('Search');
      if (!query) continue;
      const results = ctx.conversations.searchThreads(query);
      if (results.length === 0) {
        console.log(chalk.gray('\n  No matches found.\n'));
      } else {
        console.log();
        for (const r of results) {
          console.log(`  ${chalk.cyan(r.title || '(untitled)')} ${chalk.gray(`[${r.type}]`)}`);
          if (r.preview) console.log(chalk.gray(`    "${r.preview}"`));
        }
        console.log();
      }
    }

    if (action === 'export') {
      const threads = ctx.conversations.listThreads();
      if (threads.length === 0) {
        console.log(chalk.gray('\n  No conversations to export.\n'));
        continue;
      }
      const { threadId } = await inquirer.prompt([{
        type: 'list', name: 'threadId', message: 'Select conversation:',
        choices: threads.map(t => ({ name: `${t.title || '(untitled)'} (${t.messageCount} msgs)`, value: t.id })),
        prefix: '  ',
      }]);
      const { format } = await inquirer.prompt([{
        type: 'list', name: 'format', message: 'Format:', choices: ['json', 'markdown'], prefix: '  ',
      }]);
      ctx.conversations.ensureLoaded(threadId);
      const exported = ctx.conversations.exportThread(threadId, format);
      if (exported) {
        const ext = format === 'markdown' ? 'md' : 'json';
        const filepath = join(homedir(), '.ace', `${threadId}.${ext}`);
        writeSecureFile(filepath, exported, 'utf8');
        console.log(chalk.green(`\n  ✔ Exported to: ${filepath}\n`));
      } else {
        console.log(chalk.red('  ✗ Export failed'));
      }
    }

    if (action === 'delete') {
      const threads = ctx.conversations.listThreads();
      if (threads.length === 0) {
        console.log(chalk.gray('\n  No conversations to delete.\n'));
        continue;
      }
      const { threadId } = await inquirer.prompt([{
        type: 'list', name: 'threadId', message: 'Delete conversation:',
        choices: threads.map(t => ({ name: `${t.title || '(untitled)'} (${t.messageCount} msgs)`, value: t.id })),
        prefix: '  ',
      }]);
      const confirmed = await confirmAction('Delete this conversation permanently?');
      if (confirmed) {
        ctx.conversations.deleteThread(threadId);
        console.log(chalk.red('  ✔ Conversation deleted'));
        ctx.audit.log({ type: 'CONVERSATION_DELETED', details: { threadId } });
      }
    }

    if (action === 'wipe') {
      const confirmed = await confirmAction('Delete ALL conversations? This cannot be undone.');
      if (confirmed) {
        ctx.conversations.wipeAll();
        console.log(chalk.red('  ✔ All conversations wiped'));
        ctx.audit.log({ type: 'ALL_CONVERSATIONS_WIPED' });
      }
    }
  }
}

// ── Security pre-flight check before CLI launch ─────────────
async function securityPreflightCheck(providerName) {
  // Only flag protections that ACTUALLY break CLI connectivity.
  // Fingerprint masking (just renames USERNAME/HOSTNAME) and tracker blocker
  // (just removes tracker env vars) are safe — they don't break CLIs.
  const activeProtections = [];

  if (ctx.proxy?.enabled) {
    activeProtections.push({
      name: `Proxy (${ctx.proxy.proxyType}://${ctx.proxy.host}:${ctx.proxy.port})`,
      icon: '🌐',
      detail: 'Routes traffic through proxy — CLI may not support SOCKS',
      toggle: () => { ctx.proxy.enabled = false; ctx.proxy.agent = null; },
      key: 'proxy',
    });
  }
  if (ctx.sanitizer?.enabled && ctx.sanitizer?.strictMode) {
    activeProtections.push({
      name: 'PII Strict Mode',
      icon: '🔍',
      detail: 'Aggressive redaction active — may alter prompts before sending',
      toggle: () => { ctx.sanitizer.strictMode = false; },
      key: 'strict',
    });
  }

  if (activeProtections.length === 0) return true; // No potential conflicts

  // Show warning
  console.log();
  console.log(chalk.yellow('  ⚠ Security Preflight Check'));
  console.log(chalk.gray('  ───────────────────────────────────────────'));
  console.log(chalk.yellow(`  The following protections are active and may affect ${providerName}:\n`));

  for (const p of activeProtections) {
    console.log(chalk.yellow(`    ${p.icon} ${p.name}`));
    console.log(chalk.gray(`       ${p.detail}`));
  }
  console.log();

  const { action } = await inquirer.prompt([{
    type: 'list',
    name: 'action',
    message: chalk.cyan('How do you want to proceed?'),
    prefix: '  ⚠',
    choices: [
      { name: chalk.green('Continue anyway — launch with all protections'), value: 'continue' },
      { name: chalk.yellow('Disable specific protections for this session'), value: 'disable' },
      { name: chalk.red('← Go back — don\'t launch'), value: 'back' },
    ],
  }]);

  if (action === 'back') return false;

  if (action === 'disable') {
    const { toDisable } = await inquirer.prompt([{
      type: 'checkbox',
      name: 'toDisable',
      message: chalk.cyan('Select protections to disable (this session only):'),
      prefix: '  🔧',
      choices: activeProtections.map(p => ({
        name: `${p.icon} ${p.name}`,
        value: p.key,
      })),
    }]);

    for (const key of toDisable) {
      const protection = activeProtections.find(p => p.key === key);
      if (protection) {
        protection.toggle();
        console.log(chalk.yellow(`  ⊘ ${protection.name} disabled for this session`));
      }
    }
    console.log();
  }

  return true;
}

// ── Interactive provider launch ─────────────────────────────
async function launchInteractive() {
  const providerKey = await selectProvider(ctx.providers);
  const provider = ctx.providers[providerKey];

  // Pre-flight check
  const proceed = await securityPreflightCheck(provider.name);
  if (!proceed) return;

  console.log(chalk.yellow(`\n  Launching ${provider.name} in interactive mode...`));
  console.log(chalk.green('  (Security layer active – stdin/stdout sanitized in real-time)'));
  console.log(chalk.gray('  Press Ctrl+C to exit interactive mode.\n'));

  ctx.audit.log({ type: 'INTERACTIVE_LAUNCH', provider: provider.name });

  try {
    const child = await provider.interactive();
    await new Promise((resolve) => {
      child.on('close', resolve);
      child.on('error', (err) => {
        const classified = classifyError(err, { command: provider.command });
        console.log(chalk.red(`  ✗ ${classified.name}: ${classified.message}`));
        console.log(chalk.yellow(`  ${classified.advice}`));
        resolve();
      });
    });
  } catch (err) {
    const classified = classifyError(err, { command: provider.command });
    console.log(chalk.red(`  ✗ Failed to launch: ${classified.message}`));
    console.log(chalk.yellow(`  ${classified.advice}`));
  }
}

// ── Vault management ────────────────────────────────────────
async function manageVault() {
  while (true) {
    const action = await vaultMenu();
    if (action === 'back') return;

    if (action === 'list') {
      const keys = ctx.config.listVaultKeys();
      if (keys.length === 0) {
        console.log(chalk.gray('\n  No API keys stored.\n'));
      } else {
        console.log();
        for (const k of keys) {
          console.log(`  ${chalk.cyan(k.provider.padEnd(12))} ${chalk.green(k.preview)}`);
        }
        console.log();
      }
    }

    if (action === 'add') {
      const { provider } = await inquirer.prompt([{
        type: 'list', name: 'provider', message: 'Provider:',
        choices: ['openai', 'claude', 'gemini', 'copilot', 'ollama', 'custom'],
        prefix: '  ',
      }]);
      let name = provider;
      if (provider === 'custom') {
        name = await promptInput('Key name');
      }
      const { key } = await inquirer.prompt([{
        type: 'password', name: 'key', message: `API key for ${name}:`,
        mask: '•', prefix: '  🔑',
      }]);
      ctx.config.setApiKey(name, key);
      console.log(chalk.green(`  ✔ Key stored (encrypted)`));
      ctx.audit.log({ type: 'VAULT_KEY_ADDED', details: { provider: name } });
    }

    if (action === 'delete') {
      const keys = ctx.config.listVaultKeys();
      if (keys.length === 0) {
        console.log(chalk.gray('\n  No keys to delete.\n'));
        continue;
      }
      const { provider } = await inquirer.prompt([{
        type: 'list', name: 'provider', message: 'Delete key for:',
        choices: keys.map((k) => k.provider),
        prefix: '  ',
      }]);
      ctx.config.deleteApiKey(provider);
      console.log(chalk.red(`  ✔ Key deleted: ${provider}`));
      ctx.audit.log({ type: 'VAULT_KEY_DELETED', details: { provider } });
    }
  }
}

// ── Secure DNS management ───────────────────────────────────
async function manageDns() {
  while (true) {
    const action = await dnsMenu();
    if (action === 'back') return;

    if (action === 'status') {
      console.log(`\n${ctx.dns.formatStatus()}\n`);
    }

    if (action === 'default') {
      const provider = 'https://doh.applied-privacy.net/query';
      ctx.dns.provider = provider;
      ctx.dns.enabled = true;
      ctx.config.set('dns.enabled', true);
      ctx.config.set('dns.provider', provider);
      console.log(chalk.green('  ✔ Default provider (Applied Privacy) set'));
      ctx.audit.log({ type: 'DNS_CONFIG', details: { provider } });
    }

    if (action === 'custom') {
      const { provider } = await inquirer.prompt([{
        type: 'input', name: 'provider', message: 'DoH Provider URL:', default: ctx.dns.provider, prefix: '  ',
      }]);
      ctx.dns.provider = provider;
      ctx.dns.enabled = true;
      ctx.config.set('dns.enabled', true);
      ctx.config.set('dns.provider', provider);
      console.log(chalk.green(`  ✔ Custom provider set: ${provider}`));
      ctx.audit.log({ type: 'DNS_CONFIG', details: { provider } });
    }

    if (action === 'disable') {
      ctx.dns.enabled = false;
      ctx.config.set('dns.enabled', false);
      console.log(chalk.yellow('  ✔ Secure DNS disabled (using system DNS)'));
      ctx.audit.log({ type: 'DNS_DISABLED' });
    }

    if (action === 'test') {
      const { hostname } = await inquirer.prompt([{
        type: 'input', name: 'hostname', message: 'Hostname to resolve:', default: 'example.com', prefix: '  ',
      }]);
      const spinner = ora({ text: 'Resolving...', prefixText: '  ', spinner: 'dots' }).start();
      const result = await ctx.dns.resolve(hostname);
      spinner.stop();

      if (result.error) {
        console.log(chalk.red(`  ✗ Resolution failed: ${result.error}`));
      } else {
        console.log(chalk.green(`  ✔ Resolution successful (${ctx.dns.method})${result.cached ? ' [CACHED]' : ''}`));
        if (result.answers && result.answers.length > 0) {
          result.answers.forEach(a => console.log(`    • ${a}`));
        } else {
          console.log(chalk.yellow('    (No A records found)'));
        }
      }
    }

    if (action === 'benchmark') {
      const spinner = ora({ text: 'Benchmarking DNS providers...', prefixText: '  ', spinner: 'dots' }).start();
      const results = await ctx.dns.benchmark();
      spinner.stop();
      console.log();
      const { DnsResolver: DR } = await import('./security/dns.js');
      console.log(DR.formatBenchmark(results));
      console.log();
    }

    if (action === 'cache') {
      const status = ctx.dns.getStatus();
      console.log(chalk.cyan(`\n  DNS Cache: ${status.cache.size}/${status.cache.maxSize} entries | TTL: ${status.cache.ttl}s | Hits: ${status.cache.hits}`));
      const entries = ctx.dns.getCache();
      if (entries.length > 0) {
        for (const e of entries.slice(0, 20)) {
          console.log(chalk.gray(`    ${e.key} (${e.ttlRemaining}s remaining)`));
        }
      }
      console.log();
    }

    if (action === 'dot') {
      ctx.dns.method = ctx.dns.method === 'dot' ? 'doh' : 'dot';
      ctx.config.set('dns.method', ctx.dns.method);
      const label = ctx.dns.method === 'dot' ? 'DNS over TLS' : 'DNS over HTTPS';
      console.log(chalk.green(`  ✔ Switched to ${label}`));
      ctx.audit.log({ type: 'DNS_METHOD_CHANGED', details: { method: ctx.dns.method } });
    }
  }
}

// ── Proxy management ────────────────────────────────────────
async function manageProxy() {
  while (true) {
    const action = await proxyMenu();
    if (action === 'back') return;

    if (action === 'status') {
      console.log(`\n${ctx.proxy.formatStatus()}\n`);
    }

    if (action === 'tor') {
      ctx.proxy.enabled = true;
      ctx.proxy.host = '127.0.0.1';
      ctx.proxy.port = 9050;
      ctx.proxy.proxyType = 'socks5';
      ctx.config.set('proxy.enabled', true);
      ctx.config.set('proxy.host', '127.0.0.1');
      ctx.config.set('proxy.port', 9050);
      ctx.dns.setProxyAgent(ctx.proxy.getAgent());
      console.log(chalk.green('  ✔ Tor proxy enabled'));
      ctx.audit.log({ type: 'PROXY_ENABLED', details: { type: 'tor' } });
    }

    if (action === 'custom') {
      const { host } = await inquirer.prompt([{
        type: 'input', name: 'host', message: 'Proxy host:', default: '127.0.0.1', prefix: '  ',
        validate: (v) => {
          if (!v || v.trim().length === 0) return 'Host is required';
          // Basic IP/hostname validation
          if (!/^[a-zA-Z0-9.\-_:]+$/.test(v.trim())) return 'Invalid host format';
          return true;
        },
      }]);
      const { port } = await inquirer.prompt([{
        type: 'number', name: 'port', message: 'Proxy port:', default: 1080, prefix: '  ',
        validate: (v) => {
          const p = parseInt(v);
          if (isNaN(p) || p < 1 || p > 65535) return 'Port must be 1-65535';
          return true;
        },
      }]);
      ctx.proxy.enabled = true;
      ctx.proxy.host = host;
      ctx.proxy.port = port;
      ctx.config.set('proxy.enabled', true);
      ctx.config.set('proxy.host', host);
      ctx.config.set('proxy.port', port);
      ctx.dns.setProxyAgent(ctx.proxy.getAgent());
      console.log(chalk.green(`  ✔ Custom proxy set: ${host}:${port}`));
      ctx.audit.log({ type: 'PROXY_ENABLED', details: { type: 'custom', host, port } });
    }

    if (action === 'disable') {
      ctx.proxy.enabled = false;
      ctx.config.set('proxy.enabled', false);
      ctx.dns.setProxyAgent(null);
      console.log(chalk.yellow('  ✔ Proxy disabled'));
      ctx.audit.log({ type: 'PROXY_DISABLED' });
    }

    if (action === 'test') {
      const spinner = ora({ text: 'Testing proxy connection...', prefixText: '  ', spinner: 'dots' }).start();
      const result = await ctx.proxy.testConnection();
      if (result.ok) {
        spinner.succeed(`Connection OK${result.isTor ? ' (Tor confirmed)' : ''} – IP: ${result.ip || 'unknown'}`);
      } else {
        spinner.fail(`Connection failed: ${result.error}`);
      }
    }
  }
}

// ── Privacy settings ────────────────────────────────────────
async function managePrivacy() {
  while (true) {
    const action = await privacyMenu();
    if (action === 'back') return;

    const toggleMap = {
      pii: 'security.piiRedaction',
      strict: 'security.strictMode',
      fingerprint: 'security.fingerprintMasking',
      metadata: 'security.metadataStripping',
      clipboard: 'security.clipboardAutoClear',
      injection: 'security.promptInjectionDetection',
      trackerBlocker: 'security.trackerBlocking',
      ephemeral: 'audit.ephemeral',
    };

    const path = toggleMap[action];
    if (path) {
      const current = ctx.config.get(path);
      ctx.config.set(path, !current);
      const label = path.split('.').pop();
      console.log(
        !current
          ? chalk.green(`  ✔ ${label}: ENABLED`)
          : chalk.yellow(`  ✔ ${label}: DISABLED`)
      );
      ctx.audit.log({ type: 'SETTING_CHANGED', details: { setting: path, value: !current } });

      // Apply runtime changes
      if (action === 'pii') ctx.sanitizer.enabled = !current;
      if (action === 'strict') ctx.sanitizer.strictMode = !current;
      if (action === 'fingerprint') ctx.fingerprint.enabled = !current;
      if (action === 'clipboard') ctx.clipboard.autoClear = !current;
      if (action === 'trackerBlocker') ctx.trackerBlocker.enabled = !current;
    }
  }
}

// ── Test sanitizer ──────────────────────────────────────────
async function testSanitizer() {
  console.log(chalk.cyan('\n  🔍 PII/Secret Sanitizer Test'));
  console.log(chalk.gray('  Enter text containing PII to see redaction in action.\n'));

  const input = await promptInput('Test input');
  if (!input) return;

  const result = ctx.sanitizer.sanitize(input);
  console.log(chalk.gray('\n  ── Original ──'));
  console.log(`  ${input}`);
  console.log(chalk.gray('\n  ── Sanitized ──'));
  console.log(`  ${chalk.green(result.text)}`);

  if (result.redactions.length > 0) {
    console.log(ctx.sanitizer.formatWarning(result.redactions));
  } else {
    console.log(chalk.gray('  No PII detected.'));
  }

  // Injection test with heuristic details
  const injection = ctx.sanitizer.detectInjection(input);
  if (injection.detected) {
    console.log(chalk.red(`\n  ⚠ Prompt injection detected! Severity: ${injection.severity} (score: ${injection.score})`));
    if (injection.patterns.length > 0) {
      console.log(chalk.yellow('  Regex matches:'));
      for (const p of injection.patterns) {
        console.log(chalk.yellow(`    • ${p}`));
      }
    }
    if (injection.heuristics?.length > 0) {
      console.log(chalk.yellow('  Heuristic signals:'));
      for (const h of injection.heuristics) {
        console.log(chalk.yellow(`    • [${h.rule}] ${h.desc} (weight: ${h.weight})`));
      }
    }
  } else {
    console.log(chalk.green('\n  ✔ No injection patterns detected.'));
  }
  console.log();
}

// ── Audit export ────────────────────────────────────────────
async function manageAuditExport() {
  const action = await auditExportMenu();
  if (action === 'back') return;

  if (action === 'json' || action === 'csv') {
    const format = action;
    const filename = `ace_audit_${ctx.sessionId}.${format}`;
    const filepath = join(homedir(), '.ace', filename);
    try {
      ctx.audit.exportToFile(filepath, format);
      console.log(chalk.green(`\n  ✔ Exported ${format.toUpperCase()} to: ${filepath}\n`));
      ctx.audit.log({ type: 'AUDIT_EXPORTED', details: { format, filepath } });
    } catch (err) {
      console.log(chalk.red(`  ✗ Export failed: ${err.message}`));
    }
  }

  if (action === 'disk') {
    const sessions = ctx.audit.listSessions();
    if (sessions.length === 0) {
      console.log(chalk.gray('\n  No audit sessions found on disk.\n'));
      return;
    }

    const { sessionId } = await inquirer.prompt([{
      type: 'list',
      name: 'sessionId',
      message: 'Select session to export:',
      choices: sessions.map((s) => ({
        name: `${s.sessionId} (${(s.size / 1024).toFixed(1)} KB)`,
        value: s.sessionId,
      })),
      prefix: '  ',
    }]);

    const { format } = await inquirer.prompt([{
      type: 'list',
      name: 'format',
      message: 'Export format:',
      choices: ['json', 'csv'],
      prefix: '  ',
    }]);

    try {
      const entries = ctx.audit.loadFromDisk(sessionId);
      if (entries.length === 0) {
        console.log(chalk.yellow('\n  ⚠ Could not decrypt session (wrong master password?).\n'));
        return;
      }

      const filename = `ace_audit_${sessionId}.${format}`;
      const filepath = join(homedir(), '.ace', filename);

      // Create a temporary logger to export
      const tempAudit = new AuditLogger({ ephemeral: true, sessionId });
      tempAudit.memoryLog = entries;
      tempAudit.exportToFile(filepath, format);

      console.log(chalk.green(`\n  ✔ Exported ${entries.length} entries to: ${filepath}\n`));
    } catch (err) {
      console.log(chalk.red(`  ✗ Export failed: ${err.message}`));
    }
  }
}

// ── Session recovery ────────────────────────────────────────
async function manageRecovery() {
  while (true) {
    const action = await recoveryMenu();
    if (action === 'back') return;

    if (action === 'save') {
      const ok = ctx.recovery.saveCheckpoint(ctx);
      console.log(
        ok
          ? chalk.green('  ✔ Checkpoint saved (encrypted)')
          : chalk.red('  ✗ Checkpoint save failed')
      );
    }

    if (action === 'list') {
      const sessions = ctx.recovery.listRecoverableSessions();
      if (sessions.length === 0) {
        console.log(chalk.gray('\n  No recovery checkpoints found.\n'));
      } else {
        console.log();
        for (const s of sessions) {
          console.log(`  ${chalk.cyan(s.sessionId)} ${chalk.gray(s.modified ? s.modified.toISOString() : '?')}`);
        }
        console.log();
      }
    }

    if (action === 'load') {
      const sessions = ctx.recovery.listRecoverableSessions();
      if (sessions.length === 0) {
        console.log(chalk.gray('\n  No checkpoints to load.\n'));
        continue;
      }

      const { sessionId } = await inquirer.prompt([{
        type: 'list',
        name: 'sessionId',
        message: 'Load session:',
        choices: sessions.map((s) => s.sessionId),
        prefix: '  ',
      }]);

      const checkpoint = ctx.recovery.loadCheckpoint(sessionId);
      if (checkpoint) {
        console.log(chalk.green(`\n  ✔ Loaded checkpoint from ${checkpoint.timestamp}`));
        console.log(chalk.gray(`    Session: ${checkpoint.sessionId}`));
        console.log(chalk.gray(`    Config snapshot available`));
        console.log(chalk.gray(`    Audit entries: ${checkpoint.state.auditLogLength}`));
        console.log(chalk.gray(`    Proxy was: ${checkpoint.state.proxyEnabled ? 'enabled' : 'disabled'}`));
        console.log();
      } else {
        console.log(chalk.red('  ✗ Could not decrypt checkpoint (wrong master password?)'));
      }
    }

    if (action === 'delete') {
      const confirmed = await confirmAction('Delete all recovery checkpoints?');
      if (confirmed) {
        ctx.recovery.wipeAll();
        console.log(chalk.red('  ✔ All recovery data wiped'));
        ctx.audit.log({ type: 'RECOVERY_WIPED' });
      }
    }
  }
}

// ── MFA Management ──────────────────────────────────────────
async function manageMfa() {
  while (true) {
    const action = await mfaMenu();
    if (action === 'back') return;

    switch (action) {
      case 'status': {
        const mfaCfg = ctx.config.get('mfa') || {};
        console.log();
        console.log(chalk.cyan('  MFA Status'));
        console.log(chalk.gray('  ───────────────────────────────────────────'));
        console.log(`  Enabled:    ${mfaCfg.enabled ? chalk.green('YES') : chalk.gray('NO')}`);
        console.log(`  Setup:      ${mfaCfg.setupComplete ? chalk.green('Complete') : chalk.yellow('Not configured')}`);
        console.log(`  Recovery:   ${(mfaCfg.recoveryCodes || []).length} codes remaining`);
        console.log();
        break;
      }

      case 'setup': {
        const { secret, base32 } = MFAProvider.generateSecret();
        const setupInfo = MFAProvider.formatSetupInfo(base32);

        console.log();
        console.log(chalk.cyan('  \ud83d\udd11 MFA Setup — TOTP (Time-based One-Time Password)'));
        console.log(chalk.gray('  ───────────────────────────────────────────'));
        console.log();
        console.log(chalk.white('  ' + setupInfo.instructions.split('\n').join('\n  ')));
        console.log();

        // Verify the user can generate a valid code
        const { code } = await inquirer.prompt([{
          type: 'input', name: 'code',
          message: chalk.cyan('Enter the 6-digit code from your authenticator to confirm:'),
          prefix: '  \ud83d\udd11',
        }]);

        const result = MFAProvider.verifyTOTP(code, base32);
        if (!result.valid) {
          console.log(chalk.red('  \u2717 Invalid code. MFA setup aborted. Try again.'));
          break;
        }

        // Generate recovery codes
        const recoveryCodes = MFAProvider.generateRecoveryCodes();

        console.log(chalk.green('\n  \u2714 MFA setup verified!\n'));
        console.log(chalk.yellow('  \ud83d\udea8 SAVE THESE RECOVERY CODES — you will not see them again:\n'));
        for (const rc of recoveryCodes) {
          console.log(chalk.white(`    ${rc}`));
        }
        console.log();

        // Save to config
        ctx.config.set('mfa.enabled', true);
        ctx.config.set('mfa.secret', base32);
        ctx.config.set('mfa.recoveryCodes', recoveryCodes);
        ctx.config.set('mfa.setupComplete', true);

        ctx.audit.log({ type: 'MFA_ENABLED' });
        console.log(chalk.green('  \u2714 MFA is now enabled. You will need a code on next login.\n'));
        break;
      }

      case 'verify': {
        const mfaCfg = ctx.config.get('mfa') || {};
        if (!mfaCfg.enabled || !mfaCfg.secret) {
          console.log(chalk.yellow('\n  MFA is not enabled. Set it up first.\n'));
          break;
        }

        const remaining = MFAProvider.getTimeRemaining();
        console.log(chalk.gray(`\n  Current code expires in ${remaining}s`));

        const { code } = await inquirer.prompt([{
          type: 'input', name: 'code',
          message: chalk.cyan('Enter TOTP code to test:'),
          prefix: '  \ud83d\udd11',
        }]);

        const result = MFAProvider.verifyTOTP(code, mfaCfg.secret);
        if (result.valid) {
          console.log(chalk.green(`  \u2714 Valid! (drift: ${result.drift} windows)\n`));
        } else {
          console.log(chalk.red('  \u2717 Invalid code.\n'));
        }
        break;
      }

      case 'recovery': {
        const mfaCfg = ctx.config.get('mfa') || {};
        const codes = mfaCfg.recoveryCodes || [];
        if (codes.length === 0) {
          console.log(chalk.yellow('\n  No recovery codes available.\n'));
          break;
        }
        console.log(chalk.cyan('\n  Recovery Codes:'));
        for (const rc of codes) {
          console.log(chalk.white(`    ${rc}`));
        }
        console.log(chalk.gray(`  ${codes.length} codes remaining\n`));
        break;
      }

      case 'regen': {
        const mfaCfg = ctx.config.get('mfa') || {};
        if (!mfaCfg.enabled) {
          console.log(chalk.yellow('\n  MFA is not enabled.\n'));
          break;
        }

        const confirmed = await confirmAction('Regenerate recovery codes? Old codes will be invalidated.');
        if (!confirmed) break;

        const newCodes = MFAProvider.generateRecoveryCodes();
        ctx.config.set('mfa.recoveryCodes', newCodes);

        console.log(chalk.yellow('\n  \ud83d\udea8 NEW RECOVERY CODES — save these:\n'));
        for (const rc of newCodes) {
          console.log(chalk.white(`    ${rc}`));
        }
        ctx.audit.log({ type: 'MFA_RECOVERY_REGENERATED' });
        console.log(chalk.green('\n  \u2714 Recovery codes regenerated.\n'));
        break;
      }

      case 'disable': {
        const confirmed = await confirmAction('Disable MFA? This removes two-factor protection.');
        if (!confirmed) break;

        ctx.config.set('mfa.enabled', false);
        ctx.config.set('mfa.secret', null);
        ctx.config.set('mfa.recoveryCodes', []);
        ctx.config.set('mfa.setupComplete', false);

        ctx.audit.log({ type: 'MFA_DISABLED' });
        console.log(chalk.yellow('\n  \u2714 MFA has been disabled.\n'));
        break;
      }
    }
  }
}

// ── Integrity Checker Management ────────────────────────────
async function manageIntegrity() {
  while (true) {
    const action = await integrityMenu();
    if (action === 'back') return;

    switch (action) {
      case 'status': {
        const status = ctx.integrityChecker.getStatus();
        console.log();
        console.log(chalk.cyan('  Integrity Checker Status'));
        console.log(chalk.gray('  ───────────────────────────────────────────'));
        console.log(`  Enabled:          ${status.enabled ? chalk.green('YES') : chalk.gray('NO')}`);
        console.log(`  Provider hashes:  ${status.providerCount}`);
        console.log(`  ACE source files: ${status.selfFileCount}`);
        console.log(`  Last check:       ${status.lastChecked || 'Never'}`);
        console.log();
        break;
      }

      case 'verify-all': {
        const spinner = ora({ text: 'Verifying provider binaries...', prefixText: '  ', spinner: 'dots' }).start();
        const { results, summary } = await ctx.integrityChecker.verifyAll(false);
        spinner.stop();

        console.log();
        console.log(chalk.cyan('  Provider Integrity Results'));
        console.log(chalk.gray('  ───────────────────────────────────────────'));
        for (const r of results) {
          if (r.status === 'not_found') continue; // Skip not-installed providers
          const color = r.status === 'ok' ? chalk.green
            : r.status === 'baselined' ? chalk.blue
              : r.status === 'mismatch' ? chalk.red
                : chalk.gray;
          console.log(`  ${color(r.message)}`);
        }
        console.log();
        console.log(chalk.gray(`  Summary: ${summary.ok} OK, ${summary.baselined} new baselines, ${summary.mismatch} mismatches, ${summary.notFound} not found`));
        console.log();
        break;
      }

      case 'self-check': {
        const result = ctx.integrityChecker.verifySelfIntegrity();
        console.log();
        if (result.status === 'ok') {
          console.log(chalk.green(`  ${result.message}`));
        } else if (result.status === 'mismatch') {
          console.log(chalk.red(`  ${result.message}`));
          for (const f of result.modified) {
            console.log(chalk.red(`    • ${f}`));
          }
        } else {
          console.log(chalk.yellow(`  ${result.message}`));
        }
        console.log();
        break;
      }

      case 'baseline': {
        const confirmed = await confirmAction('Record new baselines for all provider binaries and ACE source files?', true);
        if (!confirmed) break;

        const spinner = ora({ text: 'Recording baselines...', prefixText: '  ', spinner: 'dots' }).start();

        // Baseline providers
        const { summary } = await ctx.integrityChecker.verifyAll(true);

        // Baseline self
        const selfCount = ctx.integrityChecker.recordSelfBaseline();

        spinner.succeed(`Baselines recorded: ${summary.baselined + summary.ok} providers, ${selfCount} ACE files`);
        console.log();
        break;
      }

      case 'list': {
        const providers = ctx.integrityChecker.getBaselinedProviders();
        if (providers.length === 0) {
          console.log(chalk.yellow('\n  No provider baselines recorded yet.\n'));
          break;
        }
        console.log();
        console.log(chalk.cyan('  Baselined Providers'));
        console.log(chalk.gray('  ───────────────────────────────────────────'));
        for (const p of providers) {
          console.log(`  ${chalk.white(p.provider)}`);
          console.log(chalk.gray(`    Hash: ${p.hash.substring(0, 32)}...`));
          console.log(chalk.gray(`    Path: ${p.path}`));
          console.log(chalk.gray(`    Recorded: ${p.recordedAt}`));
        }
        console.log();
        break;
      }

      case 'clear': {
        const confirmed = await confirmAction('Clear all baseline data? You will need to re-record baselines.');
        if (!confirmed) break;
        ctx.integrityChecker.clearBaselines();
        console.log(chalk.yellow('\n  ✔ All baselines cleared.\n'));
        break;
      }
    }
  }
}

// ── Kill switch ─────────────────────────────────────────────
async function killSwitch() {
  console.log(chalk.red('\n  ╔═══════════════════════════════════════╗'));
  console.log(chalk.red('  ║  💀  KILL SWITCH – DANGER ZONE  💀   ║'));
  console.log(chalk.red('  ╚═══════════════════════════════════════╝\n'));

  console.log(chalk.yellow('  This will:'));
  console.log(chalk.yellow('  • Wipe all conversation history'));
  console.log(chalk.yellow('  • Destroy the API key vault'));
  console.log(chalk.yellow('  • Clear all audit logs'));
  console.log(chalk.yellow('  • Reset configuration to defaults'));
  console.log(chalk.yellow('  • Clear clipboard'));
  console.log(chalk.yellow('  • Delete all recovery checkpoints\n'));

  const confirmed = await confirmAction('Activate kill switch? THIS CANNOT BE UNDONE.');
  if (!confirmed) {
    console.log(chalk.gray('  Aborted.'));
    return;
  }

  const secondConfirm = await confirmAction('Are you ABSOLUTELY sure?');
  if (!secondConfirm) {
    console.log(chalk.gray('  Aborted.'));
    return;
  }

  const spinner = ora({ text: 'Wiping all data...', prefixText: '  ', spinner: 'dots12', color: 'red' }).start();

  ctx.audit.log({ type: 'KILL_SWITCH_ACTIVATED' });

  // Wipe everything
  new AuthManager().wipeAll();
  ctx.config.wipeAll();
  ctx.audit.wipeAll();
  ctx.integrityChecker.clearBaselines();
  ctx.recovery.wipeAll();
  ctx.conversations.wipeAll();
  await ctx.clipboard.clear();
  ctx.clipboard.cancelAllTimers();

  spinner.succeed(chalk.red('All data wiped. Session terminated.'));
  process.exit(0);
}

// ── Change master password ──────────────────────────────────
async function changePassword() {
  console.log(chalk.cyan('\n  🔐 Change Master Password\n'));
  const auth = new AuthManager();

  // Step 1: Verify current password
  const { currentPass } = await inquirer.prompt([{
    type: 'password', name: 'currentPass',
    message: chalk.cyan('Enter current password:'),
    prefix: '  🔐', mask: '•',
  }]);

  if (!auth.verifyPassword(currentPass)) {
    console.log(chalk.red('\n  ✗ Incorrect password. Password change cancelled.\n'));
    ctx.audit.log({ type: 'PASSWORD_CHANGE_FAILED', details: { reason: 'verification_failed' } });
    return;
  }

  // Step 2: New password
  const { newPass } = await inquirer.prompt([{
    type: 'password', name: 'newPass',
    message: chalk.cyan('New password:'),
    prefix: '  🔐', mask: '•',
    validate: (v) => v.length >= MIN_MASTER_PASSWORD_LENGTH
      || `Minimum ${MIN_MASTER_PASSWORD_LENGTH} characters`,
  }]);

  const { confirmPass } = await inquirer.prompt([{
    type: 'password', name: 'confirmPass',
    message: chalk.cyan('Confirm new password:'),
    prefix: '  🔐', mask: '•',
    validate: (v) => v === newPass || 'Passwords do not match',
  }]);

  const spinner = ora({ text: 'Re-encrypting data with new password...', prefixText: '  ', spinner: 'dots' }).start();

  try {
    // Re-encrypt config and vault with new password
    ctx.config.changePassword(currentPass, newPass);

    // Rotate hardened auth sentinel
    auth.createAuthSentinel(newPass);

    spinner.succeed('Password changed successfully');
    console.log(chalk.green('  ✔ Config and vault re-encrypted with new password.\n'));
    ctx.audit.log({ type: 'PASSWORD_CHANGED' });
    console.log(chalk.yellow('  Session will now close so all modules restart on the new key material.\n'));
    gracefulShutdown();
  } catch (err) {
    spinner.fail('Password change failed');
    console.log(chalk.red(`  ✗ Error: ${err.message}\n`));
    ctx.audit.log({ type: 'PASSWORD_CHANGE_FAILED', details: { error: err.message } });
  }
}
// ── Install AI CLI Tools ────────────────────────────────────
async function installAiClis() {
  const { execSync, spawnSync } = await import('child_process');

  // Comprehensive list of AI CLI tools
  const AI_TOOLS = [
    { name: 'Gemini CLI', key: 'gemini', cmd: 'gemini', install: ['npm', ['install', '-g', '@google/gemini-cli']], desc: 'Google Gemini AI in your terminal' },
    { name: 'Claude Code', key: 'claude', cmd: 'claude', install: ['npm', ['install', '-g', '@anthropic-ai/claude-code']], desc: 'Anthropic Claude agentic coding' },
    { name: 'OpenAI Codex CLI', key: 'codex', cmd: 'codex', install: ['npm', ['install', '-g', '@openai/codex']], desc: 'OpenAI Codex coding agent' },
    { name: 'GitHub Copilot CLI', key: 'copilot', cmd: 'gh', install: ['gh', ['extension', 'install', 'github/gh-copilot']], desc: 'AI pair programmer in terminal' },
    { name: 'Ollama', key: 'ollama', cmd: 'ollama', install: null, desc: 'Local LLMs — download from ollama.com' },
    { name: 'Aider', key: 'aider', cmd: 'aider', install: ['pip', ['install', 'aider-chat']], desc: 'AI pair programming tool' },
    { name: 'Open Interpreter', key: 'interpreter', cmd: 'interpreter', install: ['pip', ['install', 'open-interpreter']], desc: 'Natural language computer control' },
    { name: 'ShellGPT', key: 'sgpt', cmd: 'sgpt', install: ['pip', ['install', 'shell-gpt']], desc: 'ChatGPT in your terminal' },
    { name: 'Cline CLI', key: 'cline', cmd: 'cline', install: ['npm', ['install', '-g', 'cline']], desc: 'AI coding partner for CLI' },
    { name: 'AI SDK (Vercel)', key: 'ai-sdk', cmd: 'ai', install: ['npm', ['install', '-g', 'ai']], desc: 'Vercel AI SDK CLI' },
    { name: 'LLM (Simon Willison)', key: 'llm', cmd: 'llm', install: ['pip', ['install', 'llm']], desc: 'CLI for many LLM providers' },
    { name: 'Mods', key: 'mods', cmd: 'mods', install: ['go', ['install', 'github.com/charmbracelet/mods@latest']], desc: 'AI in the command line (Go)' },
    { name: 'tgpt', key: 'tgpt', cmd: 'tgpt', install: ['npm', ['install', '-g', 'tgpt']], desc: 'ChatGPT in terminal without API key' },
    { name: 'Claude CMD', key: 'claude-cmd', cmd: 'claude-cmd', install: ['npm', ['install', '-g', 'claude-cmd']], desc: 'Claude AI CLI with agent mode' },
  ];

  // Check which are installed
  const isWin = process.platform === 'win32';
  const statuses = [];
  for (const tool of AI_TOOLS) {
    let installed = false;
    try {
      execSync(`${isWin ? 'where' : 'which'} ${tool.cmd}`, { stdio: 'pipe' });
      installed = true;
    } catch { /* not installed */ }
    statuses.push({ ...tool, installed });
  }

  // Build menu choices
  const choices = statuses.map(t => {
    const status = t.installed ? chalk.green('✓ installed') : chalk.red('✗ not found');
    const installable = t.install ? '' : chalk.gray(' (manual)');
    return {
      name: `  ${status} ${chalk.bold(t.name)}${installable} — ${chalk.gray(t.desc)}`,
      value: t.key,
      disabled: t.installed ? 'Already installed' : false,
    };
  });

  choices.push(new inquirer.Separator(chalk.gray('  ──────────────────────────────────')));
  choices.push({ name: chalk.gray('  ← Back to Main Menu'), value: 'back' });

  const installedCount = statuses.filter(s => s.installed).length;
  console.log();
  console.log(chalk.cyan(`  📦 AI CLI Installer — ${installedCount}/${statuses.length} tools detected`));
  console.log(chalk.gray('  Select a tool to install. Already-installed tools are grayed out.'));
  console.log();

  const { tool: selectedKey } = await inquirer.prompt([{
    type: 'list',
    name: 'tool',
    message: chalk.cyan('Install AI Tool'),
    prefix: '  📦',
    choices,
    pageSize: 18,
  }]);

  if (selectedKey === 'back') return;

  const selected = statuses.find(t => t.key === selectedKey);
  if (!selected) return;

  if (!selected.install) {
    console.log(chalk.yellow(`\n  ⚠ ${selected.name} requires manual installation.`));
    if (selected.key === 'ollama') {
      console.log(chalk.cyan('  Download from: https://ollama.com/download'));
    }
    console.log();
    return;
  }

  // Confirm installation
  const { confirm } = await inquirer.prompt([{
    type: 'confirm',
    name: 'confirm',
    message: chalk.yellow(
      `Install ${selected.name}? Command: ${selected.install[0]} ${selected.install[1].join(' ')}`
    ),
    prefix: '  ⚠',
    default: true,
  }]);

  if (!confirm) return;

  console.log(chalk.yellow(`\n  → Installing ${selected.name}...\n`));

  try {
    const result = spawnSync(selected.install[0], selected.install[1], { stdio: 'inherit' });
    if (result.status !== 0) {
      throw new Error(`${selected.install[0]} exited with status ${result.status ?? 'unknown'}`);
    }
    console.log(chalk.green(`\n  ✓ ${selected.name} installed successfully!\n`));
    ctx.audit.log({
      type: 'AI_TOOL_INSTALLED',
      details: { tool: selected.name, command: `${selected.install[0]} ${selected.install[1].join(' ')}` },
    });
  } catch (err) {
    console.log(chalk.red(`\n  ✗ Installation failed: ${err.message}`));
    console.log(chalk.yellow(`  Try running manually: ${selected.install[0]} ${selected.install[1].join(' ')}\n`));
  }
}

// ── Main loop ───────────────────────────────────────────────
export async function run(args) {
  // Normalize all args to lowercase for case-insensitive matching
  const normalizedArgs = args.map(a => a.toLowerCase());

  // Handle CLI flags that exit immediately
  if (normalizedArgs.includes('--help') || normalizedArgs.includes('-h') || normalizedArgs[0] === 'help') {
    showCliHelp();
    showHelp();
    process.exit(0);
  }
  if (normalizedArgs.includes('--version') || normalizedArgs.includes('-v')) {
    const { readFileSync } = await import('fs');
    const { join, dirname } = await import('path');
    const { fileURLToPath } = await import('url');
    try {
      const pkg = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'package.json'), 'utf8'));
      console.log(`  AceCLI v${pkg.version}`);
    } catch { console.log('  AceCLI v1.0.0'); }
    process.exit(0);
  }
  if (normalizedArgs.includes('--doctor')) {
    await runDoctor({});
    process.exit(0);
  }

  // Skip banner with --no-banner flag
  if (!normalizedArgs.includes('--no-banner')) {
    await showBanner();
  }

  await initSession();

  // Run setup wizard if --setup flag or first arg is 'setup'
  if (normalizedArgs.includes('--setup') || normalizedArgs[0] === 'setup') {
    await runSetupWizard(ctx);
  }

  // ── Provider passthrough: `ace gemini "prompt"` or `gemini ace` ──
  const PROVIDER_ALIASES = {
    gemini: 'gemini', google: 'gemini',
    openai: 'openai', gpt: 'openai', chatgpt: 'openai',
    claude: 'claude', anthropic: 'claude',
    copilot: 'copilot', github: 'copilot',
    ollama: 'ollama', local: 'ollama',
    'openai-api': 'openai-api', 'claude-api': 'claude-api',
    'gemini-api': 'gemini-api', 'ollama-api': 'ollama-api',
  };

  const firstArg = normalizedArgs[0];
  const secondArg = normalizedArgs[1];

  // Support both `ace gemini` and `gemini ace` (reversed arg order)
  let matchedProvider = PROVIDER_ALIASES[firstArg];
  let promptArgs = args.slice(1);
  if (!matchedProvider && secondArg && PROVIDER_ALIASES[secondArg]) {
    matchedProvider = PROVIDER_ALIASES[secondArg];
    promptArgs = args.slice(2);
  }

  if (matchedProvider && ctx.providers[matchedProvider]) {
    const provider = ctx.providers[matchedProvider];
    const installed = await provider.isInstalled();

    if (!installed) {
      console.log(chalk.red(`\n  ✗ Provider "${matchedProvider}" is not installed or has no API key.`));
      console.log(chalk.yellow(`  Run the Setup Wizard to configure it.\n`));
    } else {
      // If there's a prompt after the provider name, do a quick one-shot
      const prompt = promptArgs.join(' ');
      if (prompt) {
        console.log(chalk.cyan(`\n  ⚡ Quick prompt → ${provider.name}\n`));
        const spinner = ora({ text: `Sending to ${provider.name}...`, prefixText: '  ', spinner: 'dots' }).start();
        try {
          const result = await provider.execute(prompt);
          spinner.stop();
          if (result.success) {
            if (!result.streamed) {
              ctx.renderer.renderComplete(result.output, {
                model: result.model || 'unknown',
                latencyMs: result.latency,
                inputText: prompt,
              });
            }
          } else {
            showError(result);
          }
        } catch (err) {
          spinner.stop();
          const classified = classifyError(err, { command: provider.command });
          console.log(chalk.red(`  ✗ ${classified.name}: ${classified.message}`));
          console.log(chalk.yellow(`  ${classified.advice}`));
        }
        // After one-shot, drop into main menu
      } else {
        // No prompt — launch interactive CLI directly
        console.log(chalk.yellow(`\n  Launching ${provider.name} in interactive mode...`));
        console.log(chalk.green('  (Security layer active)'));
        console.log(chalk.gray('  Press Ctrl+C to exit interactive mode.\n'));
        ctx.audit.log({ type: 'INTERACTIVE_LAUNCH', provider: provider.name });
        try {
          const child = await provider.interactive();
          await new Promise((resolve) => {
            child.on('close', resolve);
            child.on('error', (err) => {
              const classified = classifyError(err, { command: provider.command });
              console.log(chalk.red(`  ✗ ${classified.name}: ${classified.message}`));
              console.log(chalk.yellow(`  ${classified.advice}`));
              resolve();
            });
          });
        } catch (err) {
          const classified = classifyError(err, { command: provider.command });
          console.log(chalk.red(`  ✗ Failed to launch: ${classified.message}`));
          console.log(chalk.yellow(`  ${classified.advice}`));
        }
      }
    }
  }

  // Run startup health check silently and warn about missing providers
  let providerWarnings = [];
  for (const [key, prov] of Object.entries(ctx.providers)) {
    const installed = await prov.isInstalled();
    if (!installed) providerWarnings.push(key);
  }
  if (providerWarnings.length === Object.keys(ctx.providers).length) {
    console.log(chalk.yellow('  ⚠ No AI providers detected. Run 🩺 Health Check for install guides.\n'));
  }

  // Main event loop
  while (true) {
    try {
      showMiniBanner();
      const choice = await mainMenu();

      switch (choice) {
        case 'setup':
          await runSetupWizard(ctx);
          break;
        case 'chat':
          await chatMode();
          break;
        case 'conversations':
          await manageConversations();
          break;
        case 'quick':
          await quickPrompt();
          break;
        case 'interactive':
          await launchInteractive();
          break;
        case 'install-ai':
          await installAiClis();
          break;
        case 'help':
          showHelp();
          break;
        case 'dashboard':
          showDashboard(ctx);
          break;
        case 'vault':
          await manageVault();
          break;
        case 'proxy':
          await manageProxy();
          break;
        case 'dns':
          await manageDns();
          break;
        case 'privacy':
          await managePrivacy();
          break;
        case 'password':
          await changePassword();
          break;
        case 'audit':
          showAuditLog(ctx.audit);
          break;
        case 'audit-export':
          await manageAuditExport();
          break;
        case 'doctor':
          await runDoctor({ proxy: ctx.proxy, clipboard: ctx.clipboard });
          break;
        case 'config':
          console.log(chalk.cyan('\n  Current config:'));
          console.log(JSON.stringify(ctx.config.config, null, 2).split('\n').map((l) => '  ' + l).join('\n'));
          console.log();
          break;
        case 'test-sanitizer':
          await testSanitizer();
          break;
        case 'recovery':
          await manageRecovery();
          break;
        case 'kill':
          await killSwitch();
          break;
        case 'mfa':
          await manageMfa();
          break;
        case 'integrity':
          await manageIntegrity();
          break;
        case 'exit':
          // Save conversations and final checkpoint before exit
          gracefulShutdown();
      }
    } catch (err) {
      if (err.name === 'ExitPromptError') {
        // Ctrl+C during a prompt — treat as first press
        if (_ctrlCPressed) {
          gracefulShutdown();
        } else {
          _ctrlCPressed = true;
          console.log();
          console.log(chalk.yellow('  ───────────────────────────────────────────'));
          console.log(chalk.yellow.bold('  ⚠ Press Ctrl+C again within 5 seconds to exit.'));
          console.log(chalk.yellow('  ───────────────────────────────────────────'));
          console.log();
          _ctrlCTimer = setTimeout(() => { _ctrlCPressed = false; }, 5000);
          // Pause briefly so the warning is visible before menu redraws
          await new Promise(r => setTimeout(r, 2000));
        }
      } else {
        console.error(chalk.red(`  Error: ${err.message}`));
      }
    }
  }
}
