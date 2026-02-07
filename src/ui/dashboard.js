// ============================================================
//  AceCLI – Security Status Dashboard
// ============================================================
import chalk from 'chalk';
import boxen from 'boxen';
import gradient from 'gradient-string';
import Table from 'cli-table3';

const g = gradient(['#00ff88', '#00ccff', '#8844ff']);

export function showDashboard(ctx) {
  const { config, sanitizer, fingerprint, proxy, dns, audit, clipboard, recovery, trackerBlocker } = ctx;
  const cfg = config.config;

  console.log();
  console.log(g('  ╔══════════════════════════════════════════════════╗'));
  console.log(g('  ║         🛡️  SECURITY STATUS DASHBOARD  🛡️         ║'));
  console.log(g('  ╚══════════════════════════════════════════════════╝'));
  console.log();

  // Security features table
  const table = new Table({
    chars: {
      'top': '─', 'top-mid': '┬', 'top-left': '┌', 'top-right': '┐',
      'bottom': '─', 'bottom-mid': '┴', 'bottom-left': '└', 'bottom-right': '┘',
      'left': '│', 'left-mid': '├', 'mid': '─', 'mid-mid': '┼',
      'right': '│', 'right-mid': '┤', 'middle': '│'
    },
    colWidths: [32, 14, 30],
    head: [
      chalk.cyan('Security Feature'),
      chalk.cyan('Status'),
      chalk.cyan('Details'),
    ],
  });

  const on = chalk.green.bold('● ON');
  const off = chalk.red.bold('○ OFF');

  table.push(
    ['🔍 PII Auto-Redaction', cfg.security.piiRedaction ? on : off,
      `${sanitizer.getRedactionStats().totalRedactions} items redacted`],
    ['🔒 Strict Mode', cfg.security.strictMode ? on : off,
      cfg.security.strictMode ? 'Originals hidden' : 'Partial preview'],
    ['🛡️  AES-256-GCM Encryption', on, 'Config & logs encrypted'],
    ['👤 Fingerprint Masking', cfg.security.fingerprintMasking ? on : off,
      fingerprint.enabled ? `As: ${fingerprint.fakeHostname}` : 'Real identity'],
    ['📋 Metadata Stripping', cfg.security.metadataStripping ? on : off,
      'Env vars sanitized'],
    ['🌐 Proxy Routing', cfg.proxy.enabled ? on : off,
      proxy.formatStatus().replace(/\s+/g, ' ').trim()],
    ['🛡️  Secure DNS (DoH)', dns.enabled ? on : off,
      dns.enabled ? new URL(dns.provider).hostname : 'System DNS'],
    ['🧹 Clipboard Auto-Clear', cfg.security.clipboardAutoClear ? on : off,
      clipboard ? `${cfg.security.clipboardClearDelay}s delay (clipboardy)` : `${cfg.security.clipboardClearDelay}s delay`],
    ['⚠️  Injection Detection', cfg.security.promptInjectionDetection ? on : off,
      'Regex + heuristic engine'],
    ['🚫 Tracker Blocking', cfg.security.trackerBlocking ? on : off,
      `${trackerBlocker.getStats().totalTrackerDomains.toLocaleString()}+ domains blocked`],
    ['🔌 Interactive Sanitizer', on, 'Stream proxy on stdin/stdout'],
    ['📝 Audit Trail', cfg.audit.enabled ? on : off,
      cfg.audit.ephemeral ? 'Ephemeral (memory only)' : 'Encrypted on disk'],
    ['📤 Audit Export', on, 'JSON / CSV export available'],
    ['🔄 Session Recovery', recovery?.enabled ? on : off,
      recovery?.enabled ? 'Encrypted checkpoints' : 'Disabled'],
    ['🩺 Health Check', on, 'Provider & system diagnostics'],
    ['💀 Kill Switch', on, 'Ready (wipe all data)'],
  );

  console.log(table.toString());
  console.log();

  // Audit stats
  const auditStats = audit.getStats();
  console.log(
    boxen(
      [
        chalk.cyan('📊 Session Audit Stats'),
        '',
        `  Total events:      ${chalk.white(auditStats.totalEntries)}`,
        `  Integrity valid:   ${auditStats.integrityValid ? chalk.green('✓ YES') : chalk.red('✗ TAMPERED')}`,
        `  Storage mode:      ${auditStats.ephemeral ? chalk.yellow('EPHEMERAL') : chalk.green('PERSISTENT')}`,
        '',
        ...Object.entries(auditStats.eventTypes).map(
          ([k, v]) => `  ${chalk.gray(k)}: ${v}`
        ),
      ].join('\n'),
      {
        padding: 1,
        margin: { left: 2 },
        borderStyle: 'round',
        borderColor: 'cyan',
      }
    )
  );

  // Fingerprint comparison
  if (fingerprint.enabled) {
    const report = fingerprint.getReport();
    console.log();
    console.log(chalk.gray('  ── Fingerprint Masking ──'));
    console.log(`  ${chalk.red('Real hostname:')}  ${report.real.hostname}  →  ${chalk.green('Masked:')} ${report.masked.hostname}`);
    console.log(`  ${chalk.red('Real username:')}  ${report.real.username}  →  ${chalk.green('Masked:')} ${report.masked.username}`);
    console.log(`  ${chalk.red('Real platform:')}  ${report.real.platform}  →  ${chalk.green('Masked:')} ${report.masked.platform}`);
  }

  console.log();
}

export function showAuditLog(audit) {
  const log = audit.getLog();

  if (log.length === 0) {
    console.log(chalk.gray('  No audit entries yet.'));
    return;
  }

  console.log();
  console.log(g('  📋 Audit Trail'));
  console.log(chalk.gray('  ─────────────────────────────────────────────────'));

  const table = new Table({
    head: [
      chalk.cyan('Time'),
      chalk.cyan('Event'),
      chalk.cyan('Provider'),
      chalk.cyan('Details'),
    ],
    colWidths: [24, 22, 12, 30],
  });

  for (const entry of log.slice(-20)) {
    table.push([
      chalk.gray(entry.timestamp.replace('T', ' ').substring(0, 19)),
      entry.event,
      entry.provider,
      JSON.stringify(entry.details).substring(0, 28),
    ]);
  }

  console.log(table.toString());

  // Integrity check
  const integrity = audit.verifyIntegrity();
  console.log(
    integrity.valid
      ? chalk.green('  ✔ Audit chain integrity: VALID')
      : chalk.red(`  ✗ Audit chain integrity: TAMPERED (${integrity.errors.length} errors)`)
  );
  console.log();
}
