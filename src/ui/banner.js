// ============================================================
//  AceCLI – Instant ASCII Banner
// ============================================================
import figlet from 'figlet';
import gradient from 'gradient-string';
import chalk from 'chalk';

export async function showBanner() {
  console.clear();

  const aceGradient = gradient(['#00ff88', '#00ccff', '#8844ff']);

  // Compact single-line figlet
  const bannerText = figlet.textSync('ACE', {
    font: 'ANSI Shadow',
    horizontalLayout: 'fitted',
  });

  console.log(aceGradient(bannerText));
  console.log(
    gradient(['#ff6600', '#ff0066'])(
      '  ⚡ Secure AI Gateway ⚡'
    )
  );
  console.log();
  console.log(
    chalk.gray('  🛡️  Encryption  ') +
    chalk.gray('│  🔍 PII Redaction  ') +
    chalk.gray('│  👤 Fingerprint Mask')
  );
  console.log(
    chalk.gray('  🌐 Proxy/Tor   ') +
    chalk.gray('│  📋 Audit Trail   ') +
    chalk.gray('│  🚫 Tracker Blocker')
  );
  console.log();
}

export function showMiniBanner() {
  const aceGradient = gradient(['#00ff88', '#00ccff', '#8844ff']);
  console.log(aceGradient('  ◈ ACE CLI') + chalk.gray(' │ Secure AI Gateway'));
}
