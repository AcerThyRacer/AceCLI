// ============================================================
//  AceCLI – System Fingerprint Masking
// ============================================================
import { hostname, userInfo, platform, arch, release, cpus, networkInterfaces } from 'os';
import { randomBytes } from 'crypto';

const FAKE_HOSTNAMES = [
  'workstation-01', 'dev-node', 'builder-vm', 'ci-runner-42',
  'cloud-instance', 'sandbox-env', 'compute-7b3f', 'node-alpha',
];

const FAKE_USERNAMES = [
  'user', 'dev', 'builder', 'operator', 'anon', 'worker', 'agent', 'runner',
];

export class FingerprintMask {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.sessionSeed = randomBytes(16).toString('hex');
    this.fakeHostname = FAKE_HOSTNAMES[Math.floor(Math.random() * FAKE_HOSTNAMES.length)];
    this.fakeUsername = FAKE_USERNAMES[Math.floor(Math.random() * FAKE_USERNAMES.length)];
  }

  getRealFingerprint() {
    return {
      hostname: hostname(),
      username: userInfo().username,
      platform: platform(),
      arch: arch(),
      release: release(),
      cpuModel: cpus()[0]?.model || 'unknown',
      cpuCount: cpus().length,
      interfaces: Object.keys(networkInterfaces()),
    };
  }

  getMaskedFingerprint() {
    if (!this.enabled) return this.getRealFingerprint();

    return {
      hostname: this.fakeHostname,
      username: this.fakeUsername,
      platform: 'linux',
      arch: 'x64',
      release: '6.1.0-generic',
      cpuModel: 'Virtual CPU',
      cpuCount: 4,
      interfaces: ['eth0'],
    };
  }

  // Strip system info from environment variables before passing to subprocesses
  getSanitizedEnv() {
    const env = { ...process.env };

    // Only delete truly identifying vars — NOT functional paths that CLIs need
    const identifyingVars = [
      'COMPUTERNAME', 'USERDOMAIN', 'USERDOMAIN_ROAMINGPROFILE',
      'SESSIONNAME', 'CLIENTNAME',
      'PROCESSOR_IDENTIFIER', 'NUMBER_OF_PROCESSORS',
      'SSH_AUTH_SOCK', 'SSH_AGENT_PID', 'GPG_AGENT_INFO',
      'DISPLAY', 'WAYLAND_DISPLAY', 'XDG_SESSION_TYPE',
      'TERM_PROGRAM', 'TERM_PROGRAM_VERSION',
      'LANG', 'LC_ALL',
    ];

    for (const v of identifyingVars) {
      delete env[v];
    }

    // Mask identifying values but keep paths functional
    env.USERNAME = this.fakeUsername;
    env.USER = this.fakeUsername;
    env.LOGNAME = this.fakeUsername;
    env.HOSTNAME = this.fakeHostname;

    // CRITICAL: preserve HOME, USERPROFILE, APPDATA, LOCALAPPDATA, TEMP, TMP,
    // PATH, SystemRoot, etc. — CLI tools (Gemini, OpenAI, etc.) need real paths
    // to find their config files and function properly.

    return env;
  }

  // Generate a randomized User-Agent string
  getAnonymousUserAgent() {
    const agents = [
      'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15',
    ];
    return agents[Math.floor(Math.random() * agents.length)];
  }

  getReport() {
    const real = this.getRealFingerprint();
    const masked = this.getMaskedFingerprint();
    return { real, masked, masking: this.enabled };
  }
}
