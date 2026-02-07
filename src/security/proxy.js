// ============================================================
//  AceCLI – Tor / SOCKS Proxy Routing
// ============================================================
import { SocksProxyAgent } from 'socks-proxy-agent';
import chalk from 'chalk';

const DEFAULT_TOR_HOST = '127.0.0.1';
const DEFAULT_TOR_PORT = 9050;

export class ProxyRouter {
  constructor(options = {}) {
    this.enabled = options.enabled || false;
    this.proxyType = options.proxyType || 'socks5';
    this.host = options.host || DEFAULT_TOR_HOST;
    this.port = options.port || DEFAULT_TOR_PORT;
    this.agent = null;
  }

  getProxyUrl() {
    return `${this.proxyType}://${this.host}:${this.port}`;
  }

  createAgent() {
    if (!this.enabled) return null;
    this.agent = new SocksProxyAgent(this.getProxyUrl());
    return this.agent;
  }

  getAgent() {
    if (!this.enabled) return null;
    if (!this.agent) this.createAgent();
    return this.agent;
  }

  // Environment variables for subprocess proxy routing
  getProxyEnv() {
    if (!this.enabled) return {};
    const url = this.getProxyUrl();
    return {
      HTTP_PROXY: url,
      HTTPS_PROXY: url,
      http_proxy: url,
      https_proxy: url,
      ALL_PROXY: url,
      NO_PROXY: 'localhost,127.0.0.1',
    };
  }

  async testConnection() {
    if (!this.enabled) return { ok: false, error: 'Proxy not enabled' };

    try {
      const agent = this.createAgent();
      // Simple connectivity test
      const { default: https } = await import('https');
      return new Promise((resolve) => {
        const req = https.get('https://check.torproject.org/api/ip', { agent, timeout: 10000 }, (res) => {
          let data = '';
          res.on('data', (chunk) => (data += chunk));
          res.on('end', () => {
            try {
              const json = JSON.parse(data);
              resolve({
                ok: true,
                isTor: json.IsTor,
                ip: json.IP,
              });
            } catch {
              resolve({ ok: true, raw: data });
            }
          });
        });
        req.on('error', (err) => resolve({ ok: false, error: err.message }));
        req.on('timeout', () => {
          req.destroy();
          resolve({ ok: false, error: 'Connection timed out' });
        });
      });
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  getStatus() {
    return {
      enabled: this.enabled,
      proxyType: this.proxyType,
      endpoint: this.enabled ? this.getProxyUrl() : 'none',
    };
  }

  formatStatus() {
    if (!this.enabled) {
      return chalk.yellow('  🌐 Proxy: DISABLED – direct connection');
    }
    return chalk.green(`  🌐 Proxy: ${this.proxyType.toUpperCase()} via ${this.host}:${this.port}`);
  }
}
