// ============================================================
//  AceCLI – Tor / SOCKS Proxy Routing
//  - TLS certificate verification enforcement
//  - Audit logging on connection tests
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
    this.tlsVerify = options.tlsVerify !== false; // Default: true
    this.agent = null;
    this.audit = options.audit || null;
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
      const { default: https } = await import('https');
      return new Promise((resolve) => {
        const req = https.get('https://check.torproject.org/api/ip', {
          agent,
          timeout: 10000,
          // Enforce TLS certificate verification to detect MITM proxies
          rejectUnauthorized: this.tlsVerify,
        }, (res) => {
          let data = '';

          // Capture TLS certificate info for verification
          const tlsInfo = {};
          const socket = res.socket;
          if (socket && socket.getPeerCertificate) {
            try {
              const cert = socket.getPeerCertificate();
              tlsInfo.subject = cert.subject?.CN || 'unknown';
              tlsInfo.issuer = cert.issuer?.CN || 'unknown';
              tlsInfo.fingerprint = cert.fingerprint256 || cert.fingerprint || 'unknown';
              tlsInfo.validTo = cert.valid_to || 'unknown';
              tlsInfo.authorized = socket.authorized || false;
            } catch { /* cert info is best-effort */ }
          }

          res.on('data', (chunk) => (data += chunk));
          res.on('end', () => {
            try {
              const json = JSON.parse(data);
              const result = {
                ok: true,
                isTor: json.IsTor,
                ip: json.IP,
                tls: tlsInfo,
              };

              this.audit?.log({
                type: 'PROXY_TEST_SUCCESS',
                details: {
                  isTor: json.IsTor,
                  ip: json.IP,
                  tlsSubject: tlsInfo.subject,
                  tlsIssuer: tlsInfo.issuer,
                  tlsAuthorized: tlsInfo.authorized,
                },
              });

              resolve(result);
            } catch {
              resolve({ ok: true, raw: data, tls: tlsInfo });
            }
          });
        });

        req.on('error', (err) => {
          const isTlsError = err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE'
            || err.code === 'CERT_HAS_EXPIRED'
            || err.code === 'DEPTH_ZERO_SELF_SIGNED_CERT'
            || err.code === 'SELF_SIGNED_CERT_IN_CHAIN'
            || err.message?.includes('certificate');

          this.audit?.log({
            type: isTlsError ? 'PROXY_TLS_ERROR' : 'PROXY_TEST_FAILED',
            details: { error: err.message, code: err.code },
          });

          resolve({
            ok: false,
            error: err.message,
            isTlsError,
            advice: isTlsError
              ? 'TLS certificate verification failed — possible MITM proxy detected'
              : undefined,
          });
        });

        req.on('timeout', () => {
          req.destroy();
          this.audit?.log({
            type: 'PROXY_TEST_TIMEOUT',
            details: { endpoint: this.getProxyUrl() },
          });
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
      tlsVerify: this.tlsVerify,
    };
  }

  formatStatus() {
    if (!this.enabled) {
      return chalk.yellow('  🌐 Proxy: DISABLED – direct connection');
    }
    const tlsTag = this.tlsVerify ? chalk.green(' [TLS✓]') : chalk.red(' [TLS✗]');
    return chalk.green(`  🌐 Proxy: ${this.proxyType.toUpperCase()} via ${this.host}:${this.port}`) + tlsTag;
  }
}
