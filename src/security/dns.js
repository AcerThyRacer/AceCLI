// ============================================================
//  AceCLI – DNS over HTTPS (DoH) & DNS over TLS (DoT) Resolver
//  - Multi-provider failover chain
//  - LRU DNS cache with configurable TTL
//  - Provider benchmarking
// ============================================================
import https from 'https';
import tls from 'tls';
import dnsPacket from 'dns-packet';
import chalk from 'chalk';

// Provider registry with failover order
const DOH_PROVIDERS = {
  'applied-privacy': 'https://doh.applied-privacy.net/query',
  'cloudflare': 'https://cloudflare-dns.com/dns-query',
  'google': 'https://dns.google/dns-query',
  'quad9': 'https://dns.quad9.net:5053/dns-query',
};

const DOT_PROVIDERS = {
  'cloudflare': { host: '1.1.1.1', port: 853 },
  'google': { host: '8.8.8.8', port: 853 },
  'quad9': { host: '9.9.9.9', port: 853 },
};

const DEFAULT_DOH_PROVIDER = DOH_PROVIDERS['applied-privacy'];

export class DnsResolver {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.provider = options.provider || DEFAULT_DOH_PROVIDER;
    this.method = options.method || 'doh'; // 'doh' or 'dot'
    this.proxyAgent = options.proxyAgent || null;
    this.audit = options.audit || null;

    // Failover chain
    this.failoverProviders = options.failoverProviders || [
      DOH_PROVIDERS['applied-privacy'],
      DOH_PROVIDERS['cloudflare'],
      DOH_PROVIDERS['google'],
    ];

    // DNS cache: LRU with TTL
    this._cache = new Map();
    this._cacheTTL = options.cacheTTL || 300; // 300 seconds default
    this._cacheMax = options.cacheMax || 500;

    // Stats
    this._queryCount = 0;
    this._cacheHits = 0;
    this._failovers = 0;
  }

  setProxyAgent(agent) {
    this.proxyAgent = agent;
  }

  // ── Cache Management ────────────────────────────────────────

  _cacheKey(hostname, type) {
    return `${hostname}:${type}`;
  }

  _getCached(hostname, type) {
    const key = this._cacheKey(hostname, type);
    const entry = this._cache.get(key);
    if (!entry) return null;

    // Check TTL
    if (Date.now() - entry.timestamp > this._cacheTTL * 1000) {
      this._cache.delete(key);
      return null;
    }

    this._cacheHits++;
    return entry.result;
  }

  _setCache(hostname, type, result) {
    const key = this._cacheKey(hostname, type);

    // LRU eviction
    if (this._cache.size >= this._cacheMax) {
      const firstKey = this._cache.keys().next().value;
      this._cache.delete(firstKey);
    }

    this._cache.set(key, {
      result,
      timestamp: Date.now(),
    });
  }

  getCache() {
    const entries = [];
    for (const [key, entry] of this._cache) {
      const age = Math.round((Date.now() - entry.timestamp) / 1000);
      entries.push({ key, age, ttlRemaining: Math.max(0, this._cacheTTL - age) });
    }
    return entries;
  }

  clearCache() {
    this._cache.clear();
  }

  // ── Main Resolve ────────────────────────────────────────────

  async resolve(hostname, type = 'A') {
    if (!this.enabled) {
      return { error: 'Secure DNS disabled' };
    }

    this._queryCount++;

    // Check cache first
    const cached = this._getCached(hostname, type);
    if (cached) {
      return { ...cached, cached: true };
    }

    this.audit?.log({
      type: 'DNS_QUERY',
      details: { hostname, type, provider: this.provider, method: this.method },
    });

    try {
      let result;

      if (this.method === 'dot') {
        result = await this._resolveDoT(hostname, type);
      } else {
        // Try primary provider, then failover chain
        result = await this._resolveWithFailover(hostname, type);
      }

      // Cache successful results
      if (result.success) {
        this._setCache(hostname, type, result);
      }

      return result;
    } catch (err) {
      return { error: err.message };
    }
  }

  // ── DoH with Failover ───────────────────────────────────────

  async _resolveWithFailover(hostname, type) {
    // Try primary provider first
    try {
      return await this._resolveDoH(hostname, type, this.provider);
    } catch { /* continue to failover */ }

    // Try failover providers
    for (const provider of this.failoverProviders) {
      if (provider === this.provider) continue;
      try {
        this._failovers++;
        this.audit?.log({
          type: 'DNS_FAILOVER',
          details: { hostname, failoverTo: provider },
        });
        return await this._resolveDoH(hostname, type, provider);
      } catch { /* try next */ }
    }

    return { error: 'All DNS providers failed' };
  }

  async _resolveDoH(hostname, type, providerUrl = this.provider) {
    const buf = dnsPacket.encode({
      type: 'query',
      id: Math.floor(Math.random() * 65534),
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{
        type: type,
        name: hostname
      }]
    });

    return new Promise((resolve, reject) => {
      const url = new URL(providerUrl);
      const options = {
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname + url.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/dns-message',
          'Content-Length': buf.length,
          'Accept': 'application/dns-message',
        },
        agent: this.proxyAgent, // Route DoH through proxy if set
        timeout: 5000,
      };

      const req = https.request(options, (res) => {
        const chunks = [];
        res.on('data', (d) => chunks.push(d));
        res.on('end', () => {
          if (res.statusCode !== 200) {
            reject(new Error(`DoH Error: ${res.statusCode}`));
            return;
          }
          try {
            const buffer = Buffer.concat(chunks);
            const decoded = dnsPacket.decode(buffer);
            const answers = decoded.answers.map(a => a.data);
            resolve({
              success: true,
              answers,
              raw: decoded,
              provider: providerUrl,
            });
          } catch (e) {
            reject(new Error('Failed to decode DNS response'));
          }
        });
      });

      req.on('error', (e) => reject(e));
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('DNS request timed out'));
      });
      req.write(buf);
      req.end();
    });
  }

  // ── DNS over TLS (DoT) ──────────────────────────────────────

  async _resolveDoT(hostname, type) {
    const dotProvider = DOT_PROVIDERS['cloudflare']; // Default DoT provider

    const buf = dnsPacket.encode({
      type: 'query',
      id: Math.floor(Math.random() * 65534),
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{
        type: type,
        name: hostname
      }]
    });

    // DNS over TLS uses a 2-byte length prefix
    const lengthPrefix = Buffer.alloc(2);
    lengthPrefix.writeUInt16BE(buf.length, 0);
    const payload = Buffer.concat([lengthPrefix, buf]);

    return new Promise((resolve, reject) => {
      const socket = tls.connect({
        host: dotProvider.host,
        port: dotProvider.port,
        servername: dotProvider.host,
        timeout: 5000,
      });

      socket.on('secureConnect', () => {
        socket.write(payload);
      });

      const chunks = [];
      socket.on('data', (data) => {
        chunks.push(data);
        const buffer = Buffer.concat(chunks);

        // Check if we have the full response (2-byte length prefix + data)
        if (buffer.length >= 2) {
          const responseLength = buffer.readUInt16BE(0);
          if (buffer.length >= 2 + responseLength) {
            try {
              const dnsData = buffer.slice(2, 2 + responseLength);
              const decoded = dnsPacket.decode(dnsData);
              const answers = decoded.answers.map(a => a.data);
              socket.destroy();
              resolve({
                success: true,
                answers,
                raw: decoded,
                method: 'dot',
                provider: `${dotProvider.host}:${dotProvider.port}`,
              });
            } catch (e) {
              socket.destroy();
              reject(new Error('Failed to decode DoT response'));
            }
          }
        }
      });

      socket.on('error', (e) => reject(e));
      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error('DoT connection timed out'));
      });
    });
  }

  // ── Benchmarking ────────────────────────────────────────────

  /**
   * Benchmark all DNS providers and return latency results.
   * @param {string} hostname - Hostname to test (default: example.com)
   * @returns {Promise<Array<{provider: string, latencyMs: number, success: boolean}>>}
   */
  async benchmark(hostname = 'example.com') {
    const results = [];

    // Benchmark DoH providers
    for (const [name, url] of Object.entries(DOH_PROVIDERS)) {
      const start = Date.now();
      try {
        const result = await this._resolveDoH(hostname, 'A', url);
        results.push({
          provider: `[DoH] ${name}`,
          url,
          latencyMs: Date.now() - start,
          success: result.success,
          answers: result.answers?.length || 0,
        });
      } catch (err) {
        results.push({
          provider: `[DoH] ${name}`,
          url,
          latencyMs: Date.now() - start,
          success: false,
          error: err.message,
        });
      }
    }

    // Benchmark DoT providers
    for (const [name, config] of Object.entries(DOT_PROVIDERS)) {
      const start = Date.now();
      try {
        const buf = dnsPacket.encode({
          type: 'query',
          id: Math.floor(Math.random() * 65534),
          flags: dnsPacket.RECURSION_DESIRED,
          questions: [{ type: 'A', name: hostname }]
        });
        const lengthPrefix = Buffer.alloc(2);
        lengthPrefix.writeUInt16BE(buf.length, 0);
        const payload = Buffer.concat([lengthPrefix, buf]);

        const result = await new Promise((resolve, reject) => {
          const socket = tls.connect({
            host: config.host,
            port: config.port,
            servername: config.host,
            timeout: 5000,
          });
          socket.on('secureConnect', () => socket.write(payload));
          socket.on('data', () => {
            socket.destroy();
            resolve({ success: true });
          });
          socket.on('error', (e) => reject(e));
          socket.on('timeout', () => {
            socket.destroy();
            reject(new Error('timeout'));
          });
        });

        results.push({
          provider: `[DoT] ${name}`,
          host: `${config.host}:${config.port}`,
          latencyMs: Date.now() - start,
          success: result.success,
        });
      } catch (err) {
        results.push({
          provider: `[DoT] ${name}`,
          host: `${config.host}:${config.port}`,
          latencyMs: Date.now() - start,
          success: false,
          error: err.message,
        });
      }
    }

    // Sort by latency
    results.sort((a, b) => a.latencyMs - b.latencyMs);

    this.audit?.log({
      type: 'DNS_BENCHMARK',
      details: { hostname, results: results.map(r => ({ provider: r.provider, latencyMs: r.latencyMs, success: r.success })) },
    });

    return results;
  }

  // ── Status ──────────────────────────────────────────────────

  getStatus() {
    return {
      enabled: this.enabled,
      provider: this.provider,
      method: this.method,
      proxyActive: !!this.proxyAgent,
      cache: {
        size: this._cache.size,
        maxSize: this._cacheMax,
        ttl: this._cacheTTL,
        hits: this._cacheHits,
      },
      stats: {
        queries: this._queryCount,
        cacheHits: this._cacheHits,
        failovers: this._failovers,
      },
    };
  }

  formatStatus() {
    if (!this.enabled) return chalk.yellow('  🛡️  Secure DNS: DISABLED (System DNS)');
    const method = this.method === 'doh' ? 'HTTPS' : 'TLS';
    const cacheInfo = `cache: ${this._cache.size}/${this._cacheMax}`;
    return chalk.green(`  🛡️  Secure DNS: Do${method} via ${new URL(this.provider).hostname} (${cacheInfo})`);
  }

  /**
   * Format benchmark results for terminal display.
   * @param {Array} results - Benchmark results
   * @returns {string}
   */
  static formatBenchmark(results) {
    const lines = [
      chalk.cyan.bold('  🌐 DNS Provider Benchmark'),
      chalk.gray('  ─────────────────────────────────────────'),
    ];

    for (const r of results) {
      const status = r.success ? chalk.green('✓') : chalk.red('✗');
      const latency = r.success
        ? chalk.white(`${r.latencyMs}ms`)
        : chalk.red(`${r.latencyMs}ms (${r.error || 'failed'})`);
      lines.push(`  ${status} ${r.provider.padEnd(24)} ${latency}`);
    }

    if (results.length > 0 && results[0].success) {
      lines.push('');
      lines.push(chalk.green(`  🏆 Fastest: ${results[0].provider} (${results[0].latencyMs}ms)`));
    }

    return lines.join('\n');
  }
}

export { DOH_PROVIDERS, DOT_PROVIDERS };
