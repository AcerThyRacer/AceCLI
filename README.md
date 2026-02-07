# 🛡️ ACE CLI

**Security & Anonymity Layer for AI Command Lines**

ACE wraps major AI CLIs (OpenAI, Claude, Gemini, GitHub Copilot, Ollama) with a comprehensive security, privacy, and anonymity layer.

## Quick Start

```bash
# Install
npm install && npm link

# Launch
ace

# Launch without animation
ace --no-banner

# Run health check
npm run doctor

# Run tests
npm test
```

## Security Features

| Feature | Description |
|---|---|
| 🔍 **PII Auto-Redaction** | Detects & strips emails, IPs, SSNs, phone numbers, API keys, JWTs, private keys, paths, and more (17 pattern categories) |
| 🛡️ **AES-256-GCM Encryption** | All config, vault, and audit logs encrypted at rest with scrypt key derivation |
| 🌐 **Tor/SOCKS5 Proxy** | Route all AI API traffic through Tor or custom SOCKS proxies |
| 🚫 **Mass Tracker Blocking** | Blocks 500+ tracker domains, strips 150+ tracking parameters from URLs, sanitizes 50+ tracking headers, detects fingerprinting scripts |
| 👤 **Fingerprint Masking** | Spoofs hostname, username, platform, CPU info to AI providers |
| 📋 **Metadata Stripping** | Removes 30+ sensitive environment variables before subprocess calls |
| ⚠️ **Injection Detection** | Regex + heuristic engine with 8 detection strategies (role reassignment, context overflow, base64 evasion, homoglyph, fictional framing, delimiter abuse, etc.) |
| 🔑 **Encrypted API Vault** | Store API keys encrypted, never exposed in plaintext |
| 📝 **Tamper-Proof Audit** | Hash-chained audit log with integrity verification |
| 📤 **Audit Export** | Export decrypted audit logs as JSON or CSV for compliance |
| 🔌 **Interactive Sanitizer** | Stream proxy on stdin/stdout – sanitizes real-time interactive sessions |
| 🔄 **Session Recovery** | Encrypted checkpoints with auto-save for crash recovery |
| 🩺 **Health Check (Doctor)** | Verifies all external CLIs, system deps, and security subsystems |
| 💀 **Kill Switch** | Instant wipe of all data, keys, logs, clipboard, and recovery |
| 🧹 **Clipboard Auto-Clear** | Cross-platform (clipboardy) auto-clear after sensitive operations |
| 🕶️ **Ephemeral Mode** | Zero disk writes, memory-only operation |
| 🔒 **Strict Mode** | Hides even partial previews of redacted content |
| ❌ **Typed Error Handling** | Network, Auth, Runtime errors with specific recovery advice |

## Architecture

```
ace (bin entry)
├── src/
│   ├── index.js              Main entry, menus, session lifecycle
│   ├── config.js             Encrypted config & API key vault
│   ├── doctor.js             Health check / diagnostics system
│   ├── errors.js             Typed error classes with recovery advice
│   ├── security/
│   │   ├── sanitizer.js      PII redaction + heuristic injection engine
│   │   ├── encryption.js     AES-256-GCM with scrypt KDF
│   │   ├── fingerprint.js    System fingerprint spoofing
│   │   ├── proxy.js          Tor / SOCKS proxy routing
│   │   ├── audit.js          Hash-chain audit logger + export
│   │   ├── clipboard.js      Cross-platform clipboard (clipboardy)
│   │   └── recovery.js       Encrypted session checkpoints
│   ├── providers/
│   │   ├── base.js           Base provider + stream sanitizer
│   │   ├── registry.js       Dynamic provider registry (plugin-ready)
│   │   ├── openai.js         OpenAI CLI wrapper
│   │   ├── claude.js         Claude CLI wrapper
│   │   ├── gemini.js         Gemini CLI wrapper
│   │   ├── copilot.js        GitHub Copilot CLI wrapper
│   │   └── ollama.js         Ollama wrapper
│   └── ui/
│       ├── banner.js         ASCII art & animation
│       ├── menu.js           Interactive menus
│       └── dashboard.js      Security status dashboard
└── test/
    └── test-all.js           50 unit tests (sanitizer, encryption, config, audit, errors)
```

## Supported AI CLIs

- **OpenAI CLI** (`openai`)
- **Claude CLI** (`claude`)
- **Gemini CLI** (`gemini`)
- **GitHub Copilot CLI** (`gh copilot`)
- **Ollama** (`ollama`) – local/private

## Plugin System

Add custom providers via the `ProviderRegistry`:

```js
import { ProviderRegistry } from './src/providers/registry.js';
const registry = new ProviderRegistry();
await registry.loadPlugin('my-provider', './path/to/my-provider.js');
```

## Configuration

- Config: `~/.ace/config.enc` (AES-256-GCM encrypted)
- API Vault: `~/.ace/vault.enc` (AES-256-GCM encrypted)
- Audit Logs: `~/.ace/audit/` (hash-chained, optionally encrypted)
- Recovery: `~/.ace/recovery/` (encrypted checkpoints)

## License

GPLv3
