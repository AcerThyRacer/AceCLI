// ============================================================
//  AceCLI – PII & Secret Sanitization Engine
// ============================================================
import chalk from 'chalk';

const PII_PATTERNS = [
  { name: 'Email', regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, replacement: '[REDACTED_EMAIL]' },
  { name: 'IPv4', regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, replacement: '[REDACTED_IP]' },
  { name: 'IPv6', regex: /\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g, replacement: '[REDACTED_IPV6]' },
  { name: 'SSN', regex: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: '[REDACTED_SSN]' },
  { name: 'Phone (US)', regex: /\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, replacement: '[REDACTED_PHONE]' },
  { name: 'Credit Card', regex: /\b(?:\d[ -]*?){13,19}\b/g, replacement: '[REDACTED_CC]' },
  { name: 'AWS Key', regex: /AKIA[0-9A-Z]{16}/g, replacement: '[REDACTED_AWS_KEY]' },
  { name: 'Generic Secret', regex: /(?:secret|password|token|api[_-]?key|apikey|auth)[\s]*[=:]\s*['"]?[^\s'"]{8,}/gi, replacement: '[REDACTED_SECRET]' },
  { name: 'Bearer Token', regex: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/g, replacement: 'Bearer [REDACTED_TOKEN]' },
  { name: 'Private Key', regex: /-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----[\s\S]*?-----END\s+(RSA\s+)?PRIVATE KEY-----/g, replacement: '[REDACTED_PRIVATE_KEY]' },
  { name: 'JWT', regex: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*/g, replacement: '[REDACTED_JWT]' },
  { name: 'GitHub Token', regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g, replacement: '[REDACTED_GH_TOKEN]' },
  { name: 'Slack Token', regex: /xox[bpors]-[0-9]+-[0-9]+-[a-zA-Z0-9]+/g, replacement: '[REDACTED_SLACK_TOKEN]' },
  { name: 'UUID', regex: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, replacement: '[REDACTED_UUID]' },
  { name: 'MAC Address', regex: /\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b/g, replacement: '[REDACTED_MAC]' },
  { name: 'Windows Path', regex: /[A-Z]:\\(?:Users|Documents|home)\\[^\s\\]+/gi, replacement: '[REDACTED_PATH]' },
  { name: 'Unix Path', regex: /\/(?:home|Users)\/[a-zA-Z0-9._-]+/g, replacement: '[REDACTED_PATH]' },
];

// Prompt injection patterns – regex layer
const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /disregard\s+(all\s+)?(above|previous)/i,
  /you\s+are\s+now\s+(a|an)\s+/i,
  /system\s*:\s*/i,
  /\[INST\]/i,
  /<\|im_start\|>/i,
  /pretend\s+you\s+are/i,
  /act\s+as\s+if\s+you\s+have\s+no\s+restrictions/i,
  /do\s+anything\s+now/i,
  /jailbreak/i,
  /bypass\s+(your\s+)?restrictions/i,
  /override\s+(your\s+)?(safety|rules|guidelines)/i,
  /reveal\s+(your\s+)?(system\s+)?prompt/i,
  /what\s+are\s+your\s+(instructions|rules|guidelines)/i,
  /respond\s+without\s+(any\s+)?filter/i,
  /in\s+developer\s+mode/i,
  /enable\s+debug\s+mode/i,
  /sudo\s+mode/i,
  /<\|system\|>/i,
  /\[system\]/i,
  /###\s*(instruction|system)/i,
  /translate\s+the\s+above/i,
  /repeat\s+(everything|all)\s+(above|before)/i,
];

// Advanced heuristic injection detection engine
class InjectionHeuristics {
  static analyze(text) {
    const signals = [];
    let score = 0;

    // 1. Role reassignment: attempts to redefine the AI's identity
    if (/(?:you\s+(?:are|will\s+be|should\s+act\s+as|must\s+be)\s+(?:a|an|my|the))\s+\w+/i.test(text)) {
      signals.push({ rule: 'role_reassignment', weight: 3, desc: 'Attempts to redefine AI identity' });
      score += 3;
    }

    // 2. Instruction boundary: special tokens / markdown abuse
    if (/<\|[^|]+\|>/.test(text) || /\[(?:INST|SYS|SYSTEM|HUMAN|ASSISTANT)\]/i.test(text)) {
      signals.push({ rule: 'boundary_markers', weight: 4, desc: 'Contains instruction boundary markers' });
      score += 4;
    }

    // 3. Context overflow: very long padding followed by instructions
    if (text.length > 5000 && /(?:now|then|finally|after\s+that)\s+(?:ignore|forget|disregard)/i.test(text.slice(-500))) {
      signals.push({ rule: 'context_overflow', weight: 5, desc: 'Possible context overflow attack' });
      score += 5;
    }

    // 4. Encoding evasion: base64 encoded instructions
    const b64Segments = text.match(/[A-Za-z0-9+/]{40,}={0,2}/g);
    if (b64Segments) {
      for (const seg of b64Segments) {
        try {
          const decoded = Buffer.from(seg, 'base64').toString('utf8');
          if (/ignore|instruction|system|jailbreak/i.test(decoded)) {
            signals.push({ rule: 'base64_evasion', weight: 5, desc: 'Base64-encoded injection attempt' });
            score += 5;
            break;
          }
        } catch { /* not valid base64 */ }
      }
    }

    // 5. Unicode homoglyph evasion (Cyrillic lookalikes etc.)
    const homoglyphs = /[\u0400-\u04FF\u0500-\u052F]/.test(text) && /[a-zA-Z]/.test(text);
    if (homoglyphs && text.length < 200) {
      signals.push({ rule: 'homoglyph_mixing', weight: 2, desc: 'Mixed Unicode scripts detected' });
      score += 2;
    }

    // 6. Multi-language switching: attempts to confuse via language
    const langSwitch = /(?:en español|in french|auf deutsch|на русском)\s*:/i.test(text);
    if (langSwitch && /(?:ignore|forget|new\s+rules)/i.test(text)) {
      signals.push({ rule: 'language_switch', weight: 3, desc: 'Language-switch injection attempt' });
      score += 3;
    }

    // 7. Fictional framing: "in a fictional world where you can..."
    if (/(?:fictional|hypothetical|imagine|pretend|roleplay|story)\s+(?:where|scenario|world|universe)/i.test(text)) {
      if (/(?:no\s+rules|no\s+restrictions|anything|harmful|illegal|bypass)/i.test(text)) {
        signals.push({ rule: 'fictional_framing', weight: 3, desc: 'Fictional framing to bypass safety' });
        score += 3;
      }
    }

    // 8. Repeated delimiter abuse
    const delimiterAbuse = (text.match(/[-=]{10,}/g) || []).length;
    if (delimiterAbuse >= 2) {
      signals.push({ rule: 'delimiter_abuse', weight: 2, desc: 'Repeated delimiter patterns' });
      score += 2;
    }

    return { score, signals };
  }
}

export class Sanitizer {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.strictMode = options.strictMode || false;
    this.customPatterns = options.customPatterns || [];
    this.redactionLog = [];
  }

  // Patterns that match filesystem paths (can break CLI tool output)
  static PATH_PATTERN_NAMES = new Set(['Windows Path', 'Unix Path']);

  sanitize(text, options = {}) {
    if (!this.enabled || !text) return { text, redactions: [] };

    let result = text;
    const redactions = [];

    let allPatterns = [...PII_PATTERNS, ...this.customPatterns];

    // skipPaths: exclude path patterns (used by SanitizingTransform to
    // avoid breaking functional paths in CLI subprocess I/O)
    if (options.skipPaths) {
      allPatterns = allPatterns.filter(p => !Sanitizer.PATH_PATTERN_NAMES.has(p.name));
    }

    for (const pattern of allPatterns) {
      const matches = result.match(pattern.regex);
      if (matches) {
        for (const match of matches) {
          redactions.push({
            type: pattern.name,
            original: this.strictMode ? '[STRICT_MODE]' : match.substring(0, 4) + '***',
            position: result.indexOf(match),
          });
        }
        result = result.replace(pattern.regex, pattern.replacement);
      }
    }

    if (redactions.length > 0) {
      this.redactionLog.push({
        timestamp: new Date().toISOString(),
        count: redactions.length,
        types: [...new Set(redactions.map((r) => r.type))],
      });
    }

    return { text: result, redactions };
  }

  detectInjection(text) {
    if (!text) return { detected: false, patterns: [], heuristics: [], score: 0 };

    // Layer 1: Regex pattern matching
    const detected = [];
    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.test(text)) {
        detected.push(pattern.source);
      }
    }

    // Layer 2: Heuristic analysis engine
    const heuristics = InjectionHeuristics.analyze(text);

    // Combined scoring: regex matches + heuristic score
    const totalScore = detected.length * 2 + heuristics.score;

    let severity;
    if (totalScore >= 8) severity = 'CRITICAL';
    else if (totalScore >= 5) severity = 'HIGH';
    else if (totalScore > 0) severity = 'MEDIUM';
    else severity = 'NONE';

    return {
      detected: totalScore > 0,
      patterns: detected,
      heuristics: heuristics.signals,
      score: totalScore,
      severity,
    };
  }

  getRedactionStats() {
    return {
      totalSessions: this.redactionLog.length,
      totalRedactions: this.redactionLog.reduce((s, l) => s + l.count, 0),
      typeBreakdown: this.redactionLog.reduce((acc, l) => {
        for (const t of l.types) acc[t] = (acc[t] || 0) + 1;
        return acc;
      }, {}),
    };
  }

  formatWarning(redactions) {
    if (redactions.length === 0) return '';
    const lines = [
      chalk.yellow('  ⚠  PII/Secrets detected and redacted:'),
      ...redactions.map(
        (r) => chalk.yellow(`     • ${r.type}: ${r.original}`)
      ),
    ];
    return lines.join('\n');
  }
}
