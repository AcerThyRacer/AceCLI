// ============================================================
//  AceCLI – Response Renderer
//  Terminal markdown rendering, syntax highlighting, cost display
//  No external dependencies — uses chalk for all formatting
// ============================================================
import chalk from 'chalk';
import { createHash } from 'crypto';
import { estimateCost, estimateTokens, formatCost } from './cost-table.js';

// Basic keyword sets for syntax highlighting
const JS_KEYWORDS = new Set([
    'const', 'let', 'var', 'function', 'return', 'if', 'else', 'for', 'while',
    'class', 'extends', 'import', 'export', 'from', 'async', 'await', 'new',
    'try', 'catch', 'throw', 'switch', 'case', 'break', 'continue', 'default',
    'typeof', 'instanceof', 'in', 'of', 'true', 'false', 'null', 'undefined',
    'this', 'super', 'yield', 'delete', 'void', 'debugger',
]);

const PYTHON_KEYWORDS = new Set([
    'def', 'class', 'return', 'if', 'elif', 'else', 'for', 'while', 'import',
    'from', 'as', 'try', 'except', 'finally', 'raise', 'with', 'yield',
    'lambda', 'pass', 'break', 'continue', 'and', 'or', 'not', 'in', 'is',
    'True', 'False', 'None', 'async', 'await', 'self', 'global', 'nonlocal',
]);

const COMMON_KEYWORDS = new Set([
    ...JS_KEYWORDS, ...PYTHON_KEYWORDS,
    'int', 'float', 'string', 'bool', 'void', 'char', 'double', 'long',
    'struct', 'enum', 'interface', 'public', 'private', 'protected', 'static',
    'final', 'abstract', 'override', 'virtual', 'const', 'readonly',
]);

export class ResponseRenderer {
    constructor(options = {}) {
        this.cache = new Map();    // SHA-256(prompt) → response
        this.maxCache = options.maxCache || 50;
        this.showCost = options.showCost !== false;
        this.showTokens = options.showTokens !== false;
    }

    // ── Markdown Rendering ──────────────────────────────────────

    /**
     * Render full markdown text for terminal display.
     * @param {string} text - Markdown text
     * @returns {string} - Chalk-formatted terminal output
     */
    renderMarkdown(text) {
        if (!text) return '';

        const lines = text.split('\n');
        const rendered = [];
        let inCodeBlock = false;
        let codeBlockLang = '';
        let codeBlockLines = [];

        for (const line of lines) {
            // Code block toggle
            if (line.trimStart().startsWith('```')) {
                if (inCodeBlock) {
                    // End of code block — render accumulated code
                    rendered.push(this._renderCodeBlock(codeBlockLines, codeBlockLang));
                    inCodeBlock = false;
                    codeBlockLines = [];
                    codeBlockLang = '';
                    continue;
                }
                // Start of code block
                inCodeBlock = true;
                codeBlockLang = line.trimStart().replace(/^```/, '').trim();
                continue;
            }

            if (inCodeBlock) {
                codeBlockLines.push(line);
                continue;
            }

            // Headers
            if (line.startsWith('### ')) {
                rendered.push(chalk.cyan.bold('   ' + line.slice(4)));
                continue;
            }
            if (line.startsWith('## ')) {
                rendered.push(chalk.magenta.bold('  ' + line.slice(3)));
                continue;
            }
            if (line.startsWith('# ')) {
                rendered.push(chalk.white.bold.underline(' ' + line.slice(2)));
                continue;
            }

            // Horizontal rule
            if (/^[-*_]{3,}$/.test(line.trim())) {
                rendered.push(chalk.gray('  ─────────────────────────────────────────'));
                continue;
            }

            // Blockquote
            if (line.startsWith('> ')) {
                rendered.push(chalk.gray('  │ ') + chalk.italic(line.slice(2)));
                continue;
            }

            // Unordered list
            if (/^\s*[-*+]\s/.test(line)) {
                const indent = line.match(/^(\s*)/)[1];
                const content = line.replace(/^\s*[-*+]\s/, '');
                rendered.push(`  ${indent}${chalk.cyan('•')} ${this._renderInline(content)}`);
                continue;
            }

            // Ordered list
            if (/^\s*\d+\.\s/.test(line)) {
                const match = line.match(/^(\s*)(\d+)\.\s(.*)/);
                if (match) {
                    rendered.push(`  ${match[1]}${chalk.cyan(match[2] + '.')} ${this._renderInline(match[3])}`);
                    continue;
                }
            }

            // Normal paragraph text
            rendered.push('  ' + this._renderInline(line));
        }

        // Handle unclosed code block
        if (inCodeBlock && codeBlockLines.length > 0) {
            rendered.push(this._renderCodeBlock(codeBlockLines, codeBlockLang));
        }

        return rendered.join('\n');
    }

    /**
     * Render inline markdown formatting (bold, italic, code, links).
     */
    _renderInline(text) {
        return text
            // Bold
            .replace(/\*\*(.+?)\*\*/g, (_, content) => chalk.bold(content))
            .replace(/__(.+?)__/g, (_, content) => chalk.bold(content))
            // Italic
            .replace(/\*(.+?)\*/g, (_, content) => chalk.italic(content))
            .replace(/_(.+?)_/g, (_, content) => chalk.italic(content))
            // Inline code
            .replace(/`([^`]+)`/g, (_, content) => chalk.bgGray.white(` ${content} `))
            // Strikethrough
            .replace(/~~(.+?)~~/g, (_, content) => chalk.strikethrough(content))
            // Links [text](url)
            .replace(/\[(.+?)\]\((.+?)\)/g, (_, text, url) => `${chalk.cyan(text)} ${chalk.gray(`(${url})`)}`);
    }

    /**
     * Render a fenced code block with basic syntax highlighting.
     */
    _renderCodeBlock(lines, lang) {
        const border = chalk.gray('  ┌─' + (lang ? ` ${lang} ` : '') + '─'.repeat(Math.max(0, 40 - (lang?.length || 0))) + '┐');
        const bottom = chalk.gray('  └' + '─'.repeat(44) + '┘');

        const highlighted = lines.map((line) => {
            const hl = this._highlightSyntax(line, lang);
            return chalk.gray('  │ ') + hl;
        });

        return [border, ...highlighted, bottom].join('\n');
    }

    /**
     * Basic keyword-based syntax highlighting.
     */
    _highlightSyntax(line, lang) {
        // Determine keyword set from language
        let keywords = COMMON_KEYWORDS;
        if (['javascript', 'js', 'jsx', 'ts', 'tsx', 'typescript'].includes(lang)) {
            keywords = JS_KEYWORDS;
        } else if (['python', 'py'].includes(lang)) {
            keywords = PYTHON_KEYWORDS;
        }

        // Comments
        if (line.trimStart().startsWith('//') || line.trimStart().startsWith('#')) {
            return chalk.gray(line);
        }

        // Simple tokenization and highlighting
        return line.replace(/\b(\w+)\b/g, (match) => {
            if (keywords.has(match)) return chalk.magenta(match);
            if (/^\d+(\.\d+)?$/.test(match)) return chalk.yellow(match);
            return match;
        })
            // String literals
            .replace(/(["'`])(?:(?!\1|\\).|\\.)*?\1/g, (match) => chalk.green(match));
    }

    // ── Streaming Support ───────────────────────────────────────

    /**
     * Render a single streaming token (write directly to stdout).
     * @param {string} token
     */
    renderStream(token) {
        process.stdout.write(token);
    }

    // ── Response Metadata Display ───────────────────────────────

    /**
     * Display response metadata (tokens, latency, cost).
     * @param {Object} options
     */
    showResponseMeta(options = {}) {
        const { text, model, latencyMs, inputText } = options;
        const parts = [];

        // Token count
        if (this.showTokens && text) {
            const outputTokens = estimateTokens(text);
            parts.push(chalk.gray(`~${outputTokens} tokens`));
        }

        // Latency
        if (latencyMs !== undefined) {
            const sec = (latencyMs / 1000).toFixed(1);
            parts.push(chalk.gray(`${sec}s`));
        }

        // Cost estimation
        if (this.showCost && model && text) {
            const inputTokens = estimateTokens(inputText || '');
            const outputTokens = estimateTokens(text);
            const cost = estimateCost(model, inputTokens, outputTokens);
            if (cost.found) {
                parts.push(chalk.gray(`≈${formatCost(cost.cost)}`));
            }
        }

        // Model info
        if (model) {
            parts.push(chalk.gray(model));
        }

        if (parts.length > 0) {
            console.log(chalk.gray(`\n  ── ${parts.join(' · ')} ──`));
        }
    }

    // ── Response Caching ────────────────────────────────────────

    /**
     * Get cached response for a prompt.
     * @param {string} prompt
     * @returns {string|null}
     */
    getCached(prompt) {
        const key = createHash('sha256').update(prompt).digest('hex');
        return this.cache.get(key) || null;
    }

    /**
     * Cache a response for a prompt.
     * @param {string} prompt
     * @param {string} response
     */
    setCached(prompt, response) {
        if (this.cache.size >= this.maxCache) {
            // Evict oldest entry
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }
        const key = createHash('sha256').update(prompt).digest('hex');
        this.cache.set(key, response);
    }

    /**
     * Get cache stats.
     * @returns {{size: number, maxSize: number}}
     */
    getCacheStats() {
        return { size: this.cache.size, maxSize: this.maxCache };
    }

    /**
     * Clear the response cache.
     */
    clearCache() {
        this.cache.clear();
    }

    // ── Complete Render Pipeline ────────────────────────────────

    /**
     * Full rendering pipeline: render markdown + show metadata.
     * @param {string} text - Response text
     * @param {Object} meta - {model, latencyMs, inputText}
     */
    renderComplete(text, meta = {}) {
        console.log();
        console.log(this.renderMarkdown(text));
        this.showResponseMeta({ text, ...meta });
        console.log();
    }
}
