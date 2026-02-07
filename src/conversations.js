// ============================================================
//  AceCLI – Conversation Manager (Encrypted Persistence)
//  Multi-turn conversation threads with encrypted storage
// ============================================================
import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, unlinkSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { randomBytes } from 'crypto';
import { Encryption } from './security/encryption.js';

const CONV_DIR = join(homedir(), '.ace', 'conversations');
const INDEX_FILE = join(CONV_DIR, 'index.enc');

export class ConversationManager {
    constructor(options = {}) {
        this.masterPassword = options.masterPassword;
        this.encryption = this.masterPassword ? new Encryption(this.masterPassword) : null;
        this.threads = new Map();   // id → thread object
        this.activeThreadId = null;
        this.audit = options.audit || null;

        // Ensure directory exists
        if (!existsSync(CONV_DIR)) {
            mkdirSync(CONV_DIR, { recursive: true });
        }

        // Load index on init
        this._loadIndex();
    }

    // ── Thread Lifecycle ────────────────────────────────────────

    createThread(provider, model) {
        const id = `conv_${randomBytes(6).toString('hex')}`;
        const thread = {
            id,
            title: null,       // Auto-generated from first prompt
            provider,
            model,
            created: new Date().toISOString(),
            updated: new Date().toISOString(),
            messages: [],
            messageCount: 0,
        };
        this.threads.set(id, thread);
        this.activeThreadId = id;
        this._saveIndex();
        return id;
    }

    addMessage(threadId, role, content) {
        const thread = this.threads.get(threadId);
        if (!thread) return false;

        thread.messages.push({
            role,
            content,
            timestamp: new Date().toISOString(),
        });
        thread.messageCount = thread.messages.length;
        thread.updated = new Date().toISOString();

        // Auto-title from first user message
        if (!thread.title && role === 'user') {
            thread.title = content.length > 60
                ? content.substring(0, 57) + '...'
                : content;
        }

        return true;
    }

    getMessages(threadId) {
        const thread = this.threads.get(threadId);
        if (!thread) return [];
        // Return messages in API format (just role + content)
        return thread.messages.map(m => ({ role: m.role, content: m.content }));
    }

    getThread(threadId) {
        return this.threads.get(threadId) || null;
    }

    getActiveThread() {
        if (!this.activeThreadId) return null;
        return this.threads.get(this.activeThreadId) || null;
    }

    setActiveThread(threadId) {
        if (this.threads.has(threadId)) {
            this.activeThreadId = threadId;
            return true;
        }
        return false;
    }

    listThreads() {
        const list = [];
        for (const [id, thread] of this.threads) {
            list.push({
                id,
                title: thread.title || '(untitled)',
                provider: thread.provider,
                model: thread.model,
                created: thread.created,
                updated: thread.updated,
                messageCount: thread.messages.length,
            });
        }
        // Sort by most recently updated
        list.sort((a, b) => new Date(b.updated) - new Date(a.updated));
        return list;
    }

    deleteThread(threadId) {
        this.threads.delete(threadId);
        if (this.activeThreadId === threadId) {
            this.activeThreadId = null;
        }
        // Delete file
        const filepath = join(CONV_DIR, `${threadId}.enc`);
        if (existsSync(filepath)) {
            try { unlinkSync(filepath); } catch (err) {
                this.audit?.log({ type: 'DEBUG_ERROR', details: { op: 'deleteThreadFile', error: err.message } });
            }
        }
        this._saveIndex();
    }

    setTitle(threadId, title) {
        const thread = this.threads.get(threadId);
        if (!thread) return false;
        thread.title = title;
        this._saveIndex();
        return true;
    }

    searchThreads(query) {
        const results = [];
        const q = query.toLowerCase();
        for (const [id, thread] of this.threads) {
            // Search title
            if (thread.title?.toLowerCase().includes(q)) {
                results.push({ threadId: id, title: thread.title, type: 'title' });
                continue;
            }
            // Search messages
            for (const msg of thread.messages) {
                if (msg.content.toLowerCase().includes(q)) {
                    results.push({
                        threadId: id,
                        title: thread.title,
                        type: 'message',
                        role: msg.role,
                        preview: msg.content.substring(0, 80),
                    });
                    break; // One match per thread is enough
                }
            }
        }
        return results;
    }

    // ── Persistence (Encrypted) ─────────────────────────────────

    saveThread(threadId) {
        if (!this.encryption) return false;
        const thread = this.threads.get(threadId);
        if (!thread) return false;

        try {
            const data = JSON.stringify(thread);
            const encrypted = this.encryption.encrypt(data);
            const filepath = join(CONV_DIR, `${threadId}.enc`);
            writeFileSync(filepath, encrypted, 'utf8');
            this._saveIndex();
            return true;
        } catch (err) {
            this.audit?.log({ type: 'DEBUG_ERROR', details: { op: 'saveThread', error: err.message } });
            return false;
        }
    }

    loadThread(threadId) {
        if (!this.encryption) return null;

        // Check if already in memory
        if (this.threads.has(threadId)) {
            return this.threads.get(threadId);
        }

        const filepath = join(CONV_DIR, `${threadId}.enc`);
        if (!existsSync(filepath)) return null;

        try {
            const encrypted = readFileSync(filepath, 'utf8');
            const decrypted = this.encryption.decrypt(encrypted);
            const thread = JSON.parse(decrypted);
            this.threads.set(threadId, thread);
            return thread;
        } catch (err) {
            this.audit?.log({ type: 'DEBUG_ERROR', details: { op: 'loadThread', error: err.message } });
            return null;
        }
    }

    saveAll() {
        for (const [id] of this.threads) {
            this.saveThread(id);
        }
    }

    _saveIndex() {
        if (!this.encryption) return;
        try {
            const index = [];
            for (const [id, thread] of this.threads) {
                index.push({
                    id,
                    title: thread.title,
                    provider: thread.provider,
                    model: thread.model,
                    created: thread.created,
                    updated: thread.updated,
                    messageCount: thread.messages.length,
                });
            }
            const data = JSON.stringify(index);
            const encrypted = this.encryption.encrypt(data);
            writeFileSync(INDEX_FILE, encrypted, 'utf8');
        } catch (err) {
            this.audit?.log({ type: 'DEBUG_ERROR', details: { op: 'saveIndex', error: err.message } });
        }
    }

    _loadIndex() {
        if (!this.encryption) return;
        if (!existsSync(INDEX_FILE)) return;

        try {
            const encrypted = readFileSync(INDEX_FILE, 'utf8');
            const decrypted = this.encryption.decrypt(encrypted);
            const index = JSON.parse(decrypted);

            // Load thread metadata into memory (messages loaded on demand)
            for (const entry of index) {
                if (!this.threads.has(entry.id)) {
                    // Create a lightweight stub — messages loaded when needed
                    this.threads.set(entry.id, {
                        id: entry.id,
                        title: entry.title,
                        provider: entry.provider,
                        model: entry.model,
                        created: entry.created,
                        updated: entry.updated,
                        messages: [],
                        messageCount: entry.messageCount,
                        _needsLoad: true,
                    });
                }
            }
        } catch (err) {
            this.audit?.log({ type: 'DEBUG_ERROR', details: { op: 'loadIndex', error: err.message } });
        }
    }

    // Ensure thread messages are loaded from disk
    ensureLoaded(threadId) {
        const thread = this.threads.get(threadId);
        if (!thread) return null;
        if (thread._needsLoad) {
            const loaded = this.loadThread(threadId);
            if (loaded) {
                loaded._needsLoad = false;
                return loaded;
            }
        }
        return thread;
    }

    // ── Export ──────────────────────────────────────────────────

    exportThread(threadId, format = 'json') {
        const thread = this.ensureLoaded(threadId);
        if (!thread) return null;

        if (format === 'json') {
            return JSON.stringify(thread, null, 2);
        }

        if (format === 'markdown') {
            let md = `# ${thread.title || 'Untitled Conversation'}\n\n`;
            md += `**Provider:** ${thread.provider} | **Model:** ${thread.model}\n`;
            md += `**Created:** ${thread.created}\n\n---\n\n`;

            for (const msg of thread.messages) {
                const label = msg.role === 'user' ? '**You**' : '**AI**';
                md += `### ${label}\n${msg.content}\n\n`;
            }
            return md;
        }

        return null;
    }

    // ── Stats ──────────────────────────────────────────────────

    getStats() {
        let totalMessages = 0;
        for (const [, thread] of this.threads) {
            totalMessages += thread.messageCount || thread.messages.length;
        }
        return {
            totalThreads: this.threads.size,
            totalMessages,
            activeThread: this.activeThreadId,
        };
    }

    // ── Wipe All ───────────────────────────────────────────────

    wipeAll() {
        this.threads.clear();
        this.activeThreadId = null;

        try {
            const files = readdirSync(CONV_DIR);
            for (const f of files) {
                try { unlinkSync(join(CONV_DIR, f)); } catch (err) {
                    this.audit?.log({ type: 'DEBUG_ERROR', details: { op: 'wipeFile', error: err.message } });
                }
            }
        } catch (err) {
            this.audit?.log({ type: 'DEBUG_ERROR', details: { op: 'wipeAll', error: err.message } });
        }
    }

    // ── Detailed Stats ──────────────────────────────────────────

    getDetailedStats() {
        let totalWords = 0;
        let totalTokens = 0;
        const providerBreakdown = {};
        let totalMsgLength = 0;
        let msgCount = 0;

        for (const [, thread] of this.threads) {
            const provider = thread.provider || 'unknown';
            if (!providerBreakdown[provider]) {
                providerBreakdown[provider] = { threads: 0, messages: 0, words: 0 };
            }
            providerBreakdown[provider].threads++;

            for (const msg of thread.messages) {
                const words = msg.content ? msg.content.split(/\s+/).filter(w => w.length > 0).length : 0;
                totalWords += words;
                totalTokens += Math.ceil((msg.content || '').length / 4);
                totalMsgLength += (msg.content || '').length;
                msgCount++;
                providerBreakdown[provider].messages++;
                providerBreakdown[provider].words += words;
            }
        }

        return {
            ...this.getStats(),
            totalWords,
            estimatedTokens: totalTokens,
            averageMessageLength: msgCount > 0 ? Math.round(totalMsgLength / msgCount) : 0,
            providerBreakdown,
        };
    }
}
