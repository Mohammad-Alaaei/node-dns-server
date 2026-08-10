import { promises as fs } from 'node:fs';
import path from 'node:path';

const LOG_DIR = process.env.LOG_DIR ?? './logs';
const FLUSH_INTERVAL = Number(process.env.LOG_FLUSH_INTERVAL ?? process.env.FLUSH_INTERVAL ?? 5000);
const MAX_BUFFER_SIZE = Number(process.env.LOG_MAX_BUFFER_SIZE ?? process.env.MAX_BUFFER_SIZE ?? 100);
/** Max file size in KB (default 10240 = 10 MB). */
const MAX_SIZE_KB = Number(process.env.LOG_MAX_SIZE_KB ?? 10240);
const MAX_SIZE_BYTES = Math.max(1, MAX_SIZE_KB) * 1024;

let sessionLogFile = '';
let logBuffer = [];
let flushTimer = null;
let isFlushing = false;
let rotating = false;

function write(level, ...args) {
    const timestamp = new Date().toISOString();

    const message = args
        .map(arg =>
            typeof arg === 'string'
                ? arg
                : JSON.stringify(arg, null, 2)
        )
        .join(' ');

    const line = `[${timestamp}] [${process.pid}] [${level}] ${message}`;

    switch (level) {
        case 'ERROR':
            console.error(...args);
            break;
        case 'WARN':
            console.warn(...args);
            break;
        default:
            console.log(...args);
            break;
    }

    logBuffer.push(line);

    if (logBuffer.length >= MAX_BUFFER_SIZE) {
        void flush();
    }
}

/**
 * Flush buffer to the current session file, then rotate if over size limit.
 */
export async function flush() {
    if (isFlushing) {
        return;
    }

    isFlushing = true;

    try {
        // Snapshot buffer so concurrent writes go to a new buffer
        const lines = logBuffer;
        logBuffer = [];

        if (lines.length > 0 && sessionLogFile) {
            await fs.appendFile(
                sessionLogFile,
                lines.join('\n') + '\n'
            );
        }

        if (sessionLogFile && !rotating) {
            await maybeRotateBySize();
        }
    } finally {
        isFlushing = false;
    }
}

async function fileSize(filePath) {
    try {
        const st = await fs.stat(filePath);
        return st.size;
    } catch {
        return 0;
    }
}

async function maybeRotateBySize() {
    const size = await fileSize(sessionLogFile);
    if (size < MAX_SIZE_BYTES) {
        return;
    }
    await rotate('size limit reached');
}

function buildSessionPath() {
    const now = new Date();
    const dateString = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
    const timeString = `${String(now.getHours()).padStart(2, '0')}-${String(now.getMinutes()).padStart(2, '0')}-${String(now.getSeconds()).padStart(2, '0')}`;
    return path.join(LOG_DIR, `${dateString}_${timeString}.log`);
}

/**
 * Force a new log file.
 * 1. Write reason into buffer
 * 2. Flush all pending lines to the *old* file
 * 3. Open a new session file
 */
export async function rotate(reason = 'manual') {
    if (rotating) {
        return { ok: false, error: 'rotation already in progress' };
    }

    rotating = true;

    try {
        const oldFile = sessionLogFile;

        write(
            'INFO',
            `Log rotate (${reason}). Closing file: ${oldFile || '(none)'}`
        );

        // Flush everything currently buffered into the old file
        // (bypass nested rotate while we hold the lock)
        const lines = logBuffer;
        logBuffer = [];

        if (lines.length > 0 && oldFile) {
            await fs.appendFile(oldFile, lines.join('\n') + '\n');
        }

        sessionLogFile = buildSessionPath();

        write(
            'INFO',
            `Log rotate complete. New file: ${sessionLogFile}`
        );

        // Flush the "new file" line into the new session immediately
        const openLines = logBuffer;
        logBuffer = [];
        if (openLines.length > 0) {
            await fs.appendFile(sessionLogFile, openLines.join('\n') + '\n');
        }

        return {
            ok: true,
            previous: oldFile ? path.basename(oldFile) : null,
            current: path.basename(sessionLogFile)
        };
    } finally {
        rotating = false;
    }
}

export function info(...args) {
    return write('INFO', ...args);
}

export function success(...args) {
    return write('SUCCESS', ...args);
}

export function warn(...args) {
    return write('WARN', ...args);
}

export function error(...args) {
    return write('ERROR', ...args);
}

export function debug(...args) {
    return write('DEBUG', ...args);
}

export function getCurrentLogFile() {
    return sessionLogFile ? path.basename(sessionLogFile) : null;
}

export function getLogDir() {
    return LOG_DIR;
}

/** Absolute path of the active session log file. */
export function getSessionLogFile() {
    return sessionLogFile || null;
}

export async function init() {
    await fs.mkdir(LOG_DIR, { recursive: true });
    sessionLogFile = buildSessionPath();
    flushTimer = setInterval(() => {
        void flush();
    }, FLUSH_INTERVAL);
}

export async function shutdown() {
    clearInterval(flushTimer);
    await flush();
}
