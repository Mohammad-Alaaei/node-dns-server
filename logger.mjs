import { promises as fs } from 'node:fs';
import path from 'node:path';

const LOG_DIR = process.env.LOG_DIR ?? './logs';
const FLUSH_INTERVAL = process.env.FLUSH_INTERVAL ?? 5000;     // 5 seconds
const MAX_BUFFER_SIZE = process.env.MAX_BUFFER_SIZE ?? 100;     // Flush immediately after 100 lines

let sessionLogFile = '';
let logBuffer = [];
let flushTimer = null;
let isFlushing = false;


/**
 * Adds a log message to the buffer.
 *
 * @param {'INFO'|'SUCCESS'|'WARN'|'ERROR'|'DEBUG'} level
 * @param {...any} args
 */
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
 * Flushes buffered logs to disk.
 */
export async function flush() {
    if (isFlushing || logBuffer.length === 0) {
        return;
    }

    isFlushing = true;

    const lines = logBuffer;
    logBuffer = [];

    try {
        await fs.appendFile(
            sessionLogFile,
            lines.join('\n') + '\n'
        );
    } finally {
        isFlushing = false;
    }
}


/* -------------------------------------------------------------------------- */
/*                               PUBLIC WRAPPERS                              */
/* -------------------------------------------------------------------------- */

/**
 * Logs an informational message.
 *
 * @param {...any} args
 */
export function info(...args) {
    return write('INFO', ...args);
}

/**
 * Logs a success message.
 *
 * @param {...any} args
 */
export function success(...args) {
    return write('SUCCESS', ...args);
}

/**
 * Logs a warning.
 *
 * @param {...any} args
 */
export function warn(...args) {
    return write('WARN', ...args);
}

/**
 * Logs an error.
 *
 * @param {...any} args
 */
export function error(...args) {
    return write('ERROR', ...args);
}

/**
 * Logs a debug message.
 *
 * @param {...any} args
 */
export function debug(...args) {
    return write('DEBUG', ...args);
}



/**
 * Initializes the logger.
 *
 * @returns {Promise<void>}
 */
export async function init() {
    await fs.mkdir(LOG_DIR, { recursive: true });

    const now = new Date();

    const dateString = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`
    const timeString = `${String(now.getHours()).padStart(2, '0')}-${String(now.getMinutes()).padStart(2, '0')}-${String(now.getSeconds()).padStart(2, '0')}`;

    sessionLogFile  = path.join(
        LOG_DIR,
        `${dateString}_${timeString}.log`
    );

    flushTimer = setInterval(flush, FLUSH_INTERVAL);
}

/**
 * Stops the logger and writes remaining logs.
 */
export async function shutdown() {
    clearInterval(flushTimer);

    await flush();
}