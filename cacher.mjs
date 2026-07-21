import { promises as fs } from 'node:fs';
import * as logger from './logger.mjs';

const CACHE_FILE = process.env.CACHE_FILE ?? 'resolved.cache';
const FLUSH_INTERVAL_MS = Number(process.env.FLUSH_INTERVAL_MS ?? 60_000);
const IGNORE_LIST = new Set(
    (process.env.IGNORE_LIST ?? '')
        .split(/\s+/)
        .filter(Boolean)
);
const MAX_BUFFER_SIZE = Number(process.env.MAX_BUFFER_SIZE ?? 100);

const resolvedDomains = new Map();

let pendingLines = [];
let flushTimer = null;
let isFlushing = false;

/**
 * Loads previously resolved domain mappings from disk.
 *
 * @returns {Promise<void>}
 */
async function loadSeen() {
    try {
        const data = await fs.readFile(CACHE_FILE, 'utf8');

        for (const line of data.split('\n')) {
            const trimmed = line.trim();
            if (!trimmed) continue;

            const [domain, ...ips] = trimmed.split(/\s+/);
            resolvedDomains.set(domain, new Set(ips));
        }

        logger.info(`Loaded ${resolvedDomains.size} domains from ${CACHE_FILE}`);
    } catch (err) {
        if (err.code !== 'ENOENT') {
            logger.error(err);
        }
    }
}


async function flush() {
    if (isFlushing || pendingLines.length === 0) {
        return;
    }

    isFlushing = true;

    const lines = [...pendingLines];
    pendingLines.length = 0;

    try {
        await fs.appendFile(
            CACHE_FILE,
            lines.join('\n') + '\n'
        );
    } finally {
        isFlushing = false;
    }
}

async function compact() {
    await flush();

    const lines = [];

    for (const [domain, ips] of resolvedDomains) {
        lines.push(
            `${domain} ${Array.from(ips).join(' ')}`
        );
    }

    await fs.writeFile(
        CACHE_FILE,
        lines.join('\n') + '\n'
    );
}

/**
 * Stores or replaces IP addresses for a domain.
 *
 * @param {string} domain
 * @param {string[]} ips
 */
function upsertDomain(domain, ips) {
    const filtered = ips.filter(ip => !IGNORE_LIST.has(ip));

    if (filtered.length === 0) {
        return;
    }

    const previous = resolvedDomains.get(domain);

    filtered.sort();
    const next = new Set(filtered);

    const changed =
        !previous ||
        previous.size !== next.size ||
        [...next].some(ip => !previous.has(ip));

    if (!changed) {
        return;
    }

    resolvedDomains.set(domain, next);

    pendingLines.push(
        `${domain} ${filtered.join(' ')}`
    );

    if (pendingLines.length >= MAX_BUFFER_SIZE) {
        void flush();
    }
}

/**
 * Initializes the cacher.
 *
 * @returns {Promise<void>}
 */
async function init() {
    await loadSeen();

    flushTimer = setInterval(() => {
        void flush();
    }, FLUSH_INTERVAL_MS);

}

async function shutdown() {
    clearInterval(flushTimer);

    await compact();
}

export {
    init,
    shutdown,
    flush,
    upsertDomain
};