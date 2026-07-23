import { promises as fs } from 'node:fs';
import * as logger from './logger.mjs';

const CACHE_FILE = process.env.CACHE_FILE ?? 'resolved.cache';
const FILTER_FILE = process.env.FILTER_FILE ?? 'filtered.cache';

const FLUSH_INTERVAL_MS = Number(process.env.FLUSH_INTERVAL_MS ?? 60_000);
const IGNORE_IPS = new Set(
    (process.env.IGNORE_IPS ?? '')
        .split(/\s+/)
        .filter(Boolean)
);
const FILTER_IPS = (process.env.FILTER_IPS ?? '')
    .split(/\s+/)
    .filter(Boolean)

const MAX_BUFFER_SIZE = Number(process.env.MAX_BUFFER_SIZE ?? 100);

const CACHE_LEVELS = {
    'ALL': 'ALL',
    'FILTERED_ONLY': 'FILTERED_ONLY',
}

const resolvedDomains = new Map();
const filteredDomains = new Set();

let pendingResolvedDomains = [];
let pendingFilteredDomains = [];
let flushTimer = null;
let isFlushing = false;

let cacheLevel;


function getNextDomain(previousDomains, domain, ips) {
    const previous = previousDomains.get(domain);

    ips.sort();
    const next = new Set(ips);

    const changed =
        !previous ||
        previous.size !== next.size ||
        [...next].some(ip => !previous.has(ip));

    if (!changed) {
        return;
    }

    return next;
}

/**
 * Loads previously resolved domain mappings from disk.
 *
 * @returns {Promise<void>}
 */
async function loadResolvedCache() {
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

/**
 * Loads previously resolved domain mappings from disk.
 *
 * @returns {Promise<void>}
 */
async function loadFilteredCache() {
    try {
        const data = await fs.readFile(FILTER_FILE, 'utf8');

        for (const line of data.split('\n')) {
            const trimmed = line.trim();
            if (!trimmed) continue;

            filteredDomains.add(trimmed);
        }

        logger.info(`Loaded ${filteredDomains.size} domains from ${FILTER_FILE}`);
    } catch (err) {
        if (err.code !== 'ENOENT') {
            logger.error(err);
        }
    }
}


/**
 * 
 * @param {Array} list 
 * @returns 
 */
async function flush(list, file) {
    if (isFlushing || list.length === 0) {
        return;
    }

    isFlushing = true;

    const lines = [...list];
    list.length = 0;

    try {
        await fs.appendFile(
            file,
            lines.join('\n') + '\n'
        );
    } finally {
        isFlushing = false;
    }
}

async function compactResolvedDomains() {
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

async function compactFilteredDomains() {
    const lines = [];

     for (const domain of filteredDomains) {  
        lines.push(domain);
    }

    await fs.writeFile(
        FILTER_FILE,
        lines.join('\n') + '\n'
    );
}

/**
 * Stores or replaces IP addresses for a domain.
 *
 * @param {string} domain
 * @param {string[]} ips
 */
function cacheFilteredDomains(domain, ips) {
    const isFiltered = ips.some(ip => FILTER_IPS.includes(ip));

    if (!isFiltered) {
        return;
    }

    // cache log filtered domains
    filteredDomains.add(domain);

    pendingFilteredDomains.push(domain);

    if (pendingFilteredDomains.length >= MAX_BUFFER_SIZE) {
        void flush(pendingFilteredDomains, FILTER_FILE);
    }
}


/**
 * Stores or replaces IP addresses for a domain.
 *
 * @param {string} domain
 * @param {string[]} ips
 */
function cacheResolvedDomains(domain, ips) {
    const filtered = ips.filter(ip => !IGNORE_IPS.has(ip));

    if (filtered.length === 0) {
        return;
    }

    const next = getNextDomain(resolvedDomains, domain, filtered);

    resolvedDomains.set(domain, next);

    pendingResolvedDomains.push(
        `${domain} ${filtered.join(' ')}`
    );

    if (pendingResolvedDomains.length >= MAX_BUFFER_SIZE) {
        void flush(pendingResolvedDomains, CACHE_FILE);
    }
}

function cache(domain, ips) {
    switch (cacheLevel) {
        case CACHE_LEVELS.ALL:
            cacheResolvedDomains(domain, ips);
            cacheFilteredDomains(domain, ips);
            break;

        case CACHE_LEVELS.FILTERED_ONLY:
            cacheFilteredDomains(domain, ips);
            break;
    }
}

/**
 * Initializes the cacher.
 *
 * @param {keyof typeof CACHE_LEVELS} initCacheLevel level of caching. (this will ignore IGNORE_IPS env variable)
 * @returns {Promise<void>}
 */
async function init(initCacheLevel = CACHE_LEVELS.ALL) {
    cacheLevel = initCacheLevel;

    switch (initCacheLevel) {
        case CACHE_LEVELS.ALL:
            await loadResolvedCache();
            await loadFilteredCache();

            flushTimer = setInterval(() => {
                void flush(pendingFilteredDomains, FILTER_FILE);
                void flush(pendingResolvedDomains, CACHE_FILE);
            }, FLUSH_INTERVAL_MS);

            break;

        case CACHE_LEVELS.FILTERED_ONLY:
            await loadFilteredCache();

            flushTimer = setInterval(() => {
                void flush(pendingFilteredDomains, FILTER_FILE);
            }, FLUSH_INTERVAL_MS);

            break;
    }

}

async function shutdown() {
    clearInterval(flushTimer);

    switch (cacheLevel) {
        case CACHE_LEVELS.ALL:
            await flush(pendingResolvedDomains, CACHE_FILE);
            await compactResolvedDomains();

            await flush(pendingFilteredDomains, FILTER_FILE);
            await compactFilteredDomains();
            break;
        case CACHE_LEVELS.FILTERED_ONLY:
            await flush(pendingFilteredDomains, FILTER_FILE);
            await compactFilteredDomains();
            break;
    }

}

export {
    init,
    shutdown,
    flush,
    cache
};