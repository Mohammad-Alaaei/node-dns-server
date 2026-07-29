import * as logger from '../utils/logger.mjs';
import { config } from '../config/config.mjs';

import {
    upsertCacheRecord
} from '../database/repository.mjs';
import { mergeRecords } from '../utils/array_utils.mjs';

const FLUSH_INTERVAL_MS = config.cache.flushInterval;
const FILTER_IPS = new Set(config.cache.filterIps);

const pendingCache = new Map();

let flushTimer = null;
let flushing = false;
let flushPromise = null;


/* -------------------------------------------------------------------------- */
/*                                  Cache                                     */
/* -------------------------------------------------------------------------- */

async function flushCache() {
    if (flushing) {
        return flushPromise;
    }

    if (pendingCache.size === 0) {
        return;
    }

    flushing = true;

    flushPromise = (async () => {

        const records = [...pendingCache.values()];
        pendingCache.clear();

        try {
            for (const record of records) {
                try {
                    await upsertCacheRecord(record);
                } catch (err) {
                    console.error(err);
                }

            }
        } catch (err) {
            logger.error(err);
            for (const record of records) {
                pendingCache.set(record.domain, record);
            }
        } finally {
            flushing = false;
            flushPromise = null;
        }

    })();

    return flushPromise;
}

/* -------------------------------------------------------------------------- */
/*                                  Public                                    */
/* -------------------------------------------------------------------------- */

export function cacheRecord(
    domain,
    A = [],
    AAAA = [],
    CNAME = [],
    ttl = 300
) {

    const source =
        [...A, ...AAAA].some(r => FILTER_IPS.has(r.address))
            ? 'FILTERED'
            : 'CACHE';

    const existing = pendingCache.get(domain);

    if (existing) {

        mergeRecords(existing.A, A, 'address');
        mergeRecords(existing.AAAA, AAAA, 'address');
        mergeRecords(existing.CNAME, CNAME, 'domain');

        existing.ttl = Math.min(existing.ttl, ttl);
        existing.expiresAt = Date.now() + existing.ttl * 1000;

        return;
    }

    pendingCache.set(domain, {

        domain,
        isRegex: false,

        // Keep the original dns2 answer objects.
        A: [...A],
        AAAA: [...AAAA],
        CNAME: [...CNAME],

        source,

        ttl,
        expiresAt: Date.now() + ttl * 1000,

        hits: 0,
        lastHit: null
    });
}

export async function flush() {
    await flushCache();
}

export async function init() {

    flushTimer = setInterval(() => {
        void flush();
    }, FLUSH_INTERVAL_MS);

}

export async function shutdown() {

    clearInterval(flushTimer);

    await flushCache();

    while (pendingCache.size > 0) {
        await flushCache();
    }

}