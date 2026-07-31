import * as logger from '../utils/logger.mjs';
import { config } from '../config/config.mjs';

import { saveRecord } from '../database/repository.mjs';
import { mergeRecords } from '../utils/array_utils.mjs';
import { putRecord } from '../memory/cache_memory.mjs';

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
                    await saveRecord(record);
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

export function cacheRecord(record, dnsServerId = null) {

    const now = Date.now();

    const source =
        [...record.A, ...record.AAAA]
            .some(r => FILTER_IPS.has(r.address))
            ? 'FILTERED'
            : 'CACHE';

    record.source = source;
    record.dnsServerId = dnsServerId;

    const existing = pendingCache.get(record.domain);

    if (existing) {

        mergeRecords(existing.A, record.A, 'address');
        mergeRecords(existing.AAAA, record.AAAA, 'address');
        mergeRecords(existing.CNAME, record.CNAME, 'domain');

        existing.hits++;
        existing.lastHit = now;
        existing.dnsServerId = dnsServerId;

        if (source === 'FILTERED') {
            existing.source = 'FILTERED';
        }

        putRecord(existing);

        return;
    }

    record.isRegex = false;
    record.hits = 1;
    record.lastHit = now;

    pendingCache.set(
        record.domain,
        record
    );

    putRecord(record);
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