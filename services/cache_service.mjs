import * as logger from '../utils/logger.mjs';
import { config } from '../config/config.mjs';

import { loadRecords, saveRecord } from '../database/repository.mjs';
import { mergeRecords } from '../utils/array_utils.mjs';
import { RECORD_SOURCE } from '../config/constants.mjs';

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
                    logger.error(err);
                }

            }
        } catch (err) {
            logger.error(err);
            for (const record of records) {
                pendingCache.set(record.domain, record);
            }
        } finally {
            await loadRecords();

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
            ? RECORD_SOURCE.FILTERED
            : RECORD_SOURCE.CACHE;

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

        // Escalate to FILTERED, or demote back to CACHE when a clean answer arrives.
        existing.source = source;

        return;
    }

    record.isRegex = false;
    record.hits = 1;
    record.lastHit = now;

    pendingCache.set(
        record.domain,
        record
    );

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