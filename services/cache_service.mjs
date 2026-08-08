import * as logger from '../utils/logger.mjs';
import { config } from '../config/config.mjs';

import { loadRecords, saveRecord } from '../database/repository.mjs';
import { mergeRecords } from '../utils/array_utils.mjs';
import { RECORD_SOURCE, RECORD_STATUS } from '../config/constants.mjs';
import { hasLocalRecord } from '../memory/resolver.mjs';
import { normalizeDomain } from '../utils/domain_utils.mjs';
import { store } from '../memory/store.mjs';

function getFlushIntervalMs() {
    return config.system.cache.flushInterval;
}

function getFilterIpSet() {
    return new Set(config.system.cache.filterIps ?? []);
}

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
                    if (hasLocalRecord(record.domain)) {
                        continue;
                    }
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
            // Reload from DB — promoteToMemory already serves until this completes
            await loadRecords();

            flushing = false;
            flushPromise = null;
        }

    })();

    return flushPromise;
}

/**
 * Push a cached answer into the in-memory store immediately so the next
 * request can be served by findRecord without waiting for DB flush.
 * This is required for rapid repeated queries (custom or default upstream).
 */
function promoteToMemory(record, dnsServerId) {

    const domain = normalizeDomain(record.domain);

    if (hasLocalRecord(domain)) {
        return;
    }

    let mem = store.exactRecords.get(domain);

    if (!mem) {
        mem = {
            id: null,
            domain,
            enabled: true,
            isRegex: false,
            source: record.source,
            servers: [],
            hits: record.hits ?? 1,
            lastHit: record.lastHit ?? Date.now(),
            createdAt: Date.now(),
            updatedAt: Date.now()
        };
        store.exactRecords.set(domain, mem);
    } else {
        if (mem.source === RECORD_SOURCE.LOCAL) {
            return;
        }
        mem.source = record.source;
        mem.hits = record.hits ?? mem.hits;
        mem.lastHit = record.lastHit ?? mem.lastHit;
        mem.updatedAt = Date.now();
    }

    for (const s of mem.servers) {
        s.selected = false;
    }

    let server = mem.servers.find(s => s.dnsServerId === dnsServerId);

    if (!server) {
        server = {
            dnsServerId,
            selected: true,
            status: record.source === RECORD_SOURCE.FILTERED
                ? RECORD_STATUS.FILTERED
                : RECORD_STATUS.SUCCESS,
            isStale: record.source === RECORD_SOURCE.FILTERED,
            lastSuccessAt: Date.now(),
            A: [],
            AAAA: [],
            CNAME: []
        };
        mem.servers.push(server);
    } else {
        server.selected = true;
        server.status = record.source === RECORD_SOURCE.FILTERED
            ? RECORD_STATUS.FILTERED
            : RECORD_STATUS.SUCCESS;
        server.isStale = record.source === RECORD_SOURCE.FILTERED;
        server.lastSuccessAt = Date.now();
    }

    if (record.A?.length) {
        server.A = record.A.map(a => ({ ...a, name: domain }));
    }
    if (record.AAAA?.length) {
        server.AAAA = record.AAAA.map(a => ({ ...a, name: domain }));
    }
    if (record.CNAME?.length) {
        server.CNAME = record.CNAME.map(c => ({ ...c, name: domain }));
    }
}

/* -------------------------------------------------------------------------- */
/*                                  Public                                    */
/* -------------------------------------------------------------------------- */

export function cacheRecord(record, dnsServerId = null) {

    record.domain = normalizeDomain(record.domain);

    if (hasLocalRecord(record.domain)) {
        return;
    }

    const now = Date.now();

    const source =
        [...(record.A ?? []), ...(record.AAAA ?? [])]
            .some(r => getFilterIpSet().has(r.address))
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
        existing.source = source;

        // Immediate reuse for the next query (before DB flush)
        promoteToMemory(existing, dnsServerId);
        return;
    }

    record.isRegex = false;
    record.hits = 1;
    record.lastHit = now;

    pendingCache.set(record.domain, record);

    // Immediate reuse for the next query (before DB flush)
    promoteToMemory(record, dnsServerId);
}

export async function flush() {
    await flushCache();
}

/**
 * Snapshot of records waiting for DB flush (for API / debug).
 * Returns plain objects — safe to JSON-serialize.
 */
export function getPendingCache() {
    return [...pendingCache.values()].map(r => ({
        domain: r.domain,
        source: r.source,
        isRegex: r.isRegex,
        hits: r.hits,
        lastHit: r.lastHit,
        dnsServerId: r.dnsServerId ?? null,
        A: r.A ?? [],
        AAAA: r.AAAA ?? [],
        CNAME: r.CNAME ?? []
    }));
}

export async function init() {

    flushTimer = setInterval(() => {
        void flush();
    }, getFlushIntervalMs());

}

export async function shutdown() {

    clearInterval(flushTimer);

    await flushCache();

    while (pendingCache.size > 0) {
        await flushCache();
    }

}