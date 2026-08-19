import { store } from '../../../memory/store.mjs';
import * as cacheService from '../../../services/cache_service.mjs';
import { paginateArray } from '../utils/pagination.mjs';

function serializeMemoryRecord(domain, record) {
    return {
        id: record.id ?? null,
        domain: domain ?? record.domain,
        enabled: record.enabled,
        isRegex: record.isRegex,
        source: record.source,
        hits: record.hits,
        lastHit: record.lastHit,
        createdAt: record.createdAt,
        updatedAt: record.updatedAt,
        servers: record.servers ?? []
    };
}

class MemoryService {
    getStore(query) {
        const exact = [];
        for (const [domain, record] of store.exactRecords.entries()) {
            exact.push(serializeMemoryRecord(domain, record));
        }

        const regex = store.regexRecords.map(r =>
            serializeMemoryRecord(r.domain, r)
        );

        return {
            exactRecords: paginateArray(exact, query),
            regexRecords: paginateArray(regex, query),
            defaultDnsServers: paginateArray(store.defaultDnsServers, query),
            customDnsServers: paginateArray(store.customDnsServers, query)
        };
    }

    getPendingCache(query) {
        const pending = typeof cacheService.getPendingCache === 'function'
            ? cacheService.getPendingCache()
            : [];
        return paginateArray(pending, query);
    }
}

export default new MemoryService();
