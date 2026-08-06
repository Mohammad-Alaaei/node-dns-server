import { Router } from 'express';
import { store } from '../../../memory/store.mjs';
import * as cacheService from '../../../services/cache_service.mjs';
import { authenticate, requireRole } from '../middleware/auth.mjs';

const router = Router();

// All memory/debug routes require auth. superadmin for now; viewer can be added later.
router.use(authenticate, requireRole('superadmin', 'admin', 'viewer'));

/**
 * GET /api/memory/store
 * Snapshot of in-memory resolver data (exact + regex records, upstream lists).
 */
router.get('/store', (req, res) => {
    const exact = [];

    for (const [domain, record] of store.exactRecords.entries()) {
        exact.push(serializeMemoryRecord(domain, record));
    }

    const regex = store.regexRecords.map(r =>
        serializeMemoryRecord(r.domain, r)
    );

    res.json({
        exactRecords: exact,
        regexRecords: regex,
        defaultDnsServers: store.defaultDnsServers,
        customDnsServers: store.customDnsServers
    });
});

/**
 * GET /api/memory/pending-cache
 * Records waiting to be flushed to DB by cache_service.
 */
router.get('/pending-cache', (req, res) => {
    const pending = cacheService.getPendingCache
        ? cacheService.getPendingCache()
        : [];

    res.json({
        count: pending.length,
        records: pending
    });
});

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

export default router;
