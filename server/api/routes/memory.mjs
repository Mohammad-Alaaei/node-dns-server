import { Router } from 'express';
import { store } from '../../../memory/store.mjs';
import * as cacheService from '../../../services/cache_service.mjs';
import { authenticate, requireRole } from '../middleware/auth.mjs';
import { paginateArray } from '../utils/pagination.mjs';

const router = Router();

router.use(authenticate, requireRole('superadmin', 'admin', 'viewer'));

/**
 * GET /api/memory/store?page=1&limit=20
 * Each in-memory collection is paginated with the same page/limit.
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
        exactRecords: paginateArray(exact, req.query),
        regexRecords: paginateArray(regex, req.query),
        defaultDnsServers: paginateArray(store.defaultDnsServers, req.query),
        customDnsServers: paginateArray(store.customDnsServers, req.query)
    });
});

/**
 * GET /api/memory/pending-cache?page=1&limit=20
 */
router.get('/pending-cache', (req, res) => {
    const pending = typeof cacheService.getPendingCache === 'function'
        ? cacheService.getPendingCache()
        : [];

    res.json(paginateArray(pending, req.query));
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
