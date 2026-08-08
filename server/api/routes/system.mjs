import { Router } from 'express';
import * as cacheService from '../../../services/cache_service.mjs';
import { loadRecords, loadDnsServers } from '../../../database/repository.mjs';
import { memoryCounts } from '../../../memory/apply.mjs';
import { authenticate, requireRole } from '../middleware/auth.mjs';

const router = Router();

router.use(authenticate, requireRole('superadmin'));

/**
 * POST /api/system/flush
 * Flush pending cache entries to DB (same path as the periodic flusher).
 */
router.post('/flush', async (req, res, next) => {
    try {
        const pending = typeof cacheService.getPendingCache === 'function'
            ? cacheService.getPendingCache()
            : [];
        const pendingBefore = pending.length;

        await cacheService.flush();

        return res.json({
            ok: true,
            pendingBefore
        });
    } catch (err) {
        return next(err);
    }
});

/**
 * POST /api/system/reload
 * Body: { scope?: 'all' | 'records' | 'dns-servers' }
 * Full rebuild of the selected in-memory collections from DB.
 */
router.post('/reload', async (req, res, next) => {
    try {
        const scope = req.body?.scope ?? 'all';
        const allowed = new Set(['all', 'records', 'dns-servers']);

        if (!allowed.has(scope)) {
            return res.status(400).json({
                error: `scope must be one of: ${[...allowed].join(', ')}`
            });
        }

        if (scope === 'all' || scope === 'records') {
            await loadRecords();
        }

        if (scope === 'all' || scope === 'dns-servers') {
            await loadDnsServers();
        }

        return res.json({
            ok: true,
            scope,
            ...memoryCounts()
        });
    } catch (err) {
        return next(err);
    }
});

export default router;
