import * as cacheService from '../../../services/cache_service.mjs';
import {
    loadRecords,
    loadDnsServers,
    loadRewriteRules
} from '../../../database/repository.mjs';
import { memoryCounts } from '../../../memory/apply.mjs';
import { httpError } from '../utils/http_errors.mjs';

class SystemService {
    async flush() {
        const pending = typeof cacheService.getPendingCache === 'function'
            ? cacheService.getPendingCache()
            : [];
        const pendingBefore = pending.length;
        await cacheService.flush();
        return { ok: true, pendingBefore };
    }

    async reload(scope = 'all') {
        const allowed = new Set([
            'all',
            'records',
            'dns-servers',
            'rewrite-rules'
        ]);
        if (!allowed.has(scope)) {
            throw httpError(
                `scope must be one of: ${[...allowed].join(', ')}`,
                400
            );
        }

        if (scope === 'all' || scope === 'records') {
            await loadRecords();
        }
        if (scope === 'all' || scope === 'dns-servers') {
            await loadDnsServers();
        }
        if (scope === 'all' || scope === 'rewrite-rules') {
            await loadRewriteRules();
        }

        return {
            ok: true,
            scope,
            ...memoryCounts()
        };
    }
}

export default new SystemService();
