import { Router } from 'express';
import { fn, col, literal } from 'sequelize';
import { Record, DnsServer } from '../../../database/models/index.mjs';
import { RECORD_SOURCE, DNS_SERVER_TYPE } from '../../../config/constants.mjs';
import * as cacheService from '../../../services/cache_service.mjs';
import { memoryCounts } from '../../../memory/apply.mjs';
import { authenticate, requireRole } from '../middleware/auth.mjs';
import { paginateQuery } from '../utils/pagination.mjs';

const router = Router();

router.use(authenticate, requireRole('superadmin', 'admin', 'viewer'));

const TOP_MAX = 100;
const TOP_DEFAULT = 20;

/**
 * GET /api/statistics/summary
 * Dashboard aggregates from DB + in-memory + process.
 */
router.get('/summary', async (req, res, next) => {
    try {
        const [
            totalRecords,
            enabledRecords,
            totalHitsRow,
            sourceRows,
            totalServers,
            enabledServers,
            typeRows,
            upstreamRow
        ] = await Promise.all([
            Record.count(),
            Record.count({ where: { enabled: true } }),
            Record.findOne({
                attributes: [[fn('COALESCE', fn('SUM', col('hits')), 0), 'totalHits']],
                raw: true
            }),
            Record.findAll({
                attributes: ['source', [fn('COUNT', col('id')), 'count']],
                group: ['source'],
                raw: true
            }),
            DnsServer.count(),
            DnsServer.count({ where: { enabled: true } }),
            DnsServer.findAll({
                attributes: ['type', [fn('COUNT', col('id')), 'count']],
                group: ['type'],
                raw: true
            }),
            DnsServer.findOne({
                attributes: [
                    [fn('COALESCE', fn('SUM', col('successes')), 0), 'successes'],
                    [fn('COALESCE', fn('SUM', col('failures')), 0), 'failures'],
                    [fn('COALESCE', fn('SUM', col('timeouts')), 0), 'timeouts'],
                    [
                        // Weighted-ish average across servers that have successes
                        literal(`
                            CASE
                              WHEN COALESCE(SUM(successes), 0) = 0 THEN 0
                              ELSE SUM(average_latency * successes) / SUM(successes)
                            END
                        `),
                        'avgLatencyMs'
                    ]
                ],
                raw: true
            })
        ]);

        const bySource = {
            [RECORD_SOURCE.LOCAL]: 0,
            [RECORD_SOURCE.CACHE]: 0,
            [RECORD_SOURCE.FILTERED]: 0
        };
        for (const row of sourceRows) {
            bySource[row.source] = Number(row.count) || 0;
        }

        const byType = {
            [DNS_SERVER_TYPE.DEFAULT]: 0,
            [DNS_SERVER_TYPE.CUSTOM]: 0
        };
        for (const row of typeRows) {
            byType[row.type] = Number(row.count) || 0;
        }

        const pending = typeof cacheService.getPendingCache === 'function'
            ? cacheService.getPendingCache()
            : [];

        const totalHits = Number(totalHitsRow?.totalHits) || 0;
        const successes = Number(upstreamRow?.successes) || 0;
        const failures = Number(upstreamRow?.failures) || 0;
        const timeouts = Number(upstreamRow?.timeouts) || 0;
        const avgLatencyMs = Number(upstreamRow?.avgLatencyMs) || 0;

        return res.json({
            records: {
                total: totalRecords,
                bySource,
                enabled: enabledRecords,
                disabled: Math.max(0, totalRecords - enabledRecords),
                totalHits
            },
            dnsServers: {
                total: totalServers,
                enabled: enabledServers,
                byType
            },
            upstream: {
                successes,
                failures,
                timeouts,
                avgLatencyMs: Math.round(avgLatencyMs * 100) / 100
            },
            memory: {
                ...memoryCounts(),
                pendingCache: pending.length
            },
            process: {
                uptimeSec: Math.floor(process.uptime()),
                pid: process.pid
            }
        });
    } catch (err) {
        return next(err);
    }
});

/**
 * GET /api/statistics/dns-servers?page=1&limit=20
 * Upstream health table (same counters as dns_servers rows).
 */
router.get('/dns-servers', async (req, res, next) => {
    try {
        const result = await paginateQuery(req.query, ({ limit, offset }) =>
            DnsServer.findAndCountAll({
                attributes: [
                    'id',
                    'ip',
                    'type',
                    'enabled',
                    'priority',
                    'average_latency',
                    'successes',
                    'failures',
                    'timeouts'
                ],
                order: [
                    ['type', 'ASC'],
                    ['priority', 'DESC'],
                    ['average_latency', 'ASC'],
                    ['id', 'ASC']
                ],
                limit,
                offset
            })
        );

        result.items = result.items.map(row => {
            const s = row.get ? row.get({ plain: true }) : row;
            return {
                id: s.id,
                ip: s.ip,
                type: s.type,
                enabled: !!s.enabled,
                priority: s.priority,
                average_latency: s.average_latency,
                successes: s.successes,
                failures: s.failures,
                timeouts: s.timeouts
            };
        });

        return res.json(result);
    } catch (err) {
        return next(err);
    }
});

/**
 * GET /api/statistics/top-records?by=hits|last_hit&limit=20
 * Top domains by hits or last_hit (fixed limit, not page-based).
 */
router.get('/top-records', async (req, res, next) => {
    try {
        const by = String(req.query.by ?? 'hits').toLowerCase();
        if (by !== 'hits' && by !== 'last_hit') {
            return res.status(400).json({ error: 'by must be hits or last_hit' });
        }

        let limit = Number.parseInt(String(req.query.limit ?? TOP_DEFAULT), 10);
        if (!Number.isFinite(limit) || limit < 1) {
            limit = TOP_DEFAULT;
        }
        if (limit > TOP_MAX) {
            limit = TOP_MAX;
        }

        const orderCol = by === 'last_hit' ? 'last_hit' : 'hits';

        const rows = await Record.findAll({
            attributes: [
                'id',
                'domain',
                'enabled',
                'source',
                'hits',
                'last_hit',
                'updated_at'
            ],
            order: [
                [orderCol, 'DESC'],
                ['id', 'DESC']
            ],
            limit
        });

        const items = rows.map(row => {
            const r = row.get({ plain: true });
            return {
                id: r.id,
                domain: r.domain,
                enabled: !!r.enabled,
                source: r.source,
                hits: r.hits,
                last_hit: r.last_hit,
                updated_at: r.updated_at
            };
        });

        return res.json({
            by,
            limit,
            items
        });
    } catch (err) {
        return next(err);
    }
});

export default router;
