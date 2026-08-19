import { Op, fn, col, literal } from 'sequelize';
import { Record, DnsServer } from '../../../database/models/index.mjs';
import { RECORD_SOURCE, DNS_SERVER_TYPE } from '../../../config/constants.mjs';
import * as cacheService from '../../../services/cache_service.mjs';
import { memoryCounts, applyRecordPatchByIds } from '../../../memory/apply.mjs';
import { store } from '../../../memory/store.mjs';
import { listQuery } from '../utils/list_query.mjs';
import { httpError } from '../utils/http_errors.mjs';
import * as logger from '../../../utils/logger.mjs';

function normalizeIdList(ids) {
    if (!Array.isArray(ids)) return [];
    const out = [];
    const seen = new Set();
    for (const x of ids) {
        const n = Number(x);
        if (!Number.isFinite(n) || n < 1 || seen.has(n)) continue;
        seen.add(n);
        out.push(n);
    }
    return out;
}

function resetMemoryHits(idList) {
    if (idList.length) {
        applyRecordPatchByIds(idList, { hits: 0, lastHit: null });
        return;
    }
    for (const r of store.exactRecords.values()) {
        r.hits = 0;
        r.lastHit = null;
    }
    for (const r of store.regexRecords) {
        r.hits = 0;
        r.lastHit = null;
    }
}

class StatisticsService {
    async summary() {
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

        return {
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
        };
    }

    async dnsServers(query) {
        const result = await listQuery(
            query,
            {
                searchable: ['ip', 'type'],
                filterable: ['id', 'ip', 'type', 'enabled', 'priority'],
                sortable: [
                    'id', 'ip', 'type', 'enabled', 'priority',
                    'average_latency', 'successes', 'failures', 'timeouts'
                ],
                defaultSort: ['type', 'ASC'],
                fieldTypes: {
                    id: 'number',
                    enabled: 'boolean',
                    priority: 'number',
                    average_latency: 'number',
                    successes: 'number',
                    failures: 'number',
                    timeouts: 'number'
                }
            },
            ({ where, order, limit, offset }) =>
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
                    where,
                    order,
                    limit,
                    offset
                })
        );

        if (result.error) {
            throw httpError(result.error, result.status ?? 400);
        }

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

        return result;
    }

    async topRecords(queryIn) {
        const query = { ...queryIn };

        if (!query.sortBy && query.by) {
            const by = String(query.by).toLowerCase();
            if (by !== 'hits' && by !== 'last_hit') {
                throw httpError('by must be hits or last_hit', 400);
            }
            query.sortBy = by;
            query.sortDir = query.sortDir ?? 'DESC';
        }

        const result = await listQuery(
            query,
            {
                searchable: ['domain', 'source'],
                filterable: ['id', 'domain', 'enabled', 'source', 'hits'],
                sortable: ['id', 'domain', 'enabled', 'source', 'hits', 'last_hit', 'updated_at'],
                defaultSort: ['hits', 'DESC'],
                fieldTypes: {
                    id: 'number',
                    enabled: 'boolean',
                    hits: 'number',
                    last_hit: 'number',
                    updated_at: 'number'
                }
            },
            ({ where, order, limit, offset }) =>
                Record.findAndCountAll({
                    attributes: [
                        'id',
                        'domain',
                        'enabled',
                        'source',
                        'hits',
                        'last_hit',
                        'updated_at'
                    ],
                    where,
                    order,
                    limit,
                    offset
                }),
            { defaultLimit: 20, maxLimit: 100 }
        );

        if (result.error) {
            throw httpError(result.error, result.status ?? 400);
        }

        result.items = result.items.map(row => {
            const r = row.get ? row.get({ plain: true }) : row;
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

        return result;
    }

    async resetServers(ids, who) {
        const idList = normalizeIdList(ids);
        const where = idList.length ? { id: { [Op.in]: idList } } : {};

        const [affected] = await DnsServer.update(
            {
                successes: 0,
                failures: 0,
                timeouts: 0,
                average_latency: 0
            },
            { where }
        );

        logger.info(
            `[RESET] user=${who} action=reset_server_stats target=${idList.length ? idList.join(',') : 'ALL'} updated=${affected}`
        );

        return {
            ok: true,
            scope: idList.length ? 'selected' : 'all',
            requested: idList.length || null,
            updated: affected
        };
    }

    async resetRecords(ids, who) {
        const idList = normalizeIdList(ids);
        const where = idList.length ? { id: { [Op.in]: idList } } : {};

        const [affected] = await Record.update(
            {
                hits: 0,
                last_hit: null
            },
            { where }
        );

        resetMemoryHits(idList);

        logger.info(
            `[RESET] user=${who} action=reset_record_stats target=${idList.length ? idList.join(',') : 'ALL'} updated=${affected}`
        );

        return {
            ok: true,
            scope: idList.length ? 'selected' : 'all',
            requested: idList.length || null,
            updated: affected
        };
    }

    async resetAll(who) {
        const [serversUpdated] = await DnsServer.update(
            {
                successes: 0,
                failures: 0,
                timeouts: 0,
                average_latency: 0
            },
            { where: {} }
        );

        const [recordsUpdated] = await Record.update(
            {
                hits: 0,
                last_hit: null
            },
            { where: {} }
        );

        resetMemoryHits([]);

        logger.info(
            `[RESET] user=${who} action=reset_all_stats servers=${serversUpdated} records=${recordsUpdated}`
        );

        return {
            ok: true,
            serversUpdated,
            recordsUpdated
        };
    }
}

export default new StatisticsService();
