import { Router } from 'express';
import { Op } from 'sequelize';
import { Record, RecordValue, DnsServer } from '../../../database/models/index.mjs';
import { RECORD_SOURCE } from '../../../config/constants.mjs';
import { normalizeDomain } from '../../../utils/domain_utils.mjs';
import { store } from '../../../memory/store.mjs';
import { authenticate, requireRole } from '../middleware/auth.mjs';
import { paginateQuery } from '../utils/pagination.mjs';

const router = Router();

const LIST_ATTRIBUTES = [
    'id',
    'domain',
    'enabled',
    'source',
    'hits',
    'last_hit',
    'created_at',
    'updated_at'
];

const DETAIL_ATTRIBUTES = [
    ...LIST_ATTRIBUTES,
    'is_regex'
];

/** Upstream fields exposed on record detail / resolvedServers. */
const DNS_SERVER_ATTRIBUTES = [
    'id',
    'ip',
    'enabled',
    'priority'
];

router.use(authenticate, requireRole('superadmin', 'admin', 'viewer'));

/**
 * GET /api/records?page=1&limit=20
 * Brief list for the records page (no is_regex, no values).
 */
router.get('/', async (req, res, next) => {
    try {
        const result = await paginateQuery(req.query, ({ limit, offset }) =>
            Record.findAndCountAll({
                attributes: LIST_ATTRIBUTES,
                order: [
                    ['updated_at', 'DESC'],
                    ['id', 'DESC']
                ],
                limit,
                offset
            })
        );

        result.items = result.items.map(row => {
            const plain = row.get ? row.get({ plain: true }) : row;
            return plain;
        });

        return res.json(result);
    } catch (err) {
        return next(err);
    }
});

/**
 * PATCH /api/records/enabled
 * Body: { ids: number[], enabled: boolean }
 * Bulk enable/disable. DB only for now (in-memory left for a later pass).
 */
router.patch(
    '/enabled',
    requireRole('superadmin', 'admin'),
    async (req, res, next) => {
        try {
            const { ids, enabled } = req.body ?? {};

            const idList = normalizeIdList(ids);
            if (!idList.length) {
                return res.status(400).json({ error: 'ids must be a non-empty array of numbers' });
            }

            if (typeof enabled !== 'boolean') {
                return res.status(400).json({ error: 'enabled must be a boolean' });
            }

            const now = Date.now();
            const [affected] = await Record.update(
                { enabled, updated_at: now },
                { where: { id: { [Op.in]: idList } } }
            );

            // Best-effort in-memory flag so resolver sees disable without full reload
            patchMemoryByIds(idList, { enabled });

            return res.json({
                ok: true,
                enabled,
                requested: idList.length,
                updated: affected
            });
        } catch (err) {
            return next(err);
        }
    }
);

/**
 * POST /api/records/promote
 * Body: { ids: number[] }
 * Sets source=LOCAL on selected rows only. Does not touch record_values.
 * Only CACHE / FILTERED rows are promoted (already-LOCAL skipped).
 */
router.post(
    '/promote',
    requireRole('superadmin', 'admin'),
    async (req, res, next) => {
        try {
            const idList = normalizeIdList(req.body?.ids);
            if (!idList.length) {
                return res.status(400).json({ error: 'ids must be a non-empty array of numbers' });
            }

            const now = Date.now();
            const [affected] = await Record.update(
                {
                    source: RECORD_SOURCE.LOCAL,
                    updated_at: now
                },
                {
                    where: {
                        id: { [Op.in]: idList },
                        source: {
                            [Op.in]: [RECORD_SOURCE.CACHE, RECORD_SOURCE.FILTERED]
                        }
                    }
                }
            );

            patchMemoryByIds(idList, { source: RECORD_SOURCE.LOCAL });

            return res.json({
                ok: true,
                requested: idList.length,
                promoted: affected
            });
        } catch (err) {
            return next(err);
        }
    }
);

/**
 * GET /api/records/:id
 * Full record + all record_values (every status).
 * If any value is CNAME, recursively include those domains' records + values.
 */
router.get('/:id', async (req, res, next) => {
    try {
        const id = Number.parseInt(String(req.params.id), 10);
        if (!Number.isFinite(id) || id < 1) {
            return res.status(400).json({ error: 'invalid id' });
        }

        const record = await Record.findByPk(id, {
            attributes: DETAIL_ATTRIBUTES,
            include: [
                {
                    model: RecordValue,
                    as: 'values',
                    required: false,
                    include: [
                        {
                            model: DnsServer,
                            as: 'dnsServer',
                            required: false,
                            attributes: DNS_SERVER_ATTRIBUTES
                        }
                    ]
                }
            ]
        });

        if (!record) {
            return res.status(404).json({ error: 'Record not found' });
        }

        const plain = serializeRecordDetail(record);
        const resolvedServers = pickResolvedServers(plain.values);
        const cnameChain = await resolveCnameChain(plain);

        return res.json({
            record: plain,
            /** Upstream(s) currently selected to answer this domain (if any). */
            resolvedServers,
            cnameChain
        });
    } catch (err) {
        return next(err);
    }
});

/* -------------------------------------------------------------------------- */
/*                                   helpers                                  */
/* -------------------------------------------------------------------------- */

function normalizeIdList(ids) {
    if (!Array.isArray(ids)) {
        return [];
    }

    const out = [];
    const seen = new Set();

    for (const raw of ids) {
        const n = Number(raw);
        if (!Number.isFinite(n) || n < 1 || seen.has(n)) {
            continue;
        }
        seen.add(n);
        out.push(n);
    }

    return out;
}

function serializeDnsServer(server) {
    if (!server) {
        return null;
    }

    const s = server.get ? server.get({ plain: true }) : server;

    return {
        id: s.id,
        ip: s.ip,
        enabled: !!s.enabled,
        priority: s.priority
    };
}

function serializeRecordDetail(record) {
    const plain = record.get ? record.get({ plain: true }) : { ...record };
    plain.values = (plain.values ?? []).map(v => ({
        id: v.id,
        record_id: v.record_id,
        dns_server_id: v.dns_server_id,
        type: v.type,
        status: v.status,
        value: parseJsonValue(v.value),
        ttl: v.ttl,
        selected: !!v.selected,
        is_stale: !!v.is_stale,
        last_success_at: v.last_success_at,
        expires_at: v.expires_at,
        created_at: v.created_at,
        updated_at: v.updated_at,
        /** Upstream that produced this value row (null for pure LOCAL static answers). */
        dnsServer: serializeDnsServer(v.dnsServer)
    }));
    return plain;
}

/**
 * Servers that currently answer this domain: distinct dnsServer from values
 * where selected === true. Empty when LOCAL with no upstream id, or nothing selected.
 */
function pickResolvedServers(values) {
    const byId = new Map();

    for (const v of values ?? []) {
        if (!v.selected || !v.dnsServer) {
            continue;
        }
        byId.set(v.dnsServer.id, v.dnsServer);
    }

    return [...byId.values()];
}

function parseJsonValue(raw) {
    if (raw == null) {
        return null;
    }
    if (typeof raw !== 'string') {
        return raw;
    }
    try {
        return JSON.parse(raw);
    } catch {
        return raw;
    }
}

/**
 * Collect CNAME target domain strings from a detail record's values.
 */
function extractCnameTargets(detail) {
    const targets = [];

    for (const v of detail.values ?? []) {
        if (v.type !== 'CNAME' || v.value == null) {
            continue;
        }

        const list = Array.isArray(v.value) ? v.value : [v.value];
        for (const item of list) {
            const domain = typeof item === 'string'
                ? item
                : item?.domain ?? item?.name;
            if (domain) {
                targets.push(normalizeDomain(domain));
            }
        }
    }

    return targets;
}

/**
 * Walk CNAME targets recursively. Returns array of detail records
 * (same shape as main record, without nested cnameChain to avoid cycles).
 * Cycle-safe via visited set of domain names.
 */
async function resolveCnameChain(rootDetail, maxDepth = 16) {
    const chain = [];
    const visited = new Set([normalizeDomain(rootDetail.domain)]);
    let frontier = extractCnameTargets(rootDetail);
    let depth = 0;

    while (frontier.length && depth < maxDepth) {
        depth += 1;
        const nextFrontier = [];

        for (const domain of frontier) {
            if (!domain || visited.has(domain)) {
                continue;
            }
            visited.add(domain);

            const row = await Record.findOne({
                where: { domain },
                attributes: DETAIL_ATTRIBUTES,
                include: [
                    {
                        model: RecordValue,
                        as: 'values',
                        required: false,
                        include: [
                            {
                                model: DnsServer,
                                as: 'dnsServer',
                                required: false,
                                attributes: DNS_SERVER_ATTRIBUTES
                            }
                        ]
                    }
                ]
            });

            if (!row) {
                chain.push({
                    domain,
                    missing: true,
                    values: [],
                    resolvedServers: []
                });
                continue;
            }

            const detail = serializeRecordDetail(row);
            chain.push({
                ...detail,
                resolvedServers: pickResolvedServers(detail.values)
            });
            nextFrontier.push(...extractCnameTargets(detail));
        }

        frontier = nextFrontier;
    }

    return chain;
}

/**
 * Best-effort patch of in-memory store by record id.
 * Does not rebuild servers/values — only scalar fields (enabled, source, …).
 */
function patchMemoryByIds(ids, patch) {
    const idSet = new Set(ids);

    for (const record of store.exactRecords.values()) {
        if (record.id != null && idSet.has(record.id)) {
            Object.assign(record, patch);
            if (patch.source != null) {
                record.source = patch.source;
            }
            if (patch.enabled != null) {
                record.enabled = patch.enabled;
            }
        }
    }

    for (const record of store.regexRecords) {
        if (record.id != null && idSet.has(record.id)) {
            Object.assign(record, patch);
            if (patch.source != null) {
                record.source = patch.source;
            }
            if (patch.enabled != null) {
                record.enabled = patch.enabled;
            }
        }
    }
}

export default router;
