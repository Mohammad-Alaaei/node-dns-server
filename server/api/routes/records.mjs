import { Router } from 'express';
import { Op } from 'sequelize';
import { Record, RecordValue, DnsServer } from '../../../database/models/index.mjs';
import { RECORD_SOURCE, RECORD_STATUS } from '../../../config/constants.mjs';
import { authenticate, requireRole } from '../middleware/auth.mjs';
import { listQuery } from '../utils/list_query.mjs';
import { sendSequelizeError } from '../utils/http_errors.mjs';
import { normalizeDomain, prepareRuleDomain } from '../../../utils/domain_utils.mjs';
import {
    applyRecordPatchByIds,
    applyRecordReplace,
    applyRecordRemoveById
} from '../../../memory/apply.mjs';

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
const RECORDS_LIST_SCHEMA = {
    searchable: ['domain', 'source'],
    filterable: ['id', 'domain', 'enabled', 'source', 'hits'],
    sortable: ['id', 'domain', 'enabled', 'source', 'hits', 'last_hit', 'created_at', 'updated_at'],
    defaultSort: ['id', 'ASC'],
    fieldTypes: {
        id: 'number',
        enabled: 'boolean',
        hits: 'number',
        last_hit: 'number',
        created_at: 'number',
        updated_at: 'number'
    }
};

/**
 * GET /api/records?page=1&limit=20
 *   &searchField=domain&search=google
 *   &filter[source]=CACHE&filterLogic=AND
 *   &sortBy=hits&sortDir=DESC
 */
router.get('/', async (req, res, next) => {
    try {
        const result = await listQuery(
            req.query,
            RECORDS_LIST_SCHEMA,
            ({ where, order, limit, offset }) =>
                Record.findAndCountAll({
                    attributes: LIST_ATTRIBUTES,
                    where,
                    order,
                    limit,
                    offset
                })
        );

        if (result.error) {
            return res.status(result.status ?? 400).json({ error: result.error });
        }

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

            applyRecordPatchByIds(idList, {
                enabled,
                updatedAt: now
            });

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

            applyRecordPatchByIds(idList, {
                source: RECORD_SOURCE.LOCAL,
                updatedAt: now
            });

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

/**
 * POST /api/records/demote
 * Body: { ids: number[] }
 * LOCAL → CACHE (bulk). Does not touch record_values.
 */
router.post('/demote',
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
                    source: RECORD_SOURCE.CACHE,
                    updated_at: now
                },
                {
                    where: {
                        id: { [Op.in]: idList },
                        source: RECORD_SOURCE.LOCAL
                    }
                }
            );

            applyRecordPatchByIds(idList, {
                source: RECORD_SOURCE.CACHE,
                updatedAt: now
            });

            return res.json({
                ok: true,
                requested: idList.length,
                demoted: affected
            });
        } catch (err) {
            return next(err);
        }
    }
);

const VALUE_TYPES = new Set(['A', 'AAAA', 'CNAME']);

function encodeRecordValue(type, value) {
    if (!Array.isArray(value) || value.length === 0) {
        return { error: 'value must be a non-empty array' };
    }
    if (type === 'A' || type === 'AAAA') {
        const addrs = value.map(v => (typeof v === 'string' ? v : v?.address)).filter(Boolean);
        if (!addrs.length) return { error: 'value must contain addresses' };
        return { json: JSON.stringify(addrs) };
    }
    if (type === 'CNAME') {
        const domains = value.map(v => (typeof v === 'string' ? v : v?.domain)).filter(Boolean);
        if (!domains.length) return { error: 'value must contain domains' };
        return { json: JSON.stringify(domains) };
    }
    return { error: `unsupported type: ${type}` };
}

async function loadRecordWithValues(id) {
    return Record.findByPk(id, {
        include: [
            {
                model: RecordValue,
                as: 'values',
                required: false
            }
        ]
    });
}

async function syncRecordMemory(id) {
    const row = await loadRecordWithValues(id);
    if (!row) {
        applyRecordRemoveById(id);
        return null;
    }
    applyRecordReplace(row.get({ plain: true }));
    return row;
}

/**
 * POST /api/records
 * Create LOCAL record. Body: { domain, enabled?, values?: [{ type, value, ttl?, dns_server_id? }] }
 */
router.post('/',
    requireRole('superadmin', 'admin'),
    async (req, res, next) => {
        try {
            const prepared = prepareRuleDomain(req.body?.domain);
            if (prepared.error) {
                return res.status(400).json({ error: prepared.error });
            }

            const now = Date.now();
            const enabled = req.body?.enabled === undefined ? true : !!req.body.enabled;

            let created;
            try {
                created = await Record.create({
                    domain: prepared.domain,
                    enabled,
                    is_regex: prepared.is_regex,
                    source: RECORD_SOURCE.LOCAL,
                    hits: 0,
                    last_hit: null,
                    created_at: now,
                    updated_at: now
                });
            } catch (err) {
                const handled = sendSequelizeError(res, err);
                if (handled) return handled;
                throw err;
            }

            const rawValues = Array.isArray(req.body?.values) ? req.body.values : [];
            for (const item of rawValues) {
                const type = String(item?.type ?? '').toUpperCase();
                if (!VALUE_TYPES.has(type)) {
                    await created.destroy();
                    return res.status(400).json({ error: `invalid value type: ${type}` });
                }
                const enc = encodeRecordValue(type, item.value);
                if (enc.error) {
                    await created.destroy();
                    return res.status(400).json({ error: enc.error });
                }
                try {
                    await RecordValue.create({
                        record_id: created.id,
                        dns_server_id: item.dns_server_id ?? null,
                        type,
                        status: RECORD_STATUS.SUCCESS,
                        value: enc.json,
                        ttl: item.ttl ?? null,
                        selected: item.selected !== false,
                        is_stale: false,
                        last_success_at: now,
                        expires_at: null,
                        created_at: now,
                        updated_at: now
                    });
                } catch (err) {
                    await created.destroy();
                    const handled = sendSequelizeError(res, err);
                    if (handled) return handled;
                    throw err;
                }
            }

            const full = await syncRecordMemory(created.id);
            return res.status(201).json({
                record: serializeRecordDetail(full)
            });
        } catch (err) {
            return next(err);
        }
    }
);

/**
 * PATCH /api/records/:id
 * Body: { domain?, enabled? } — source via promote/demote only.
 */
router.patch('/:id',
    requireRole('superadmin', 'admin'),
    async (req, res, next) => {
        try {
            const id = Number.parseInt(String(req.params.id), 10);
            if (!Number.isFinite(id) || id < 1) {
                return res.status(400).json({ error: 'invalid id' });
            }

            const record = await Record.findByPk(id);
            if (!record) {
                return res.status(404).json({ error: 'Record not found' });
            }

            const updates = { updated_at: Date.now() };

            if (req.body?.domain !== undefined) {
                const prepared = prepareRuleDomain(req.body.domain);
                if (prepared.error) {
                    return res.status(400).json({ error: prepared.error });
                }
                updates.domain = prepared.domain;
                updates.is_regex = prepared.is_regex;
            }

            if (req.body?.enabled !== undefined) {
                updates.enabled = !!req.body.enabled;
            }

            try {
                await record.update(updates);
            } catch (err) {
                const handled = sendSequelizeError(res, err);
                if (handled) return handled;
                throw err;
            }

            const full = await syncRecordMemory(id);
            return res.json({ record: serializeRecordDetail(full) });
        } catch (err) {
            return next(err);
        }
    }
);

/**
 * DELETE /api/records/:id
 */
router.delete('/:id',
    requireRole('superadmin', 'admin'),
    async (req, res, next) => {
        try {
            const id = Number.parseInt(String(req.params.id), 10);
            if (!Number.isFinite(id) || id < 1) {
                return res.status(400).json({ error: 'invalid id' });
            }

            const record = await Record.findByPk(id);
            if (!record) {
                return res.status(404).json({ error: 'Record not found' });
            }

            // values cascade if FK on delete; otherwise explicit
            await RecordValue.destroy({ where: { record_id: id } });
            await record.destroy();
            applyRecordRemoveById(id);

            return res.json({ ok: true, id });
        } catch (err) {
            return next(err);
        }
    }
);

/**
 * POST /api/records/:id/values
 * Body: { type, value, ttl?, dns_server_id?, selected? }
 */
router.post('/:id/values',
    requireRole('superadmin', 'admin'),
    async (req, res, next) => {
        try {
            const id = Number.parseInt(String(req.params.id), 10);
            if (!Number.isFinite(id) || id < 1) {
                return res.status(400).json({ error: 'invalid id' });
            }

            const record = await Record.findByPk(id);
            if (!record) {
                return res.status(404).json({ error: 'Record not found' });
            }

            const type = String(req.body?.type ?? '').toUpperCase();
            if (!VALUE_TYPES.has(type)) {
                return res.status(400).json({ error: `type must be one of: ${[...VALUE_TYPES].join(', ')}` });
            }

            const enc = encodeRecordValue(type, req.body?.value);
            if (enc.error) {
                return res.status(400).json({ error: enc.error });
            }

            const now = Date.now();
            let row;
            try {
                row = await RecordValue.create({
                    record_id: id,
                    dns_server_id: req.body?.dns_server_id ?? null,
                    type,
                    status: RECORD_STATUS.SUCCESS,
                    value: enc.json,
                    ttl: req.body?.ttl ?? null,
                    selected: req.body?.selected !== false,
                    is_stale: false,
                    last_success_at: now,
                    expires_at: null,
                    created_at: now,
                    updated_at: now
                });
            } catch (err) {
                const handled = sendSequelizeError(res, err);
                if (handled) return handled;
                throw err;
            }

            await record.update({ updated_at: now });
            await syncRecordMemory(id);

            return res.status(201).json({
                value: {
                    id: row.id,
                    record_id: row.record_id,
                    dns_server_id: row.dns_server_id,
                    type: row.type,
                    status: row.status,
                    value: parseJsonValue(row.value),
                    ttl: row.ttl,
                    selected: !!row.selected,
                    is_stale: !!row.is_stale,
                    expires_at: row.expires_at
                }
            });
        } catch (err) {
            return next(err);
        }
    }
);

/**
 * PATCH /api/records/:id/values/:valueId
 * Body: { value?, ttl?, selected?, dns_server_id?, type? }
 * Unique (record_id, dns_server_id, type) enforced by DB.
 */
router.patch('/:id/values/:valueId',
    requireRole('superadmin', 'admin'),
    async (req, res, next) => {
        try {
            const id = Number.parseInt(String(req.params.id), 10);
            const valueId = Number.parseInt(String(req.params.valueId), 10);
            if (!Number.isFinite(id) || id < 1 || !Number.isFinite(valueId) || valueId < 1) {
                return res.status(400).json({ error: 'invalid id' });
            }

            const row = await RecordValue.findOne({
                where: { id: valueId, record_id: id }
            });
            if (!row) {
                return res.status(404).json({ error: 'Record value not found' });
            }

            const updates = { updated_at: Date.now() };

            if (req.body?.type !== undefined) {
                const type = String(req.body.type).toUpperCase();
                if (!VALUE_TYPES.has(type)) {
                    return res.status(400).json({ error: `invalid type: ${type}` });
                }
                updates.type = type;
            }

            if (req.body?.dns_server_id !== undefined) {
                updates.dns_server_id = req.body.dns_server_id;
            }

            if (req.body?.value !== undefined) {
                const type = updates.type ?? row.type;
                const enc = encodeRecordValue(type, req.body.value);
                if (enc.error) {
                    return res.status(400).json({ error: enc.error });
                }
                updates.value = enc.json;
                updates.status = RECORD_STATUS.SUCCESS;
                updates.is_stale = false;
                updates.last_success_at = Date.now();
            }

            if (req.body?.ttl !== undefined) {
                updates.ttl = req.body.ttl;
            }

            if (req.body?.selected !== undefined) {
                updates.selected = !!req.body.selected;
            }

            try {
                await row.update(updates);
            } catch (err) {
                const handled = sendSequelizeError(res, err);
                if (handled) return handled;
                throw err;
            }

            await Record.update(
                { updated_at: Date.now() },
                { where: { id } }
            );
            await syncRecordMemory(id);

            await row.reload();
            return res.json({
                value: {
                    id: row.id,
                    record_id: row.record_id,
                    dns_server_id: row.dns_server_id,
                    type: row.type,
                    status: row.status,
                    value: parseJsonValue(row.value),
                    ttl: row.ttl,
                    selected: !!row.selected,
                    is_stale: !!row.is_stale,
                    expires_at: row.expires_at
                }
            });
        } catch (err) {
            return next(err);
        }
    }
);

/**
 * DELETE /api/records/:id/values/:valueId
 */
router.delete('/:id/values/:valueId',
    requireRole('superadmin', 'admin'),
    async (req, res, next) => {
        try {
            const id = Number.parseInt(String(req.params.id), 10);
            const valueId = Number.parseInt(String(req.params.valueId), 10);
            if (!Number.isFinite(id) || id < 1 || !Number.isFinite(valueId) || valueId < 1) {
                return res.status(400).json({ error: 'invalid id' });
            }

            const deleted = await RecordValue.destroy({
                where: { id: valueId, record_id: id }
            });
            if (!deleted) {
                return res.status(404).json({ error: 'Record value not found' });
            }

            await Record.update(
                { updated_at: Date.now() },
                { where: { id } }
            );
            await syncRecordMemory(id);

            return res.json({ ok: true, id: valueId });
        } catch (err) {
            return next(err);
        }
    }
);


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

export default router;
