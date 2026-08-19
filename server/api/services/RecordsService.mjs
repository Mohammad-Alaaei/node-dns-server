import { Op } from 'sequelize';
import { Record, RecordValue, DnsServer } from '../../../database/models/index.mjs';
import { RECORD_SOURCE, RECORD_STATUS } from '../../../config/constants.mjs';
import { listQuery } from '../utils/list_query.mjs';
import { httpError } from '../utils/http_errors.mjs';
import { normalizeDomain, prepareRuleDomain } from '../../../utils/domain_utils.mjs';
import {
    applyRecordPatchByIds,
    applyRecordReplace,
    applyRecordRemoveById
} from '../../../memory/apply.mjs';

function raiseSequelize(err) {
    if (err?.name === 'SequelizeUniqueConstraintError') {
        const fields = err.errors?.map(e => e.path).filter(Boolean) ?? [];
        const msg = fields.length
            ? `Duplicate value for: ${fields.join(', ')}`
            : 'Duplicate entry';
        throw httpError(msg, 409);
    }
    if (err?.name === 'SequelizeForeignKeyConstraintError') {
        throw httpError('Invalid reference (foreign key)', 400);
    }
    if (err?.name === 'SequelizeValidationError') {
        throw httpError('Validation failed', 400);
    }
    throw err;
}

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
/**
 * PATCH /api/records/enabled
 * Body: { ids: number[], enabled: boolean }
 * Bulk enable/disable. DB only for now (in-memory left for a later pass).
 */
/**
 * POST /api/records/promote
 * Body: { ids: number[] }
 * Sets source=LOCAL on selected rows only. Does not touch record_values.
 * Only CACHE / FILTERED rows are promoted (already-LOCAL skipped).
 */
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
/**
 * PATCH /api/records/:id
 * Body: { domain?, enabled? } — source via promote/demote only.
 */
/**
 * DELETE /api/records/:id
 */
/**
 * POST /api/records/:id/values
 * Body: { type, value, ttl?, dns_server_id?, selected? }
 */
/**
 * PATCH /api/records/:id/values/:valueId
 * Body: { value?, ttl?, selected?, dns_server_id?, type? }
 * Unique (record_id, dns_server_id, type) enforced by DB.
 */
/**
 * DELETE /api/records/:id/values/:valueId
 */
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


class RecordsService {
    async list(query) {
        const result = await listQuery(
            query,
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
            throw httpError(result.error, result.status ?? 400);
        }
        result.items = result.items.map(row => {
            const plain = row.get ? row.get({ plain: true }) : row;
            return plain;
        });
        return result;
    }

    async setEnabled(ids, enabled) {
        const idList = normalizeIdList(ids);
        if (!idList.length) {
            throw httpError('ids must be a non-empty array of numbers', 400);
        }
        if (typeof enabled !== 'boolean') {
            throw httpError('enabled must be a boolean', 400);
        }
        const now = Date.now();
        const [affected] = await Record.update(
            { enabled, updated_at: now },
            { where: { id: { [Op.in]: idList } } }
        );
        applyRecordPatchByIds(idList, { enabled, updatedAt: now });
        return { ok: true, enabled, requested: idList.length, updated: affected };
    }

    async promote(ids) {
        const idList = normalizeIdList(ids);
        if (!idList.length) {
            throw httpError('ids must be a non-empty array of numbers', 400);
        }
        const now = Date.now();
        const [affected] = await Record.update(
            { source: RECORD_SOURCE.LOCAL, updated_at: now },
            {
                where: {
                    id: { [Op.in]: idList },
                    source: { [Op.in]: [RECORD_SOURCE.CACHE, RECORD_SOURCE.FILTERED] }
                }
            }
        );
        applyRecordPatchByIds(idList, {
            source: RECORD_SOURCE.LOCAL,
            updatedAt: now
        });
        return { ok: true, requested: idList.length, promoted: affected };
    }

    async demote(ids) {
        const idList = normalizeIdList(ids);
        if (!idList.length) {
            throw httpError('ids must be a non-empty array of numbers', 400);
        }
        const now = Date.now();
        const [affected] = await Record.update(
            { source: RECORD_SOURCE.CACHE, updated_at: now },
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
        return { ok: true, requested: idList.length, demoted: affected };
    }

    async create(body) {
        const prepared = prepareRuleDomain(body?.domain);
        if (prepared.error) {
            throw httpError(prepared.error, 400);
        }
        const now = Date.now();
        const enabled = body?.enabled === undefined ? true : !!body.enabled;

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
            raiseSequelize(err);
        }

        const rawValues = Array.isArray(body?.values) ? body.values : [];
        for (const item of rawValues) {
            const type = String(item?.type ?? '').toUpperCase();
            if (!VALUE_TYPES.has(type)) {
                await created.destroy();
                throw httpError(`invalid value type: ${type}`, 400);
            }
            const enc = encodeRecordValue(type, item.value);
            if (enc.error) {
                await created.destroy();
                throw httpError(enc.error, 400);
            }
            try {
                await RecordValue.create({
                    record_id: created.id,
                    dns_server_id: item.dns_server_id ?? null,
                    type,
                    status: RECORD_STATUS.SUCCESS,
                    value: enc.json,
                    ttl: item.ttl ?? null,
                    selected: item.selected !== undefined ? !!item.selected : true,
                    is_stale: false,
                    expires_at: null,
                    last_success_at: now,
                    created_at: now,
                    updated_at: now
                });
            } catch (err) {
                await created.destroy();
                raiseSequelize(err);
            }
        }

        await syncRecordMemory(created.id);
        const detail = await this.getById(created.id);
        return { ...detail, status: 201 };
    }

    async update(rawId, body) {
        const id = Number.parseInt(String(rawId), 10);
        if (!Number.isFinite(id) || id < 1) {
            throw httpError('invalid id', 400);
        }
        const record = await Record.findByPk(id);
        if (!record) {
            throw httpError('Record not found', 404);
        }

        const updates = { updated_at: Date.now() };
        if (body?.domain !== undefined) {
            const prepared = prepareRuleDomain(body.domain);
            if (prepared.error) throw httpError(prepared.error, 400);
            updates.domain = prepared.domain;
            updates.is_regex = prepared.is_regex;
        }
        if (body?.enabled !== undefined) {
            updates.enabled = !!body.enabled;
        }
        if (body?.source !== undefined) {
            const src = String(body.source).toUpperCase();
            if (!Object.values(RECORD_SOURCE).includes(src)) {
                throw httpError(`source must be one of: ${Object.values(RECORD_SOURCE).join(', ')}`, 400);
            }
            updates.source = src;
        }

        try {
            await record.update(updates);
        } catch (err) {
            raiseSequelize(err);
        }

        await syncRecordMemory(id);
        return this.getById(id);
    }

    async remove(rawId) {
        const id = Number.parseInt(String(rawId), 10);
        if (!Number.isFinite(id) || id < 1) {
            throw httpError('invalid id', 400);
        }
        const deleted = await Record.destroy({ where: { id } });
        if (!deleted) {
            throw httpError('Record not found', 404);
        }
        applyRecordRemoveById(id);
        return { ok: true };
    }

    async addValue(rawId, body) {
        const id = Number.parseInt(String(rawId), 10);
        if (!Number.isFinite(id) || id < 1) {
            throw httpError('invalid id', 400);
        }
        const record = await Record.findByPk(id);
        if (!record) {
            throw httpError('Record not found', 404);
        }

        const type = String(body?.type ?? '').toUpperCase();
        if (!VALUE_TYPES.has(type)) {
            throw httpError(`invalid value type: ${type}`, 400);
        }
        const enc = encodeRecordValue(type, body?.value);
        if (enc.error) {
            throw httpError(enc.error, 400);
        }

        const now = Date.now();
        let row;
        try {
            row = await RecordValue.create({
                record_id: id,
                dns_server_id: body?.dns_server_id ?? null,
                type,
                status: RECORD_STATUS.SUCCESS,
                value: enc.json,
                ttl: body?.ttl ?? null,
                selected: body?.selected !== undefined ? !!body.selected : true,
                is_stale: false,
                expires_at: null,
                last_success_at: now,
                created_at: now,
                updated_at: now
            });
        } catch (err) {
            raiseSequelize(err);
        }

        await record.update({ updated_at: now });
        await syncRecordMemory(id);

        return {
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
            },
            status: 201
        };
    }

    async updateValue(rawId, rawValueId, body) {
        const id = Number.parseInt(String(rawId), 10);
        const valueId = Number.parseInt(String(rawValueId), 10);
        if (!Number.isFinite(id) || id < 1 || !Number.isFinite(valueId) || valueId < 1) {
            throw httpError('invalid id', 400);
        }

        const row = await RecordValue.findOne({
            where: { id: valueId, record_id: id }
        });
        if (!row) {
            throw httpError('Record value not found', 404);
        }

        const updates = { updated_at: Date.now() };

        if (body?.type !== undefined) {
            const type = String(body.type).toUpperCase();
            if (!VALUE_TYPES.has(type)) {
                throw httpError(`invalid type: ${type}`, 400);
            }
            updates.type = type;
        }

        if (body?.dns_server_id !== undefined) {
            updates.dns_server_id = body.dns_server_id;
        }

        if (body?.value !== undefined) {
            const type = updates.type ?? row.type;
            const enc = encodeRecordValue(type, body.value);
            if (enc.error) {
                throw httpError(enc.error, 400);
            }
            updates.value = enc.json;
            updates.status = RECORD_STATUS.SUCCESS;
            updates.is_stale = false;
            updates.last_success_at = Date.now();
        }

        if (body?.ttl !== undefined) {
            updates.ttl = body.ttl;
        }

        if (body?.selected !== undefined) {
            updates.selected = !!body.selected;
        }

        try {
            await row.update(updates);
        } catch (err) {
            raiseSequelize(err);
        }

        await Record.update({ updated_at: Date.now() }, { where: { id } });
        await syncRecordMemory(id);
        await row.reload();

        return {
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
        };
    }

    async deleteValue(rawId, rawValueId) {
        const id = Number.parseInt(String(rawId), 10);
        const valueId = Number.parseInt(String(rawValueId), 10);
        if (!Number.isFinite(id) || id < 1 || !Number.isFinite(valueId) || valueId < 1) {
            throw httpError('invalid id', 400);
        }

        const deleted = await RecordValue.destroy({
            where: { id: valueId, record_id: id }
        });
        if (!deleted) {
            throw httpError('Record value not found', 404);
        }

        await Record.update({ updated_at: Date.now() }, { where: { id } });
        await syncRecordMemory(id);
        return { ok: true };
    }

    async getById(rawId) {
        const id = Number.parseInt(String(rawId), 10);
        if (!Number.isFinite(id) || id < 1) {
            throw httpError('invalid id', 400);
        }

        const row = await Record.findByPk(id, {
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
            throw httpError('Record not found', 404);
        }

        const detail = serializeRecordDetail(row);
        const resolvedServers = pickResolvedServers(detail.values);
        const cnameChain = await resolveCnameChain(detail);

        return {
            record: {
                ...detail,
                resolvedServers,
                cnameChain
            }
        };
    }
}

export default new RecordsService();
