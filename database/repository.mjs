import { Op } from 'sequelize';
import { sequelize } from './connection.mjs';
import {
    DnsServer,
    DnsRule,
    Record,
    RecordValue,
    Setting
} from './models/index.mjs';
import { store } from '../memory/store.mjs';
import { RECORD_SOURCE, RECORD_STATUS, DNS_SERVER_TYPE } from '../config/constants.mjs';
import {
    config,
    getSystemSettingsDefaults,
    getUserSettingsDefaults
} from '../config/config.mjs';
import {
    SYSTEM_USER_ID,
    deepMerge,
    sanitizeSystemPatch,
    sanitizeUserPatch
} from '../config/settings_schema.mjs';

/* -------------------------------------------------------------------------- */
/*                                   Hits                                     */
/* -------------------------------------------------------------------------- */

export async function incrementHits(domain) {
    await Record.increment('hits', {
        by: 1,
        where: { domain }
    });

    await Record.update(
        { last_hit: Date.now() },
        { where: { domain } }
    );
}

/* -------------------------------------------------------------------------- */
/*                                  Loading                                   */
/* -------------------------------------------------------------------------- */

export async function loadRecords() {

    store.exactRecords.clear();
    store.regexRecords.length = 0;

    // Prefer LOCAL when ordering so ensureMemoryRecord keeps LOCAL source
    const rows = await Record.findAll({
        where: {
            [Op.or]: [
                { enabled: true },
                { source: RECORD_SOURCE.LOCAL }
            ]
        },
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
                        attributes: ['id', 'average_latency']
                    }
                ]
            }
        ],
        order: [
            // LOCAL first so it wins the in-memory map slot for a domain
            [sequelize.literal(`CASE WHEN source = '${RECORD_SOURCE.LOCAL}' THEN 0 ELSE 1 END`), 'ASC'],
            ['is_regex', 'ASC'],
            [sequelize.fn('LENGTH', sequelize.col('records.domain')), 'DESC'],
            ['domain', 'ASC']
        ]
    });

    for (const row of rows) {
        const values = row.values ?? [];
        const record = ensureMemoryRecord(row);

        for (const rv of values) {

            if (
                rv.status !== RECORD_STATUS.SUCCESS &&
                rv.status !== RECORD_STATUS.FILTERED
            ) {
                continue;
            }

            let parsed = [];

            try {
                parsed = JSON.parse(rv.value ?? '[]');
            } catch (err) {
                console.error('Failed to load data', {
                    domain: row.domain,
                    values: rv.value
                }, err);
                throw err;
            }

            if (!parsed.length) {
                continue;
            }

            let server = record.servers.find(
                s => s.dnsServerId === rv.dns_server_id
            );

            if (!server) {
                server = {
                    dnsServerId: rv.dns_server_id,
                    selected: !!rv.selected,
                    status: rv.status,
                    isStale: !!rv.is_stale,
                    lastSuccessAt: rv.last_success_at,
                    A: [],
                    AAAA: [],
                    CNAME: []
                };
                record.servers.push(server);
            }

            const mapped = parsed.map(item => {
                if (rv.type === 'CNAME') {
                    return {
                        name: record.domain,
                        domain: item,
                        ttl: rv.ttl,
                        expiresAt: rv.expires_at
                    };
                }
                return {
                    name: record.domain,
                    address: item,
                    ttl: rv.ttl,
                    expiresAt: rv.expires_at
                };
            });

            if (rv.type === 'A') server.A.push(...mapped);
            else if (rv.type === 'AAAA') server.AAAA.push(...mapped);
            else if (rv.type === 'CNAME') server.CNAME.push(...mapped);
        }
    }

    store.regexRecords.sort(
        (a, b) => b.domain.length - a.domain.length
    );
}

function ensureMemoryRecord(row) {
    const collection = row.is_regex
        ? store.regexRecords
        : store.exactRecords;

    if (row.is_regex) {
        let record = collection.find(r => r.domain === row.domain);

        if (!record) {
            record = createRecord(row);
            record.regex = new RegExp(`^(?:${row.domain})$`, 'i');
            collection.push(record);
            return record;
        }

        // Prefer LOCAL if a later row is LOCAL (should be rare with unique domain)
        if (
            row.source === RECORD_SOURCE.LOCAL &&
            record.source !== RECORD_SOURCE.LOCAL
        ) {
            record.id = row.id;
            record.source = RECORD_SOURCE.LOCAL;
            record.enabled = !!row.enabled;
            record.isRegex = !!row.is_regex;
        }

        return record;
    }

    let record = collection.get(row.domain);

    if (!record) {
        record = createRecord(row);
        collection.set(row.domain, record);
        return record;
    }

    if (
        row.source === RECORD_SOURCE.LOCAL &&
        record.source !== RECORD_SOURCE.LOCAL
    ) {
        record.id = row.id;
        record.source = RECORD_SOURCE.LOCAL;
        record.enabled = !!row.enabled;
        record.isRegex = !!row.is_regex;
    }

    return record;
}

function createRecord(row) {
    return {
        id: row.id,
        domain: row.domain,
        enabled: !!row.enabled,
        isRegex: !!row.is_regex,
        source: row.source,
        servers: [],
        hits: row.hits,
        lastHit: row.last_hit,
        createdAt: row.created_at,
        updatedAt: row.updated_at
    };
}

/* -------------------------------------------------------------------------- */
/*                                  Records                                   */
/* -------------------------------------------------------------------------- */

/**
 * One row per domain.
 * - Lookup by domain only
 * - Never change source away from LOCAL
 * - Cache paths do not create a second row
 */
async function ensureRecord(record) {
    const now = Date.now();
    const requestedSource = record.source ?? RECORD_SOURCE.CACHE;

    const existing = await Record.findOne({
        where: { domain: record.domain }
    });

    if (existing) {
        const updates = {
            hits: record.hits ?? existing.hits ?? 0,
            last_hit: record.lastHit ?? existing.last_hit,
            updated_at: now
        };

        // Never overwrite LOCAL with CACHE/FILTERED
        if (existing.source !== RECORD_SOURCE.LOCAL) {
            updates.enabled = record.enabled ?? true;
            updates.is_regex = !!record.isRegex;

            // Allow CACHE <-> FILTERED updates only when not LOCAL
            if (
                requestedSource === RECORD_SOURCE.CACHE ||
                requestedSource === RECORD_SOURCE.FILTERED
            ) {
                // source is finalized by updateRecordSource after values write
            }
        }

        await existing.update(updates);
        return existing.id;
    }

    // New domain — use requested source (CACHE/FILTERED/LOCAL)
    const created = await Record.create({
        domain: record.domain,
        enabled: record.enabled ?? true,
        is_regex: !!record.isRegex,
        source: requestedSource,
        hits: record.hits ?? 0,
        last_hit: record.lastHit ?? null,
        created_at: now,
        updated_at: now
    });

    return created.id;
}

async function upsertRecordValue(
    recordId,
    dnsServerId,
    type,
    status,
    values,
    selected = false
) {
    const now = Date.now();
    const serverId = dnsServerId ?? null;

    const lookup = {
        record_id: recordId,
        dns_server_id: serverId,
        type
    };

    let existing = await RecordValue.findOne({ where: lookup });

    let ttl = existing?.ttl ?? null;
    let expiresAt = existing?.expires_at ?? null;
    let value = existing?.value ?? null;
    let lastSuccessAt = existing?.last_success_at ?? null;
    let isStale = existing?.is_stale ?? false;
    let selectedValue = existing?.selected ?? false;

    if (status === RECORD_STATUS.SUCCESS && values.length) {
        ttl = Math.min(...values.map(v => v.ttl ?? 300));
        expiresAt = Math.min(
            ...values.map(v => v.expiresAt ?? (now + ttl * 1000))
        );

        switch (type) {
            case 'A':
            case 'AAAA':
                value = JSON.stringify(values.map(v => v.address));
                break;
            case 'CNAME':
                value = JSON.stringify(values.map(v => v.domain));
                break;
            default:
                value = JSON.stringify(values);
        }

        lastSuccessAt = now;
        isStale = false;
        selectedValue = !!selected;
    }
    else if (status === RECORD_STATUS.FILTERED) {
        if (existing?.value != null) {
            value = existing.value;
            ttl = existing.ttl;
            expiresAt = existing.expires_at;
            lastSuccessAt = existing.last_success_at;
        }
        isStale = true;
        selectedValue = existing?.selected ?? !!selected;
    }
    else {
        // TIMEOUT / NXDOMAIN / SERVFAIL / REFUSED / empty
        if (existing && existing.last_success_at != null) {
            value = existing.value;
            ttl = existing.ttl;
            expiresAt = existing.expires_at;
            selectedValue = existing.selected;
            isStale = true;
        } else {
            value = null;
            ttl = null;
            expiresAt = null;
            selectedValue = false;
            isStale = true;
        }
    }

    const payload = {
        status,
        selected: selectedValue,
        is_stale: isStale,
        value,
        ttl,
        expires_at: expiresAt,
        updated_at: now,
        last_success_at: lastSuccessAt
    };

    if (existing) {
        await existing.update(payload);
        return;
    }

    try {
        await RecordValue.create({
            record_id: recordId,
            dns_server_id: serverId,
            type,
            ...payload,
            created_at: now
        });
    } catch (err) {
        // Concurrent insert won the race — update that row instead
        if (err.name === 'SequelizeUniqueConstraintError') {
            existing = await RecordValue.findOne({ where: lookup });
            if (existing) {
                await existing.update(payload);
                return;
            }
        }
        throw err;
    }
}

async function clearSelected(recordId, type) {
    await RecordValue.update(
        { selected: false },
        {
            where: {
                record_id: recordId,
                type
            }
        }
    );
}

async function updateRecordSource(recordId) {
    const record = await Record.findByPk(recordId);

    // LOCAL is permanent unless changed manually.
    if (!record || record.source === RECORD_SOURCE.LOCAL) {
        return;
    }

    const rows = await RecordValue.findAll({
        where: { record_id: recordId },
        attributes: ['status']
    });

    const source =
        rows.length &&
            rows.every(r => r.status === RECORD_STATUS.FILTERED)
            ? RECORD_SOURCE.FILTERED
            : RECORD_SOURCE.CACHE;

    await record.update({
        source,
        updated_at: Date.now()
    });
}

export async function saveRecord(record) {
    // Refuse to cache-write when a LOCAL row already exists for this domain
    const existing = await Record.findOne({
        where: { domain: record.domain }
    });

    if (existing?.source === RECORD_SOURCE.LOCAL) {
        return;
    }

    const status = record.source === RECORD_SOURCE.FILTERED
        ? RECORD_STATUS.FILTERED
        : RECORD_STATUS.SUCCESS;

    const source = record.source === RECORD_SOURCE.FILTERED
        ? RECORD_SOURCE.FILTERED
        : RECORD_SOURCE.CACHE;

    const recordId = await ensureRecord({
        ...record,
        source
    });

    if (record.A?.length) {
        await clearSelected(recordId, 'A');
        await upsertRecordValue(recordId, record.dnsServerId, 'A', status, record.A, true);
    }

    if (record.AAAA?.length) {
        await clearSelected(recordId, 'AAAA');
        await upsertRecordValue(recordId, record.dnsServerId, 'AAAA', status, record.AAAA, true);
    }

    if (record.CNAME?.length) {
        await clearSelected(recordId, 'CNAME');
        await upsertRecordValue(recordId, record.dnsServerId, 'CNAME', status, record.CNAME, true);
    }

    await updateRecordSource(recordId);
}

export async function deleteRecord(domain) {
    await Record.destroy({ where: { domain } });
    await loadRecords();
}

export async function enableLocalRecord(domain) {
    await Record.update(
        { enabled: true, updated_at: Date.now() },
        {
            where: {
                domain,
                source: RECORD_SOURCE.LOCAL
            }
        }
    );
    await loadRecords();
}

export async function disableLocalRecord(domain) {
    await Record.update(
        { enabled: false, updated_at: Date.now() },
        {
            where: {
                domain,
                source: RECORD_SOURCE.LOCAL
            }
        }
    );
    await loadRecords();
}

export async function saveLookupStatus(domain, dnsServerId, type, status) {
    const existing = await Record.findOne({
        where: { domain }
    });

    // Do not attach lookup noise to LOCAL domains
    if (existing?.source === RECORD_SOURCE.LOCAL) {
        return;
    }

    const recordId = await ensureRecord({
        domain,
        source: RECORD_SOURCE.CACHE
    });

    await upsertRecordValue(
        recordId,
        dnsServerId,
        type,
        status,
        [],
        false
    );

    await updateRecordSource(recordId);
}

export async function setSelectedVariant(domain, dnsServerId, type) {
    const record = await Record.findOne({ where: { domain } });

    if (!record) {
        return;
    }

    await sequelize.transaction(async (t) => {
        await RecordValue.update(
            { selected: false },
            {
                where: {
                    record_id: record.id,
                    type
                },
                transaction: t
            }
        );

        await RecordValue.update(
            { selected: true },
            {
                where: {
                    record_id: record.id,
                    dns_server_id: dnsServerId ?? null,
                    type
                },
                transaction: t
            }
        );
    });

    await loadRecords();
}

export async function promoteRecordToLocal(domain) {
    await Record.update(
        {
            source: RECORD_SOURCE.LOCAL,
            updated_at: Date.now()
        },
        { where: { domain } }
    );
    await loadRecords();
}

/* -------------------------------------------------------------------------- */
/*                               DNS Servers                                  */
/* -------------------------------------------------------------------------- */

export async function loadDnsServers() {
    store.customDnsServers.length = 0;
    store.defaultDnsServers.length = 0;

    const defaultServers = await DnsServer.findAll({
        where: {
            enabled: true,
            type: DNS_SERVER_TYPE.DEFAULT
        },
        order: [
            ['priority', 'DESC'],
            ['average_latency', 'ASC']
        ]
    });

    store.defaultDnsServers.push(
        ...defaultServers.map(s => s.get({ plain: true }))
    );

    const rules = await DnsRule.findAll({
        include: [
            {
                model: DnsServer,
                as: 'server',
                required: true,
                where: { enabled: true }
            }
        ],
        order: [
            [sequelize.fn('LENGTH', sequelize.col('dns_rules.domain')), 'DESC'],
            ['domain', 'ASC'],
            [{ model: DnsServer, as: 'server' }, 'priority', 'DESC'],
            [{ model: DnsServer, as: 'server' }, 'average_latency', 'ASC']
        ]
    });

    for (const row of rules) {
        let group = store.customDnsServers.find(g => g.domain === row.domain);

        if (!group) {
            group = {
                domain: row.domain,
                isRegex: !!row.is_regex,
                regex: new RegExp(`^(?:${row.domain})$`, 'i'),
                servers: []
            };
            store.customDnsServers.push(group);
        }

        const s = row.server;
        group.servers.push({
            id: s.id,
            ip: s.ip,
            type: s.type,
            enabled: s.enabled,
            priority: s.priority,
            average_latency: s.average_latency,
            successes: s.successes,
            failures: s.failures,
            timeouts: s.timeouts
        });
    }
}

export async function insertDnsServer(server) {
    const created = await DnsServer.create({
        ip: server.ip,
        type: server.type,
        enabled: server.enabled ?? true,
        priority: server.priority ?? 0
    });
    return created.id;
}

export async function insertDnsRule(serverId, domain, isRegex) {
    await DnsRule.create({
        server_id: serverId,
        domain,
        is_regex: !!isRegex
    });
}

export async function clearDnsConfiguration() {
    await sequelize.transaction(async (t) => {
        await DnsRule.destroy({ where: {}, transaction: t });
        await DnsServer.destroy({ where: {}, transaction: t });
    });
}

export async function findDnsServer(ip) {
    const row = await DnsServer.findOne({ where: { ip } });
    return row ? row.get({ plain: true }) : null;
}

/* -------------------------------------------------------------------------- */
/*                             DNS Statistics                                 */
/* -------------------------------------------------------------------------- */

export async function recordDnsSuccess(ip, latency) {
    const server = await DnsServer.findOne({ where: { ip } });
    if (!server) return;

    const successes = server.successes;
    const average =
        successes === 0
            ? latency
            : ((server.average_latency * successes) + latency) / (successes + 1);

    await server.update({
        successes: successes + 1,
        average_latency: average
    });
}

export async function recordDnsFailure(ip) {
    await DnsServer.increment('failures', {
        by: 1,
        where: { ip }
    });
}

export async function recordDnsTimeout(ip) {
    await DnsServer.increment('timeouts', {
        by: 1,
        where: { ip }
    });
}

export async function getDnsServers() {
    const rows = await DnsServer.findAll({
        order: [
            ['priority', 'DESC'],
            ['average_latency', 'ASC']
        ]
    });
    return rows.map(r => r.get({ plain: true }));
}

/* -------------------------------------------------------------------------- */
/*                                 Settings                                   */
/* -------------------------------------------------------------------------- */

function parseSettingsJson(raw) {
    if (raw == null || raw === '') {
        return {};
    }
    try {
        const v = typeof raw === 'string' ? JSON.parse(raw) : raw;
        return v && typeof v === 'object' && !Array.isArray(v) ? v : {};
    } catch {
        return {};
    }
}

/**
 * Load system settings from DB (user_id = 0) and merge into config.system in-place.
 * config.system remains the single runtime source of truth.
 */
export async function loadSystemSettings() {
    const row = await Setting.findByPk(SYSTEM_USER_ID);
    const fromDb = row ? parseSettingsJson(row.value) : {};
    const merged = deepMerge(getSystemSettingsDefaults(), fromDb);

    // Mutate nested objects so existing references to config.system.* stay valid
    Object.assign(config.system.cache, merged.cache);
    config.system.ignoreIps = [...(merged.ignoreIps ?? [])];
    Object.assign(config.system.dns, merged.dns);
    Object.assign(config.system.server, merged.server);

    return structuredClone(config.system);
}

/** Current system settings (same object as config.system). */
export function getSystemSettings() {
    return structuredClone(config.system);
}

/**
 * Validate, merge into config.system, persist full JSON for user_id = 0.
 */
export async function patchSystemSettings(patch) {
    const sanitized = sanitizeSystemPatch(patch);
    if (sanitized.error) {
        return sanitized;
    }

    const next = deepMerge(structuredClone(config.system), sanitized.data);

    Object.assign(config.system.cache, next.cache);
    config.system.ignoreIps = [...(next.ignoreIps ?? [])];
    Object.assign(config.system.dns, next.dns);
    Object.assign(config.system.server, next.server);

    const now = Date.now();
    await Setting.upsert({
        user_id: SYSTEM_USER_ID,
        value: JSON.stringify(config.system),
        updated_at: now
    });

    return { data: structuredClone(config.system) };
}

export async function getUserSettings(userId) {
    if (!userId || userId === SYSTEM_USER_ID) {
        return getUserSettingsDefaults();
    }

    const row = await Setting.findByPk(userId);
    const fromDb = row ? parseSettingsJson(row.value) : {};
    return deepMerge(getUserSettingsDefaults(), fromDb);
}

export async function patchUserSettings(userId, patch) {
    if (!userId || userId === SYSTEM_USER_ID) {
        return { error: 'invalid user id', status: 400 };
    }

    const sanitized = sanitizeUserPatch(patch);
    if (sanitized.error) {
        return { error: sanitized.error, status: 400 };
    }

    const current = await getUserSettings(userId);
    const next = deepMerge(current, sanitized.data);
    const now = Date.now();

    await Setting.upsert({
        user_id: userId,
        value: JSON.stringify(next),
        updated_at: now
    });

    return { data: next };
}
