import { Op } from 'sequelize';
import { sequelize } from './connection.mjs';
import {
    DnsServer,
    DnsRule,
    Record,
    RecordValue
} from './models/index.mjs';
import { store } from '../memory/store.mjs';
import { RECORD_SOURCE, RECORD_STATUS } from '../config/constants.mjs';

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
        }
        return record;
    }

    let record = collection.get(row.domain);
    if (!record) {
        record = createRecord(row);
        collection.set(row.domain, record);
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
 * Lookup / create by (domain, source).
 * Cache paths never attach to a LOCAL row.
 */
async function ensureRecord(record) {
    const now = Date.now();
    const source = record.source ?? RECORD_SOURCE.CACHE;

    const existing = await Record.findOne({
        where: {
            domain: record.domain,
            source
        }
    });

    if (existing) {
        await existing.update({
            enabled: record.enabled ?? true,
            is_regex: !!record.isRegex,
            hits: record.hits ?? existing.hits ?? 0,
            last_hit: record.lastHit ?? existing.last_hit,
            updated_at: now
        });
        return existing.id;
    }

    const created = await Record.create({
        domain: record.domain,
        enabled: record.enabled ?? true,
        is_regex: !!record.isRegex,
        source,
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

    const existing = await RecordValue.findOne({
        where: {
            record_id: recordId,
            dns_server_id: dnsServerId ?? null,
            type
        }
    });

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
        isStale = false;          // SUCCESS clears stale for this type
        selectedValue = !!selected;
    }
    else if (status === RECORD_STATUS.FILTERED) {
        // Keep previous cached payload; mark FILTERED + stale.
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

    await RecordValue.create({
        record_id: recordId,
        dns_server_id: dnsServerId ?? null,
        type,
        ...payload,
        created_at: now
    });
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
    const status = record.source === RECORD_SOURCE.FILTERED
        ? RECORD_STATUS.FILTERED
        : RECORD_STATUS.SUCCESS;

    // Force CACHE/FILTERED so ensureRecord never touches LOCAL rows.
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
            type: 'DEFAULT'
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