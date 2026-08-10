import { store } from './store.mjs';
import { DNS_SERVER_TYPE, RECORD_STATUS } from '../config/constants.mjs';

/**
 * Surgical in-memory updates so CRUD does not need a full store rebuild.
 * Full rebuild remains available via loadRecords / loadDnsServers (API /system/reload).
 */

/* -------------------------------------------------------------------------- */
/*                                  Records                                   */
/* -------------------------------------------------------------------------- */

/**
 * Patch scalar fields on in-memory records matched by DB id.
 */
export function applyRecordPatchByIds(ids, patch) {
    const idSet = new Set(ids);

    for (const record of store.exactRecords.values()) {
        if (record.id != null && idSet.has(record.id)) {
            applyRecordFields(record, patch);
        }
    }

    for (const record of store.regexRecords) {
        if (record.id != null && idSet.has(record.id)) {
            applyRecordFields(record, patch);
        }
    }
}

function applyRecordFields(record, patch) {
    if (patch.enabled != null) {
        record.enabled = !!patch.enabled;
    }
    if (patch.source != null) {
        record.source = patch.source;
    }
    if (patch.hits != null) {
        record.hits = patch.hits;
    }
    if (patch.lastHit != null) {
        record.lastHit = patch.lastHit;
    }
    if (patch.updatedAt != null) {
        record.updatedAt = patch.updatedAt;
    } else {
        record.updatedAt = Date.now();
    }
}

/* -------------------------------------------------------------------------- */
/*                                DNS servers                                 */
/* -------------------------------------------------------------------------- */

/**
 * Normalize a DB/plain server row to the shape used inside customDnsServers groups.
 */
export function toMemoryServer(server) {
    const s = server.get ? server.get({ plain: true }) : server;
    return {
        id: s.id,
        ip: s.ip,
        type: s.type,
        enabled: !!s.enabled,
        priority: s.priority ?? 0,
        average_latency: s.average_latency ?? 0,
        successes: s.successes ?? 0,
        failures: s.failures ?? 0,
        timeouts: s.timeouts ?? 0
    };
}

/**
 * After create/update of a dns_servers row: sync default list + any rule groups
 * that already reference this server id.
 */
export function applyDnsServerUpsert(server) {
    const mem = toMemoryServer(server);

    // DEFAULT pool: only enabled DEFAULT servers
    removeFromDefaultPool(mem.id);

    if (mem.enabled && mem.type === DNS_SERVER_TYPE.DEFAULT) {
        store.defaultDnsServers.push(plainDefault(server));
        sortDefaultPool();
    }

    // Update existing entries inside custom rule groups
    for (const group of store.customDnsServers) {
        const idx = group.servers.findIndex(s => s.id === mem.id);
        if (idx === -1) {
            continue;
        }

        if (!mem.enabled) {
            group.servers.splice(idx, 1);
        } else {
            group.servers[idx] = mem;
            sortGroupServers(group);
        }
    }

    // Drop empty groups
    pruneEmptyCustomGroups();
}

/**
 * Ensure server is not used as upstream in memory (e.g. after disable).
 * Prefer applyDnsServerUpsert with enabled:false when the full row is available.
 */
export function applyDnsServerRemovedFromMemory(serverId) {
    removeFromDefaultPool(serverId);

    for (const group of store.customDnsServers) {
        group.servers = group.servers.filter(s => s.id !== serverId);
    }

    pruneEmptyCustomGroups();
}

function plainDefault(server) {
    const s = server.get ? server.get({ plain: true }) : server;
    return { ...s, enabled: !!s.enabled };
}

function removeFromDefaultPool(serverId) {
    const i = store.defaultDnsServers.findIndex(s => s.id === serverId);
    if (i !== -1) {
        store.defaultDnsServers.splice(i, 1);
    }
}

function sortDefaultPool() {
    store.defaultDnsServers.sort((a, b) => {
        const p = (b.priority ?? 0) - (a.priority ?? 0);
        if (p !== 0) return p;
        return (a.average_latency ?? 0) - (b.average_latency ?? 0);
    });
}

function sortGroupServers(group) {
    group.servers.sort((a, b) => {
        const p = (b.priority ?? 0) - (a.priority ?? 0);
        if (p !== 0) return p;
        return (a.average_latency ?? 0) - (b.average_latency ?? 0);
    });
}

function pruneEmptyCustomGroups() {
    for (let i = store.customDnsServers.length - 1; i >= 0; i--) {
        if (!store.customDnsServers[i].servers.length) {
            store.customDnsServers.splice(i, 1);
        }
    }
}

/* -------------------------------------------------------------------------- */
/*                                  DNS rules                                 */
/* -------------------------------------------------------------------------- */

/**
 * Add or refresh a rule: domain group gets this server (if server enabled).
 * @param {object} rule — { id, domain, is_regex, server_id }
 * @param {object} server — full dns server row/plain
 * @param {string} [previousDomain] — if domain changed, remove from old group first
 */
export function applyDnsRuleUpsert(rule, server, previousDomain = null) {
    const r = rule.get ? rule.get({ plain: true }) : rule;
    const memServer = toMemoryServer(server);

    if (previousDomain && previousDomain !== r.domain) {
        removeServerFromDomainGroup(previousDomain, memServer.id);
    }

    // Disabled servers must not appear in custom routing
    if (!memServer.enabled) {
        removeServerFromDomainGroup(r.domain, memServer.id);
        pruneEmptyCustomGroups();
        return;
    }

    let group = store.customDnsServers.find(g => g.domain === r.domain);

    if (!group) {
        group = {
            domain: r.domain,
            isRegex: !!r.is_regex,
            regex: new RegExp(`^(?:${r.domain})$`, 'i'),
            servers: []
        };
        store.customDnsServers.push(group);
        sortCustomGroups();
    } else {
        group.isRegex = !!r.is_regex;
        group.regex = new RegExp(`^(?:${r.domain})$`, 'i');
    }

    const idx = group.servers.findIndex(s => s.id === memServer.id);
    if (idx === -1) {
        group.servers.push(memServer);
    } else {
        group.servers[idx] = memServer;
    }

    sortGroupServers(group);
}

/**
 * Remove a rule: drop this server from that domain group.
 */
export function applyDnsRuleRemove(domain, serverId) {
    removeServerFromDomainGroup(domain, serverId);
    pruneEmptyCustomGroups();
}

function removeServerFromDomainGroup(domain, serverId) {
    const group = store.customDnsServers.find(g => g.domain === domain);
    if (!group) {
        return;
    }

    group.servers = group.servers.filter(s => s.id !== serverId);
}

function sortCustomGroups() {
    // Longer patterns first (same as loadDnsServers / main sort)
    store.customDnsServers.sort(
        (a, b) => b.domain.length - a.domain.length || a.domain.localeCompare(b.domain)
    );
}

/* -------------------------------------------------------------------------- */
/*                                   Counts                                   */
/* -------------------------------------------------------------------------- */

export function memoryCounts() {
    return {
        exactRecords: store.exactRecords.size,
        regexRecords: store.regexRecords.length,
        defaultDnsServers: store.defaultDnsServers.length,
        customDnsServers: store.customDnsServers.length
    };
}

/* -------------------------------------------------------------------------- */
/*                     Full record replace / remove (CRUD)                      */
/* -------------------------------------------------------------------------- */


/**
 * Remove a memory record by DB id from both exact and regex collections.
 */
export function applyRecordRemoveById(id) {
    for (const [domain, record] of store.exactRecords.entries()) {
        if (record.id === id) {
            store.exactRecords.delete(domain);
        }
    }

    for (let i = store.regexRecords.length - 1; i >= 0; i--) {
        if (store.regexRecords[i].id === id) {
            store.regexRecords.splice(i, 1);
        }
    }
}

/**
 * Rebuild one in-memory record from a DB row + its values.
 * `row` plain: { id, domain, enabled, is_regex, source, hits, last_hit, created_at, updated_at, values?: [...] }
 */
export function applyRecordReplace(row) {
    if (!row?.id) {
        return;
    }

    applyRecordRemoveById(row.id);

    if (row.enabled === false && row.source !== 'LOCAL') {
        // disabled non-LOCAL still kept? loadRecords keeps enabled OR LOCAL.
        // Match loadRecords: skip disabled non-LOCAL
        // Actually load keeps LOCAL even if disabled. For non-LOCAL disabled, omit.
    }

    // Match loadRecords: keep LOCAL always; skip disabled non-LOCAL
    if (row.source !== 'LOCAL' && row.enabled === false) {
        return;
    }

    const record = {
        id: row.id,
        domain: row.domain,
        enabled: !!row.enabled,
        isRegex: !!row.is_regex,
        source: row.source,
        servers: [],
        hits: row.hits ?? 0,
        lastHit: row.last_hit ?? null,
        createdAt: row.created_at,
        updatedAt: row.updated_at
    };

    const values = row.values ?? [];

    for (const rv of values) {
        if (
            rv.status !== RECORD_STATUS.SUCCESS &&
            rv.status !== RECORD_STATUS.FILTERED &&
            rv.status !== 'SUCCESS' &&
            rv.status !== 'FILTERED'
        ) {
            continue;
        }

        let parsed = [];
        try {
            if (typeof rv.value === 'string') {
                parsed = JSON.parse(rv.value || '[]');
            } else if (Array.isArray(rv.value)) {
                parsed = rv.value;
            }
        } catch {
            continue;
        }

        if (!parsed.length) {
            continue;
        }

        let server = record.servers.find(
            s => s.dnsServerId === (rv.dns_server_id ?? null)
        );

        if (!server) {
            server = {
                dnsServerId: rv.dns_server_id ?? null,
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
                    domain: typeof item === 'string' ? item : item?.domain,
                    ttl: rv.ttl,
                    expiresAt: rv.expires_at
                };
            }
            return {
                name: record.domain,
                address: typeof item === 'string' ? item : item?.address,
                ttl: rv.ttl,
                expiresAt: rv.expires_at
            };
        });

        if (rv.type === 'A') server.A.push(...mapped);
        else if (rv.type === 'AAAA') server.AAAA.push(...mapped);
        else if (rv.type === 'CNAME') server.CNAME.push(...mapped);
    }

    if (record.isRegex) {
        record.regex = new RegExp(`^(?:${row.domain})$`, 'i');
        store.regexRecords.push(record);
        store.regexRecords.sort((a, b) => b.domain.length - a.domain.length);
    } else {
        store.exactRecords.set(row.domain, record);
    }
}
