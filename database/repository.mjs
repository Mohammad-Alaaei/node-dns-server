import { all, get, run, transaction } from './sqlite.mjs';
import { store } from '../memory/store.mjs';
import { RECORD_SOURCE, RECORD_STATUS } from '../config/constants.mjs';

/* -------------------------------------------------------------------------- */
/*                                   Hits                                     */
/* -------------------------------------------------------------------------- */

export async function incrementHits(domain) {

    await run(`
        UPDATE records
        SET
            hits = hits + 1,
            last_hit = ?
        WHERE domain = ?
    `, [
        Date.now(),
        domain
    ]);
}

/* -------------------------------------------------------------------------- */
/*                                  Loading                                   */
/* -------------------------------------------------------------------------- */

export async function loadRecords() {

    store.exactRecords.clear();
    store.regexRecords.length = 0;

    const rows = await all(`
        SELECT

            r.id,
            r.domain,
            r.enabled,
            r.is_regex,
            r.source,
            r.hits,
            r.last_hit,
            r.created_at,
            r.updated_at,

            rv.dns_server_id,
            rv.type,
            rv.status,
            rv.selected,
            rv.value,
            rv.ttl,
            rv.expires_at,
            rv.is_stale,
            rv.last_success_at,
            ds.average_latency

        FROM records r

        LEFT JOIN record_values rv
            ON rv.record_id = r.id

        LEFT JOIN dns_servers ds
            ON ds.id = rv.dns_server_id

        WHERE
            (
            r.enabled = 1
            AND (
                rv.id IS NULL
                OR rv.selected = 1
            )) OR r.source = "${RECORD_SOURCE.LOCAL}"

        ORDER BY
            r.is_regex ASC,
            LENGTH(r.domain) DESC,
            r.domain ASC,

            rv.selected DESC,
            ds.average_latency ASC,
            rv.last_success_at DESC
    `);

    for (const row of rows) {

        // Only SUCCESS and FILTERED values are usable for answers.
        if (
            row.status != null &&
            row.status !== RECORD_STATUS.SUCCESS &&
            row.status !== RECORD_STATUS.FILTERED
        ) {
            continue;
        }

        let record;

        const collection = row.is_regex
            ? store.regexRecords
            : store.exactRecords;

        if (row.is_regex) {

            record = collection.find(
                r => r.domain === row.domain
            );

            if (!record) {

                record = createRecord(row);
                record.regex = new RegExp(`^(?:${row.domain})$`, 'i');

                collection.push(record);
            }

        } else {
            record = collection.get(row.domain);

            if (!record) {
                record = createRecord(row);
                collection.set(
                    row.domain,
                    record
                );
            }
        }

        if (!row.type) {
            continue;
        }

        // SUCCESS and FILTERED both load values (FILTERED are stale fallbacks).
        if (
            row.status !== RECORD_STATUS.SUCCESS &&
            row.status !== RECORD_STATUS.FILTERED
        ) {
            continue;
        }

        let values = [];

        try {
            values = JSON.parse(row.value ?? '[]');
        } catch (err) {
            console.error(`Failed to load data`, {
                domain: row.domain,
                values: row.value
            }, err);

            throw new Error(err);
        }

        // Skip empty payloads.
        if (!values.length) {
            continue;
        }

        let server = record.servers.find(
            s => s.dnsServerId === row.dns_server_id
        );

        if (!server) {

            server = {
                dnsServerId: row.dns_server_id,
                selected: !!row.selected,
                status: row.status,
                isStale: !!row.is_stale,
                lastSuccessAt: row.last_success_at,

                A: [],
                AAAA: [],
                CNAME: []
            };

            record.servers.push(server);
        }

        switch (row.type) {
            case 'A':
                server.A.push(
                    ...values.map(address => ({
                        name: record.domain,
                        address,
                        ttl: row.ttl,
                        expiresAt: row.expires_at
                    }))
                );
                break;

            case 'AAAA':
                server.AAAA.push(
                    ...values.map(address => ({
                        name: record.domain,
                        address,
                        ttl: row.ttl,
                        expiresAt: row.expires_at
                    }))
                );
                break;

            case 'CNAME':
                server.CNAME.push(
                    ...values.map(domain => ({
                        name: record.domain,
                        domain,
                        ttl: row.ttl,
                        expiresAt: row.expires_at
                    }))
                );
                break;
        }
    }

    store.regexRecords.sort(
        (a, b) => b.domain.length - a.domain.length
    );

}

/* -------------------------------------------------------------------------- */
/*                                  Records                                   */
/* -------------------------------------------------------------------------- */

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

async function ensureRecord(record) {

    const now = Date.now();
    const source = record.source ?? RECORD_SOURCE.CACHE;

    // Automatic paths must never attach to a LOCAL row.
    // Lookup is scoped to domain + source (matches unique index).
    const existing = await get(`
        SELECT id, source
        FROM records
        WHERE domain = ?
          AND source = ?
    `, [
        record.domain,
        source
    ]);

    if (existing) {

        await run(`
            UPDATE records
            SET
                enabled = ?,
                is_regex = ?,
                hits = ?,
                last_hit = ?,
                updated_at = ?
            WHERE id = ?
        `, [
            record.enabled ?? 1,
            record.isRegex ? 1 : 0,
            record.hits ?? 0,
            record.lastHit,
            now,
            existing.id
        ]);

        return existing.id;
    }

    const result = await run(`
        INSERT INTO records(

            domain,
            enabled,
            is_regex,
            source,

            hits,
            last_hit,

            created_at,
            updated_at

        )
        VALUES(?,?,?,?,?,?,?,?)
    `, [

        record.domain,
        record.enabled ?? 1,
        record.isRegex ? 1 : 0,
        source,

        record.hits ?? 0,
        record.lastHit,

        now,
        now
    ]);

    return result.lastID;
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

    const existing = await get(`
        SELECT *
        FROM record_values
        WHERE
            record_id = ?
            AND dns_server_id IS ?
            AND type = ?
    `, [
        recordId,
        dnsServerId,
        type
    ]);

    let ttl = existing?.ttl ?? null;
    let expiresAt = existing?.expires_at ?? null;
    let value = existing?.value ?? null;
    let lastSuccessAt = existing?.last_success_at ?? null;
    let isStale = existing?.is_stale ?? 0;
    let selectedValue = existing?.selected ?? 0;

    if (
        status === RECORD_STATUS.SUCCESS &&
        values.length
    ) {

        ttl = Math.min(
            ...values.map(v => v.ttl ?? 300)
        );

        expiresAt = Math.min(
            ...values.map(
                v => v.expiresAt ?? (now + ttl * 1000)
            )
        );

        switch (type) {

            case 'A':
            case 'AAAA':
                value = JSON.stringify(
                    values.map(v => v.address)
                );
                break;

            case 'CNAME':
                value = JSON.stringify(
                    values.map(v => v.domain)
                );
                break;

            default:
                value = JSON.stringify(values);
        }

        lastSuccessAt = now;
        isStale = 0;          // SUCCESS clears stale for this type
        selectedValue = selected ? 1 : 0;
    }
    else if (status === RECORD_STATUS.FILTERED) {

        // Keep previous cached payload; only mark FILTERED + stale.
        // If there was no previous value, still store status as FILTERED.
        if (existing?.value != null) {
            value = existing.value;
            ttl = existing.ttl;
            expiresAt = existing.expires_at;
            lastSuccessAt = existing.last_success_at;
        }

        isStale = 1;
        selectedValue = existing?.selected ?? (selected ? 1 : 0);
    }
    else {
        // TIMEOUT / NXDOMAIN / SERVFAIL / REFUSED / empty
        const hasSuccessfulValue = existing?.last_success_at != null;

        if (existing && hasSuccessfulValue) {
            value = existing.value;
            ttl = existing.ttl;
            expiresAt = existing.expires_at;
            selectedValue = existing.selected;
            isStale = 1;
        }
        else {
            value = null;
            ttl = null;
            expiresAt = null;
            selectedValue = 0;
            isStale = 1;
        }
    }

    if (existing) {

        await run(`
            UPDATE record_values
            SET
                status = ?,
                selected = ?,
                is_stale = ?,
                value = ?,
                ttl = ?,
                expires_at = ?,
                updated_at = ?,
                last_success_at = ?
            WHERE id = ?
        `, [
            status,
            selectedValue,
            isStale,
            value,
            ttl,
            expiresAt,
            now,
            lastSuccessAt,
            existing.id
        ]);

        return;
    }

    await run(`
        INSERT INTO record_values(

            record_id,
            dns_server_id,

            type,
            status,
            selected,
            is_stale,

            value,
            ttl,
            expires_at,

            created_at,
            updated_at,
            last_success_at

        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
    `, [

        recordId,
        dnsServerId,

        type,
        status,
        selectedValue,
        isStale,

        value,
        ttl,
        expiresAt,

        now,
        now,
        lastSuccessAt
    ]);
}

async function clearSelected(recordId, type) {
    await run(`
        UPDATE record_values
        SET selected = 0
        WHERE
            record_id = ?
            AND type = ?
    `, [
        recordId,
        type
    ]);
}

async function updateRecordSource(recordId) {

    const record = await get(`
        SELECT source
        FROM records
        WHERE id = ?
    `, [recordId]);

    // LOCAL is permanent unless changed manually.
    if (!record || record.source === RECORD_SOURCE.LOCAL) {
        return;
    }

    const rows = await all(`
        SELECT status
        FROM record_values
        WHERE record_id = ?
    `, [recordId]);

    const source =
        rows.length &&
            rows.every(r => r.status === RECORD_STATUS.FILTERED)
            ? RECORD_SOURCE.FILTERED
            : RECORD_SOURCE.CACHE;

    await run(`
        UPDATE records
        SET
            source = ?,
            updated_at = ?
        WHERE id = ?
    `, [
        source,
        Date.now(),
        recordId
    ]);
}

export async function saveRecord(record) {

    // record.source is RECORD_SOURCE (CACHE | FILTERED), never LOCAL here.
    const status = record.source === RECORD_SOURCE.FILTERED
        ? RECORD_STATUS.FILTERED
        : RECORD_STATUS.SUCCESS;

    // Force CACHE/FILTERED source so ensureRecord never touches LOCAL rows.
    const source =
        record.source === RECORD_SOURCE.FILTERED
            ? RECORD_SOURCE.FILTERED
            : RECORD_SOURCE.CACHE;

    const recordId = await ensureRecord({
        ...record,
        source
    });

    if (record.A.length) {
        await clearSelected(recordId, 'A');
        await upsertRecordValue(recordId, record.dnsServerId, 'A', status, record.A, true);
    }

    if (record.AAAA.length) {
        await clearSelected(recordId, 'AAAA');
        await upsertRecordValue(recordId, record.dnsServerId, 'AAAA', status, record.AAAA, true);
    }

    if (record.CNAME.length) {
        await clearSelected(recordId, 'CNAME');
        await upsertRecordValue(recordId, record.dnsServerId, 'CNAME', status, record.CNAME, true);
    }

    await updateRecordSource(recordId);
}

export async function deleteRecord(domain) {

    await run(`
        DELETE FROM records
        WHERE domain = ?
    `, [domain]);

    await loadRecords();
}

export async function enableLocalRecord(domain) {

    await run(`
        UPDATE records
        SET
            enabled = 1,
            updated_at = ?
        WHERE
            domain = ?
            AND source = '${RECORD_SOURCE.LOCAL}'
    `, [
        Date.now(),
        domain
    ]);

    await loadRecords();
}

export async function disableLocalRecord(domain) {

    await run(`
        UPDATE records
        SET
            enabled = 0,
            updated_at = ?
        WHERE
            domain = ?
            AND source = '${RECORD_SOURCE.LOCAL}'
    `, [
        Date.now(),
        domain
    ]);

    await loadRecords();
}

export async function saveLookupStatus(
    domain,
    dnsServerId,
    type,
    status
) {

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

export async function setSelectedVariant(
    domain,
    dnsServerId,
    type
) {

    const record = await get(`
        SELECT id
        FROM records
        WHERE domain = ?
    `, [domain]);

    if (!record) {
        return;
    }

    await transaction(async () => {
        await run(`
            UPDATE record_values
            SET selected = 0
            WHERE
                record_id = ?
                AND type = ?
        `, [
            record.id,
            type
        ]);

        await run(`
            UPDATE record_values
            SET selected = 1
            WHERE
                record_id = ?
                AND dns_server_id IS ?
                AND type = ?
        `, [
            record.id,
            dnsServerId,
            type
        ]);

    });

    await loadRecords();
}

export async function promoteRecordToLocal(domain) {
    await run(`
        UPDATE records
        SET
            source = '${RECORD_SOURCE.LOCAL}',
            updated_at = ?
        WHERE domain = ?
    `, [
        Date.now(),
        domain
    ]);

    await loadRecords();
}

/* -------------------------------------------------------------------------- */
/*                               DNS Servers                                  */
/* -------------------------------------------------------------------------- */

export async function loadDnsServers() {

    store.customDnsServers.length = 0;
    store.defaultDnsServers.length = 0;

    const defaultServers = await all(`
        SELECT *
        FROM dns_servers
        WHERE
            enabled = 1
            AND type = 'DEFAULT'
        ORDER BY
            priority DESC,
            average_latency ASC
    `);

    store.defaultDnsServers.push(...defaultServers);

    const rows = await all(`
        SELECT
            dns_rules.domain,
            dns_rules.is_regex,

            dns_servers.id,
            dns_servers.ip,
            dns_servers.type,
            dns_servers.enabled,
            dns_servers.priority,
            dns_servers.average_latency,
            dns_servers.successes,
            dns_servers.failures,
            dns_servers.timeouts

        FROM dns_rules

        INNER JOIN dns_servers
            ON dns_servers.id = dns_rules.server_id

        WHERE
            dns_servers.enabled = 1

        ORDER BY
            LENGTH(dns_rules.domain) DESC,
            dns_rules.domain ASC,
            dns_servers.priority DESC,
            dns_servers.average_latency ASC
    `);

    for (const row of rows) {

        let group = store.customDnsServers.find(
            g => g.domain === row.domain
        );

        if (!group) {

            group = {
                domain: row.domain,
                isRegex: !!row.is_regex,
                regex: new RegExp(`^(?:${row.domain})$`, 'i'),
                servers: []
            };

            store.customDnsServers.push(group);
        }

        group.servers.push({
            id: row.id,
            ip: row.ip,
            type: row.type,
            enabled: row.enabled,
            priority: row.priority,
            average_latency: row.average_latency,
            successes: row.successes,
            failures: row.failures,
            timeouts: row.timeouts
        });
    }
}

export async function insertDnsServer(server) {

    const result = await run(`
        INSERT INTO dns_servers(
            ip,
            type,
            enabled,
            priority
        )
        VALUES(?,?,?,?)
    `, [
        server.ip,
        server.type,
        server.enabled ?? 1,
        server.priority ?? 0
    ]);

    return result.lastID;
}

export async function insertDnsRule(serverId, domain, isRegex) {

    await run(`
        INSERT INTO dns_rules(
            server_id,
            domain,
            is_regex
        )
        VALUES(?,?,?)
    `, [
        serverId,
        domain,
        isRegex ? 1 : 0
    ]);
}

export async function clearDnsConfiguration() {

    await transaction(async () => {

        await run(`DELETE FROM dns_rules`);
        await run(`DELETE FROM dns_servers`);

    });
}

export async function findDnsServer(ip) {

    return get(
        `SELECT * FROM dns_servers WHERE ip=?`,
        [ip]
    );
}

/* -------------------------------------------------------------------------- */
/*                             DNS Statistics                                 */
/* -------------------------------------------------------------------------- */

export async function recordDnsSuccess(ip, latency) {

    await run(`
        UPDATE dns_servers
        SET
            successes = successes + 1,
            average_latency =
                CASE
                    WHEN successes = 0 THEN ?
                    ELSE ((average_latency * successes) + ?) / (successes + 1)
                END
        WHERE ip = ?
    `, [
        latency,
        latency,
        ip
    ]);
}

export async function recordDnsFailure(ip) {

    await run(`
        UPDATE dns_servers
        SET failures = failures + 1
        WHERE ip = ?
    `, [ip]);
}

export async function recordDnsTimeout(ip) {

    await run(`
        UPDATE dns_servers
        SET timeouts = timeouts + 1
        WHERE ip = ?
    `, [ip]);
}

export async function getDnsServers() {
    return all(`
        SELECT *
        FROM dns_servers
        ORDER BY
            priority DESC,
            average_latency ASC
    `);
}