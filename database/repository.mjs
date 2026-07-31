import { all, get, run, transaction } from './sqlite.mjs';
import { store } from '../memory/store.mjs';
import { RECORD_STATUS } from '../config/constants.mjs';

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

            rv.type,
            rv.status,
            rv.value,
            rv.ttl,
            rv.expires_at

        FROM records r

        LEFT JOIN record_values rv
            ON rv.record_id = r.id

        WHERE
            r.enabled = 1

        ORDER BY
            r.is_regex ASC,
            LENGTH(r.domain) DESC,
            r.domain ASC
    `);

    for (const row of rows) {
        
        // skip invalid requests
        if (
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

        if (row.status !== RECORD_STATUS.SUCCESS) {
            continue;
        }

        const values = JSON.parse(row.value ?? '[]');

        switch (row.type) {
            case 'A':
                record.A.push(
                    ...values.map(address => ({
                        name: record.domain,
                        address,
                        ttl: row.ttl,
                        expiresAt: row.expires_at
                    }))
                );

                break;

            case 'AAAA':
                record.AAAA.push(
                    ...values.map(address => ({
                        name: record.domain,
                        address,
                        ttl: row.ttl,
                        expiresAt: row.expires_at
                    }))
                );

                break;

            case 'CNAME':
                record.CNAME.push(
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

        A: [],
        AAAA: [],
        CNAME: [],

        hits: row.hits,
        lastHit: row.last_hit,

        createdAt: row.created_at,
        updatedAt: row.updated_at
    };
}

async function ensureRecord(record) {

    const now = Date.now();

    const existing = await get(`
        SELECT id
        FROM records
        WHERE domain = ?
    `, [
        record.domain
    ]);

    if (existing) {

        await run(`
            UPDATE records
            SET
                enabled = ?,
                is_regex = ?,
                source = ?,
                hits = ?,
                last_hit = ?,
                updated_at = ?
            WHERE id = ?
        `, [
            record.enabled ?? 1,
            record.isRegex ? 1 : 0,
            record.source,
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
        record.source,

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
    values
) {

    const now = Date.now();

    let ttl = null;
    let expiresAt = null;

    if (status === RECORD_STATUS.SUCCESS && values.length) {

        ttl = Math.min(
            ...values.map(v => v.ttl ?? 300)
        );

        expiresAt = Math.min(
            ...values.map(v => v.expiresAt ?? (now + ttl * 1000))
        );
    }

    let value = null;

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

    const existing = await get(`
        SELECT id
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

    if (existing) {

        await run(`
            UPDATE record_values
            SET
                status = ?,
                value = ?,
                ttl = ?,
                expires_at = ?,
                updated_at = ?
            WHERE id = ?
        `, [
            status,
            value,
            ttl,
            expiresAt,
            now,
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

            value,
            ttl,
            expires_at,

            created_at,
            updated_at

        )
        VALUES(?,?,?,?,?,?,?,?,?)
    `, [

        recordId,
        dnsServerId,

        type,
        status,

        value,
        ttl,
        expiresAt,

        now,
        now
    ]);
}

export async function saveRecord(record) {

    const status = record.source === 'FILTERED'
        ? RECORD_STATUS.FILTERED
        : RECORD_STATUS.SUCCESS;

    const recordId = await ensureRecord(record);

    if (record.A.length) {
        await upsertRecordValue(recordId, record.dnsServerId, 'A', status, record.A);
    }

    if (record.AAAA.length) {
        await upsertRecordValue(recordId, record.dnsServerId, 'AAAA', status, record.AAAA);
    }

    if (record.CNAME.length) {
        await upsertRecordValue(recordId, record.dnsServerId, 'CNAME', status, record.CNAME);
    }
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
            AND source = 'LOCAL'
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
            AND source = 'LOCAL'
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
        source: 'CACHE'
    });

    await upsertRecordValue(
        recordId,
        dnsServerId,
        type,
        status,
        []
    );
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