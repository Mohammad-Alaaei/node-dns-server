import { all, get, run, transaction } from './sqlite.mjs';
import { store } from '../memory/store.mjs';

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
        SELECT *
        FROM records
        WHERE enabled = 1
        ORDER BY
            is_regex ASC,
            LENGTH(domain) DESC,
            domain ASC
    `);

    for (const row of rows) {

        const collection = row.is_regex
            ? store.regexRecords
            : store.exactRecords;

        let record;

        if (row.is_regex) {

            record = collection.find(r => r.domain === row.domain);

            if (!record) {

                record = createRecord(row);
                record.regex = new RegExp(`^(?:${row.domain})$`, 'i');

                collection.push(record);
            }

        } else {

            record = collection.get(row.domain);

            if (!record) {

                record = createRecord(row);

                collection.set(row.domain, record);
            }
        }

        switch (row.type) {

            case 'A':
                record.A.push({
                    name: row.canonical_name ?? row.domain,
                    address: row.value
                });

                break;

            case 'AAAA':
                record.AAAA.push({
                    name: row.canonical_name ?? row.domain,
                    address: row.value
                });

                break;

            case 'CNAME':
                record.CNAME.push({
                    name: row.domain,
                    domain: row.value
                });

                break;
        }
    }

    store.regexRecords.sort(
        (a, b) => b.domain.length - a.domain.length
    );

}

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

/* -------------------------------------------------------------------------- */
/*                                  Records                                   */
/* -------------------------------------------------------------------------- */

function createRecord(row) {

    return {

        domain: row.domain,
        isRegex: !!row.is_regex,

        A: [],
        AAAA: [],
        CNAME: [],

        source: row.source,
        ttl: row.ttl,
        expiresAt: row.source === 'CACHE' || row.source === 'FILTERED'
            ? row.expires_at
            : null,

        hits: row.hits,
        lastHit: row.last_hit,

        createdAt: row.created_at,
        updatedAt: row.updated_at
    };
}

export async function insertRecord(record, reload = true) {
    const now = Date.now();

    await transaction(async () => {
        if (record.source === 'LOCAL') {
            await run(`
                UPDATE records
                SET enabled = 0
                WHERE domain = ?
                AND source IN ('CACHE', 'FILTERED')
            `, [record.domain]);
        }

        await insertValues(record, 'A', record.A ?? [], now);
        await insertValues(record, 'AAAA', record.AAAA ?? [], now);
        await insertValues(record, 'CNAME', record.CNAME ?? [], now);

    }, reload);

    if (reload) {
        await loadRecords();
    }
}

export async function updateRecord(record) {

    await transaction(async () => {

        await run(
            `DELETE FROM records WHERE domain=?`,
            [record.domain]
        );

        await insertRecord(record, false);

    });

    await loadRecords();
}

export async function deleteRecord(domain) {

    await run(
        `DELETE FROM records WHERE domain=?`,
        [domain]
    );

    await loadRecords();
}

async function insertValues(record, type, values, now) {

    for (const value of values) {

        let recordValue;

        switch (type) {

            case 'A':
            case 'AAAA':
                recordValue = value.address;
                break;

            case 'CNAME':
                recordValue = value.domain;
                break;
        }

        await run(`
            INSERT INTO records(
                domain,
                is_regex,
                type,
                value,
                source,
                enabled,
                ttl,
                expires_at,
                hits,
                last_hit,
                created_at,
                updated_at
            )
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            `, [
            record.domain,
            record.isRegex ? 1 : 0,
            type,
            recordValue,
            record.source,
            record.enabled ?? 1,
            record.ttl,
            record.expiresAt,
            record.hits ?? 0,
            record.lastHit,
            record.createdAt ?? now,
            record.updatedAt ?? now
        ]);
    }
}

export async function upsertCacheRecord(record, reload = true) {

    await transaction(async () => {

        const local = await get(`
            SELECT 1
            FROM records
            WHERE domain = ?
              AND source = 'LOCAL'
              AND enabled = 1
            LIMIT 1
        `, [record.domain]);

        record.enabled = local ? 0 : 1;

        await run(`
            DELETE FROM records
            WHERE domain = ?
              AND source IN ('CACHE', 'FILTERED')
        `, [record.domain]);

        await insertRecord(record, false);

    });

    if (reload) {
        await loadRecords();
    }
}

export async function deleteExpiredCacheRecords() {

    const now = Date.now();

    await run(`
        DELETE FROM records
        WHERE source IN ('CACHE', 'FILTERED')
          AND expires_at IS NOT NULL
          AND expires_at <= ?
    `, [now]);

    await loadRecords();
}

export async function enableLocalRecord(domain) {

    await transaction(async () => {

        await run(`
            UPDATE records
            SET enabled = 0
            WHERE domain = ?
              AND source IN ('CACHE', 'FILTERED')
        `, [domain]);

        await run(`
            UPDATE records
            SET enabled = 1
            WHERE domain = ?
              AND source = 'LOCAL'
        `, [domain]);

    });

    await loadRecords();
}

export async function disableLocalRecord(domain) {

    await transaction(async () => {

        await run(`
            UPDATE records
            SET enabled = 0
            WHERE domain = ?
              AND source = 'LOCAL'
        `, [domain]);

        await run(`
            UPDATE records
            SET enabled = 1
            WHERE domain = ?
              AND source IN ('CACHE', 'FILTERED')
        `, [domain]);

    });

    await loadRecords();
}

/* -------------------------------------------------------------------------- */
/*                               DNS Servers                                  */
/* -------------------------------------------------------------------------- */

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

    return get(`
        SELECT *
        FROM dns_servers
    `);
}