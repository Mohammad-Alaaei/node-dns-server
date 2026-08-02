import { promises as fs } from 'node:fs';

import { transaction, run } from './sqlite.mjs';
import { RECORD_SOURCE } from '../config/constants.mjs';

const DOMAIN_FILE = process.env.DOMAIN_FILE ?? 'domains.txt';

function isRegex(pattern) {
    return /[()[\]{}*+?|^$]/.test(pattern);
}

function normalizeDomain(pattern) {
    return pattern.replace(/\\\./g, '.');
}

export async function importDomains() {

    const now = Date.now();

    const text = await fs.readFile(DOMAIN_FILE, 'utf8');

    const records = new Map();

    for (const line of text.split(/\r?\n/)) {

        const trimmed = line.trim();

        if (!trimmed || trimmed.startsWith('#')) {
            continue;
        }

        const [pattern, ...entries] = trimmed.split(/\s+/);

        if (!entries.length) {
            continue;
        }

        const regex = isRegex(pattern);

        const domain = regex
            ? pattern
            : normalizeDomain(pattern);

        let record = records.get(domain);

        if (!record) {

            record = {
                regex,
                A: [],
                AAAA: [],
                CNAME: []
            };

            records.set(domain, record);
        }

        for (const value of entries) {

            if (value.includes(':')) {
                record.AAAA.push(value);
            }
            else if (/^\d+\.\d+\.\d+\.\d+$/.test(value)) {
                record.A.push(value);
            }
            else {
                record.CNAME.push(value);
            }
        }
    }

    await transaction(async () => {

        await run(`
            DELETE FROM records
            WHERE source = '${RECORD_SOURCE.LOCAL}'
        `);

        for (const [domain, record] of records) {

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
                domain,
                1,
                record.regex ? 1 : 0,
                RECORD_SOURCE.LOCAL,
                0,
                null,
                now,
                now
            ]);

            const recordId = result.lastID;

            if (record.A.length) {

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
                    null,
                    'A',
                    'SUCCESS',
                    JSON.stringify(record.A),
                    null,
                    null,
                    now,
                    now
                ]);
            }

            if (record.AAAA.length) {

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
                    null,
                    'AAAA',
                    'SUCCESS',
                    JSON.stringify(record.AAAA),
                    null,
                    null,
                    now,
                    now
                ]);
            }

            if (record.CNAME.length) {

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
                    null,
                    'CNAME',
                    'SUCCESS',
                    JSON.stringify(record.CNAME),
                    null,
                    null,
                    now,
                    now
                ]);
            }
        }
    });
}