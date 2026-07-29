import { promises as fs } from 'node:fs';

import { transaction, run } from './sqlite.mjs';

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

    await transaction(async () => {

        await run(`
            DELETE FROM records
            WHERE source='LOCAL'
        `);

        for (const line of text.split(/\r?\n/)) {

            const trimmed = line.trim();

            if (!trimmed || trimmed.startsWith('#')) {
                continue;
            }

            const [pattern, ...values] = trimmed.split(/\s+/);

            if (values.length === 0) {
                continue;
            }

            const regex = isRegex(pattern);

            const domain = regex
                ? pattern
                : normalizeDomain(pattern);

            for (const value of values) {

                let type = 'A';

                if (value.includes(':')) {
                    type = 'AAAA';
                }
                else if (!/^\d+\.\d+\.\d+\.\d+$/.test(value)) {
                    type = 'CNAME';
                }

                await run(`
                    INSERT INTO records(
                        domain,
                        is_regex,
                        type,
                        value,
                        source,
                        ttl,
                        expires_at,
                        hits,
                        last_hit,
                        created_at,
                        updated_at
                    )
                    VALUES(?,?,?,?,?,?,?,?,?,?,?)
                `, [
                    domain,
                    regex ? 1 : 0,
                    type,
                    value,
                    'LOCAL',
                    0,
                    null,
                    0,
                    null,
                    now,
                    now
                ]);
            }
        }
    });
}