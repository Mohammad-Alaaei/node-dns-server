import { promises as fs } from 'node:fs';
import { sequelize } from './connection.mjs';
import { Record, RecordValue } from './models.mjs';
import { RECORD_SOURCE, RECORD_STATUS } from '../config/constants.mjs';

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
            } else if (/^\d+\.\d+\.\d+\.\d+$/.test(value)) {
                record.A.push(value);
            } else {
                record.CNAME.push(value);
            }
        }
    }

    await sequelize.transaction(async (t) => {

        await Record.destroy({
            where: { source: RECORD_SOURCE.LOCAL },
            transaction: t
        });

        for (const [domain, record] of records) {

            const created = await Record.create({
                domain,
                enabled: true,
                is_regex: !!record.regex,
                source: RECORD_SOURCE.LOCAL,
                hits: 0,
                last_hit: null,
                created_at: now,
                updated_at: now
            }, { transaction: t });

            const recordId = created.id;

            async function insertType(type, list) {
                if (!list.length) return;
                await RecordValue.create({
                    record_id: recordId,
                    dns_server_id: null,
                    type,
                    status: RECORD_STATUS.SUCCESS,
                    value: JSON.stringify(list),
                    ttl: null,
                    selected: true,
                    is_stale: false,
                    expires_at: null,
                    last_success_at: now,
                    created_at: now,
                    updated_at: now
                }, { transaction: t });
            }

            await insertType('A', record.A);
            await insertType('AAAA', record.AAAA);
            await insertType('CNAME', record.CNAME);
        }
    });
}
