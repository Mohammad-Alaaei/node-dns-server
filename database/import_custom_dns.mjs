import { promises as fs } from 'node:fs';
import path from 'node:path';

import {
    clearDnsConfiguration,
    findDnsServer,
    insertDnsRule,
    insertDnsServer
} from './repository.mjs';

const DOMAIN_FILE = process.env.DOMAIN_FILE ?? 'domains.txt';
const TXT_FILES_DIR = process.env.TXT_FILES_DIR ?? './';

function isRegex(pattern) {
    return /[()[\]{}*+?|^$]/.test(pattern);
}

function normalizeDomain(pattern) {
    return pattern.replace(/\\\./g, '.');
}

export async function importCustomDnsServers() {

    await clearDnsConfiguration();

    const files = await fs.readdir(TXT_FILES_DIR);

    for (const file of files) {

        if (!file.endsWith('.txt') || file === DOMAIN_FILE) {
            continue;
        }

        const ip = file.slice(0, -4);

        const serverId = await insertDnsServer({
            ip,
            type: 'CUSTOM'
        });

        const text = await fs.readFile(
            path.join(TXT_FILES_DIR, file),
            'utf8'
        );

        for (const line of text.split(/\r?\n/)) {

            const domain = line.trim();

            if (!domain || domain.startsWith('#')) {
                continue;
            }

            const regex = isRegex(domain);

            await insertDnsRule(
                serverId,
                regex ? domain : normalizeDomain(domain),
                regex
            );
        }
    }
}