import { store } from './store.mjs';

export function findRecord(domain, type = null) {

    const exact = store.exactRecords.get(domain);

    if (exact) {

        if (
            !type ||
            exact[type].length ||
            (
                (type === 'A' || type === 'AAAA') &&
                exact.CNAME.length
            )
        ) {
            return exact;
        }
    }

    for (const record of store.regexRecords) {

        if (!record.regex.test(domain)) {
            continue;
        }

        if (
            !type ||
            record[type].length ||
            (
                (type === 'A' || type === 'AAAA') &&
                record.CNAME.length
            )
        ) {
            return record;
        }
    }

    return null;
}

export function findCustomDnsServer(domain) {

    for (const group of store.customDnsServers) {

        const matched = group.isRegex
            ? group.regex.test(domain)
            : group.domain.toLowerCase() === domain.toLowerCase();

        if (matched) {
            return group.servers[0];
        }
    }

    return null;
}

let defaultIndex = 0;

export function getDefaultDnsServer() {

    if (store.defaultDnsServers.length === 0) {
        throw new Error('No default DNS server configured.');
    }

    const server = store.defaultDnsServers[
        defaultIndex++ % store.defaultDnsServers.length
    ];

    return server;
}