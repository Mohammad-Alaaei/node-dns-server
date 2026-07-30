import { store } from './store.mjs';

export function findRecord(domain, type) {

    const exact = store.exactRecords.get(domain);

    if (exact && isRecordValid(exact, type)) {
        return exact;
    }

    for (const record of store.regexRecords) {

        if (
            record.regex.test(domain) &&
            isRecordValid(record, type)
        ) {
            return record;
        }
    }

    return null;
}

function isExpired(values) {
    if (!values.length) {
        return true;
    }

    const now = Date.now();

    return values.every(v =>
        v.expiresAt !== null &&
        v.expiresAt <= now
    );
}

function isRecordValid(record, type) {

    if (!record) {
        console.warn('--------------NULL RECORD!')
        return false;
    }

    if (
        isExpired(record.A) &&
        isExpired(record.AAAA) &&
        isExpired(record.CNAME)
    ) {
        return false;
    }

    return (
        record?.CNAME?.length > 0 ||
        record[type]?.length > 0
    );
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