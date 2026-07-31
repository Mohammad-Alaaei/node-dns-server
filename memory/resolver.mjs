import { store } from './store.mjs';


function selectVariant(record) {

    const variants = [...record.variants.values()];

    let selected = variants.find(v => v.selected);

    if (selected) {
        return selected;
    }

    selected = variants.find(
        v => v.status === RECORD_STATUS.SUCCESS
    );

    if (selected) {
        return selected;
    }

    return variants.find(
        v => v.status === RECORD_STATUS.FILTERED
    ) ?? null;
}

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
            const variant = selectVariant(record);

            if (!variant)
                return null;

            return {
                ...record,
                A: variant.A,
                AAAA: variant.AAAA,
                CNAME: variant.CNAME
            };
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
        v.expiresAt != null &&
        v.expiresAt <= now
    );
}

function isRecordValid(record, type) {

    // LOCAL records never expire.
    if (record.source === 'LOCAL') {
        return true;
    }

    for (const server of record.servers) {

        if (server.isStale) {
            continue;
        }

        if (server.CNAME.length) {
            return true;
        }

        if (!isExpired(server[type])) {
            return true;
        }
    }

    return false;
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