import { RECORD_SOURCE } from '../config/constants.mjs';
import { store } from './store.mjs';

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

/**
 * A record is servable when:
 * - LOCAL and has values, or
 * - has non-expired non-stale values, or
 * - has stale values (FILTERED fallback — still serve old payload).
 *
 * Purely expired non-stale CACHE is NOT servable → triggers re-resolve.
 */
function isRecordValid(record, type) {

    if (record.source === RECORD_SOURCE.LOCAL) {
        const server = record.servers[0];

        return (
            server &&
            (
                (server[type] && server[type].length > 0) ||
                (server.CNAME && server.CNAME.length > 0)
            )
        );
    }

    for (const server of record.servers) {

        const hasType =
            (server[type] && server[type].length > 0) ||
            (server.CNAME && server.CNAME.length > 0);

        if (!hasType) {
            continue;
        }

        if (server.isStale) {
            return true;
        }

        if (server.CNAME.length && !isExpired(server.CNAME)) {
            return true;
        }

        if (server[type].length && !isExpired(server[type])) {
            return true;
        }
    }

    return false;
}

/**
 * Find an exact/regex record that can be served right now.
 */
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

/**
 * Find a stored record even if expired (for preferred-server re-resolve).
 * Skips LOCAL (authoritative, never re-resolved upstream).
 */
export function findStoredRecord(domain) {

    const exact = store.exactRecords.get(domain);

    if (exact && exact.source !== RECORD_SOURCE.LOCAL) {
        return exact;
    }

    for (const record of store.regexRecords) {
        if (
            record.regex.test(domain) &&
            record.source !== RECORD_SOURCE.LOCAL
        ) {
            return record;
        }
    }

    return null;
}

export function hasLocalRecord(domain) {
    const exact = store.exactRecords.get(domain);

    if (exact && exact.source === RECORD_SOURCE.LOCAL) {
        return true;
    }

    for (const record of store.regexRecords) {
        if (
            record.source === RECORD_SOURCE.LOCAL &&
            record.regex.test(domain)
        ) {
            return true;
        }
    }

    return false;
}

export function findServerById(dnsServerId) {

    if (dnsServerId == null) {
        return null;
    }

    for (const server of store.defaultDnsServers) {
        if (server.id === dnsServerId) {
            return server;
        }
    }

    for (const group of store.customDnsServers) {
        for (const server of group.servers) {
            if (server.id === dnsServerId) {
                return server;
            }
        }
    }

    return null;
}

/**
 * Preferred (selected) upstream for an existing record + type.
 */
export function getPreferredServer(record, type) {

    if (!record?.servers?.length) {
        return null;
    }

    const selected = record.servers.find(s =>
        s.selected &&
        (s[type]?.length || s.CNAME?.length || s.dnsServerId != null)
    );

    const candidate = selected ?? record.servers[0];

    return findServerById(candidate?.dnsServerId) ?? null;
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

    return store.defaultDnsServers[
        defaultIndex++ % store.defaultDnsServers.length
    ];
}