import { RECORD_SOURCE, RECORD_STATUS } from '../config/constants.mjs';
import { store } from './store.mjs';
import { normalizeDomain } from '../utils/domain_utils.mjs';

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
 * LOCAL: valid when requested type or CNAME exists (never expires).
 * CACHE: valid when a non-expired SUCCESS exists.
 *        Expired SUCCESS is not valid here (triggers a refresh) but is still
 *        preferred over FILTERED by selectServer if the refresh fails.
 * FILTERED-only: valid so we don't hammer upstream when nothing better exists.
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

    const isFiltered = (s) =>
        s.status === RECORD_STATUS.FILTERED || s.status === 'FILTERED';

    const hasType = (s) =>
        (s[type] && s[type].length > 0) ||
        (s.CNAME && s.CNAME.length > 0);

    const success = [];
    const filtered = [];

    for (const server of record.servers) {
        if (!hasType(server)) continue;
        if (isFiltered(server)) filtered.push(server);
        else success.push(server);
    }

    if (success.length) {
        return success.some(s =>
            (s.CNAME?.length && !isExpired(s.CNAME)) ||
            (s[type]?.length && !isExpired(s[type]))
        );
    }

    return filtered.length > 0;
}

/**
 * Find a servable record for domain + type.
 * Exact match first, then regex (longer patterns preferred via load sort).
 */
export function findRecord(domain, type) {

    domain = normalizeDomain(domain);

    const exact = store.exactRecords.get(domain);

    if (exact && isRecordValid(exact, type)) {
        return exact;
    }

    for (const record of store.regexRecords) {
        if (
            record.regex.test(domain) &&
            isRecordValid(record, type)
        ) {
            // Same shape as exact — selectServer picks among servers
            return record;
        }
    }

    return null;
}

/**
 * Find stored non-LOCAL record even if expired (preferred-server re-resolve).
 */
export function findStoredRecord(domain) {

    domain = normalizeDomain(domain);

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

/**
 * True if domain has a LOCAL record in memory (any type).
 */
export function hasLocalRecord(domain) {

    domain = normalizeDomain(domain);

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

    domain = normalizeDomain(domain);

    for (const group of store.customDnsServers) {

        const matched = group.isRegex
            ? group.regex.test(domain)
            : normalizeDomain(group.domain) === domain;

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
