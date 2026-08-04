import { store } from '../memory/store.mjs';
import { RECORD_SOURCE } from '../config/constants.mjs';

export function resetStore() {
    store.exactRecords.clear();
    store.regexRecords.length = 0;
    store.defaultDnsServers.length = 0;
    store.customDnsServers.length = 0;
}

export function makeValues(addresses, { expired = false, ttl = 60 } = {}) {
    const now = Date.now();
    return addresses.map(address => ({
        name: 'example.com',
        address,
        ttl,
        expiresAt: expired ? now - 1000 : now + ttl * 1000
    }));
}

export function makeCnameValues(domains, { expired = false, ttl = 60 } = {}) {
    const now = Date.now();
    return domains.map(domain => ({
        name: 'example.com',
        domain,
        ttl,
        expiresAt: expired ? now - 1000 : now + ttl * 1000
    }));
}

export function makeServer({
    dnsServerId = 1,
    selected = true,
    isStale = false,
    status = 'SUCCESS',
    A = [],
    AAAA = [],
    CNAME = [],
    lastSuccessAt = Date.now()
} = {}) {
    return {
        dnsServerId,
        selected,
        isStale,
        status,
        lastSuccessAt,
        A,
        AAAA,
        CNAME
    };
}

export function putExact(domain, source, servers, extra = {}) {
    store.exactRecords.set(domain, {
        id: extra.id ?? 1,
        domain,
        enabled: true,
        isRegex: false,
        source,
        servers,
        hits: 0,
        lastHit: null,
        createdAt: Date.now(),
        updatedAt: Date.now(),
        ...extra
    });
}

export function putRegex(pattern, source, servers, extra = {}) {
    store.regexRecords.push({
        id: extra.id ?? 1,
        domain: pattern,
        enabled: true,
        isRegex: true,
        source,
        regex: new RegExp(`^(?:${pattern})$`, 'i'),
        servers,
        hits: 0,
        lastHit: null,
        createdAt: Date.now(),
        updatedAt: Date.now(),
        ...extra
    });
}

export { RECORD_SOURCE, store };