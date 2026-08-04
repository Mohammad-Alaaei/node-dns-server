import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { store } from '../memory/store.mjs';
import {
    findRecord,
    findStoredRecord,
    getPreferredServer,
    findServerById
} from '../memory/resolver.mjs';
import { selectServer } from '../records/record_utils.mjs';
import { RECORD_SOURCE } from '../config/constants.mjs';

/* -------------------------------------------------------------------------- */
/*                              Mock helpers                                  */
/* -------------------------------------------------------------------------- */

function resetStore() {
    store.exactRecords.clear();
    store.regexRecords.length = 0;
    store.defaultDnsServers.length = 0;
    store.customDnsServers.length = 0;
}

function makeValues(addresses, { expired = false, ttl = 60 } = {}) {
    const now = Date.now();
    return addresses.map(address => ({
        name: 'example.com',
        address,
        ttl,
        expiresAt: expired ? now - 1000 : now + ttl * 1000
    }));
}

function makeServer({
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

function putExact(domain, source, servers) {
    store.exactRecords.set(domain, {
        id: 1,
        domain,
        enabled: true,
        isRegex: false,
        source,
        servers,
        hits: 0,
        lastHit: null,
        createdAt: Date.now(),
        updatedAt: Date.now()
    });
}

/* -------------------------------------------------------------------------- */
/*                                   Tests                                    */
/* -------------------------------------------------------------------------- */

describe('LOCAL source', () => {

    beforeEach(resetStore);

    it('is always servable when values exist (never expires)', () => {
        putExact('local.test', RECORD_SOURCE.LOCAL, [
            makeServer({
                A: makeValues(['1.2.3.4'], { expired: true })
            })
        ]);

        const record = findRecord('local.test', 'A');
        assert.ok(record, 'LOCAL must remain valid even with expired timestamps');
        assert.equal(record.source, RECORD_SOURCE.LOCAL);

        const server = selectServer(record, 'A');
        assert.ok(server);
        assert.equal(server.A[0].address, '1.2.3.4');
    });

    it('is not returned by findStoredRecord (no upstream re-resolve)', () => {
        putExact('local.test', RECORD_SOURCE.LOCAL, [
            makeServer({ A: makeValues(['1.2.3.4']) })
        ]);

        assert.equal(findStoredRecord('local.test'), null);
    });
});

describe('CACHE source — fresh vs expired', () => {

    beforeEach(resetStore);

    it('serves non-expired CACHE answers', () => {
        putExact('cache.test', RECORD_SOURCE.CACHE, [
            makeServer({
                isStale: false,
                A: makeValues(['10.0.0.1'], { expired: false })
            })
        ]);

        const record = findRecord('cache.test', 'A');
        assert.ok(record);
        assert.equal(selectServer(record, 'A').A[0].address, '10.0.0.1');
    });

    it('does not serve pure expired non-stale CACHE (must re-resolve)', () => {
        putExact('cache.test', RECORD_SOURCE.CACHE, [
            makeServer({
                isStale: false,
                A: makeValues(['10.0.0.1'], { expired: true })
            })
        ]);

        assert.equal(
            findRecord('cache.test', 'A'),
            null,
            'expired non-stale CACHE must not be served'
        );

        // But the stored record is still discoverable for preferred-server lookup
        const stored = findStoredRecord('cache.test');
        assert.ok(stored);
        assert.equal(stored.source, RECORD_SOURCE.CACHE);
    });
});

describe('FILTERED source — stale fallback', () => {

    beforeEach(resetStore);

    it('still serves stale FILTERED values (old cache kept)', () => {
        putExact('filtered.test', RECORD_SOURCE.FILTERED, [
            makeServer({
                isStale: true,
                status: 'FILTERED',
                A: makeValues(['9.9.9.9'], { expired: true }) // even expired is OK when stale
            })
        ]);

        const record = findRecord('filtered.test', 'A');
        assert.ok(record, 'stale FILTERED must remain servable');

        const server = selectServer(record, 'A');
        assert.ok(server);
        assert.equal(server.isStale, true);
        assert.equal(server.A[0].address, '9.9.9.9');
    });

    it('prefers fresh non-stale over stale when both exist', () => {
        putExact('mixed.test', RECORD_SOURCE.CACHE, [
            makeServer({
                dnsServerId: 1,
                selected: false,
                isStale: true,
                A: makeValues(['1.1.1.1'])
            }),
            makeServer({
                dnsServerId: 2,
                selected: true,
                isStale: false,
                A: makeValues(['2.2.2.2'], { expired: false })
            })
        ]);

        const record = findRecord('mixed.test', 'A');
        const server = selectServer(record, 'A');
        assert.equal(server.dnsServerId, 2);
        assert.equal(server.A[0].address, '2.2.2.2');
    });
});

describe('preferred (selected) server for re-resolve', () => {

    beforeEach(() => {
        resetStore();
        store.defaultDnsServers.push(
            { id: 10, ip: '8.8.8.8', type: 'DEFAULT', enabled: 1 },
            { id: 20, ip: '1.1.1.1', type: 'DEFAULT', enabled: 1 }
        );
    });

    it('maps dnsServerId to live upstream via findServerById', () => {
        assert.equal(findServerById(20).ip, '1.1.1.1');
        assert.equal(findServerById(999), null);
    });

    it('returns selected server as preferred for expired CACHE', () => {
        putExact('pref.test', RECORD_SOURCE.CACHE, [
            makeServer({
                dnsServerId: 10,
                selected: false,
                isStale: false,
                A: makeValues(['10.0.0.1'], { expired: true })
            }),
            makeServer({
                dnsServerId: 20,
                selected: true,
                isStale: false,
                A: makeValues(['10.0.0.2'], { expired: true })
            })
        ]);

        // Not servable (expired)
        assert.equal(findRecord('pref.test', 'A'), null);

        const stored = findStoredRecord('pref.test');
        const preferred = getPreferredServer(stored, 'A');

        assert.ok(preferred);
        assert.equal(preferred.id, 20);
        assert.equal(preferred.ip, '1.1.1.1');
    });

    it('falls back to first server when none selected', () => {
        putExact('pref2.test', RECORD_SOURCE.CACHE, [
            makeServer({
                dnsServerId: 10,
                selected: false,
                A: makeValues(['10.0.0.1'], { expired: true })
            })
        ]);

        const preferred = getPreferredServer(findStoredRecord('pref2.test'), 'A');
        assert.equal(preferred.ip, '8.8.8.8');
    });
});

describe('selectServer priority', () => {

    beforeEach(resetStore);

    it('order: selected fresh → any fresh → newest stale', () => {
        const older = Date.now() - 10_000;
        const newer = Date.now() - 1_000;

        putExact('prio.test', RECORD_SOURCE.CACHE, [
            makeServer({
                dnsServerId: 1,
                selected: false,
                isStale: true,
                lastSuccessAt: older,
                A: makeValues(['1.1.1.1'])
            }),
            makeServer({
                dnsServerId: 2,
                selected: false,
                isStale: true,
                lastSuccessAt: newer,
                A: makeValues(['2.2.2.2'])
            }),
            makeServer({
                dnsServerId: 3,
                selected: true,
                isStale: false,
                A: makeValues(['3.3.3.3'], { expired: false })
            })
        ]);

        const record = findRecord('prio.test', 'A');
        assert.equal(selectServer(record, 'A').dnsServerId, 3);

        // Remove fresh selected → should pick newest stale
        record.servers = record.servers.filter(s => s.dnsServerId !== 3);
        assert.equal(selectServer(record, 'A').dnsServerId, 2);
    });
});