/**
 * Bug-fix coverage:
 * 1) LOCAL + type present → findRecord hits
 * 2) LOCAL + type missing → findRecord null, hasLocalRecord true
 * 3) Regex LOCAL works (no variants map)
 * 4) One domain slot — LOCAL preferred
 */
import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import {
    resetStore,
    makeValues,
    makeCnameValues,
    makeServer,
    putExact,
    putRegex,
    RECORD_SOURCE,
    store
} from './helpers.mjs';

import {
    findRecord,
    hasLocalRecord,
    findStoredRecord
} from '../memory/resolver.mjs';
import { selectServer } from '../records/record_utils.mjs';

describe('LOCAL isolation — type present vs missing', () => {

    beforeEach(resetStore);

    it('findRecord returns LOCAL when A exists', () => {
        putExact('static.example', RECORD_SOURCE.LOCAL, [
            makeServer({ A: makeValues(['203.0.113.10']) })
        ]);

        const record = findRecord('static.example', 'A');
        assert.ok(record);
        assert.equal(record.source, RECORD_SOURCE.LOCAL);
        assert.equal(selectServer(record, 'A').A[0].address, '203.0.113.10');
    });

    it('findRecord returns null for missing type on LOCAL, but hasLocalRecord stays true', () => {
        putExact('static.example', RECORD_SOURCE.LOCAL, [
            makeServer({
                A: makeValues(['203.0.113.10']),
                AAAA: [],
                CNAME: []
            })
        ]);

        assert.equal(findRecord('static.example', 'AAAA'), null);
        assert.equal(hasLocalRecord('static.example'), true);
        assert.equal(findStoredRecord('static.example'), null);
    });

    it('LOCAL with CNAME is valid for A request', () => {
        putExact('alias.example', RECORD_SOURCE.LOCAL, [
            makeServer({
                A: [],
                CNAME: makeCnameValues(['target.example'])
            })
        ]);

        const record = findRecord('alias.example', 'A');
        assert.ok(record);
        assert.equal(record.source, RECORD_SOURCE.LOCAL);
    });
});

describe('Regex LOCAL (bug: selectVariant / variants)', () => {

    beforeEach(resetStore);

    it('serves regex LOCAL without variants map', () => {
        putRegex(String.raw`.*\.cdn\.example`, RECORD_SOURCE.LOCAL, [
            makeServer({ A: makeValues(['198.51.100.1']) })
        ]);

        const record = findRecord('img.cdn.example', 'A');
        assert.ok(record, 'regex LOCAL must match and be valid');
        assert.equal(record.source, RECORD_SOURCE.LOCAL);
        assert.equal(selectServer(record, 'A').A[0].address, '198.51.100.1');
    });

    it('hasLocalRecord true for regex LOCAL match', () => {
        putRegex(String.raw`.*\.cdn\.example`, RECORD_SOURCE.LOCAL, [
            makeServer({ A: makeValues(['198.51.100.1']) })
        ]);

        assert.equal(hasLocalRecord('img.cdn.example'), true);
        assert.equal(hasLocalRecord('other.com'), false);
    });
});

describe('One domain in memory — LOCAL wins', () => {

    beforeEach(resetStore);

    it('exact map holds a single record per domain', () => {
        putExact('dup.example', RECORD_SOURCE.CACHE, [
            makeServer({ A: makeValues(['1.1.1.1']) })
        ]);

        const existing = store.exactRecords.get('dup.example');
        existing.source = RECORD_SOURCE.LOCAL;
        existing.servers = [
            makeServer({ A: makeValues(['9.9.9.9']) })
        ];

        assert.equal(store.exactRecords.size, 1);
        assert.equal(findRecord('dup.example', 'A').source, RECORD_SOURCE.LOCAL);
        assert.equal(
            selectServer(findRecord('dup.example', 'A'), 'A').A[0].address,
            '9.9.9.9'
        );
    });
});

describe('CACHE must not shadow LOCAL for re-resolve helpers', () => {

    beforeEach(resetStore);

    it('findStoredRecord ignores LOCAL', () => {
        putExact('only.local', RECORD_SOURCE.LOCAL, [
            makeServer({ A: makeValues(['1.2.3.4']) })
        ]);
        assert.equal(findStoredRecord('only.local'), null);
    });

    it('findStoredRecord returns CACHE when present', () => {
        putExact('cached.example', RECORD_SOURCE.CACHE, [
            makeServer({
                A: makeValues(['5.6.7.8'], { expired: true })
            })
        ]);
        const stored = findStoredRecord('cached.example');
        assert.ok(stored);
        assert.equal(stored.source, RECORD_SOURCE.CACHE);
    });
});