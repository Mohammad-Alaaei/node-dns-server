/**
 * CACHE_LEVEL matrix tests.
 *
 * Verifies shouldProcessUpstreamAnswer + evaluateUpstreamHandling for:
 *   ALL | CUSTOM_ONLY | FILTERED_ONLY | NONE
 * and IGNORE_IPS log suppression.
 */
import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import { config } from '../config/config.mjs';
import { CACHE_LEVELS } from '../config/constants.mjs';
import {
    shouldProcessUpstreamAnswer,
    isCacheEnabled,
    getCacheLevel
} from '../services/cache_policy.mjs';
import { evaluateUpstreamHandling } from '../services/response_parser.mjs';

// dns2 Packet.TYPE values (avoid importing dns2 in tests)
const TYPE_A = 1;
const TYPE_AAAA = 28;
const TYPE_CNAME = 5;

const ORIGINAL = {
    level: config.cache.level,
    filterIps: [...config.cache.filterIps],
    ignoreIps: [...config.ignoreIps]
};

function setLevel(level) {
    config.cache.level = level;
}

function setFilterIps(ips) {
    config.cache.filterIps = [...ips];
}

function setIgnoreIps(ips) {
    config.ignoreIps = [...ips];
}

function makePacket(addresses = [], { cname } = {}) {
    const answers = [];

    for (const address of addresses) {
        answers.push({
            type: address.includes(':') ? TYPE_AAAA : TYPE_A,
            name: 'example.com',
            address,
            ttl: 60
        });
    }

    if (cname) {
        answers.push({
            type: TYPE_CNAME,
            name: 'example.com',
            domain: cname,
            ttl: 60
        });
    }

    return { answers };
}

beforeEach(() => {
    setLevel(ORIGINAL.level);
    setFilterIps(ORIGINAL.filterIps);
    setIgnoreIps(ORIGINAL.ignoreIps);
});

afterEach(() => {
    setLevel(ORIGINAL.level);
    setFilterIps(ORIGINAL.filterIps);
    setIgnoreIps(ORIGINAL.ignoreIps);
});

/* -------------------------------------------------------------------------- */
/*                         shouldProcessUpstreamAnswer                        */
/* -------------------------------------------------------------------------- */

describe('CACHE_LEVEL = ALL', () => {

    beforeEach(() => setLevel(CACHE_LEVELS.ALL));

    it('processes custom + default, filtered or not', () => {
        assert.equal(shouldProcessUpstreamAnswer({ isCustom: true, isFiltered: false }), true);
        assert.equal(shouldProcessUpstreamAnswer({ isCustom: false, isFiltered: false }), true);
        assert.equal(shouldProcessUpstreamAnswer({ isCustom: true, isFiltered: true }), true);
        assert.equal(shouldProcessUpstreamAnswer({ isCustom: false, isFiltered: true }), true);
    });

    it('isCacheEnabled is true', () => {
        assert.equal(isCacheEnabled(), true);
        assert.equal(getCacheLevel(), CACHE_LEVELS.ALL);
    });
});

describe('CACHE_LEVEL = CUSTOM_ONLY', () => {

    beforeEach(() => setLevel(CACHE_LEVELS.CUSTOM_ONLY));

    it('processes only custom upstream', () => {
        assert.equal(shouldProcessUpstreamAnswer({ isCustom: true, isFiltered: false }), true);
        assert.equal(shouldProcessUpstreamAnswer({ isCustom: true, isFiltered: true }), true);
        assert.equal(shouldProcessUpstreamAnswer({ isCustom: false, isFiltered: false }), false);
        assert.equal(shouldProcessUpstreamAnswer({ isCustom: false, isFiltered: true }), false);
    });
});

describe('CACHE_LEVEL = FILTERED_ONLY', () => {

    beforeEach(() => setLevel(CACHE_LEVELS.FILTERED_ONLY));

    it('processes only filtered answers (any upstream)', () => {
        assert.equal(shouldProcessUpstreamAnswer({ isCustom: true, isFiltered: true }), true);
        assert.equal(shouldProcessUpstreamAnswer({ isCustom: false, isFiltered: true }), true);
        assert.equal(shouldProcessUpstreamAnswer({ isCustom: true, isFiltered: false }), false);
        assert.equal(shouldProcessUpstreamAnswer({ isCustom: false, isFiltered: false }), false);
    });
});

describe('CACHE_LEVEL = NONE', () => {

    beforeEach(() => setLevel(CACHE_LEVELS.NONE));

    it('never processes', () => {
        assert.equal(shouldProcessUpstreamAnswer({ isCustom: true, isFiltered: true }), false);
        assert.equal(shouldProcessUpstreamAnswer({ isCustom: true, isFiltered: false }), false);
        assert.equal(shouldProcessUpstreamAnswer({ isCustom: false, isFiltered: true }), false);
        assert.equal(shouldProcessUpstreamAnswer({ isCustom: false, isFiltered: false }), false);
    });

    it('isCacheEnabled is false', () => {
        assert.equal(isCacheEnabled(), false);
    });
});

/* -------------------------------------------------------------------------- */
/*              evaluateUpstreamHandling (packet + FILTER/IGNORE)             */
/* -------------------------------------------------------------------------- */

describe('evaluateUpstreamHandling — ALL', () => {

    beforeEach(() => {
        setLevel(CACHE_LEVELS.ALL);
        setFilterIps(['10.0.0.1']);
        setIgnoreIps([]);
    });

    it('default upstream, normal IP → process + log', () => {
        const r = evaluateUpstreamHandling(makePacket(['1.2.3.4']), false);
        assert.deepEqual(r, { isFiltered: false, process: true, doLog: true });
    });

    it('default upstream, FILTER_IP → process + log, isFiltered true', () => {
        const r = evaluateUpstreamHandling(makePacket(['10.0.0.1']), false);
        assert.deepEqual(r, { isFiltered: true, process: true, doLog: true });
    });

    it('IGNORE_IPS suppresses log only', () => {
        setIgnoreIps(['1.2.3.4']);
        const r = evaluateUpstreamHandling(makePacket(['1.2.3.4']), true);
        assert.equal(r.process, true);
        assert.equal(r.doLog, false);
    });
});

describe('evaluateUpstreamHandling — CUSTOM_ONLY', () => {

    beforeEach(() => {
        setLevel(CACHE_LEVELS.CUSTOM_ONLY);
        setFilterIps(['10.0.0.1']);
        setIgnoreIps([]);
    });

    it('custom upstream → process + log', () => {
        const r = evaluateUpstreamHandling(makePacket(['8.8.8.8']), true);
        assert.equal(r.process, true);
        assert.equal(r.doLog, true);
    });

    it('default upstream → no process, no log', () => {
        const r = evaluateUpstreamHandling(makePacket(['8.8.8.8']), false);
        assert.equal(r.process, false);
        assert.equal(r.doLog, false);
    });

    it('default upstream with FILTER_IP still skipped (not custom)', () => {
        const r = evaluateUpstreamHandling(makePacket(['10.0.0.1']), false);
        assert.equal(r.isFiltered, true);
        assert.equal(r.process, false);
        assert.equal(r.doLog, false);
    });
});

describe('evaluateUpstreamHandling — FILTERED_ONLY', () => {

    beforeEach(() => {
        setLevel(CACHE_LEVELS.FILTERED_ONLY);
        setFilterIps(['10.0.0.1', '2001:db8::1']);
        setIgnoreIps([]);
    });

    it('answer with FILTER_IP → process + log (custom or default)', () => {
        assert.equal(
            evaluateUpstreamHandling(makePacket(['10.0.0.1']), false).process,
            true
        );
        assert.equal(
            evaluateUpstreamHandling(makePacket(['10.0.0.1']), true).process,
            true
        );
        assert.equal(
            evaluateUpstreamHandling(makePacket(['2001:db8::1']), false).process,
            true
        );
    });

    it('answer without FILTER_IP → no process, no log', () => {
        const r = evaluateUpstreamHandling(makePacket(['8.8.8.8']), true);
        assert.equal(r.isFiltered, false);
        assert.equal(r.process, false);
        assert.equal(r.doLog, false);
    });

    it('empty FILTER_IPS → nothing is filtered → never process', () => {
        setFilterIps([]);
        const r = evaluateUpstreamHandling(makePacket(['10.0.0.1']), true);
        assert.equal(r.isFiltered, false);
        assert.equal(r.process, false);
    });

    it('IGNORE_IPS on filtered answer → process but no log', () => {
        setIgnoreIps(['10.0.0.1']);
        const r = evaluateUpstreamHandling(makePacket(['10.0.0.1']), false);
        assert.equal(r.process, true);
        assert.equal(r.doLog, false);
    });
});

describe('evaluateUpstreamHandling — NONE', () => {

    beforeEach(() => {
        setLevel(CACHE_LEVELS.NONE);
        setFilterIps(['10.0.0.1']);
        setIgnoreIps([]);
    });

    it('never process / log even for custom + filtered', () => {
        const r = evaluateUpstreamHandling(makePacket(['10.0.0.1']), true);
        assert.equal(r.process, false);
        assert.equal(r.doLog, false);
    });
});

/* -------------------------------------------------------------------------- */
/*                         Full matrix (table-driven)                         */
/* -------------------------------------------------------------------------- */

describe('CACHE_LEVEL full matrix (process)', () => {

    const cases = [
        // level, isCustom, isFiltered, expectedProcess
        [CACHE_LEVELS.ALL, true, false, true],
        [CACHE_LEVELS.ALL, false, false, true],
        [CACHE_LEVELS.ALL, true, true, true],
        [CACHE_LEVELS.ALL, false, true, true],

        [CACHE_LEVELS.CUSTOM_ONLY, true, false, true],
        [CACHE_LEVELS.CUSTOM_ONLY, true, true, true],
        [CACHE_LEVELS.CUSTOM_ONLY, false, false, false],
        [CACHE_LEVELS.CUSTOM_ONLY, false, true, false],

        [CACHE_LEVELS.FILTERED_ONLY, true, true, true],
        [CACHE_LEVELS.FILTERED_ONLY, false, true, true],
        [CACHE_LEVELS.FILTERED_ONLY, true, false, false],
        [CACHE_LEVELS.FILTERED_ONLY, false, false, false],

        [CACHE_LEVELS.NONE, true, true, false],
        [CACHE_LEVELS.NONE, true, false, false],
        [CACHE_LEVELS.NONE, false, true, false],
        [CACHE_LEVELS.NONE, false, false, false]
    ];

    for (const [level, isCustom, isFiltered, expected] of cases) {
        it(`${level} | custom=${isCustom} filtered=${isFiltered} → process=${expected}`, () => {
            setLevel(level);
            assert.equal(
                shouldProcessUpstreamAnswer({ isCustom, isFiltered }),
                expected
            );
        });
    }
});
