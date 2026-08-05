/**
 * Integration tests against MySQL (DB_* from .env).
 * Skips the whole suite if the database is unreachable.
 *
 * Covers bug fixes:
 * - one records row per domain
 * - saveRecord does not create a second row when LOCAL exists
 * - saveLookupStatus ignores LOCAL domains
 * - unique domain constraint
 */
import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { sequelize, authenticate } from '../database/connection.mjs';
import { Record, RecordValue } from '../database/models/index.mjs';
import {
    saveRecord,
    saveLookupStatus,
    loadRecords
} from '../database/repository.mjs';
import { RECORD_SOURCE, RECORD_STATUS } from '../config/constants.mjs';
import { store } from '../memory/store.mjs';

const TEST_PREFIX = `__test_${process.pid}_`;

let dbReady = false;

async function wipeTestRows() {
    const { Op } = await import('sequelize');
    const rows = await Record.findAll({
        where: {
            domain: { [Op.like]: `${TEST_PREFIX}%` }
        }
    });

    for (const row of rows) {
        await RecordValue.destroy({ where: { record_id: row.id } });
        await row.destroy();
    }
}

before(async () => {
    try {
        await authenticate();
        // Ensure models are registered
        await import('../database/models/index.mjs');
        dbReady = true;
    } catch (err) {
        console.warn(
            '[repository.integration] DB not available — skipping integration tests:',
            err.message
        );
        dbReady = false;
    }
});

after(async () => {
    if (!dbReady) return;
    try {
        await wipeTestRows();
    } finally {
        await sequelize.close();
    }
});

beforeEach(async () => {
    if (!dbReady) return;
    await wipeTestRows();
    store.exactRecords.clear();
    store.regexRecords.length = 0;
});

function testDomain(name) {
    return `${TEST_PREFIX}${name}`;
}

describe('repository integration (MySQL)', () => {

    it('skips when DB is down (meta)', { skip: false }, () => {
        if (!dbReady) {
            console.log('Integration tests skipped — configure DB_* and run migrations.');
        }
        assert.ok(true);
    });

    it('saveRecord creates a single row per domain', async (t) => {
        if (!dbReady) return t.skip('DB not available');

        const domain = testDomain('once.example');

        await saveRecord({
            domain,
            source: RECORD_SOURCE.CACHE,
            dnsServerId: null,
            A: [{ address: '10.0.0.1', ttl: 60, expiresAt: Date.now() + 60_000 }],
            AAAA: [],
            CNAME: [],
            hits: 1,
            lastHit: Date.now()
        });

        await saveRecord({
            domain,
            source: RECORD_SOURCE.CACHE,
            dnsServerId: null,
            A: [{ address: '10.0.0.2', ttl: 60, expiresAt: Date.now() + 60_000 }],
            AAAA: [],
            CNAME: [],
            hits: 2,
            lastHit: Date.now()
        });

        const rows = await Record.findAll({ where: { domain } });
        assert.equal(rows.length, 1, 'must not create duplicate domain rows');
        assert.equal(rows[0].source, RECORD_SOURCE.CACHE);

        const values = await RecordValue.findAll({
            where: { record_id: rows[0].id, type: 'A' }
        });
        assert.ok(values.length >= 1);
        const addresses = JSON.parse(values[0].value);
        assert.ok(addresses.includes('10.0.0.2'));
    });

    it('saveRecord does not create CACHE row when LOCAL exists', async (t) => {
        if (!dbReady) return t.skip('DB not available');

        const domain = testDomain('local.example');
        const now = Date.now();

        await Record.create({
            domain,
            enabled: true,
            is_regex: false,
            source: RECORD_SOURCE.LOCAL,
            hits: 0,
            last_hit: null,
            created_at: now,
            updated_at: now
        });

        await saveRecord({
            domain,
            source: RECORD_SOURCE.CACHE,
            dnsServerId: 1,
            A: [{ address: '8.8.8.8', ttl: 60, expiresAt: now + 60_000 }],
            AAAA: [],
            CNAME: [],
            hits: 1,
            lastHit: now
        });

        const rows = await Record.findAll({ where: { domain } });
        assert.equal(rows.length, 1);
        assert.equal(rows[0].source, RECORD_SOURCE.LOCAL);

        const values = await RecordValue.findAll({
            where: { record_id: rows[0].id }
        });
        assert.equal(values.length, 0, 'LOCAL must not gain cache values from saveRecord');
    });

    it('saveLookupStatus ignores LOCAL domains', async (t) => {
        if (!dbReady) return t.skip('DB not available');

        const domain = testDomain('lookup.example');
        const now = Date.now();

        const local = await Record.create({
            domain,
            enabled: true,
            is_regex: false,
            source: RECORD_SOURCE.LOCAL,
            hits: 0,
            last_hit: null,
            created_at: now,
            updated_at: now
        });

        await saveLookupStatus(domain, 1, 'A', RECORD_STATUS.TIMEOUT);

        const rows = await Record.findAll({ where: { domain } });
        assert.equal(rows.length, 1);
        assert.equal(rows[0].id, local.id);
        assert.equal(rows[0].source, RECORD_SOURCE.LOCAL);

        const values = await RecordValue.count({
            where: { record_id: local.id }
        });
        assert.equal(values, 0);
    });

    it('domain unique constraint rejects a second insert', async (t) => {
        if (!dbReady) return t.skip('DB not available');

        const domain = testDomain('unique.example');
        const now = Date.now();

        await Record.create({
            domain,
            enabled: true,
            is_regex: false,
            source: RECORD_SOURCE.CACHE,
            hits: 0,
            last_hit: null,
            created_at: now,
            updated_at: now
        });

        await assert.rejects(
            () => Record.create({
                domain,
                enabled: true,
                is_regex: false,
                source: RECORD_SOURCE.FILTERED,
                hits: 0,
                last_hit: null,
                created_at: now,
                updated_at: now
            }),
            /UniqueConstraintError|SequelizeUniqueConstraintError|Duplicate|ER_DUP_ENTRY/i
        );
    });

    it('loadRecords puts LOCAL domain into memory store', async (t) => {
        if (!dbReady) return t.skip('DB not available');

        const domain = testDomain('mem.example');
        const now = Date.now();

        const row = await Record.create({
            domain,
            enabled: true,
            is_regex: false,
            source: RECORD_SOURCE.LOCAL,
            hits: 0,
            last_hit: null,
            created_at: now,
            updated_at: now
        });

        await RecordValue.create({
            record_id: row.id,
            dns_server_id: null,
            type: 'A',
            status: RECORD_STATUS.SUCCESS,
            value: JSON.stringify(['192.0.2.1']),
            ttl: null,
            selected: true,
            is_stale: false,
            expires_at: null,
            last_success_at: now,
            created_at: now,
            updated_at: now
        });

        await loadRecords();

        const mem = store.exactRecords.get(domain);
        assert.ok(mem);
        assert.equal(mem.source, RECORD_SOURCE.LOCAL);
        assert.ok(mem.servers[0]?.A?.length);
        assert.equal(mem.servers[0].A[0].address, '192.0.2.1');
    });
});
