import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Op } from 'sequelize';
import { parseListQuery, escapeLike } from '../server/api/utils/list_query.mjs';

const schema = {
    searchable: ['domain'],
    filterable: ['domain', 'source', 'enabled', 'hits'],
    sortable: ['id', 'domain', 'hits', 'updated_at'],
    defaultSort: ['updated_at', 'DESC'],
    fieldTypes: {
        enabled: 'boolean',
        hits: 'number',
        id: 'number'
    }
};

describe('escapeLike', () => {
    it('escapes % and _', () => {
        assert.equal(escapeLike('a%b_c'), 'a\\%b\\_c');
    });
});

describe('parseListQuery', () => {
    it('builds LIKE search on allow-listed field', () => {
        const r = parseListQuery(
            { searchField: 'domain', search: 'google' },
            schema
        );
        assert.ok(!r.error);
        assert.equal(r.meta.search, 'google');
        assert.equal(r.meta.searchField, 'domain');
        assert.ok(r.where.domain[Op.like].includes('google'));
        assert.ok(r.where.domain[Op.like].startsWith('%'));
    });

    it('rejects unknown searchField', () => {
        const r = parseListQuery(
            { searchField: 'password', search: 'x' },
            schema
        );
        assert.ok(r.error);
    });

    it('exact filter + AND logic', () => {
        const r = parseListQuery(
            {
                filter: { source: 'CACHE', enabled: 'true' },
                filterLogic: 'AND'
            },
            schema
        );
        assert.ok(!r.error);
        assert.equal(r.meta.filterLogic, 'AND');
        assert.ok(r.where[Op.and] || r.where.source === 'CACHE');
    });

    it('multi-value filter uses IN when OR', () => {
        const r = parseListQuery(
            {
                filter: { source: 'CACHE,FILTERED' },
                filterLogic: 'OR'
            },
            schema
        );
        assert.ok(!r.error);
        assert.deepEqual(r.meta.filters[0].values, ['CACHE', 'FILTERED']);
        assert.ok(r.where.source[Op.in]);
    });

    it('sort allow-list and direction', () => {
        const r = parseListQuery(
            { sortBy: 'hits', sortDir: 'DESC' },
            schema
        );
        assert.ok(!r.error);
        assert.equal(r.order[0][0], 'hits');
        assert.equal(r.order[0][1], 'DESC');
    });

    it('rejects invalid sortBy', () => {
        const r = parseListQuery({ sortBy: 'drop_table' }, schema);
        assert.ok(r.error);
    });

    it('coerces boolean and number filters', () => {
        const r = parseListQuery(
            { filter: { enabled: 'false', hits: '10' } },
            schema
        );
        assert.ok(!r.error);
        const flat = r.where[Op.and] ?? [r.where];
        const enabled = flat.find(c => 'enabled' in c);
        const hits = flat.find(c => 'hits' in c);
        assert.equal(enabled?.enabled, false);
        assert.equal(hits?.hits, 10);
    });

    it('merges baseWhere', () => {
        const r = parseListQuery(
            {},
            { ...schema, baseWhere: { server_id: 5 } }
        );
        assert.equal(r.where.server_id, 5);
    });
});
