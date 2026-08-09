/**
 * Shared list query builder for all collection endpoints.
 *
 * Query (flat):
 *   page, limit                         — pagination (see pagination.mjs)
 *   searchField, search                 — LIKE %search% on one allow-listed field
 *   filter[field]=value                 — exact match (repeat / comma = multi-value)
 *   filterLogic=AND|OR                  — combine filters (default AND)
 *   sortBy, sortDir=ASC|DESC            — one column sort
 *
 * Security:
 *   - Only allow-listed column names (no client-controlled identifiers in SQL)
 *   - Values bound via Sequelize operators (no string-concatenated SQL)
 *   - LIKE wildcards in user input are escaped
 */

import { Op } from 'sequelize';
import { paginateQuery } from './pagination.mjs';

const FILTER_LOGIC = new Set(['AND', 'OR']);
const SORT_DIR = new Set(['ASC', 'DESC']);

/** Column name: letters, digits, underscore only */
const SAFE_IDENT = /^[a-z][a-z0-9_]*$/i;

/**
 * Escape LIKE metacharacters so user input is literal.
 */
export function escapeLike(value) {
    return String(value)
        .replace(/\\/g, '\\\\')
        .replace(/%/g, '\\%')
        .replace(/_/g, '\\_');
}

function normalizeToken(value) {
    if (value === undefined || value === null) {
        return null;
    }
    const s = String(value).trim();
    return s.length ? s : null;
}

/**
 * Express may give filter[field] as string, array, or omit.
 * Also accept comma-separated multi-values.
 */
function toValueList(raw) {
    if (raw === undefined || raw === null) {
        return [];
    }

    const parts = Array.isArray(raw) ? raw : [raw];
    const out = [];

    for (const part of parts) {
        const s = String(part);
        for (const piece of s.split(',')) {
            const t = piece.trim();
            if (t.length) {
                out.push(t);
            }
        }
    }

    return out;
}

function coerceValue(raw, type) {
    if (type === 'boolean') {
        const s = String(raw).toLowerCase();
        if (s === 'true' || s === '1' || s === 'yes') return true;
        if (s === 'false' || s === '0' || s === 'no') return false;
        return { error: `invalid boolean: ${raw}` };
    }

    if (type === 'number') {
        const n = Number(raw);
        if (!Number.isFinite(n)) {
            return { error: `invalid number: ${raw}` };
        }
        return n;
    }

    // string (default)
    return String(raw);
}


/**
 * Normalize filter params regardless of Express query parser mode.
 * @returns {Record<string, string|string[]>}
 */
function collectFilters(query) {
    const out = {};

    // Nested object: ?filter[source]=CACHE
    if (query.filter && typeof query.filter === 'object' && !Array.isArray(query.filter)) {
        for (const [field, raw] of Object.entries(query.filter)) {
            out[field] = raw;
        }
    }

    // Flat bracket or dotted keys: filter[source] / filter.source
    const bracket = /^filter\[([a-z][a-z0-9_]*)\]$/i;
    const dotted = /^filter\.([a-z][a-z0-9_]*)$/i;

    for (const [key, raw] of Object.entries(query)) {
        let m = key.match(bracket);
        if (!m) {
            m = key.match(dotted);
        }
        if (!m) {
            continue;
        }
        const field = m[1];
        if (out[field] === undefined) {
            out[field] = raw;
        } else {
            // merge multi-value
            const prev = out[field];
            out[field] = Array.isArray(prev)
                ? prev.concat(raw)
                : [prev].concat(raw);
        }
    }

    return out;
}

function fieldType(schema, field) {
    return schema.fieldTypes?.[field] ?? 'string';
}

/**
 * @param {object} query - req.query
 * @param {object} schema
 * @param {string[]} schema.searchable
 * @param {string[]} schema.filterable
 * @param {string[]} schema.sortable
 * @param {[string, 'ASC'|'DESC']} [schema.defaultSort]
 * @param {Record<string, 'string'|'number'|'boolean'>} [schema.fieldTypes]
 * @param {object} [schema.baseWhere] - always applied (e.g. server_id for rules)
 * @returns {{ where: object, order: array, meta: object } | { error: string }}
 */
export function parseListQuery(query = {}, schema = {}) {
    const searchable = new Set(schema.searchable ?? []);
    const filterable = new Set(schema.filterable ?? []);
    const sortable = new Set(schema.sortable ?? []);
    const defaultSort = schema.defaultSort ?? ['id', 'ASC'];

    const conditions = [];
    const metaFilters = [];

    // ---- search (LIKE) ----
    const search = normalizeToken(query.search);
    let searchField = normalizeToken(query.searchField);

    if (search) {
        if (!searchField) {
            return { error: 'searchField is required when search is provided' };
        }
        if (!SAFE_IDENT.test(searchField) || !searchable.has(searchField)) {
            return {
                error: `searchField must be one of: ${[...searchable].join(', ') || '(none)'}`
            };
        }

        conditions.push({
            [searchField]: { [Op.like]: `%${escapeLike(search)}%` }
        });
    } else {
        searchField = null;
    }

    // ---- filters (exact) ----
    let filterLogic = String(query.filterLogic ?? 'AND').toUpperCase();
    if (!FILTER_LOGIC.has(filterLogic)) {
        return { error: 'filterLogic must be AND or OR' };
    }

    /**
     * Collect filters from:
     *   - nested:  filter[source]=CACHE  → query.filter.source (extended parser)
     *   - flat:    filter[source]=CACHE  → query['filter[source]'] (simple parser / Express 5 default)
     *   - dotted:  filter.source=CACHE   → query['filter.source']
     */
    const filterObj = collectFilters(query);

    for (const [field, raw] of Object.entries(filterObj)) {
        if (!SAFE_IDENT.test(field) || !filterable.has(field)) {
            return {
                error: `filter field not allowed: ${field}. Allowed: ${[...filterable].join(', ') || '(none)'}`
            };
        }

        const values = toValueList(raw);
        if (!values.length) {
            continue;
        }

        const type = fieldType(schema, field);
        const coerced = [];

        for (const v of values) {
            const c = coerceValue(v, type);
            if (c && typeof c === 'object' && c.error) {
                return { error: `filter[${field}]: ${c.error}` };
            }
            coerced.push(c);
        }

        metaFilters.push({ field, values: coerced });

        if (coerced.length === 1) {
            conditions.push({ [field]: coerced[0] });
        } else if (filterLogic === 'OR') {
            conditions.push({ [field]: { [Op.in]: coerced } });
        } else {
            // AND of exact equals on same column (usually empty set; still supported)
            conditions.push({
                [Op.and]: coerced.map(v => ({ [field]: v }))
            });
        }
    }

    // ---- sort (single column) ----
    let sortBy = normalizeToken(query.sortBy) ?? defaultSort[0];
    let sortDir = String(query.sortDir ?? defaultSort[1] ?? 'ASC').toUpperCase();

    if (!SORT_DIR.has(sortDir)) {
        return { error: 'sortDir must be ASC or DESC' };
    }

    if (!SAFE_IDENT.test(sortBy) || !sortable.has(sortBy)) {
        return {
            error: `sortBy must be one of: ${[...sortable].join(', ') || '(none)'}`
        };
    }

    const order = [[sortBy, sortDir]];
    // Stable tie-breaker when not sorting by id
    if (sortBy !== 'id' && sortable.has('id')) {
        order.push(['id', 'ASC']);
    }

    // ---- combine where ----
    let where = { ...(schema.baseWhere ?? {}) };

    if (conditions.length === 1) {
        Object.assign(where, conditions[0]);
    } else if (conditions.length > 1) {
        const op = filterLogic === 'OR' ? Op.or : Op.and;
        where = {
            ...where,
            [op]: conditions
        };
    }

    return {
        where,
        order,
        meta: {
            search: search ?? null,
            searchField: searchField ?? null,
            filters: metaFilters,
            filterLogic,
            sortBy,
            sortDir
        }
    };
}

/**
 * Full list: parse + paginate + echo query meta.
 *
 * @param {object} query - req.query
 * @param {object} schema - parseListQuery schema
 * @param {(args: { where, order, limit, offset }) => Promise<{rows,count}>} finder
 * @param {object} [pageOptions] - passed to paginateQuery
 */
export async function listQuery(query, schema, finder, pageOptions = {}) {
    const parsed = parseListQuery(query, schema);

    if (parsed.error) {
        return { error: parsed.error, status: 400 };
    }

    const result = await paginateQuery(
        query,
        ({ limit, offset }) =>
            finder({
                where: parsed.where,
                order: parsed.order,
                limit,
                offset
            }),
        pageOptions
    );

    result.query = parsed.meta;
    return result;
}

export default {
    parseListQuery,
    listQuery,
    escapeLike
};
