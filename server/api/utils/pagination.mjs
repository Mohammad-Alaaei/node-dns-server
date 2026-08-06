/**
 * Shared list pagination for every API collection endpoint.
 *
 * Query:
 *   page  — 1-based page index (default 1)
 *   limit — page size (default 20, max 100)
 *
 * Response envelope:
 *   {
 *     items: T[],
 *     pagination: {
 *       page, limit, total, totalPages, hasNext, hasPrev
 *     }
 *   }
 */

const DEFAULT_PAGE = 1;
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;

/**
 * Parse page/limit from req.query (or any plain object).
 */
export function parsePagination(query = {}, options = {}) {
    const defaultLimit = options.defaultLimit ?? DEFAULT_LIMIT;
    const maxLimit = options.maxLimit ?? MAX_LIMIT;

    let page = Number.parseInt(String(query.page ?? DEFAULT_PAGE), 10);
    let limit = Number.parseInt(String(query.limit ?? defaultLimit), 10);

    if (!Number.isFinite(page) || page < 1) {
        page = DEFAULT_PAGE;
    }

    if (!Number.isFinite(limit) || limit < 1) {
        limit = defaultLimit;
    }

    if (limit > maxLimit) {
        limit = maxLimit;
    }

    const offset = (page - 1) * limit;

    return { page, limit, offset };
}

/**
 * Build pagination metadata + slice an in-memory array.
 */
export function paginateArray(items, query, options = {}) {
    const list = Array.isArray(items) ? items : [];
    const { page, limit, offset } = parsePagination(query, options);
    const total = list.length;
    const totalPages = total === 0 ? 0 : Math.ceil(total / limit);
    const sliced = list.slice(offset, offset + limit);

    return {
        items: sliced,
        pagination: buildPaginationMeta({ page, limit, total, totalPages })
    };
}

/**
 * Sequelize findAndCountAll helper.
 * `finder` is async () => ({ rows, count }) — usually Model.findAndCountAll({...}).
 */
export async function paginateQuery(query, finder, options = {}) {
    const { page, limit, offset } = parsePagination(query, options);
    const result = await finder({ limit, offset, page });

    const rows = result.rows ?? result.items ?? [];
    const total = Number(result.count ?? result.total ?? rows.length);
    const totalPages = total === 0 ? 0 : Math.ceil(total / limit);

    return {
        items: rows,
        pagination: buildPaginationMeta({ page, limit, total, totalPages })
    };
}

export function buildPaginationMeta({ page, limit, total, totalPages }) {
    return {
        page,
        limit,
        total,
        totalPages,
        hasNext: totalPages > 0 && page < totalPages,
        hasPrev: page > 1 && total > 0
    };
}
