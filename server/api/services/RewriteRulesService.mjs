import { Op } from 'sequelize';
import { RewriteRule } from '../../../database/models/index.mjs';
import { REWRITE_ACTIONS } from '../../../config/constants.mjs';
import { listQuery } from '../utils/list_query.mjs';
import { httpError } from '../utils/http_errors.mjs';
import {
    applyRewriteRuleUpsert,
    applyRewriteRuleRemoveById
} from '../../../memory/apply.mjs';

const ACTIONS = new Set(Object.values(REWRITE_ACTIONS));

const LIST_ATTRIBUTES = [
    'id',
    'name',
    'pattern',
    'action',
    'params',
    'enabled',
    'created_at',
    'updated_at'
];

const LIST_SCHEMA = {
    searchable: ['name', 'pattern', 'action'],
    filterable: ['id', 'name', 'pattern', 'action', 'enabled'],
    sortable: [
        'id',
        'name',
        'pattern',
        'action',
        'enabled',
        'created_at',
        'updated_at'
    ],
    defaultSort: ['id', 'ASC'],
    fieldTypes: {
        id: 'number',
        enabled: 'boolean',
        created_at: 'number',
        updated_at: 'number'
    }
};

function raiseSequelize(err) {
    if (err?.name === 'SequelizeUniqueConstraintError') {
        const fields = err.errors?.map(e => e.path).filter(Boolean) ?? [];
        const msg = fields.length
            ? `Duplicate value for: ${fields.join(', ')}`
            : 'Duplicate entry';
        throw httpError(msg, 409);
    }
    if (err?.name === 'SequelizeValidationError') {
        throw httpError('Validation failed', 400);
    }
    throw err;
}

function serialize(row) {
    const r = row.get ? row.get({ plain: true }) : row;
    return {
        id: r.id,
        name: r.name ?? null,
        pattern: r.pattern,
        action: r.action,
        params: r.params && typeof r.params === 'object' ? r.params : {},
        enabled: !!r.enabled,
        created_at: r.created_at,
        updated_at: r.updated_at
    };
}

function parseId(raw) {
    const n = Number.parseInt(String(raw), 10);
    if (!Number.isFinite(n) || n < 1) {
        return null;
    }
    return n;
}

/**
 * Validate pattern compiles as RegExp and action/params are consistent.
 */
function validateRuleBody(body, { partial }) {
    const data = {};

    if (!partial || body.name !== undefined) {
        if (body.name === null || body.name === undefined || body.name === '') {
            data.name = null;
        } else if (typeof body.name === 'string') {
            data.name = body.name.trim().slice(0, 128) || null;
        } else {
            return { error: 'name must be a string or null' };
        }
    }

    if (!partial || body.pattern !== undefined) {
        if (typeof body.pattern !== 'string' || !body.pattern.trim()) {
            return { error: 'pattern is required' };
        }
        const pattern = body.pattern.trim();
        if (pattern.length > 512) {
            return { error: 'pattern must be at most 512 characters' };
        }
        try {
            // Same wrapping used at load time
            // eslint-disable-next-line no-new
            new RegExp(`^(?:${pattern})$`, 'i');
        } catch {
            return { error: 'pattern is not a valid regular expression' };
        }
        data.pattern = pattern;
    }

    if (!partial || body.action !== undefined) {
        if (typeof body.action !== 'string' || !ACTIONS.has(body.action)) {
            return {
                error: `action must be one of: ${[...ACTIONS].join(', ')}`
            };
        }
        data.action = body.action;
    }

    if (!partial || body.params !== undefined) {
        if (
            body.params === null ||
            typeof body.params !== 'object' ||
            Array.isArray(body.params)
        ) {
            return { error: 'params must be a plain object' };
        }
        data.params = body.params;
    }

    if (!partial || body.enabled !== undefined) {
        if (typeof body.enabled !== 'boolean') {
            return { error: 'enabled must be a boolean' };
        }
        data.enabled = body.enabled;
    }

    // Action-specific param checks (use merged view for partial updates)
    const action = data.action;
    const params = data.params;

    if (action === REWRITE_ACTIONS.CNAME_REWRITE || (!partial && !action)) {
        // On create, action is required; on update we validate when either field present
    }

    if (
        (data.action === REWRITE_ACTIONS.CNAME_REWRITE ||
            (partial && data.params !== undefined)) &&
        params !== undefined
    ) {
        const effectiveAction = data.action; // may be undefined on partial
        if (
            effectiveAction === REWRITE_ACTIONS.CNAME_REWRITE ||
            effectiveAction === undefined
        ) {
            const template = params.template;
            if (
                effectiveAction === REWRITE_ACTIONS.CNAME_REWRITE &&
                (typeof template !== 'string' || !template.trim())
            ) {
                return {
                    error: 'params.template is required for cname_rewrite'
                };
            }
        }
    }

    if (!partial) {
        if (!data.pattern) {
            return { error: 'pattern is required' };
        }
        if (!data.action) {
            return { error: 'action is required' };
        }
        if (data.params === undefined) {
            return { error: 'params is required' };
        }
        if (data.action === REWRITE_ACTIONS.CNAME_REWRITE) {
            const template = data.params?.template;
            if (typeof template !== 'string' || !template.trim()) {
                return {
                    error: 'params.template is required for cname_rewrite'
                };
            }
        }
        if (data.enabled === undefined) {
            data.enabled = true;
        }
    }

    return { data };
}

class RewriteRulesService {
    async list(query) {
        const result = await listQuery(
            query,
            LIST_SCHEMA,
            ({ where, order, limit, offset }) =>
                RewriteRule.findAndCountAll({
                    attributes: LIST_ATTRIBUTES,
                    where,
                    order,
                    limit,
                    offset
                })
        );
        if (result.error) {
            throw httpError(result.error, result.status ?? 400);
        }
        result.items = (result.items ?? []).map(serialize);
        return result;
    }

    async getById(idRaw) {
        const id = parseId(idRaw);
        if (!id) {
            throw httpError('Invalid id', 400);
        }
        const row = await RewriteRule.findByPk(id);
        if (!row) {
            throw httpError('Rewrite rule not found', 404);
        }
        return serialize(row);
    }

    async create(body) {
        const parsed = validateRuleBody(body ?? {}, { partial: false });
        if (parsed.error) {
            throw httpError(parsed.error, 400);
        }

        const now = Date.now();
        let row;
        try {
            row = await RewriteRule.create({
                ...parsed.data,
                created_at: now,
                updated_at: now
            });
        } catch (err) {
            raiseSequelize(err);
        }

        applyRewriteRuleUpsert(row);
        return { ...serialize(row), status: 201 };
    }

    async update(idRaw, body) {
        const id = parseId(idRaw);
        if (!id) {
            throw httpError('Invalid id', 400);
        }

        const row = await RewriteRule.findByPk(id);
        if (!row) {
            throw httpError('Rewrite rule not found', 404);
        }

        const parsed = validateRuleBody(body ?? {}, { partial: true });
        if (parsed.error) {
            throw httpError(parsed.error, 400);
        }

        // When updating action to cname_rewrite or changing params, ensure template
        const nextAction = parsed.data.action ?? row.action;
        const nextParams =
            parsed.data.params !== undefined ? parsed.data.params : row.params;

        if (nextAction === REWRITE_ACTIONS.CNAME_REWRITE) {
            const template = nextParams?.template;
            if (typeof template !== 'string' || !template.trim()) {
                throw httpError(
                    'params.template is required for cname_rewrite',
                    400
                );
            }
        }

        if (Object.keys(parsed.data).length === 0) {
            return serialize(row);
        }

        parsed.data.updated_at = Date.now();

        try {
            await row.update(parsed.data);
        } catch (err) {
            raiseSequelize(err);
        }

        await row.reload();
        applyRewriteRuleUpsert(row);
        return serialize(row);
    }

    async remove(idRaw) {
        const id = parseId(idRaw);
        if (!id) {
            throw httpError('Invalid id', 400);
        }

        const row = await RewriteRule.findByPk(id);
        if (!row) {
            throw httpError('Rewrite rule not found', 404);
        }

        await row.destroy();
        applyRewriteRuleRemoveById(id);
        return { ok: true, id };
    }

    /**
     * PATCH /api/rewrite-rules/enabled
     * Body: { ids: number[], enabled: boolean }
     */
    async setEnabled(ids, enabled) {
        if (!Array.isArray(ids) || ids.length === 0) {
            throw httpError('ids must be a non-empty array', 400);
        }
        if (typeof enabled !== 'boolean') {
            throw httpError('enabled must be a boolean', 400);
        }

        const normalized = [
            ...new Set(
                ids
                    .map(id => Number.parseInt(String(id), 10))
                    .filter(n => Number.isFinite(n) && n > 0)
            )
        ];

        if (!normalized.length) {
            throw httpError('ids must contain valid positive integers', 400);
        }

        const now = Date.now();
        await RewriteRule.update(
            { enabled, updated_at: now },
            { where: { id: { [Op.in]: normalized } } }
        );

        const rows = await RewriteRule.findAll({
            where: { id: { [Op.in]: normalized } }
        });

        for (const row of rows) {
            applyRewriteRuleUpsert(row);
        }

        return {
            ok: true,
            updated: rows.length,
            enabled
        };
    }
}

export default new RewriteRulesService();
