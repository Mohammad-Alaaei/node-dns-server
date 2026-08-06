import { Router } from 'express';
import { isIPv4 } from 'node:net';
import { Op } from 'sequelize';
import { DnsServer, DnsRule } from '../../../database/models/index.mjs';
import { DNS_SERVER_TYPE } from '../../../config/constants.mjs';
import { loadDnsServers } from '../../../database/repository.mjs';
import { prepareRuleDomain } from '../../../utils/domain_utils.mjs';
import { authenticate, requireRole } from '../middleware/auth.mjs';
import { paginateQuery } from '../utils/pagination.mjs';

const router = Router();

const SERVER_LIST_ATTRIBUTES = [
    'id',
    'ip',
    'type',
    'enabled',
    'priority',
    'average_latency',
    'successes',
    'failures',
    'timeouts'
];

const SERVER_TYPES = new Set(Object.values(DNS_SERVER_TYPE));

router.use(authenticate, requireRole('superadmin', 'admin', 'viewer'));

/**
 * GET /api/dns-servers?page=1&limit=20
 */
router.get('/', async (req, res, next) => {
    try {
        const result = await paginateQuery(req.query, ({ limit, offset }) =>
            DnsServer.findAndCountAll({
                attributes: SERVER_LIST_ATTRIBUTES,
                order: [
                    ['type', 'ASC'],
                    ['priority', 'DESC'],
                    ['id', 'ASC']
                ],
                limit,
                offset
            })
        );

        result.items = result.items.map(row =>
            row.get ? row.get({ plain: true }) : row
        );

        return res.json(result);
    } catch (err) {
        return next(err);
    }
});

/**
 * POST /api/dns-servers
 * Body: { ip, type, enabled?, priority? }
 * superadmin only
 */
router.post('/', requireRole('superadmin'), async (req, res, next) => {
    try {
        const parsed = parseServerBody(req.body ?? {}, { partial: false });
        if (parsed.error) {
            return res.status(400).json({ error: parsed.error });
        }

        const existing = await DnsServer.findOne({ where: { ip: parsed.data.ip } });
        if (existing) {
            return res.status(409).json({ error: 'ip already exists' });
        }

        const created = await DnsServer.create({
            ip: parsed.data.ip,
            type: parsed.data.type,
            enabled: parsed.data.enabled,
            priority: parsed.data.priority,
            average_latency: 0,
            successes: 0,
            failures: 0,
            timeouts: 0
        });

        await loadDnsServers();

        return res.status(201).json({
            server: serializeServer(created)
        });
    } catch (err) {
        return next(err);
    }
});

/**
 * GET /api/dns-servers/:id
 */
router.get('/:id', async (req, res, next) => {
    try {
        const id = parseId(req.params.id);
        if (id == null) {
            return res.status(400).json({ error: 'invalid id' });
        }

        const server = await DnsServer.findByPk(id, {
            attributes: SERVER_LIST_ATTRIBUTES
        });

        if (!server) {
            return res.status(404).json({ error: 'DNS server not found' });
        }

        return res.json({ server: serializeServer(server) });
    } catch (err) {
        return next(err);
    }
});

/**
 * PATCH /api/dns-servers/:id
 * Body: partial { ip?, type?, enabled?, priority? }
 * superadmin only — no delete endpoint
 */
router.patch('/:id', requireRole('superadmin'), async (req, res, next) => {
    try {
        const id = parseId(req.params.id);
        if (id == null) {
            return res.status(400).json({ error: 'invalid id' });
        }

        const server = await DnsServer.findByPk(id);
        if (!server) {
            return res.status(404).json({ error: 'DNS server not found' });
        }

        const parsed = parseServerBody(req.body ?? {}, { partial: true });
        if (parsed.error) {
            return res.status(400).json({ error: parsed.error });
        }

        const nextState = {
            ip: parsed.data.ip ?? server.ip,
            type: parsed.data.type ?? server.type,
            enabled: parsed.data.enabled ?? server.enabled,
            priority: parsed.data.priority ?? server.priority
        };

        if (nextState.ip !== server.ip) {
            const clash = await DnsServer.findOne({
                where: {
                    ip: nextState.ip,
                    id: { [Op.ne]: id }
                }
            });
            if (clash) {
                return res.status(409).json({ error: 'ip already exists' });
            }
        }

        const guard = await guardDefaultPool(server, nextState);
        if (guard.error) {
            return res.status(400).json({ error: guard.error });
        }

        await server.update({
            ip: nextState.ip,
            type: nextState.type,
            enabled: nextState.enabled,
            priority: nextState.priority
        });

        await loadDnsServers();

        return res.json({ server: serializeServer(server) });
    } catch (err) {
        return next(err);
    }
});

/**
 * GET /api/dns-servers/:id/rules?page=1&limit=20
 */
router.get('/:id/rules', async (req, res, next) => {
    try {
        const serverId = parseId(req.params.id);
        if (serverId == null) {
            return res.status(400).json({ error: 'invalid id' });
        }

        const server = await DnsServer.findByPk(serverId, { attributes: ['id'] });
        if (!server) {
            return res.status(404).json({ error: 'DNS server not found' });
        }

        const result = await paginateQuery(req.query, ({ limit, offset }) =>
            DnsRule.findAndCountAll({
                where: { server_id: serverId },
                order: [
                    ['is_regex', 'ASC'],
                    ['domain', 'ASC'],
                    ['id', 'ASC']
                ],
                limit,
                offset
            })
        );

        result.items = result.items.map(row => serializeRule(row));

        return res.json(result);
    } catch (err) {
        return next(err);
    }
});

/**
 * POST /api/dns-servers/:id/rules
 * Body: { domain } — is_regex is detected server-side
 * superadmin only
 */
router.post('/:id/rules', requireRole('superadmin'), async (req, res, next) => {
    try {
        const serverId = parseId(req.params.id);
        if (serverId == null) {
            return res.status(400).json({ error: 'invalid id' });
        }

        const server = await DnsServer.findByPk(serverId, { attributes: ['id'] });
        if (!server) {
            return res.status(404).json({ error: 'DNS server not found' });
        }

        const prepared = prepareRuleDomain(req.body?.domain);
        if (prepared.error) {
            return res.status(400).json({ error: prepared.error });
        }

        const rule = await DnsRule.create({
            server_id: serverId,
            domain: prepared.domain,
            is_regex: prepared.is_regex
        });

        await loadDnsServers();

        return res.status(201).json({ rule: serializeRule(rule) });
    } catch (err) {
        return next(err);
    }
});

/**
 * PATCH /api/dns-servers/rules/:ruleId
 * Body: { domain } — is_regex re-detected from domain
 * superadmin only (no server id required)
 */
router.patch('/rules/:ruleId', requireRole('superadmin'), async (req, res, next) => {
    try {
        const ruleId = parseId(req.params.ruleId);
        if (ruleId == null) {
            return res.status(400).json({ error: 'invalid id' });
        }

        const rule = await DnsRule.findByPk(ruleId);
        if (!rule) {
            return res.status(404).json({ error: 'Rule not found' });
        }

        if (req.body?.domain === undefined) {
            return res.status(400).json({ error: 'domain is required' });
        }

        const prepared = prepareRuleDomain(req.body.domain);
        if (prepared.error) {
            return res.status(400).json({ error: prepared.error });
        }

        rule.domain = prepared.domain;
        rule.is_regex = prepared.is_regex;
        await rule.save();
        await loadDnsServers();

        return res.json({ rule: serializeRule(rule) });
    } catch (err) {
        return next(err);
    }
});

/**
 * DELETE /api/dns-servers/rules/:ruleId
 * superadmin only (no server id required)
 */
router.delete('/rules/:ruleId', requireRole('superadmin'), async (req, res, next) => {
    try {
        const ruleId = parseId(req.params.ruleId);
        if (ruleId == null) {
            return res.status(400).json({ error: 'invalid id' });
        }

        const deleted = await DnsRule.destroy({ where: { id: ruleId } });

        if (!deleted) {
            return res.status(404).json({ error: 'Rule not found' });
        }

        await loadDnsServers();

        return res.json({ ok: true });
    } catch (err) {
        return next(err);
    }
});

/* -------------------------------------------------------------------------- */
/*                                   helpers                                  */
/* -------------------------------------------------------------------------- */

function parseId(raw) {
    const n = Number.parseInt(String(raw), 10);
    if (!Number.isFinite(n) || n < 1) {
        return null;
    }
    return n;
}

function serializeServer(row) {
    const s = row.get ? row.get({ plain: true }) : row;
    return {
        id: s.id,
        ip: s.ip,
        type: s.type,
        enabled: !!s.enabled,
        priority: s.priority,
        average_latency: s.average_latency,
        successes: s.successes,
        failures: s.failures,
        timeouts: s.timeouts
    };
}

function serializeRule(row) {
    const r = row.get ? row.get({ plain: true }) : row;
    return {
        id: r.id,
        server_id: r.server_id,
        domain: r.domain,
        is_regex: !!r.is_regex
    };
}

function parseServerBody(body, { partial }) {
    const data = {};

    if (!partial || body.ip !== undefined) {
        if (typeof body.ip !== 'string' || !body.ip.trim()) {
            return { error: 'ip is required' };
        }
        const ip = body.ip.trim();
        if (!isIPv4(ip)) {
            return { error: 'ip must be a valid IPv4 address' };
        }
        data.ip = ip;
    }

    if (!partial || body.type !== undefined) {
        if (typeof body.type !== 'string' || !SERVER_TYPES.has(body.type)) {
            return {
                error: `type must be one of: ${[...SERVER_TYPES].join(', ')}`
            };
        }
        data.type = body.type;
    }

    if (!partial) {
        data.enabled = body.enabled === undefined ? true : !!body.enabled;
        data.priority = body.priority === undefined
            ? 0
            : Number(body.priority);
        if (!Number.isFinite(data.priority)) {
            return { error: 'priority must be a number' };
        }
    } else {
        if (body.enabled !== undefined) {
            data.enabled = !!body.enabled;
        }
        if (body.priority !== undefined) {
            data.priority = Number(body.priority);
            if (!Number.isFinite(data.priority)) {
                return { error: 'priority must be a number' };
            }
        }
    }

    return { data };
}

/**
 * Must always keep at least one enabled DEFAULT server.
 */
async function guardDefaultPool(current, nextState) {
    const wasDefaultEnabled =
        current.type === DNS_SERVER_TYPE.DEFAULT && !!current.enabled;

    const willBeDefaultEnabled =
        nextState.type === DNS_SERVER_TYPE.DEFAULT && !!nextState.enabled;

    // Losing an enabled DEFAULT slot — ensure another remains
    if (wasDefaultEnabled && !willBeDefaultEnabled) {
        const others = await DnsServer.count({
            where: {
                id: { [Op.ne]: current.id },
                type: DNS_SERVER_TYPE.DEFAULT,
                enabled: true
            }
        });

        if (others < 1) {
            return {
                error: 'At least one enabled DEFAULT DNS server is required'
            };
        }
    }

    return { ok: true };
}

export default router;
