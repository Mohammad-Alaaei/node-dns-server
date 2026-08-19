import { isIPv4 } from 'node:net';
import { Op } from 'sequelize';
import { DnsServer, DnsRule } from '../../../database/models/index.mjs';
import { DNS_SERVER_TYPE } from '../../../config/constants.mjs';
import { prepareRuleDomain } from '../../../utils/domain_utils.mjs';
import {
    applyDnsServerUpsert,
    applyDnsRuleUpsert,
    applyDnsRuleRemove
} from '../../../memory/apply.mjs';
import { listQuery } from '../utils/list_query.mjs';
import { httpError } from '../utils/http_errors.mjs';

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

const DNS_SERVERS_LIST_SCHEMA = {
    searchable: ['ip', 'type'],
    filterable: ['id', 'ip', 'type', 'enabled', 'priority'],
    sortable: [
        'id', 'ip', 'type', 'enabled', 'priority',
        'average_latency', 'successes', 'failures', 'timeouts'
    ],
    defaultSort: ['type', 'ASC'],
    fieldTypes: {
        id: 'number',
        enabled: 'boolean',
        priority: 'number',
        average_latency: 'number',
        successes: 'number',
        failures: 'number',
        timeouts: 'number'
    }
};

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

async function guardDefaultPool(current, nextState) {
    const wasDefaultEnabled =
        current.type === DNS_SERVER_TYPE.DEFAULT && !!current.enabled;

    const willBeDefaultEnabled =
        nextState.type === DNS_SERVER_TYPE.DEFAULT && !!nextState.enabled;

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

class DnsServersService {
    async list(query) {
        const result = await listQuery(
            query,
            DNS_SERVERS_LIST_SCHEMA,
            ({ where, order, limit, offset }) =>
                DnsServer.findAndCountAll({
                    attributes: SERVER_LIST_ATTRIBUTES,
                    where,
                    order,
                    limit,
                    offset
                })
        );

        if (result.error) {
            throw httpError(result.error, result.status ?? 400);
        }

        result.items = result.items.map(row =>
            row.get ? row.get({ plain: true }) : row
        );

        return result;
    }

    async create(body) {
        const parsed = parseServerBody(body ?? {}, { partial: false });
        if (parsed.error) {
            throw httpError(parsed.error, 400);
        }

        const existing = await DnsServer.findOne({ where: { ip: parsed.data.ip } });
        if (existing) {
            throw httpError('ip already exists', 409);
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

        applyDnsServerUpsert(created);

        return { server: serializeServer(created), status: 201 };
    }

    async getById(rawId) {
        const id = parseId(rawId);
        if (id == null) {
            throw httpError('invalid id', 400);
        }

        const server = await DnsServer.findByPk(id, {
            attributes: SERVER_LIST_ATTRIBUTES
        });

        if (!server) {
            throw httpError('DNS server not found', 404);
        }

        return { server: serializeServer(server) };
    }

    async update(rawId, body) {
        const id = parseId(rawId);
        if (id == null) {
            throw httpError('invalid id', 400);
        }

        const server = await DnsServer.findByPk(id);
        if (!server) {
            throw httpError('DNS server not found', 404);
        }

        const parsed = parseServerBody(body ?? {}, { partial: true });
        if (parsed.error) {
            throw httpError(parsed.error, 400);
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
                throw httpError('ip already exists', 409);
            }
        }

        const guard = await guardDefaultPool(server, nextState);
        if (guard.error) {
            throw httpError(guard.error, 400);
        }

        await server.update({
            ip: nextState.ip,
            type: nextState.type,
            enabled: nextState.enabled,
            priority: nextState.priority
        });

        if (nextState.enabled) {
            const rules = await DnsRule.findAll({
                where: { server_id: id }
            });
            applyDnsServerUpsert(server);
            for (const rule of rules) {
                applyDnsRuleUpsert(rule, server);
            }
        } else {
            applyDnsServerUpsert(server);
        }

        return { server: serializeServer(server) };
    }

    async listRules(rawServerId, query) {
        const serverId = parseId(rawServerId);
        if (serverId == null) {
            throw httpError('invalid id', 400);
        }

        const server = await DnsServer.findByPk(serverId, { attributes: ['id'] });
        if (!server) {
            throw httpError('DNS server not found', 404);
        }

        const result = await listQuery(
            query,
            {
                searchable: ['domain'],
                filterable: ['id', 'domain', 'is_regex'],
                sortable: ['id', 'domain', 'is_regex'],
                defaultSort: ['domain', 'ASC'],
                fieldTypes: {
                    id: 'number',
                    is_regex: 'boolean'
                },
                baseWhere: { server_id: serverId }
            },
            ({ where, order, limit, offset }) =>
                DnsRule.findAndCountAll({
                    where,
                    order,
                    limit,
                    offset
                })
        );

        if (result.error) {
            throw httpError(result.error, result.status ?? 400);
        }

        result.items = result.items.map(row => serializeRule(row));
        return result;
    }

    async createRule(rawServerId, body) {
        const serverId = parseId(rawServerId);
        if (serverId == null) {
            throw httpError('invalid id', 400);
        }

        const server = await DnsServer.findByPk(serverId);
        if (!server) {
            throw httpError('DNS server not found', 404);
        }

        const prepared = prepareRuleDomain(body?.domain);
        if (prepared.error) {
            throw httpError(prepared.error, 400);
        }

        const rule = await DnsRule.create({
            server_id: serverId,
            domain: prepared.domain,
            is_regex: prepared.is_regex
        });

        applyDnsRuleUpsert(rule, server);

        return { rule: serializeRule(rule), status: 201 };
    }

    async updateRule(rawRuleId, body) {
        const ruleId = parseId(rawRuleId);
        if (ruleId == null) {
            throw httpError('invalid id', 400);
        }

        const rule = await DnsRule.findByPk(ruleId);
        if (!rule) {
            throw httpError('Rule not found', 404);
        }

        if (body?.domain === undefined) {
            throw httpError('domain is required', 400);
        }

        const prepared = prepareRuleDomain(body.domain);
        if (prepared.error) {
            throw httpError(prepared.error, 400);
        }

        const previousDomain = rule.domain;
        rule.domain = prepared.domain;
        rule.is_regex = prepared.is_regex;
        await rule.save();

        const server = await DnsServer.findByPk(rule.server_id);
        if (server) {
            applyDnsRuleUpsert(rule, server, previousDomain);
        }

        return { rule: serializeRule(rule) };
    }

    async deleteRule(rawRuleId) {
        const ruleId = parseId(rawRuleId);
        if (ruleId == null) {
            throw httpError('invalid id', 400);
        }

        const rule = await DnsRule.findByPk(ruleId);
        if (!rule) {
            throw httpError('Rule not found', 404);
        }

        const domain = rule.domain;
        const serverId = rule.server_id;

        await rule.destroy();
        applyDnsRuleRemove(domain, serverId);

        return { ok: true };
    }
}

export default new DnsServersService();
