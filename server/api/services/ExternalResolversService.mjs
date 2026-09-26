import { Op } from 'sequelize';
import {
    ExternalResolver,
    ExternalResolverKey
} from '../../../database/models/index.mjs';
import {
    EXTERNAL_RESOLVER_PROVIDERS,
    EXTERNAL_RESOLVER_MODES,
    EXTERNAL_RESOLVER_DEFAULT_PERIOD_MS,
    EXTERNAL_RESOLVER_USAGE_SYNC_MS
} from '../../../config/constants.mjs';
import { listQuery } from '../utils/list_query.mjs';
import { httpError } from '../utils/http_errors.mjs';
import * as logger from '../../../utils/logger.mjs';
import {
    fetchMxUsage,
    mxLookup,
    parseMxInformation,
    mxRemaining
} from './providers/mxtoolbox.mjs';

const PROVIDERS = new Set(Object.values(EXTERNAL_RESOLVER_PROVIDERS));
const MODES = new Set(Object.values(EXTERNAL_RESOLVER_MODES));

const LIST_ATTRIBUTES = [
    'id',
    'provider',
    'name',
    'mode',
    'enabled',
    'config',
    'created_at',
    'updated_at'
];

const LIST_SCHEMA = {
    searchable: ['name', 'provider', 'mode'],
    filterable: ['id', 'provider', 'name', 'mode', 'enabled'],
    sortable: [
        'id',
        'provider',
        'name',
        'mode',
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

let usageSyncTimer = null;

function now() {
    return Date.now();
}

function parseId(raw) {
    const n = Number.parseInt(String(raw), 10);
    if (!Number.isFinite(n) || n < 1) return null;
    return n;
}

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

/** Mask full API key for API responses (e.g. c7d8…1ec1). Never expose the secret. */
function maskApiKey(raw) {
    const s = String(raw ?? '').trim();
    if (!s) return '';
    if (s.length <= 8) return '••••';
    return `${s.slice(0, 4)}…${s.slice(-4)}`;
}

/** Local calendar midnight for timestamp `t` (server timezone). */
function startOfLocalDay(t) {
    const d = new Date(t);
    d.setHours(0, 0, 0, 0);
    return d.getTime();
}

/**
 * Midnight-aligned period start for manual (non auto_sync) keys.
 * Daily period → current local midnight. Multi-day → midnight of period block.
 */
function midnightAlignedPeriodStart(t, periodMs) {
    const dayMs = 86400000;
    const dayStart = startOfLocalDay(t);
    if (periodMs <= dayMs) {
        return dayStart;
    }
    const nDays = Math.max(1, Math.round(periodMs / dayMs));
    const epochDay = Math.floor(dayStart / dayMs);
    const periodIndex = Math.floor(epochDay / nDays);
    return periodIndex * nDays * dayMs;
}

function effectiveRemaining(limit, used) {
    if (limit <= 0) return Number.POSITIVE_INFINITY;
    return Math.max(0, limit - used);
}

function serializeKey(row) {
    const k = row.get ? row.get({ plain: true }) : row;
    const periodStart = Number(k.period_start) || 0;
    const periodMs = Number(k.period_ms) || EXTERNAL_RESOLVER_DEFAULT_PERIOD_MS;
    const used = Number(k.used_count) || 0;
    const limit = Number(k.period_limit) || 0;
    const autoSync = k.auto_sync !== false;
    const t = now();

    let effectiveUsed = used;
    let effectivePeriodStart = periodStart || null;

    if (!autoSync) {
        const aligned = midnightAlignedPeriodStart(t, periodMs);
        if (!periodStart || periodStart < aligned) {
            effectiveUsed = 0;
            effectivePeriodStart = aligned;
        }
    } else if (periodStart > 0 && t - periodStart >= periodMs) {
        effectiveUsed = 0;
        effectivePeriodStart = null;
    }

    const remaining = effectiveRemaining(limit, effectiveUsed);

    return {
        id: k.id,
        resolver_id: k.resolver_id,
        api_key_hint: maskApiKey(k.api_key),
        label: k.label ?? null,
        priority: Number(k.priority) || 0,
        enabled: !!k.enabled,
        auto_sync: autoSync,
        period_limit: limit,
        used_count: effectiveUsed,
        remaining: Number.isFinite(remaining) ? remaining : null,
        period_start: effectivePeriodStart,
        period_ms: periodMs,
        last_error: k.last_error ?? null,
        last_used_at: k.last_used_at ?? null,
        created_at: k.created_at,
        updated_at: k.updated_at
    };
}

function serializeResolver(row, keys = null) {
    const r = row.get ? row.get({ plain: true }) : row;
    const out = {
        id: r.id,
        provider: r.provider,
        name: r.name,
        mode: r.mode,
        enabled: !!r.enabled,
        config: r.config && typeof r.config === 'object' ? r.config : {},
        created_at: r.created_at,
        updated_at: r.updated_at
    };
    if (keys != null) {
        out.keys = keys.map(serializeKey);
    }
    return out;
}

/**
 * Reset period counters when the window has elapsed.
 * - auto_sync keys: sliding window from period_start + period_ms
 * - manual keys: reset at local midnight boundaries (period_ms length)
 */
async function ensurePeriodFresh(keyRow) {
    const periodMs =
        Number(keyRow.period_ms) || EXTERNAL_RESOLVER_DEFAULT_PERIOD_MS;
    const periodStart = Number(keyRow.period_start) || 0;
    const autoSync = keyRow.auto_sync !== false;
    const t = now();

    if (autoSync) {
        if (periodStart > 0 && t - periodStart < periodMs) {
            return keyRow;
        }
        await keyRow.update({
            used_count: 0,
            period_start: t,
            updated_at: t
        });
        return keyRow;
    }

    const aligned = midnightAlignedPeriodStart(t, periodMs);
    if (periodStart > 0 && periodStart >= aligned) {
        return keyRow;
    }

    await keyRow.update({
        used_count: 0,
        period_start: aligned,
        updated_at: t
    });
    return keyRow;
}

/**
 * Whether this key can still accept a request (local counters only).
 * period_limit === 0 means unlimited for local tracking (still may fail at provider).
 */
function keyHasQuota(keyPlain) {
    if (!keyPlain.enabled) return false;
    const limit = Number(keyPlain.period_limit) || 0;
    if (limit <= 0) return true;
    const used = Number(keyPlain.used_count) || 0;
    return used < limit;
}

function remainingOf(keyPlain) {
    const limit = Number(keyPlain.period_limit) || 0;
    const used = Number(keyPlain.used_count) || 0;
    return effectiveRemaining(limit, used);
}

/**
 * Prefer the enabled key with the most remaining quota; tie-break by lowest priority, then id.
 * Spreads load across keys instead of draining one first.
 * @param {number} resolverId
 * @returns {Promise<import('sequelize').Model|null>}
 */
async function pickNextKey(resolverId) {
    const keys = await ExternalResolverKey.findAll({
        where: {
            resolver_id: resolverId,
            enabled: true
        }
    });

    let best = null;
    let bestRemaining = -1;
    let bestPriority = Number.POSITIVE_INFINITY;
    let bestId = Number.POSITIVE_INFINITY;

    for (const key of keys) {
        await ensurePeriodFresh(key);
        if (!keyHasQuota(key)) continue;

        const rem = remainingOf(key);
        const remScore = Number.isFinite(rem) ? rem : Number.MAX_SAFE_INTEGER;
        const priority = Number(key.priority) || 0;
        const id = Number(key.id) || 0;

        const better =
            remScore > bestRemaining ||
            (remScore === bestRemaining && priority < bestPriority) ||
            (remScore === bestRemaining &&
                priority === bestPriority &&
                id < bestId);

        if (better) {
            best = key;
            bestRemaining = remScore;
            bestPriority = priority;
            bestId = id;
        }
    }

    return best;
}

async function incrementKeyUsage(keyRow) {
    const t = now();
    await ensurePeriodFresh(keyRow);
    await keyRow.update({
        used_count: (Number(keyRow.used_count) || 0) + 1,
        last_used_at: t,
        last_error: null,
        updated_at: t
    });
}

async function markKeyError(keyRow, message) {
    const t = now();
    const msg = String(message || 'error').slice(0, 512);
    await keyRow.update({
        last_error: msg,
        updated_at: t
    });
}

function parseResolverBody(body, { partial }) {
    const data = {};

    if (!partial || body.provider !== undefined) {
        if (typeof body.provider !== 'string' || !PROVIDERS.has(body.provider)) {
            return {
                error: `provider must be one of: ${[...PROVIDERS].join(', ')}`
            };
        }
        data.provider = body.provider;
    }

    if (!partial || body.name !== undefined) {
        if (typeof body.name !== 'string' || !body.name.trim()) {
            return { error: 'name is required' };
        }
        const name = body.name.trim().slice(0, 128);
        if (!name) return { error: 'name is required' };
        data.name = name;
    }

    if (!partial || body.mode !== undefined) {
        if (typeof body.mode !== 'string' || !MODES.has(body.mode)) {
            return {
                error: `mode must be one of: ${[...MODES].join(', ')}`
            };
        }
        data.mode = body.mode;
    }

    if (!partial || body.enabled !== undefined) {
        if (typeof body.enabled !== 'boolean') {
            return { error: 'enabled must be a boolean' };
        }
        data.enabled = body.enabled;
    }

    if (!partial || body.config !== undefined) {
        if (
            body.config === null ||
            typeof body.config !== 'object' ||
            Array.isArray(body.config)
        ) {
            return { error: 'config must be a plain object' };
        }
        data.config = body.config;
    }

    return { data };
}

function parseKeyBody(body, { partial }) {
    const data = {};

    if (!partial || body.api_key !== undefined) {
        // On create: required. On update: optional (omit / empty = keep existing).
        if (body.api_key === undefined || body.api_key === null || body.api_key === '') {
            if (!partial) {
                return { error: 'api_key is required' };
            }
            // partial update without key change
        } else if (typeof body.api_key !== 'string' || !body.api_key.trim()) {
            return { error: 'api_key is required' };
        } else {
            data.api_key = body.api_key.trim().slice(0, 512);
        }
    }

    if (!partial || body.label !== undefined) {
        if (body.label === null || body.label === undefined || body.label === '') {
            data.label = null;
        } else if (typeof body.label === 'string') {
            data.label = body.label.trim().slice(0, 128) || null;
        } else {
            return { error: 'label must be a string or null' };
        }
    }

    if (!partial || body.priority !== undefined) {
        const p = Number(body.priority);
        if (!Number.isFinite(p) || p < 0 || p > 1_000_000) {
            return { error: 'priority must be a non-negative number' };
        }
        data.priority = Math.floor(p);
    }

    if (!partial || body.enabled !== undefined) {
        if (typeof body.enabled !== 'boolean') {
            return { error: 'enabled must be a boolean' };
        }
        data.enabled = body.enabled;
    }

    if (!partial || body.auto_sync !== undefined) {
        if (typeof body.auto_sync !== 'boolean') {
            return { error: 'auto_sync must be a boolean' };
        }
        data.auto_sync = body.auto_sync;
    }

    if (!partial || body.period_limit !== undefined) {
        const lim = Number(body.period_limit);
        if (!Number.isFinite(lim) || lim < 0 || lim > 10_000_000) {
            return { error: 'period_limit must be a non-negative number' };
        }
        data.period_limit = Math.floor(lim);
    }

    if (!partial || body.period_ms !== undefined) {
        const ms = Number(body.period_ms);
        if (!Number.isFinite(ms) || ms < 60_000 || ms > 30 * 86400000) {
            return {
                error: 'period_ms must be between 60000 and 30 days in ms'
            };
        }
        data.period_ms = Math.floor(ms);
    }

    return { data };
}

async function loadKeys(resolverId) {
    return ExternalResolverKey.findAll({
        where: { resolver_id: resolverId },
        order: [
            ['priority', 'ASC'],
            ['id', 'ASC']
        ]
    });
}

class ExternalResolversService {
    /* ------------------------------------------------------------------ */
    /*                         Resolvers CRUD                             */
    /* ------------------------------------------------------------------ */

    async list(query) {
        const result = await listQuery(
            query,
            LIST_SCHEMA,
            ({ where, order, limit, offset }) =>
                ExternalResolver.findAndCountAll({
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
        result.items = (result.items ?? []).map(row => serializeResolver(row));
        return result;
    }

    async getById(rawId, { includeKeys = true } = {}) {
        const id = parseId(rawId);
        if (!id) throw httpError('Invalid id', 400);

        const row = await ExternalResolver.findByPk(id);
        if (!row) throw httpError('External resolver not found', 404);

        const keys = includeKeys ? await loadKeys(id) : null;
        return serializeResolver(row, keys);
    }

    async create(body) {
        const parsed = parseResolverBody(body ?? {}, { partial: false });
        if (parsed.error) throw httpError(parsed.error, 400);

        const t = now();
        const data = {
            provider: parsed.data.provider,
            name: parsed.data.name,
            mode: parsed.data.mode ?? EXTERNAL_RESOLVER_MODES.MANUAL_ONLY,
            enabled:
                parsed.data.enabled !== undefined ? parsed.data.enabled : true,
            config: parsed.data.config ?? {},
            created_at: t,
            updated_at: t
        };

        try {
            const row = await ExternalResolver.create(data);
            return { ...serializeResolver(row, []), status: 201 };
        } catch (err) {
            raiseSequelize(err);
        }
    }

    async update(rawId, body) {
        const id = parseId(rawId);
        if (!id) throw httpError('Invalid id', 400);

        const row = await ExternalResolver.findByPk(id);
        if (!row) throw httpError('External resolver not found', 404);

        const parsed = parseResolverBody(body ?? {}, { partial: true });
        if (parsed.error) throw httpError(parsed.error, 400);
        if (!Object.keys(parsed.data).length) {
            return this.getById(id);
        }

        // Provider is immutable after create (avoids mixed key/provider mess)
        if (
            parsed.data.provider !== undefined &&
            parsed.data.provider !== row.provider
        ) {
            throw httpError('provider cannot be changed', 400);
        }
        delete parsed.data.provider;

        parsed.data.updated_at = now();
        try {
            await row.update(parsed.data);
        } catch (err) {
            raiseSequelize(err);
        }
        return this.getById(id);
    }

    async remove(rawId) {
        const id = parseId(rawId);
        if (!id) throw httpError('Invalid id', 400);

        const row = await ExternalResolver.findByPk(id);
        if (!row) throw httpError('External resolver not found', 404);

        await ExternalResolverKey.destroy({ where: { resolver_id: id } });
        await row.destroy();
        return { ok: true, id };
    }

    /* ------------------------------------------------------------------ */
    /*                            Keys CRUD                               */
    /* ------------------------------------------------------------------ */

    async listKeys(rawResolverId) {
        const resolverId = parseId(rawResolverId);
        if (!resolverId) throw httpError('Invalid resolver id', 400);

        const resolver = await ExternalResolver.findByPk(resolverId);
        if (!resolver) throw httpError('External resolver not found', 404);

        const keys = await loadKeys(resolverId);
        return { data: keys.map(serializeKey) };
    }

    async createKey(rawResolverId, body) {
        const resolverId = parseId(rawResolverId);
        if (!resolverId) throw httpError('Invalid resolver id', 400);

        const resolver = await ExternalResolver.findByPk(resolverId);
        if (!resolver) throw httpError('External resolver not found', 404);

        const parsed = parseKeyBody(body ?? {}, { partial: false });
        if (parsed.error) throw httpError(parsed.error, 400);

        const t = now();
        const autoSync =
            parsed.data.auto_sync !== undefined ? parsed.data.auto_sync : true;
        const periodMs =
            parsed.data.period_ms ?? EXTERNAL_RESOLVER_DEFAULT_PERIOD_MS;
        const periodStart = autoSync ? t : midnightAlignedPeriodStart(t, periodMs);
        const data = {
            resolver_id: resolverId,
            api_key: parsed.data.api_key,
            label: parsed.data.label ?? null,
            priority: parsed.data.priority ?? 0,
            enabled:
                parsed.data.enabled !== undefined ? parsed.data.enabled : true,
            auto_sync: autoSync,
            period_limit: parsed.data.period_limit ?? 0,
            used_count: 0,
            period_start: periodStart,
            period_ms: periodMs,
            last_error: null,
            last_used_at: null,
            created_at: t,
            updated_at: t
        };

        try {
            const row = await ExternalResolverKey.create(data);
            return { ...serializeKey(row), status: 201 };
        } catch (err) {
            raiseSequelize(err);
        }
    }

    async updateKey(rawResolverId, rawKeyId, body) {
        const resolverId = parseId(rawResolverId);
        const keyId = parseId(rawKeyId);
        if (!resolverId || !keyId) throw httpError('Invalid id', 400);

        const key = await ExternalResolverKey.findOne({
            where: { id: keyId, resolver_id: resolverId }
        });
        if (!key) throw httpError('API key not found', 404);

        const parsed = parseKeyBody(body ?? {}, { partial: true });
        if (parsed.error) throw httpError(parsed.error, 400);
        if (!Object.keys(parsed.data).length) {
            return serializeKey(key);
        }

        // Switching to manual period: align window to local midnight
        if (parsed.data.auto_sync === false) {
            const periodMs =
                parsed.data.period_ms ??
                (Number(key.period_ms) || EXTERNAL_RESOLVER_DEFAULT_PERIOD_MS);
            parsed.data.period_start = midnightAlignedPeriodStart(
                now(),
                periodMs
            );
        }

        parsed.data.updated_at = now();
        try {
            await key.update(parsed.data);
        } catch (err) {
            raiseSequelize(err);
        }
        await key.reload();
        return serializeKey(key);
    }

    async removeKey(rawResolverId, rawKeyId) {
        const resolverId = parseId(rawResolverId);
        const keyId = parseId(rawKeyId);
        if (!resolverId || !keyId) throw httpError('Invalid id', 400);

        const key = await ExternalResolverKey.findOne({
            where: { id: keyId, resolver_id: resolverId }
        });
        if (!key) throw httpError('API key not found', 404);

        await key.destroy();
        return { ok: true, id: keyId, resolver_id: resolverId };
    }

    /**
     * Reset used_count / period_start for a key (admin action).
     */
    async resetKeyUsage(rawResolverId, rawKeyId) {
        const resolverId = parseId(rawResolverId);
        const keyId = parseId(rawKeyId);
        if (!resolverId || !keyId) throw httpError('Invalid id', 400);

        const key = await ExternalResolverKey.findOne({
            where: { id: keyId, resolver_id: resolverId }
        });
        if (!key) throw httpError('API key not found', 404);

        const t = now();
        const periodMs =
            Number(key.period_ms) || EXTERNAL_RESOLVER_DEFAULT_PERIOD_MS;
        const periodStart =
            key.auto_sync === false
                ? midnightAlignedPeriodStart(t, periodMs)
                : t;
        await key.update({
            used_count: 0,
            period_start: periodStart,
            last_error: null,
            updated_at: t
        });
        await key.reload();
        return serializeKey(key);
    }

    /* ------------------------------------------------------------------ */
    /*                     Manual lookup + usage sync                     */
    /* ------------------------------------------------------------------ */

    /**
     * Manual DNS lookup via provider queue.
     * Body: { domain, type?: 'a'|'aaaa' }  (default 'a')
     */
    async lookup(rawResolverId, body) {
        const resolverId = parseId(rawResolverId);
        if (!resolverId) throw httpError('Invalid resolver id', 400);

        const resolver = await ExternalResolver.findByPk(resolverId);
        if (!resolver) throw httpError('External resolver not found', 404);
        if (!resolver.enabled) {
            throw httpError('External resolver is disabled', 400);
        }

        const domain =
            typeof body?.domain === 'string' ? body.domain.trim() : '';
        if (!domain) throw httpError('domain is required', 400);

        let type = typeof body?.type === 'string' ? body.type.toLowerCase() : 'a';
        if (type !== 'a' && type !== 'aaaa') {
            throw httpError("type must be 'a' or 'aaaa'", 400);
        }

        if (resolver.provider === EXTERNAL_RESOLVER_PROVIDERS.MXTOOLBOX) {
            return this.#lookupMxtoolbox(resolver, domain, type);
        }

        throw httpError(`Unsupported provider: ${resolver.provider}`, 400);
    }

    async #lookupMxtoolbox(resolver, domain, type) {
        const maxAttempts = 8;
        let lastError = null;

        for (let attempt = 0; attempt < maxAttempts; attempt++) {
            const key = await pickNextKey(resolver.id);
            if (!key) {
                throw httpError(
                    lastError
                        ? `No API keys with remaining quota (${lastError})`
                        : 'No API keys with remaining quota',
                    429
                );
            }

            try {
                const raw = await mxLookup(key.api_key, type, domain);
                await incrementKeyUsage(key);

                const parsed = parseMxInformation(raw?.Information);
                return {
                    provider: EXTERNAL_RESOLVER_PROVIDERS.MXTOOLBOX,
                    resolver_id: resolver.id,
                    key_id: key.id,
                    domain: domain.replace(/\.$/, ''),
                    type,
                    a: parsed.a,
                    aaaa: parsed.aaaa,
                    cnames: parsed.cnames,
                    raw,
                    is_error: !!raw?.IsError
                };
            } catch (err) {
                const msg = err?.message || String(err);
                await markKeyError(key, msg);
                lastError = msg;

                // Hard rate-limit from provider: treat this key as exhausted for the period
                if (isLimitError(msg) || err?.status === 429) {
                    const limit = Number(key.period_limit) || 0;
                    if (limit > 0) {
                        await key.update({
                            used_count: limit,
                            updated_at: now()
                        });
                    }
                    continue;
                }

                // Auth / permanent key errors: disable key so queue skips it
                if (err?.status === 401 || err?.status === 403) {
                    await key.update({
                        enabled: false,
                        updated_at: now()
                    });
                    continue;
                }

                throw httpError(msg, err?.status && err.status < 500 ? err.status : 502);
            }
        }

        throw httpError(
            lastError
                ? `All API keys failed (${lastError})`
                : 'All API keys failed',
            429
        );
    }

    /**
     * Sync local counters from provider Usage API for all keys of a resolver.
     * Updates period_limit (DnsMax) and used_count (DnsRequests) when available.
     */
    async syncUsage(rawResolverId) {
        const resolverId = parseId(rawResolverId);
        if (!resolverId) throw httpError('Invalid resolver id', 400);

        const resolver = await ExternalResolver.findByPk(resolverId);
        if (!resolver) throw httpError('External resolver not found', 404);

        if (resolver.provider !== EXTERNAL_RESOLVER_PROVIDERS.MXTOOLBOX) {
            throw httpError(
                `Usage sync not supported for provider: ${resolver.provider}`,
                400
            );
        }

        const keys = await loadKeys(resolverId);
        const results = [];

        for (const key of keys) {
            if (!key.enabled) {
                results.push({
                    key_id: key.id,
                    ok: false,
                    skipped: true,
                    reason: 'disabled'
                });
                continue;
            }

            if (key.auto_sync === false) {
                results.push({
                    key_id: key.id,
                    ok: false,
                    skipped: true,
                    reason: 'auto_sync_disabled'
                });
                continue;
            }

            try {
                const usage = await fetchMxUsage(key.api_key);
                const max = Number(usage.DnsMax) || 0;
                const used = Number(usage.DnsRequests) || 0;
                const t = now();

                await key.update({
                    period_limit: max > 0 ? max : key.period_limit,
                    used_count: used,
                    period_start: t,
                    last_error: null,
                    updated_at: t
                });
                await key.reload();

                results.push({
                    key_id: key.id,
                    ok: true,
                    remaining: mxRemaining(usage),
                    usage,
                    key: serializeKey(key)
                });
            } catch (err) {
                const msg = err?.message || String(err);
                await markKeyError(key, msg);
                results.push({
                    key_id: key.id,
                    ok: false,
                    error: msg
                });
            }
        }

        return {
            resolver_id: resolverId,
            provider: resolver.provider,
            results
        };
    }

    /**
     * Background: sync usage for every enabled resolver (scheduled).
     */
    async syncAllUsage() {
        const resolvers = await ExternalResolver.findAll({
            where: { enabled: true }
        });

        const summary = [];
        for (const r of resolvers) {
            try {
                if (r.provider === EXTERNAL_RESOLVER_PROVIDERS.MXTOOLBOX) {
                    const res = await this.syncUsage(r.id);
                    summary.push({
                        resolver_id: r.id,
                        ok: true,
                        keys: res.results?.length ?? 0
                    });
                }
            } catch (err) {
                logger.warn(
                    `external resolver usage sync failed id=${r.id}: ${err?.message || err}`
                );
                summary.push({
                    resolver_id: r.id,
                    ok: false,
                    error: err?.message || String(err)
                });
            }
        }
        return summary;
    }

    startUsageSyncScheduler() {
        if (usageSyncTimer) return;
        usageSyncTimer = setInterval(() => {
            void this.syncAllUsage().catch(err => {
                logger.warn(
                    `external resolver scheduled sync error: ${err?.message || err}`
                );
            });
        }, EXTERNAL_RESOLVER_USAGE_SYNC_MS);
        // Don't keep process alive solely for this timer
        if (typeof usageSyncTimer.unref === 'function') {
            usageSyncTimer.unref();
        }
        logger.info(
            `External resolver usage sync every ${EXTERNAL_RESOLVER_USAGE_SYNC_MS}ms`
        );
    }

    stopUsageSyncScheduler() {
        if (usageSyncTimer) {
            clearInterval(usageSyncTimer);
            usageSyncTimer = null;
        }
    }
}

function isLimitError(message) {
    const m = String(message).toLowerCase();
    return (
        m.includes('limit') ||
        m.includes('quota') ||
        m.includes('rate') ||
        m.includes('exceed') ||
        m.includes('too many') ||
        m.includes('throttle') ||
        m.includes('429') ||
        m.includes('daily')
    );
}

export default new ExternalResolversService();
