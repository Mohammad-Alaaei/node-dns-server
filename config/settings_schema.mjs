import { CACHE_LEVELS } from './constants.mjs';
import { isIP } from 'node:net';

/**
 * Reserved user_id for system-wide JSON blob (not a real user).
 * Defaults live in config.mjs (getSystemSettingsDefaults / getUserSettingsDefaults).
 * This file only validates patches and shared helpers.
 */
export const SYSTEM_USER_ID = 0;

const CACHE_LEVEL_SET = new Set(Object.values(CACHE_LEVELS));

function asIpList(value) {
    if (Array.isArray(value)) {
        return value.map(String).map(s => s.trim()).filter(Boolean);
    }
    if (typeof value === 'string') {
        return value.split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
    }
    return null;
}

/** Accept IPv4 or IPv6 (node:net isIP → 4 | 6 | 0). */
function validateIpList(list) {
    for (const ip of list) {
        if (!isIP(ip)) {
            return `invalid IP address (IPv4 or IPv6): ${ip}`;
        }
    }
    return null;
}

/**
 * Deep-merge plain objects (arrays replaced, not concatenated).
 */
export function deepMerge(base, patch) {
    if (patch == null || typeof patch !== 'object' || Array.isArray(patch)) {
        return patch !== undefined ? patch : base;
    }

    const out = { ...(base && typeof base === 'object' && !Array.isArray(base) ? base : {}) };

    for (const [k, v] of Object.entries(patch)) {
        if (v != null && typeof v === 'object' && !Array.isArray(v)) {
            out[k] = deepMerge(out[k], v);
        } else if (v !== undefined) {
            out[k] = v;
        }
    }

    return out;
}

/**
 * Validate + normalize a partial system settings patch.
 * Returns { data } or { error }.
 */
export function sanitizeSystemPatch(patch) {
    if (patch == null || typeof patch !== 'object' || Array.isArray(patch)) {
        return { error: 'body must be a JSON object' };
    }

    const data = {};

    if (patch.cache !== undefined) {
        if (patch.cache == null || typeof patch.cache !== 'object') {
            return { error: 'cache must be an object' };
        }
        data.cache = {};

        if (patch.cache.level !== undefined) {
            if (!CACHE_LEVEL_SET.has(patch.cache.level)) {
                return {
                    error: `cache.level must be one of: ${[...CACHE_LEVEL_SET].join(', ')}`
                };
            }
            data.cache.level = patch.cache.level;
        }

        if (patch.cache.expireTime !== undefined) {
            const n = Number(patch.cache.expireTime);
            if (!Number.isFinite(n) || n < 0) {
                return { error: 'cache.expireTime must be a non-negative number' };
            }
            data.cache.expireTime = n;
        }

        if (patch.cache.flushInterval !== undefined) {
            const n = Number(patch.cache.flushInterval);
            if (!Number.isFinite(n) || n < 1000) {
                return { error: 'cache.flushInterval must be >= 1000 (ms)' };
            }
            data.cache.flushInterval = n;
        }

        if (patch.cache.filterIps !== undefined) {
            const list = asIpList(patch.cache.filterIps);
            if (!list) {
                return { error: 'cache.filterIps must be an array of IP strings (IPv4 or IPv6)' };
            }
            const err = validateIpList(list);
            if (err) return { error: err };
            data.cache.filterIps = list;
        }
    }

    if (patch.ignoreIps !== undefined) {
        const list = asIpList(patch.ignoreIps);
        if (!list) {
            return { error: 'ignoreIps must be an array of IP strings (IPv4 or IPv6)' };
        }
        const err = validateIpList(list);
        if (err) return { error: err };
        data.ignoreIps = list;
    }

    if (patch.dns !== undefined) {
        if (patch.dns == null || typeof patch.dns !== 'object') {
            return { error: 'dns must be an object' };
        }
        data.dns = {};

        if (patch.dns.ttl !== undefined) {
            const n = Number(patch.dns.ttl);
            if (!Number.isFinite(n) || n < 0) {
                return { error: 'dns.ttl must be a non-negative number' };
            }
            data.dns.ttl = n;
        }

        if (patch.dns.timeout !== undefined) {
            const n = Number(patch.dns.timeout);
            if (!Number.isFinite(n) || n < 100) {
                return { error: 'dns.timeout must be >= 100 (ms)' };
            }
            data.dns.timeout = n;
        }
    }

    if (patch.server !== undefined) {
        if (patch.server == null || typeof patch.server !== 'object') {
            return { error: 'server must be an object' };
        }
        data.server = {};

        if (patch.server.ptrHostname !== undefined) {
            if (typeof patch.server.ptrHostname !== 'string' || !patch.server.ptrHostname.trim()) {
                return { error: 'server.ptrHostname must be a non-empty string' };
            }
            data.server.ptrHostname = patch.server.ptrHostname.trim();
        }

        if (patch.server.debugPrefix !== undefined) {
            if (typeof patch.server.debugPrefix !== 'string') {
                return { error: 'server.debugPrefix must be a string' };
            }
            data.server.debugPrefix = patch.server.debugPrefix;
        }
    }

    return { data };
}

/**
 * Validate + normalize a partial user settings patch.
 */
export function sanitizeUserPatch(patch) {
    if (patch == null || typeof patch !== 'object' || Array.isArray(patch)) {
        return { error: 'body must be a JSON object' };
    }

    const data = {};

    if (patch.language !== undefined) {
        if (typeof patch.language !== 'string' || !patch.language.trim()) {
            return { error: 'language must be a non-empty string' };
        }
        data.language = patch.language.trim();
    }

    if (patch.theme !== undefined) {
        const allowed = new Set(['system', 'light', 'dark']);
        if (!allowed.has(patch.theme)) {
            return { error: 'theme must be one of: system, light, dark' };
        }
        data.theme = patch.theme;
    }

    if (patch.darkMode !== undefined) {
        data.darkMode = !!patch.darkMode;
    }

    return { data };
}
