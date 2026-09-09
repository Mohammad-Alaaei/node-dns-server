import { Packet } from 'dns2';

/**
 * ALL           → log + cache every upstream answer
 * CUSTOM_ONLY   → log + cache only answers from a custom upstream
 * FILTERED_ONLY → log + cache only answers that contain a FILTER_IPS address
 * NONE          → no upstream answer logging, no caching
 *                 (errors / app logs still work)
 */
export const CACHE_LEVELS = {
    ALL: 'ALL',
    CUSTOM_ONLY: 'CUSTOM_ONLY',
    FILTERED_ONLY: 'FILTERED_ONLY',
    NONE: 'NONE'
};

export const DNS_TYPES = {
    ...Object.fromEntries(
        Object.entries(Packet.TYPE).map(([name, value]) => [value, name])
    ),
    65: 'HTTPS'
};

export const RECORD_STATUS = {
    SUCCESS: 'SUCCESS',
    FILTERED: 'FILTERED',
    TIMEOUT: 'TIMEOUT',
    NXDOMAIN: 'NXDOMAIN',
    SERVFAIL: 'SERVFAIL',
    REFUSED: 'REFUSED'
};

export const RECORD_SOURCE = {
    LOCAL: 'LOCAL',
    CACHE: 'CACHE',
    FILTERED: 'FILTERED'
};

/**
 * Upstream DNS server kinds (dns_servers.type).
 * DEFAULT — used for general resolution (round-robin among enabled).
 * CUSTOM  — typically paired with dns_rules for domain-specific routing.
 * Rules may still be attached to either type; the resolver groups by rule domain.
 */
export const DNS_SERVER_TYPE = {
    DEFAULT: 'DEFAULT',
    CUSTOM: 'CUSTOM'
};

/**
 * Rewrite-rule actions (rewrite_rules.action).
 * Start with cname_rewrite; more actions can be added later.
 */
export const REWRITE_ACTIONS = {
    CNAME_REWRITE: 'cname_rewrite'
};

/**
 * External DNS lookup providers (HTTP APIs, not upstream DNS).
 */
export const EXTERNAL_RESOLVER_PROVIDERS = {
    MXTOOLBOX: 'mxtoolbox'
};

/**
 * When an external resolver may be used by the DNS path (future) vs manual only.
 * manual_only — frontend / API lookup only
 * filtered_only / timeout / all — reserved for automated resolve path later
 */
export const EXTERNAL_RESOLVER_MODES = {
    MANUAL_ONLY: 'manual_only',
    FILTERED_ONLY: 'filtered_only',
    TIMEOUT: 'timeout',
    ALL: 'all'
};

/** Default key quota window (1 day). */
export const EXTERNAL_RESOLVER_DEFAULT_PERIOD_MS = 86400000;

/** How often to sync usage counters from provider APIs. */
export const EXTERNAL_RESOLVER_USAGE_SYNC_MS = 15 * 60 * 1000;
