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
