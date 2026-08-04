import { findCustomDnsServer, getDefaultDnsServer } from '../memory/resolver.mjs';
import { config } from '../config/config.mjs';
import { CACHE_LEVELS } from '../config/constants.mjs';

const CACHE_LEVEL = config.cache.level;

/**
 * ALL           → cache every upstream answer
 * CUSTOM_ONLY   → cache ONLY answers from a custom upstream
 * FILTERED_ONLY → accept into pipeline; cache_service marks FILTERED by IP
 * NONE          → never cache
 */
function computeShouldCache(isCustom) {
    switch (CACHE_LEVEL) {
        case CACHE_LEVELS.NONE:
            return false;
        case CACHE_LEVELS.ALL:
            return true;
        case CACHE_LEVELS.CUSTOM_ONLY:
            return !!isCustom;
        case CACHE_LEVELS.FILTERED_ONLY:
            return true;
        default:
            return false;
    }
}

export function selectUpstream(domain, preferredServer = null) {

    const custom = findCustomDnsServer(domain);

    if (preferredServer) {
        return {
            server: preferredServer,
            custom: !!custom,
            shouldCache: computeShouldCache(!!custom)
        };
    }

    const server = custom ?? getDefaultDnsServer();

    return {
        server,
        custom: !!custom,
        shouldCache: computeShouldCache(!!custom)
    };
}