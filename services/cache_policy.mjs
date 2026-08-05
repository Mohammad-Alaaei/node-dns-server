import { config } from '../config/config.mjs';
import { CACHE_LEVELS } from '../config/constants.mjs';

/**
 * Whether this upstream response should be logged AND/OR cached.
 *
 * CACHE_LEVEL gates both behaviors the same way:
 *   ALL           → always
 *   CUSTOM_ONLY   → only if resolved via a custom upstream
 *   FILTERED_ONLY → only if answer contains a FILTER_IPS address
 *   NONE          → never
 *
 * Reads level from config on every call (tests can switch levels).
 *
 * @param {{ isCustom: boolean, isFiltered: boolean }} ctx
 */
export function shouldProcessUpstreamAnswer({ isCustom, isFiltered }) {
    switch (config.cache.level) {
        case CACHE_LEVELS.ALL:
            return true;
        case CACHE_LEVELS.CUSTOM_ONLY:
            return !!isCustom;
        case CACHE_LEVELS.FILTERED_ONLY:
            return !!isFiltered;
        case CACHE_LEVELS.NONE:
        default:
            return false;
    }
}

export function getCacheLevel() {
    return config.cache.level;
}

export function isCacheEnabled() {
    return config.cache.level !== CACHE_LEVELS.NONE;
}