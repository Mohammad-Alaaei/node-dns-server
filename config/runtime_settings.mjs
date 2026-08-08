/**
 * @deprecated Prefer `config.system` and `database/repository.mjs`.
 * Thin re-exports for any leftover imports.
 */
import { config } from './config.mjs';

export {
    loadSystemSettings,
    getSystemSettings,
    patchSystemSettings,
    getUserSettings,
    patchUserSettings
} from '../database/repository.mjs';

export function getCacheLevel() {
    return config.system.cache.level;
}

export function getCacheExpireTime() {
    return config.system.cache.expireTime;
}

export function getCacheFlushInterval() {
    return config.system.cache.flushInterval;
}

export function getFilterIps() {
    return config.system.cache.filterIps;
}

export function getIgnoreIps() {
    return config.system.ignoreIps;
}

export function getDnsTtl() {
    return config.system.dns.ttl;
}

export function getDnsTimeout() {
    return config.system.dns.timeout;
}

export function getPtrHostname() {
    return config.system.server.ptrHostname;
}

export function getDebugPrefix() {
    return config.system.server.debugPrefix;
}
