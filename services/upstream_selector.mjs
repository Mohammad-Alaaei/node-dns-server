import { findCustomDnsServer, getDefaultDnsServer } from '../memory/resolver.mjs';
import { config } from '../config/config.mjs';
import { CACHE_LEVELS } from '../config/constants.mjs';

const CACHE_LEVEL = config.cache.level;

export function selectUpstream(domain) {

    const custom = findCustomDnsServer(domain);
    const server = custom ?? getDefaultDnsServer();

    const shouldCache =
        !custom &&
        CACHE_LEVEL !== CACHE_LEVELS.NONE;

    return {
        server,
        custom: !!custom,
        shouldCache,
        dnsServerId: server.id
    };
}