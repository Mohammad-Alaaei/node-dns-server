import { findCustomDnsServer, getDefaultDnsServer } from '../memory/resolver.mjs';
import { config } from '../config/config.mjs';
import { CACHE_LEVELS } from '../config/constants.mjs';

const CACHE_LEVEL = config.cache.level;


export function selectUpstream(domain, preferredServer = null) {

    const custom = findCustomDnsServer(domain);

    if (preferredServer) {
        return {
            server: preferredServer,
            custom: !!custom
        };
    }

    const server = custom ?? getDefaultDnsServer();

    return {
        server,
        custom: !!custom
    };
}