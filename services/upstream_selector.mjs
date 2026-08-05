import { findCustomDnsServer, getDefaultDnsServer } from '../memory/resolver.mjs';

/**
 * Pick upstream server for a domain.
 * Cache/log decisions are made later in response_parser (need answer IPs
 * for FILTERED_ONLY), using isCustom from this result.
 */
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
