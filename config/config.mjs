import { CACHE_LEVELS } from "./constants.mjs";

export const config = {

    server: {
        ip: process.env.SERVER_IP ?? '127.0.0.1',
        port: Number(process.env.SERVER_PORT ?? 53),
        ptrHostname: process.env.PTR_HOSTNAME ?? 'localhost.com',
        debugPrefix: process.env.DEBUG_PREFIX ?? '_.'
    },

    dns: {
        port: Number(process.env.DNS_PORT ?? 53),
        ttl: Number(process.env.DNS_TTL ?? 60),
        timeout: Number(process.env.DNS_TIMEOUT ?? 8000)
    },

    cache: {
        level: process.env.CACHE_LEVEL ?? CACHE_LEVELS.CUSTOM_ONLY,
        expireTime: process.env.CACHE_EXPIRE_TIME ?? 60,
        flushInterval: Number(process.env.FLUSH_INTERVAL_MS ?? 60000),
        filterIps: (process.env.FILTER_IPS ?? '')
            .split(/\s+/)
            .filter(Boolean)
    }

};