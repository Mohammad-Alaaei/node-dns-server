import 'dotenv/config';
import { CACHE_LEVELS } from './constants.mjs';

function parseIpList(value) {
    return (value ?? '')
        .split(/[\s,]+/)
        .map(s => s.trim())
        .filter(Boolean);
}

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
        expireTime: Number(process.env.CACHE_EXPIRE_TIME ?? 60),
        flushInterval: Number(process.env.FLUSH_INTERVAL_MS ?? 60000),
        filterIps: parseIpList(process.env.FILTER_IPS)
    },

    ignoreIps: parseIpList(process.env.IGNORE_IPS),

    db: {
        host: process.env.DB_HOST ?? '127.0.0.1',
        port: Number(process.env.DB_PORT ?? 3306),
        name: process.env.DB_NAME ?? 'dns_server',
        user: process.env.DB_USER ?? 'dns',
        password: process.env.DB_PASSWORD ?? '',
        pool: {
            max: Number(process.env.DB_POOL_MAX ?? 10),
            min: Number(process.env.DB_POOL_MIN ?? 0),
            acquire: Number(process.env.DB_POOL_ACQUIRE ?? 30000),
            idle: Number(process.env.DB_POOL_IDLE ?? 10000)
        },
        logging: process.env.DB_LOGGING === 'true'
    }

};

export default config;