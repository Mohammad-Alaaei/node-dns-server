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
        /**
         * Controls BOTH upstream-answer logging and caching.
         * See CACHE_LEVELS in constants.mjs.
         */
        level: process.env.CACHE_LEVEL ?? CACHE_LEVELS.CUSTOM_ONLY,
        expireTime: Number(process.env.CACHE_EXPIRE_TIME ?? 60),
        flushInterval: Number(process.env.FLUSH_INTERVAL_MS ?? 60000),
        /**
         * IPs that classify an answer as FILTERED.
         * Required for FILTERED_ONLY level; also marks source=FILTERED when caching.
         */
        filterIps: parseIpList(process.env.FILTER_IPS)
    },

    /**
     * Extra log suppress list: even when CACHE_LEVEL would log an upstream
     * answer, matching A/AAAA addresses skip the log queue only (cache unchanged).
     */
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
            acquire: Number(process.env.DB_POOL_ACQUIRE || 30000),
            idle: Number(process.env.DB_POOL_IDLE || 10000)
        },
        logging: process.env.DB_LOGGING === 'true'
    },

    api: {
        enabled: process.env.API_ENABLED !== 'false',
        host: process.env.API_HOST ?? '127.0.0.1',
        port: Number(process.env.API_PORT ?? 3000),
        jwtSecret: process.env.API_JWT_SECRET ?? 'change-me-in-production',
        /** Short-lived access token only (no refresh tokens). */
        jwtExpiresIn: process.env.API_JWT_EXPIRES_IN ?? '5m',
        /**
         * Optional persistent RSA PEMs for login password encryption.
         * If unset, a fresh 2048-bit pair is generated each process start
         * (clients must re-fetch /api/auth/public-key after restart).
         */
        rsaPublicKey: process.env.API_RSA_PUBLIC_KEY
            ? process.env.API_RSA_PUBLIC_KEY.replace(/\\n/g, '\n')
            : null,
        rsaPrivateKey: process.env.API_RSA_PRIVATE_KEY
            ? process.env.API_RSA_PRIVATE_KEY.replace(/\\n/g, '\n')
            : null
    },

    /**
     * Bootstrap superadmin — created on API start if no users exist.
     * Set ADMIN_USERNAME + ADMIN_PASSWORD in .env (no registration endpoint).
     */
    admin: {
        username: process.env.ADMIN_USERNAME ?? 'admin',
        password: process.env.ADMIN_PASSWORD ?? ''
    }

};

export default config;