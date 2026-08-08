import 'dotenv/config';
import { CACHE_LEVELS } from './constants.mjs';

function parseIpList(value) {
    return (value ?? '')
        .split(/[\s,]+/)
        .map(s => s.trim())
        .filter(Boolean);
}

/**
 * Single source of truth for app configuration.
 *
 * - Top-level `server.ip/port`, `dns.port`, `db`, `api`, `admin` → secrets / infra from .env only.
 * - `config.system` → operational settings (defaults from .env, then live values from DB user_id=0).
 * - `config.ui` → default UI prefs for new user settings blobs.
 *
 * After `loadSystemSettings()` in repository, read operational knobs via `config.system.*`.
 */
export const config = {

    // Bind address (infra — not in settings DB)
    server: {
        ip: process.env.SERVER_IP ?? '127.0.0.1',
        port: Number(process.env.SERVER_PORT ?? 53)
    },

    // Upstream query port only (infra)
    dns: {
        port: Number(process.env.DNS_PORT ?? 53)
    },

    /**
     * Operational settings — baseline from env, then overwritten in-place by
     * repository.loadSystemSettings() from settings.user_id = 0.
     * This object is the runtime source of truth for cache/DNS behaviour.
     */
    system: {
        cache: {
            level: process.env.CACHE_LEVEL ?? CACHE_LEVELS.ALL,
            expireTime: Number(process.env.CACHE_EXPIRE_TIME ?? 60),
            flushInterval: Number(process.env.FLUSH_INTERVAL_MS ?? 60000),
            filterIps: parseIpList(process.env.FILTER_IPS)
        },
        ignoreIps: parseIpList(process.env.IGNORE_IPS),
        dns: {
            ttl: Number(process.env.DNS_TTL ?? 60),
            timeout: Number(process.env.DNS_TIMEOUT ?? 8000)
        },
        server: {
            ptrHostname: process.env.PTR_HOSTNAME ?? 'localhost.com',
            debugPrefix: process.env.DEBUG_PREFIX ?? '_.'
        }
    },

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
        jwtExpiresIn: process.env.API_JWT_EXPIRES_IN ?? '15m',
        refreshExpiresIn: process.env.API_REFRESH_EXPIRES_IN ?? '7d',
        rsaPublicKey: process.env.API_RSA_PUBLIC_KEY
            ? process.env.API_RSA_PUBLIC_KEY.replace(/\\n/g, '\n')
            : null,
        rsaPrivateKey: process.env.API_RSA_PRIVATE_KEY
            ? process.env.API_RSA_PRIVATE_KEY.replace(/\\n/g, '\n')
            : null
    },

    admin: {
        username: process.env.ADMIN_USERNAME ?? 'admin',
        password: process.env.ADMIN_PASSWORD ?? ''
    },

    /** Defaults for per-user settings JSON (user_id >= 1). */
    ui: {
        language: process.env.UI_LANGUAGE ?? 'en',
        theme: process.env.UI_THEME ?? 'system',
        darkMode: process.env.UI_DARK_MODE === 'true'
    }

};

/** Snapshot of system defaults (from env) — used by seeds / reset; does not track live mutations. */
export function getSystemSettingsDefaults() {
    return structuredClone(config.system);
}

export function getUserSettingsDefaults() {
    return {
        language: config.ui.language,
        theme: config.ui.theme,
        darkMode: !!config.ui.darkMode
    };
}

export default config;
