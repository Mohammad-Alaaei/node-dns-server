import { config } from './config/config.mjs';

import { createSchema } from './database/schema.mjs';
import {
    loadRecords,
    loadDnsServers,
    loadRewriteRules,
    loadSystemSettings
} from './database/repository.mjs';
import { close as closeDatabase } from './database/connection.mjs';

import * as logger from './utils/logger.mjs';
import * as cacheService from './services/cache_service.mjs';

import { startServer, stopServer } from './server/dns_server.mjs';
import { startApi, stopApi } from './server/api/index.mjs';
import { store } from './memory/store.mjs';
import { CACHE_LEVELS } from './config/constants.mjs';

const SERVER_IP = config.server.ip;
const SERVER_IPV6 = config.server.ipv6;
const SERVER_PORT = config.server.port;

let shuttingDown = false;

async function main() {
    await createSchema();
    await loadSystemSettings();

    await loadRecords();
    await loadDnsServers();
    await loadRewriteRules();

    store.regexRecords.sort((a, b) => b.domain.length - a.domain.length);
    store.rewriteRules.sort((a, b) => b.pattern.length - a.pattern.length);

    // Always init logger (errors / app messages). Upstream answer lines
    // are gated by CACHE_LEVEL inside response_parser.
    await logger.init();

    if (config.system.cache.level !== CACHE_LEVELS.NONE) {
        await cacheService.init();
    }

    await startApi();
    await startServer(SERVER_IP, SERVER_PORT, SERVER_IPV6);
}

/**
 * Single, ordered graceful shutdown.
 *
 * Order matters:
 * 1. Stop accepting new DNS / API work
 * 2. Drain in-flight DNS requests + close UDP socket
 * 3. Close HTTP API
 * 4. Flush cache to DB
 * 5. Close DB pool
 * 6. Flush logger
 * 7. Exit
 */
async function shutdown(signal) {
    if (shuttingDown) {
        return;
    }
    shuttingDown = true;

    logger.info(`Shutting down (${signal})…`);

    try {
        // 1–2. DNS: no new packets, drain active handlers, close socket
        await stopServer();

        // 3. HTTP API
        await stopApi();

        // 4. Persist any pending cache rows
        if (config.system.cache.level !== CACHE_LEVELS.NONE) {
            await cacheService.shutdown();
        }

        // 5. DB
        await closeDatabase();

        // 6. Logger (last, so previous steps can still log)
        await logger.shutdown();
    } catch (err) {
        console.error(err);
        try {
            logger.error(err);
        } catch {
            // logger may already be closed
        }
    }

    console.log('GOOD BYE!');
    process.exit(0);
}

process.once('SIGINT', () => void shutdown('SIGINT'));
process.once('SIGTERM', () => void shutdown('SIGTERM'));

main().catch(err => {
    console.error(err);
    try {
        logger.error(err);
    } catch {
        // ignore
    }
    process.exit(1);
});
