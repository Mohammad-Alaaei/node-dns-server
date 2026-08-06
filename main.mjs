import { config } from './config/config.mjs';

import { createSchema } from './database/schema.mjs';
import { loadRecords, loadDnsServers } from './database/repository.mjs';

import * as logger from './utils/logger.mjs';
import * as cacheService from './services/cache_service.mjs';

import { startServer } from './server/dns_server.mjs';
import { startApi, stopApi } from './server/api/index.mjs';
import { store } from './memory/store.mjs';
import { CACHE_LEVELS } from './config/constants.mjs';

const CACHE_LEVEL = config.cache.level;

const SERVER_IP = config.server.ip;
const SERVER_PORT = config.server.port;

async function main() {
    await createSchema();

    await loadRecords();
    await loadDnsServers();

    store.regexRecords.sort((a, b) => b.domain.length - a.domain.length);

    // Always init logger (errors / app messages). Upstream answer lines
    // are gated by CACHE_LEVEL inside response_parser.
    await logger.init();

    // Cache flusher only when some level may write records
    if (CACHE_LEVEL !== CACHE_LEVELS.NONE) {
        await cacheService.init();
    }

    await startApi();
    await startServer(SERVER_IP, SERVER_PORT);
}

async function shutdown(signal) {
    logger.info(`Shutting down (${signal})…`);
    try {
        await stopApi();

        if (CACHE_LEVEL !== CACHE_LEVELS.NONE) {
            await cacheService.shutdown();
        }

        await logger.shutdown();
    } catch (err) {
        logger.error(err);
    }

    console.log('GOOD BYE!');
    process.exit(0);
}

process.on('SIGINT', () => void shutdown('SIGINT'));
process.on('SIGTERM', () => void shutdown('SIGTERM'));

main().catch(err => {
    logger.error(err);
    process.exit(1);
});
