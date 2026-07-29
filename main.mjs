import 'dotenv/config';
import { config } from './config/config.mjs';

import { createSchema } from './database/schema.mjs';
import { loadRecords, loadDnsServers } from './database/repository.mjs';

import * as logger from './utils/logger.mjs';
import * as cacheService from './services/cache_service.mjs';

import { startServer } from './server/dns_server.mjs';
import { store } from './memory/store.mjs';
import { CACHE_LEVELS } from './config/constants.mjs';
import { importDomains } from './database/import_domains.mjs';
import { importCustomDnsServers } from './database/import_custom_dns.mjs';

/* -------------------------------------------------------------------------- */
/*                                  Constants                                 */
/* -------------------------------------------------------------------------- */

const CACHE_LEVEL = config.cache.level;

const SERVER_IP = config.server.ip;
const SERVER_PORT = config.server.port;

/* -------------------------------------------------------------------------- */
/*                                   Main                                     */
/* -------------------------------------------------------------------------- */

async function main() {
    await createSchema();

    // await importDomains();
    // await importCustomDnsServers();

    await loadRecords();
    await loadDnsServers();


    store.regexRecords.sort((a, b) => {
        return b.domain.length - a.domain.length;
    });

    await logger.init();

    if (CACHE_LEVEL !== CACHE_LEVELS.NONE) {
        await cacheService.init(CACHE_LEVEL === CACHE_LEVELS.CUSTOM_ONLY
            ? CACHE_LEVELS.ALL
            : CACHE_LEVEL
        );
    }

    await startServer(SERVER_IP, SERVER_PORT);
}

main().catch(err => {
    logger.error(err);
    process.exit(1);
});