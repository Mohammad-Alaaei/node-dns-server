import dgram from 'node:dgram';

import { close as closeDatabase } from "../database/sqlite.mjs";
import * as logger from '../utils/logger.mjs';
import * as cacheService from '../services/cache_service.mjs';
import { handleRequest } from './request_router.mjs';

let server = null;
const activeRequests = new Set();
let shuttingDown = false;

/**
 * Creates and starts the DNS server.
 *
 * @returns {Promise<void>}
 */
async function startServer(ip, port) {
    server = dgram.createSocket('udp4');

    server.on('message', (message, remote) => {

        if (shuttingDown) {
            return;
        }

        const promise = handleRequest(message, remote)
            .catch(logger.error)
            .finally(() => activeRequests.delete(promise));

        activeRequests.add(promise);
    });

    server.on('error', err => {
        logger.error(err);
    });

    server.bind(port, ip, () => {
        logger.info(`DNS server listening on ${ip}:${port}`);
        logger.info('------------------------------------------------')
    });
}

/**
 * Sends a DNS response to the client.
 *
 * @param {import('node:dgram').RemoteInfo} remote
 * @param {{
 *   packet: object|null,
 *   buffer: Buffer|null
 * }} response
 */
function sendResponse(remote, response) {

    if (shuttingDown || !server) {
        return;
    }

    try {
        if (response.packet) {
            server.send(
                response.packet.toBuffer(),
                remote.port,
                remote.address
            );

            return;
        }

        server.send(
            response.buffer,
            remote.port,
            remote.address
        );

    } catch (err) {
        if (err.code !== 'ERR_SOCKET_DGRAM_NOT_RUNNING') {
            throw err;
        }
    }
}


async function shutdown(signal) {

    if (shuttingDown) {
        return;
    }

    shuttingDown = true;

    logger.info(`${signal} received. Shutting down...`);

    try {

        await Promise.allSettled(activeRequests);

        await cacheService.shutdown();

        await new Promise(resolve => server.close(resolve));

        await logger.shutdown();

    } catch (err) {
        console.error('Error during shutdown.', err);
    } finally {
        await closeDatabase();
        process.exit(0);
    }
}

process.once('SIGINT', () => {
    void shutdown('SIGINT');
});

process.once('SIGTERM', () => {
    void shutdown('SIGTERM');
});

process.on('uncaughtException', async err => {
    logger.error('[uncaughtException]', err);
});

process.on('unhandledRejection', async err => {
    logger.error('[unhandledRejection]', err);
});

export {
    startServer,
    sendResponse
}