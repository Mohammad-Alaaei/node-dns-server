import dgram from 'node:dgram';

import { close as closeDatabase } from "../database/sqlite.mjs";
import * as logger from '../utils/logger.mjs';
import * as cacheService from '../services/cache_service.mjs';
import { handleRequest } from './request_router.mjs';

let server = null;
const activeRequests = new Set();

/**
 * Creates and starts the DNS server.
 *
 * @returns {Promise<void>}
 */
async function startServer(ip, port) {
    server = dgram.createSocket('udp4');

    server.on('message', (message, remote) => {
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
}


async function shutdown(signal) {
    logger.info(`${signal} received. Shutting down...`);

    try {
        await new Promise(resolve => server.close(resolve));

        await Promise.allSettled(activeRequests);

        await logger.shutdown();
        await cacheService.shutdown();

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

process.once('uncaughtException', async err => {
    logger.error(err);

    await shutdown('uncaughtException');
});

process.once('unhandledRejection', async err => {
    logger.error(err);

    await shutdown('unhandledRejection');
});

export {
    startServer,
    sendResponse
}