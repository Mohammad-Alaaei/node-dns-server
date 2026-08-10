import dgram from 'node:dgram';

import * as logger from '../utils/logger.mjs';
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

    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.bind(port, ip, () => {
            server.removeListener('error', reject);
            logger.info(`DNS server listening on ${ip}:${port}`);
            logger.info('------------------------------------------------');
            resolve();
        });
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

/**
 * Graceful DNS server stop:
 * 1. Reject new requests
 * 2. Drain in-flight handlers
 * 3. Close the UDP socket
 */
async function stopServer() {
    if (shuttingDown) {
        return;
    }

    shuttingDown = true;
    logger.info('Stopping DNS server…');

    // Let in-flight request handlers finish
    if (activeRequests.size > 0) {
        logger.info(`Waiting for ${activeRequests.size} active DNS request(s)…`);
        await Promise.allSettled([...activeRequests]);
    }

    if (server) {
        await new Promise(resolve => {
            server.close(() => resolve());
        });
        server = null;
    }

    logger.info('DNS server stopped');
}

// Keep process-level error logging here (not signal handlers)
process.on('uncaughtException', err => {
    logger.error('[uncaughtException]', err);
});

process.on('unhandledRejection', err => {
    logger.error('[unhandledRejection]', err);
});

export {
    startServer,
    stopServer,
    sendResponse
};
