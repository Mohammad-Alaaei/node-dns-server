import dgram from 'node:dgram';

import * as logger from '../utils/logger.mjs';
import { handleRequest } from './request_router.mjs';

/** @type {import('node:dgram').Socket | null} */
let server4 = null;
/** @type {import('node:dgram').Socket | null} */
let server6 = null;

const activeRequests = new Set();
let shuttingDown = false;

/**
 * Attach shared message / error handlers to a UDP socket.
 * @param {import('node:dgram').Socket} sock
 */
function attachHandlers(sock) {
    sock.on('message', (message, remote) => {
        if (shuttingDown) {
            return;
        }

        const promise = handleRequest(message, remote)
            .catch(logger.error)
            .finally(() => activeRequests.delete(promise));

        activeRequests.add(promise);
    });

    sock.on('error', err => {
        logger.error(err);
    });
}

/**
 * Bind one UDP socket. Rejects on hard errors (e.g. EADDRINUSE).
 *
 * @param {'udp4'|'udp6'} type
 * @param {string} address
 * @param {number} port
 * @returns {Promise<import('node:dgram').Socket>}
 */
function bindSocket(type, address, port) {
    return new Promise((resolve, reject) => {
        const sock = dgram.createSocket({
            type,
            // Allow independent IPv4 + IPv6 binds on the same port
            ipv6Only: type === 'udp6'
        });

        attachHandlers(sock);

        sock.once('error', reject);
        sock.bind(port, address, () => {
            sock.removeListener('error', reject);
            logger.info(`DNS server listening on ${address}:${port} (${type})`);
            resolve(sock);
        });
    });
}

/**
 * Creates and starts the DNS server (IPv4 + optional IPv6).
 * API is unchanged — only DNS UDP sockets are dual-stack.
 *
 * @param {string} ipv4
 * @param {number} port
 * @param {string|null|undefined} ipv6  null/empty → skip IPv6 bind
 * @returns {Promise<void>}
 */
async function startServer(ipv4, port, ipv6 = '::') {
    server4 = await bindSocket('udp4', ipv4, port);

    if (ipv6 != null && String(ipv6).trim() !== '') {
        try {
            server6 = await bindSocket('udp6', String(ipv6).trim(), port);
        } catch (err) {
            // Missing IPv6 stack / permission — keep serving IPv4
            logger.warn(
                `DNS IPv6 bind failed (${ipv6}:${port}): ${err.code ?? err.message}. Continuing IPv4-only.`
            );
            server6 = null;
        }
    }

    logger.info('------------------------------------------------');
}

/**
 * Pick the socket that matches the client's address family.
 * @param {import('node:dgram').RemoteInfo} remote
 */
function socketForRemote(remote) {
    if (remote.family === 'IPv6' || remote.family === 6) {
        return server6 ?? server4;
    }
    return server4 ?? server6;
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
    if (shuttingDown) {
        return;
    }

    const sock = socketForRemote(remote);
    if (!sock) {
        return;
    }

    try {
        const payload = response.packet
            ? response.packet.toBuffer()
            : response.buffer;

        if (!payload) {
            return;
        }

        sock.send(payload, remote.port, remote.address);
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
 * 3. Close UDP sockets
 */
async function stopServer() {
    if (shuttingDown) {
        return;
    }

    shuttingDown = true;
    logger.info('Stopping DNS server…');

    if (activeRequests.size > 0) {
        logger.info(`Waiting for ${activeRequests.size} active DNS request(s)…`);
        await Promise.allSettled([...activeRequests]);
    }

    const closeOne = (sock) =>
        new Promise(resolve => {
            if (!sock) {
                resolve();
                return;
            }
            sock.close(() => resolve());
        });

    await Promise.all([closeOne(server4), closeOne(server6)]);
    server4 = null;
    server6 = null;

    logger.info('DNS server stopped');
}

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
