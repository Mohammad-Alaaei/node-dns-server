import 'dotenv/config';

import dgram from 'node:dgram';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { Packet } from 'dns2';

import * as cacher from './cacher.mjs';
import * as logger from './logger.mjs';

/* -------------------------------------------------------------------------- */
/*                                  Constants                                 */
/* -------------------------------------------------------------------------- */

const DEFAULT_DNS = process.env.DEFAULT_DNS ?? '4.2.2.4';
const DOMAIN_FILE = process.env.DOMAIN_FILE ?? 'domains.txt';
const TXT_FILES_DIR = process.env.TXT_FILES_DIR ?? './';
const PTR_HOSTNAME = process.env.PTR_HOSTNAME ?? 'localhost123.com';

const SERVER_IP = process.env.SERVER_IP ?? '127.0.0.1';
const SERVER_PORT = Number(process.env.SERVER_PORT ?? 53);

const DNS_PORT = Number(process.env.DNS_PORT) ?? 53;
const DNS_TTL = Number(process.env.DNS_TTL) ?? 60;

const SERVER_REVERSE_IP = SERVER_IP.split('.').reverse().join('.');

/* -------------------------------------------------------------------------- */
/*                               Global State                                 */
/* -------------------------------------------------------------------------- */

let localDomains = [];
let customDnsServers = [];
let server;

/* -------------------------------------------------------------------------- */
/*                              Loading Helpers                               */
/* -------------------------------------------------------------------------- */

/**
 * Loads local domain rules from the configured domain file.
 *
 * File format:
 *   google.com          1.1.1.1
 *   .*\.spotify\.com    146.75.119.42 146.75.119.43
 *
 * Lines beginning with '#' or empty lines are ignored.
 *
 * @returns {Promise<Array<{
 *   pattern: string,
 *   regex: RegExp,
 *   ips: string[]
 * }>>}
 */
async function loadLocalDomains() {
    const rules = [];

    try {
        const data = await fs.readFile(DOMAIN_FILE, 'utf8');

        for (const line of data.split(/\r?\n/)) {
            const trimmed = line.trim();

            if (!trimmed || trimmed.startsWith('#')) {
                continue;
            }

            const [pattern, ...ips] = trimmed.split(/\s+/);

            if (!pattern || ips.length === 0) {
                continue;
            }

            try {
                rules.push({
                    pattern,
                    regex: new RegExp(pattern, 'i'),
                    ips
                });
            } catch (err) {
                logger.warn(`Ignoring invalid regex "${pattern}"`);
            }
        }

        logger.info(`Loaded ${rules.length} local domain rules from ${DOMAIN_FILE}`);
    } catch (err) {
        logger.error(`Error reading ${DOMAIN_FILE}:`, err);
    }

    return rules;
}

/**
 * Loads all custom DNS server files.
 *
 * Each file name represents a DNS server IP.
 *
 * Example:
 *   8.8.8.8.txt
 *   1.1.1.1.txt
 *
 * @returns {Promise<Array<{
 *   server: string,
 *   domains: Array<{
 *      pattern: string,
 *      regex: RegExp
 *   }>
 * }>>}
 */
async function loadCustomDnsServers() {
    const servers = [];

    try {
        const files = await fs.readdir(TXT_FILES_DIR);

        for (const file of files) {
            if (!file.endsWith('.txt') || file === DOMAIN_FILE) {
                continue;
            }

            const customServer = file.replace(/\.txt$/, '');

            const data = await fs.readFile(
                path.join(TXT_FILES_DIR, file),
                'utf8'
            );

            const domains = [];

            for (const line of data.split('\n')) {
                const trimmed = line.trim();

                if (!trimmed || trimmed.startsWith('#')) {
                    continue;
                }

                domains.push({
                    pattern: trimmed,
                    regex: new RegExp(trimmed, 'i')
                });
            }

            servers.push({
                server: customServer,
                domains
            });
        }
    } catch (err) {
        logger.error('Error reading custom DNS files:', err);
    }

    return servers;
}

/* -------------------------------------------------------------------------- */
/*                              Lookup Helpers                                */
/* -------------------------------------------------------------------------- */

/**
 * Searches local rules for a matching domain.
 *
 * @param {string} domain
 * @returns {{
 *   pattern: string,
 *   regex: RegExp,
 *   ips: string[]
 * } | null}
 */
function findLocalDomain(domain) {
    for (const rule of localDomains) {
        if (rule.regex.test(domain)) {
            return rule;
        }
    }

    return null;
}

/**
 * Finds the custom DNS server responsible for a domain.
 *
 * @param {string} domain
 * @returns {string|null}
 */
function findCustomDnsServer(domain) {
    for (const dns of customDnsServers) {
        for (const rule of dns.domains) {
            if (rule.regex.test(domain)) {
                return dns.server;
            }
        }
    }

    return null;
}

/* -------------------------------------------------------------------------- */
/*                           DNS Response Helpers                             */
/* -------------------------------------------------------------------------- */

/**
 * Creates a DNS response containing one or more IPv4 addresses.
 *
 * @param {object} request Parsed dns2 request.
 * @param {string[]} ips IPv4 addresses.
 * @returns {Buffer}
 */
function createLocalResponse(request, ips) {
    const response = Packet.createResponseFromRequest(request);

    for (const ip of ips) {
        response.answers.push({
            name: request.questions[0].name,
            type: Packet.TYPE.A,
            class: Packet.CLASS.IN,
            ttl: DNS_TTL,
            address: ip
        });
    }

    return response;
}

/**
 * Creates a DNS PTR response.
 *
 * @param {object} request Parsed dns2 request.
 * @param {string} hostname Host name returned for the PTR lookup.
 * @returns {object} dns2 Packet.
 */
function createPtrResponse(request, hostname) {
    const response = Packet.createResponseFromRequest(request);

    response.answers.push({
        name: request.questions[0].name,
        type: Packet.TYPE.PTR,
        class: Packet.CLASS.IN,
        ttl: DNS_TTL,
        domain: hostname
    });

    return response;
}

/**
 * Creates a successful DNS response with no answers.
 *
 * Used when a locally matched domain receives an unsupported query
 * type (currently AAAA).
 *
 * @param {object} request Parsed dns2 request.
 * @returns {Buffer}
 */
function createEmptyResponse(request) {
    const response = Packet.createResponseFromRequest(request);

    response.answers = [];

    return response;
}

/**
 * Sends a DNS response to the client.
 *
 * @param {import('node:dgram').RemoteInfo} remote
 * @param {{packet: object|null, buffer: Buffer|null}} response
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

/* -------------------------------------------------------------------------- */
/*                             External Resolver                              */
/* -------------------------------------------------------------------------- */

/**
 * Sends a DNS request to an upstream DNS server.
 *
 * @param {Buffer} message
 * @param {string} dnsServer
 * @returns {Promise<{
 *   packet: object,
 *   buffer: Buffer
 * }>}
 */
function forwardToExternalDns(message, dnsServer, cacheResult = false) {
    return new Promise((resolve, reject) => {
        const client = dgram.createSocket('udp4');

        const timeout = setTimeout(() => {
            client.close();
            reject(`DNS query timed out (${dnsServer})`);
        }, 8000);

        client.once('error', err => {
            clearTimeout(timeout);
            client.close();
            reject(err);
        });

        client.once('message', responseBuffer => {
            clearTimeout(timeout);
            client.close();

            try {
                const packet = Packet.parse(responseBuffer);
                logResolvedAddresses(packet, cacheResult);

                resolve({
                    packet,
                    buffer: responseBuffer
                });
            } catch (err) {
                reject(err);
            }
        });

        client.send(message, DNS_PORT, dnsServer, err => {
            if (err) {
                client.close();
                reject(err);
            }
        });
    });
}

/**
 * Logs resolved resource records from an external DNS response.
 *
 * @param {object} packet Parsed dns2 packet.
 */
function logResolvedAddresses(packet, cacheResult = false) {
    if (!packet.answers.length) {
        return;
    }

    let ips = [];
    const domain = packet.answers[0].name;

    for (const answer of packet.answers) {
        switch (answer.type) {
            case Packet.TYPE.A:
                logger.info(`Resolved A: ${answer.name} → ${answer.address}`);
                if (cacheResult) {
                    ips.push(answer.address);
                }
                break;

            case Packet.TYPE.AAAA:
                logger.info(`Resolved AAAA: ${answer.name} → ${answer.address}`);
                break;

            case Packet.TYPE.CNAME:
                logger.info(`Resolved CNAME: ${answer.name} → ${answer.domain}`);
                break;

            case Packet.TYPE.PTR:
                logger.info(`Resolved PTR: ${answer.name} → ${answer.domain}`);
                break;

            case Packet.TYPE.MX:
                logger.info(`Resolved MX: ${answer.name} → ${answer.exchange}`);
                break;
        }
    }

    if (cacheResult && ips.length > 0) {
        cacher.upsertDomain(domain, ips);
    }
    console.log('=============');
}

/* -------------------------------------------------------------------------- */
/*                             Request Handlers                               */
/* -------------------------------------------------------------------------- */

async function handleExternalRequests(message, domain, type = null) {
    const dnsServer = findCustomDnsServer(domain) ?? DEFAULT_DNS;

    logger.info(`Forwarding ${type ? type + ' lookup' : 'query'} for ${domain} to ${dnsServer}`);
    console.log('=============');

    const response = await forwardToExternalDns(message, dnsServer, dnsServer !== DEFAULT_DNS);

    return {
        packet: null,
        buffer: response.buffer
    };
}

/**
 * Handles IPv4 DNS queries.
 *
 * @param {object} request Parsed dns2 request.
 * @param {Buffer} message Original UDP packet.
 * @returns {Promise<Buffer>}
 */
async function handleARequest(request, message) {
    const domain = request.questions[0].name;

    const localRule = findLocalDomain(domain);

    if (localRule) {
        logger.info(`FOUND: ${localRule.ips.join(', ')}`);
        console.log('=============');

        return {
            packet: createLocalResponse(request, localRule.ips),
            buffer: null
        };
    }

    return handleExternalRequests(message, domain, 'A');
}

/**
 * Handles IPv6 DNS queries.
 *
 * If the domain exists locally but no IPv6 records are configured,
 * a successful empty response is returned.
 *
 * Otherwise, the request is forwarded upstream.
 *
 * @param {object} request Parsed dns2 request.
 * @param {Buffer} message Original UDP packet.
 * @returns {Promise<Buffer>}
 */
async function handleAAAARequest(request, message) {
    const domain = request.questions[0].name;

    if (findLocalDomain(domain)) {
        logger.info(`Ignoring AAAA lookup for local domain ${domain}`);

        return {
            packet: createEmptyResponse(request),
            buffer: null
        };
    }

    return handleExternalRequests(message, domain, 'AAAA');
}

/**
 * Handles PTR DNS queries.
 *
 * Local reverse lookups are answered with a fake hostname.
 * All other PTR requests are forwarded to the appropriate DNS server.
 *
 * @param {object} request Parsed dns2 request.
 * @param {Buffer} message Original UDP packet.
 * @returns {Promise<{packet: object|null, buffer: Buffer|null}>}
 */
async function handlePtrRequest(request, message) {
    const domain = request.questions[0].name;

    if (domain === `${SERVER_REVERSE_IP}.in-addr.arpa`) {
        return {
            packet: createPtrResponse(request, PTR_HOSTNAME),
            buffer: null
        };
    }

    return handleExternalRequests(message, domain, 'PTR');
}

/**
 * Handles all unsupported DNS record types by forwarding the request
 * to an upstream DNS server.
 *
 * @param {Buffer} message
 * @param {string} domain
 * @returns {Promise<Buffer>}
 */
async function handleOtherRequest(message, domain) {
    return handleExternalRequests(message, domain);
}

/**
 * Handles a DNS request.
 *
 * @param {Buffer} message
 * @param {import('node:dgram').RemoteInfo} remote
 * @returns {Promise<void>}
 */
async function handleRequest(message, remote) {
    try {
        const request = Packet.parse(message);

        if (request.questions.length !== 1) {
            return;
        }

        const question = request.questions[0];
        const domain = question.name;

        logger.info(`domainName: ${domain}`);

        let response;

        switch (question.type) {
            case Packet.TYPE.A:
                response = await handleARequest(request, message);
                break;

            case Packet.TYPE.AAAA:
                response = await handleAAAARequest(request, message);
                break;

            case Packet.TYPE.PTR:
                response = await handlePtrRequest(request, message);
                break;

            default:
                response = await handleOtherRequest(message, domain);
                break;
        }

        sendResponse(remote, response);

    } catch (err) {
        logger.error(err);
    }
}

/* -------------------------------------------------------------------------- */
/*                               DNS Server                                   */
/* -------------------------------------------------------------------------- */

/**
 * Creates and starts the DNS server.
 *
 * @returns {Promise<void>}
 */
async function startServer() {
    server = dgram.createSocket('udp4');

    server.on('message', (message, remote) => {
        handleRequest(message, remote)
            .catch(logger.error);
    });

    server.on('error', err => {
        logger.error(err);
    });

    server.bind(SERVER_PORT, SERVER_IP, () => {
        logger.info(`DNS server listening on ${SERVER_IP}:${SERVER_PORT}`);
        logger.info('------------------------------------------------')
    });
}

/* -------------------------------------------------------------------------- */
/*                                   Shutdown                                 */
/* -------------------------------------------------------------------------- */

async function shutdown(signal) {
    logger.info(`${signal} received. Shutting down...`);

    try {
        await new Promise(resolve => server.close(resolve));
        await Promise.all([
            logger.shutdown(),
            cacher.shutdown()
        ]);
    } finally {
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


/* -------------------------------------------------------------------------- */
/*                                   Main                                     */
/* -------------------------------------------------------------------------- */

/**
 * Application entry point.
 *
 * @returns {Promise<void>}
 */
async function main() {
    await logger.init();
    await cacher.init();

    localDomains = await loadLocalDomains();
    customDnsServers = await loadCustomDnsServers();

    await startServer();
}

main().catch(err => {
    logger.error(err);
    process.exit(1);
});