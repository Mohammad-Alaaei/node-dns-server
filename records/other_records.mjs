import { config } from '../config/config.mjs';
import { handleExternalRequests } from '../services/upstream_service.mjs';
import * as logger from '../utils/logger.mjs';

/**
 * Handles all unsupported DNS record types by forwarding the request
 * to an upstream DNS server.
 *
 * @param {object} request Parsed dns2 request.
 * @param {Buffer} message Original UDP packet.
 * @param {string} domain
 * @param {string|null} type
 * @param {boolean} debug
 * 
 * @returns {Promise<{
 *   packet: object|null,
 *   buffer: Buffer|null
 * }>}
 */
export async function handleOtherRequest(request, message, domain, type = null, debug = false) {
    return handleExternalRequests(request, message, domain, type, debug);
}