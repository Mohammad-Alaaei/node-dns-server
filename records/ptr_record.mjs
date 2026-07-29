import { config } from '../config/config.mjs';
import { appendDebugRecords, createPtrResponse } from '../server/response_builder.mjs';
import { handleExternalRequests } from '../services/upstream_service.mjs';
import * as logger from '../utils/logger.mjs';

const PTR_HOSTNAME = config.server.ptrHostname;
const SERVER_IP = config.server.ip;
const SERVER_REVERSE_IP = SERVER_IP.split('.').reverse().join('.');

/**
 * Handles PTR DNS queries.
 *
 * Local reverse lookups are answered with a fake hostname.
 * All other PTR requests are forwarded to the appropriate DNS server.
 *
 */
export async function handlePtrRequest(request, message, domain, debug = false) {
    if (domain === `${SERVER_REVERSE_IP}.in-addr.arpa`) {

        const packet = createPtrResponse(request, PTR_HOSTNAME);

        if (debug) {
            appendDebugRecords(packet, request, {
                resolver: 'Local',
                server: SERVER_IP,
                type: 'PTR',
                answers: [PTR_HOSTNAME]
            });
        }

        return {
            packet,
            buffer: null
        };
    }

    return handleExternalRequests(
        request,
        message,
        domain,
        'PTR',
        debug
    );
}