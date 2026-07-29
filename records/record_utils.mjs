import * as logger from '../utils/logger.mjs';
import { config } from '../config/config.mjs';
import { findRecord } from '../memory/resolver.mjs';
import { appendDebugRecords, createRecordResponse } from '../server/response_builder.mjs';
import { handleExternalRequests } from '../services/upstream_service.mjs';
import { Packet } from 'dns2';

const SERVER_IP = config.server.ip;

/**
 * Handles record types stored locally.
 *
 * @param {object} options
 * @returns {Promise<{packet: object|null, buffer: Buffer|null}>}
 */
export async function handleLocalRecord({
    request,
    message,
    domain,
    type,
    debug = false
}) {

    const record = findRecord(domain, type);

    if (!record) {

        return handleExternalRequests(
            request,
            message,
            domain,
            type,
            debug
        );
    }

    // TODO: move this to a helper function
    const answers = [
        ...record.CNAME.map(r => `CNAME=${r.domain}`),
        ...record.A.map(r => `A=${r.address}`),
        ...record.AAAA.map(r => `AAAA=${r.address}`)
    ];

    logger.info(`FOUND: ${answers.join(', ')}`);
    console.log('=============');
    // =========================

    const packet = createRecordResponse(
        request,
        record,
        type
    );

    if (debug) {

        appendDebugRecords(packet, request, {
            resolver: 'Local',
            server: SERVER_IP,
            type,
            answers: record[type]
        });
    }

    return {
        packet,
        buffer: null
    };
}