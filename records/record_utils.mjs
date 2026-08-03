import * as logger from '../utils/logger.mjs';
import { config } from '../config/config.mjs';
import { findRecord } from '../memory/resolver.mjs';
import { appendDebugRecords, createRecordResponse } from '../server/response_builder.mjs';
import { handleExternalRequests } from '../services/upstream_service.mjs';
import { Packet } from 'dns2';
import { RECORD_SOURCE } from '../config/constants.mjs';

const SERVER_IP = config.server.ip;

export function selectServer(record, type) {

    // LOCAL records are authoritative.
    if (record.source === RECORD_SOURCE.LOCAL) {
        return record.servers[0] ?? null;
    }

    const now = Date.now();

    // selected server first
    let server = record.servers.find(s =>
        s.selected &&
        !s.isStale &&
        (
            s[type].some(r => r.expiresAt > now) ||
            s.CNAME.some(r => r.expiresAt > now)
        )
    );

    if (server) {
        return server;
    }

    // any valid server
    server = record.servers.find(s =>
        !s.isStale &&
        (
            s[type].some(r => r.expiresAt > now) ||
            s.CNAME.some(r => r.expiresAt > now)
        )
    );

    if (server) {
        return server;
    }

    // newest stale
    return record.servers
        .filter(s =>
            s.isStale &&
            (
                s[type].length ||
                s.CNAME.length
            )
        )
        .sort((a, b) => b.lastSuccessAt - a.lastSuccessAt)[0] ?? null;
}

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

    const { packet, server, answers } = createRecordResponse(
        request,
        record,
        type
    );

    if (!server || (
        !server[type].length &&
        !server.CNAME.length
    )) {
        return handleExternalRequests(
            request,
            message,
            domain,
            type,
            debug
        );
    }

    const inlineAnswers = answers.join(', ');
    logger.info(`FOUND: ${inlineAnswers ? inlineAnswers : '[N/A]'}`);
    console.log('=============');
    // =========================

    if (debug) {
        const debugAnswers = packet.answers.map(answer => {
            switch (answer.type) {
                case Packet.TYPE.A:
                case Packet.TYPE.AAAA:
                    return answer.address;

                case Packet.TYPE.CNAME:
                case Packet.TYPE.PTR:
                    return answer.domain;

                case Packet.TYPE.MX:
                    return answer.exchange;

                default:
                    return null;
            }

        }).filter(Boolean);

        appendDebugRecords(packet, request, {
            resolver: 'Local',
            server: SERVER_IP,
            type,
            answers: debugAnswers
        });
    }

    return {
        packet,
        buffer: null
    };
}