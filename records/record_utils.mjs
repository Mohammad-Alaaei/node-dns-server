import * as logger from '../utils/logger.mjs';
import { config } from '../config/config.mjs';
import { findRecord } from '../memory/resolver.mjs';
import { appendDebugRecords, createRecordResponse } from '../server/response_builder.mjs';
import { handleExternalRequests } from '../services/upstream_service.mjs';
import { Packet } from 'dns2';

const SERVER_IP = config.server.ip;

function selectServer(record, type) {
    
    // LOCAL records are authoritative.
    if (record.source === 'LOCAL') {
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

    const server = selectServer(record, type);

    if (!server) {
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
        ...server.CNAME.map(r => `CNAME=${r.domain}`),
        ...server.A.map(r => `A=${r.address}`),
        ...server.AAAA.map(r => `AAAA=${r.address}`)
    ];

    logger.info(`FOUND: ${answers.join(', ')}`);
    console.log('=============');
    // =========================

    const packet = createRecordResponse(
        request,
        {
            ...record,
            A: server.A,
            AAAA: server.AAAA,
            CNAME: server.CNAME
        },
        server,
        type
    );

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