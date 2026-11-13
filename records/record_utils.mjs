import * as logger from '../utils/logger.mjs';
import { config } from '../config/config.mjs';
import {
    findRecord,
    findStoredRecord,
    getPreferredServer,
    hasLocalRecord
} from '../memory/resolver.mjs';
import { appendDebugRecords, createRecordResponse, createEmptyResponse } from '../server/response_builder.mjs';
import { handleExternalRequests } from '../services/upstream_service.mjs';
import {
    resolveRewrite,
    injectCnameAnswer,
    cacheRewriteCname,
    MAX_REWRITE_DEPTH
} from '../services/rewrite_service.mjs';
import { Packet } from 'dns2';
import { RECORD_SOURCE, RECORD_STATUS, REWRITE_ACTIONS } from '../config/constants.mjs';

const SERVER_IP = config.server.ip;

export function selectServer(record, type) {

    if (record.source === RECORD_SOURCE.LOCAL) {
        return record.servers[0] ?? null;
    }

    const now = Date.now();

    const isFiltered = (s) =>
        s.status === RECORD_STATUS.FILTERED || s.status === 'FILTERED';

    const hasFresh = (s) =>
        s[type]?.some(r => r.expiresAt > now) ||
        s.CNAME?.some(r => r.expiresAt > now);

    const hasAny = (s) =>
        (s[type]?.length || 0) > 0 || (s.CNAME?.length || 0) > 0;

    // 1. Selected fresh SUCCESS
    let server = record.servers.find(s =>
        s.selected && !isFiltered(s) && !s.isStale && hasFresh(s)
    );
    if (server) return server;

    // 2. Any fresh SUCCESS
    server = record.servers.find(s =>
        !isFiltered(s) && !s.isStale && hasFresh(s)
    );
    if (server) return server;

    // 3. Last good SUCCESS, even if expired/stale.
    //    A filtered refresh must not replace this.
    const success = record.servers
        .filter(s => !isFiltered(s) && hasAny(s))
        .sort((a, b) => (b.lastSuccessAt ?? 0) - (a.lastSuccessAt ?? 0));
    if (success.length) return success[0];

    // 4. FILTERED only when there has never been a SUCCESS
    return record.servers
        .filter(s => isFiltered(s) && hasAny(s))
        .sort((a, b) => (b.lastSuccessAt ?? 0) - (a.lastSuccessAt ?? 0))[0] ?? null;
}

/**
 * Handles record types stored in DB / memory.
 * Optionally applies rewrite rules (e.g. cname_rewrite) before normal lookup.
 */
export async function handleLocalRecord({
    request,
    message,
    domain,
    type,
    debug = false,
    _rewriteDepth = 0
}) {

    // LOCAL is authoritative for the domain. Return only what is defined
    // (or an empty answer). Never forward to upstream, and never let a
    // rewrite rule replace the static answer.
    if (hasLocalRecord(domain)) {
        const record = findRecord(domain, type);

        if (record && record.source === RECORD_SOURCE.LOCAL) {
            const { packet, server, answers } = createRecordResponse(
                request,
                record,
                type
            );

            if (server && (
                server[type].length ||
                server.CNAME.length
            )) {
                const inlineAnswers = answers.join(', ');
                logger.info(`FOUND: ${inlineAnswers ? inlineAnswers : '[N/A]'}`);
                console.log('=============');

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
        }

        logger.info(`LOCAL ${domain} has no ${type}; returning empty`);
        return {
            packet: createEmptyResponse(request),
            buffer: null
        };
    }

    // Rewrite rules run early for A/AAAA/CNAME so the original name is never
    // sent upstream when a cname_rewrite matches.
    if (
        _rewriteDepth < MAX_REWRITE_DEPTH &&
        (type === 'A' || type === 'AAAA' || type === 'CNAME')
    ) {
        const rewrite = resolveRewrite(domain);
        if (rewrite && rewrite.action === REWRITE_ACTIONS.CNAME_REWRITE) {
            logger.info(
                `REWRITE cname: ${domain} → ${rewrite.target}` +
                    (debug ? ' [debug]' : '')
            );

            const targetResult = await handleLocalRecord({
                request,
                message,
                domain: rewrite.target,
                type,
                debug,
                _rewriteDepth: _rewriteDepth + 1
            });

            // Store original domain → synthetic CNAME so it appears in records
            // (upstream cache only writes the rewritten target name).
            cacheRewriteCname(domain, rewrite.target);

            return injectCnameAnswer(
                request,
                domain,
                rewrite.target,
                targetResult,
                debug
            );
        }
    }

    const record = findRecord(domain, type);

    if (record) {

        const { packet, server, answers } = createRecordResponse(
            request,
            record,
            type
        );

        if (server && (
            server[type].length ||
            server.CNAME.length
        )) {

            const inlineAnswers = answers.join(', ');
            logger.info(`FOUND: ${inlineAnswers ? inlineAnswers : '[N/A]'}`);
            console.log('=============');

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
    }

    const stored = findStoredRecord(domain);
    const preferred = stored
        ? getPreferredServer(stored, type)
        : null;

    return handleExternalRequests(
        request,
        message,
        domain,
        type,
        debug,
        preferred
    );
}
